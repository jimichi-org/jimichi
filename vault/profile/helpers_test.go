package profile

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/vault"
)

const testMailbox = "relay-5.jimichi.svc.cluster.local:9000"

var suites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

func eachSuite(t *testing.T, run func(t *testing.T, p *spy)) {
	t.Helper()
	t.Parallel()
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()
			run(t, newSpy(t, provider(t, s)))
		})
	}
}

func provider(t testing.TB, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func otherSuite(s jcrypto.Suite) jcrypto.Suite {
	if s == jcrypto.SuiteGOST {
		return jcrypto.SuiteC25519
	}
	return jcrypto.SuiteGOST
}

// the production stretch costs seconds, so PasswordKey is a DeriveKey of a
// hash of the password, or a fixed W for the golden volume. The spy counts
// the calls, fails the test on a signing call and can hash the transcript of
// every queue to zeroes
type spy struct {
	jcrypto.CryptoProvider
	t testing.TB

	w         []byte
	zeroQueue bool

	mu    sync.Mutex
	calls map[string]int
}

func newSpy(t testing.TB, p jcrypto.CryptoProvider) *spy {
	return &spy{CryptoProvider: p, t: t, calls: map[string]int{}}
}

func (s *spy) count(call string) {
	s.mu.Lock()
	s.calls[call]++
	s.mu.Unlock()
}

func (s *spy) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	s.count("PasswordKey")
	if password == nil || !jcrypto.ValidPassword(password.Bytes()) {
		return nil, jcrypto.ErrBadPassword
	}
	if s.w != nil {
		return secmem.NewFrom(bytes.Clone(s.w))
	}
	h, err := secmem.NewFrom(s.Hash(password.Bytes()))
	if err != nil {
		return nil, err
	}
	defer h.Release()
	return s.DeriveKey(h, "test/password", ctx, s.KeySize())
}

func (s *spy) Hash(data ...[]byte) []byte {
	out := s.CryptoProvider.Hash(data...)
	head := "jimichi/v2/" + s.Suite().String() + "/transcript/mailbox/queue\x00"
	if s.zeroQueue && len(data) == 1 && strings.HasPrefix(string(data[0]), head) {
		clear(out)
	}
	return out
}

func (s *spy) GenerateSigning() (*secmem.Buffer, []byte, error) {
	s.t.Error("GenerateSigning called")
	return s.CryptoProvider.GenerateSigning()
}

func (s *spy) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	s.t.Error("Sign called")
	return s.CryptoProvider.Sign(priv, msg)
}

func (s *spy) Verify(pub, msg, sig []byte) bool {
	s.t.Error("Verify called")
	return s.CryptoProvider.Verify(pub, msg, sig)
}

func password(t testing.TB, s string) *secmem.Buffer {
	t.Helper()
	b, err := secmem.NewFrom([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Release)
	return b
}

func queue(t testing.TB) [e2e.QueueSize]byte {
	t.Helper()
	var q [e2e.QueueSize]byte
	if _, err := rand.Read(q[:]); err != nil {
		t.Fatal(err)
	}
	q[0] |= 1
	return q
}

// the card of another client of the suite on the mailbox
func peerCard(t testing.TB, p jcrypto.CryptoProvider, addr string) e2e.Card {
	t.Helper()
	id, err := e2e.NewIdentity(p, addr, queue(t))
	if err != nil {
		t.Fatal(err)
	}
	defer id.Close()
	return id.Card()
}

func vaultPath(t testing.TB) string { return filepath.Join(t.TempDir(), "client.vault") }

func create(t testing.TB, p jcrypto.CryptoProvider, volumes ...vault.Contents) string {
	t.Helper()
	path := vaultPath(t)
	if err := vault.Create(p, path, volumes...); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return path
}

func open(t testing.TB, p jcrypto.CryptoProvider, path, pw string) *vault.Volume {
	t.Helper()
	v, err := vault.Open(p, path, password(t, pw))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(v.Close)
	return v
}

func parse(t testing.TB, p jcrypto.CryptoProvider, v *vault.Volume) *Profile {
	t.Helper()
	pr, err := Parse(p, v)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	t.Cleanup(pr.Close)
	return pr
}

// a volume with any content, for the rules of Parse
func raw(content func(id *vault.Identity) []byte) vault.Fill {
	return func(id *vault.Identity, buf []byte) (int, error) { return copy(buf, content(id)), nil }
}

func versioned(c e2e.Card) []byte { return append([]byte{version}, c.Bytes()...) }

// the own card as the volume's identity and the contact's address give it
func cardOf(t testing.TB, p jcrypto.CryptoProvider, id *vault.Identity, addr string) e2e.Card {
	t.Helper()
	q, err := mailbox.QueueID(p, id.Fetch().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return e2e.Card{Suite: p.Suite(), Mailbox: addr, Queue: q, Static: id.Public()}
}

func wantErr(t testing.TB, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: %v, want %v", what, got, want)
	}
}

func noFile(t testing.TB, path string) {
	t.Helper()
	for _, p := range []string{path, path + ".tmp"} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: %v, want no file", p, err)
		}
	}
}
