package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

var suites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

func provider(t testing.TB, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// every test but the production ones stretches cheaply: seconds per stretch
// would leave no room for exhaustive checks. The tests share no state but the
// providers, which are stateless, so they run side by side: under -race a
// GOST open costs about 0.1 s
func eachSuite(t *testing.T, run func(t *testing.T, p *spy)) {
	t.Helper()
	t.Parallel()
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()
			run(t, newSpy(t, cheap{provider(t, s)}))
		})
	}
}

// the production stretch replaced by a DeriveKey of a hash of the password;
// DerivePair and the rest stay real
type cheap struct{ jcrypto.CryptoProvider }

func (c cheap) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if password == nil || !jcrypto.ValidPassword(password.Bytes()) {
		return nil, jcrypto.ErrBadPassword
	}
	h, err := secmem.NewFrom(c.Hash(password.Bytes()))
	if err != nil {
		return nil, err
	}
	defer h.Release()
	return c.DeriveKey(h, "test/password", ctx, c.KeySize())
}

// records the calls in order, keeps a copy of every secret handed out, of
// the secret into and the key out of every DeriveKey by purpose and of every
// hashed transcript, fails the test on a signing call and can make DerivePair
// or the fetch capability fail
type spy struct {
	jcrypto.CryptoProvider
	t testing.TB

	mu      sync.Mutex
	calls   []string
	secrets [][]byte
	in, out map[string][][]byte
	hashed  [][]byte
	pairs   int

	pairErr   error
	pairErrAt int
	// the call of DeriveKey under vault/fetch that gives zeroes, 0 for none
	zeroFetchAt int
	fetches     int
}

func newSpy(t testing.TB, p jcrypto.CryptoProvider) *spy { return &spy{CryptoProvider: p, t: t} }

func (s *spy) record(call string, secret *secmem.Buffer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
	if secret != nil {
		s.secrets = append(s.secrets, bytes.Clone(secret.Bytes()))
	}
}

func (s *spy) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls, s.secrets, s.hashed, s.pairs, s.fetches = nil, nil, nil, 0, 0
	s.in, s.out = nil, nil
}

func (s *spy) inputs(purpose string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.in[purpose]...)
}

func (s *spy) outputs(purpose string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.out[purpose]...)
}

func (s *spy) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *spy) count(call string) int {
	n := 0
	for _, c := range s.seen() {
		if c == call {
			n++
		}
	}
	return n
}

func (s *spy) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := s.CryptoProvider.GenerateEphemeral()
	s.record("GenerateEphemeral", priv)
	return priv, pub, err
}

func (s *spy) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	out, err := s.CryptoProvider.Agree(priv, pub, ctx)
	s.record("Agree", out)
	return out, err
}

func (s *spy) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	out, err := s.CryptoProvider.MixKey(chain, secret, ctx)
	s.record("MixKey", out)
	return out, err
}

func (s *spy) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	var in []byte
	if secret != nil {
		in = bytes.Clone(secret.Bytes())
	}
	out, err := s.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	if err == nil && purpose == purposeFetch {
		s.mu.Lock()
		s.fetches++
		zero := s.fetches == s.zeroFetchAt
		s.mu.Unlock()
		if zero {
			clear(out.Bytes())
		}
	}
	if err == nil {
		s.mu.Lock()
		if s.in == nil {
			s.in, s.out = map[string][][]byte{}, map[string][][]byte{}
		}
		s.in[purpose] = append(s.in[purpose], in)
		s.out[purpose] = append(s.out[purpose], bytes.Clone(out.Bytes()))
		s.mu.Unlock()
	}
	s.record("DeriveKey "+purpose, out)
	return out, err
}

func (s *spy) DerivePair(secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, []byte, error) {
	s.mu.Lock()
	s.pairs++
	fail := s.pairErr != nil && (s.pairErrAt == 0 || s.pairErrAt == s.pairs)
	s.mu.Unlock()
	if fail {
		s.record("DerivePair", nil)
		return nil, nil, s.pairErr
	}
	priv, pub, err := s.CryptoProvider.DerivePair(secret, ctx)
	s.record("DerivePair", priv)
	return priv, pub, err
}

func (s *spy) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	out, err := s.CryptoProvider.PasswordKey(password, ctx)
	s.record("PasswordKey", out)
	return out, err
}

func (s *spy) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	a, err := s.CryptoProvider.NewAEAD(key)
	s.record("NewAEAD", nil)
	if err != nil {
		return nil, err
	}
	return &spyAEAD{AEAD: a, s: s}, nil
}

func (s *spy) GenerateSigning() (*secmem.Buffer, []byte, error) {
	s.t.Error("GenerateSigning called")
	s.record("GenerateSigning", nil)
	return s.CryptoProvider.GenerateSigning()
}

func (s *spy) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	s.t.Error("Sign called")
	s.record("Sign", nil)
	return s.CryptoProvider.Sign(priv, msg)
}

func (s *spy) Verify(pub, msg, sig []byte) bool {
	s.t.Error("Verify called")
	s.record("Verify", nil)
	return s.CryptoProvider.Verify(pub, msg, sig)
}

func (s *spy) Hash(data ...[]byte) []byte {
	out := s.CryptoProvider.Hash(data...)
	s.mu.Lock()
	s.calls = append(s.calls, "Hash")
	s.hashed = append(s.hashed, bytes.Join(data, nil))
	s.mu.Unlock()
	return out
}

type spyAEAD struct {
	jcrypto.AEAD
	s *spy
}

func (a *spyAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	a.s.record("Seal", nil)
	return a.AEAD.Seal(dst, nonce, plaintext, ad)
}

func (a *spyAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	a.s.record("Open", nil)
	return a.AEAD.Open(dst, nonce, ciphertext, ad)
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

func content(b []byte) Fill {
	return func(_ *Identity, buf []byte) (int, error) { return copy(buf, b), nil }
}

func volume(t testing.TB, pw string, b []byte) Contents {
	return Contents{Password: password(t, pw), Fill: content(b)}
}

func vaultPath(t testing.TB) string { return filepath.Join(t.TempDir(), "client.vault") }

func mustCreate(t testing.TB, p jcrypto.CryptoProvider, volumes ...Contents) (string, []byte) {
	t.Helper()
	path := vaultPath(t)
	if err := Create(p, path, volumes...); err != nil {
		t.Fatalf("Create: %v", err)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, file
}

func mustOpen(t testing.TB, p jcrypto.CryptoProvider, file []byte, pw *secmem.Buffer) (*Volume, int) {
	t.Helper()
	v, s, err := open(p, file, pw)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(v.Close)
	return v, s
}

func wantErr(t testing.TB, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: %v, want %v", what, got, want)
	}
}

func noFile(t testing.TB, path string) {
	t.Helper()
	for _, p := range []string{path, path + tmpSuffix} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: %v, want no file", p, err)
		}
	}
}

// whether an 8-byte window of secret is in hay: for the few dozen secrets of a
// test and a few kilobytes of hay a chance match is below 2^-40
func leaks(hay, secret []byte) bool {
	for i := 0; i+8 <= len(secret); i++ {
		if bytes.Contains(hay, secret[i:i+8]) {
			return true
		}
	}
	return false
}

func isVaultTranscript(t []byte, suite jcrypto.Suite) bool {
	return strings.HasPrefix(string(t), "jimichi/v2/"+suite.String()+"/transcript/vault/")
}

// runs check for every i below n on one goroutine per processor and gives the
// first failure, for the checks that open hundreds of times
func parallel(n int, check func(i int) error) error {
	var next atomic.Int64
	var mu sync.Mutex
	var first error
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				if err := check(i); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
					next.Store(int64(n))
					return
				}
			}
		}()
	}
	wg.Wait()
	return first
}
