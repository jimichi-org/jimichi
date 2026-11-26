package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/vault"
	"github.com/jimichi-org/jimichi/vault/profile"
)

// a client process started with this variable stretches its passwords cheaply,
// as the tests in this process do
const cheapStretchVar = "JIMICHI_TEST_CHEAP_STRETCH"

func init() {
	if os.Getenv(cheapStretchVar) == "" {
		return
	}
	newProvider = func(s jcrypto.Suite) (jcrypto.CryptoProvider, error) {
		p, err := suite.New(s)
		if err != nil {
			return nil, err
		}
		return cheapStretch{CryptoProvider: p}, nil
	}
}

// the production stretch replaced by a DeriveKey of a hash of the password,
// counted when stretches is set
type cheapStretch struct {
	jcrypto.CryptoProvider
	stretches *atomic.Int32
}

func (c cheapStretch) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if c.stretches != nil {
		c.stretches.Add(1)
	}
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

func cheap(t *testing.T) (cheapStretch, *atomic.Int32) {
	t.Helper()
	n := new(atomic.Int32)
	return cheapStretch{CryptoProvider: provider(t, jcrypto.SuiteC25519), stretches: n}, n
}

// a stretch that waits until release is closed
type blockingStretch struct {
	cheapStretch
	entered chan struct{}
	release chan struct{}
}

func (b blockingStretch) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b.entered <- struct{}{}
	<-b.release
	return b.cheapStretch.PasswordKey(password, ctx)
}

// a pair that cannot be locked, as under a memlock limit too low
type unlockedPair struct{ cheapStretch }

func (unlockedPair) DerivePair(*secmem.Buffer, jcrypto.Context) (*secmem.Buffer, []byte, error) {
	return nil, nil, fmt.Errorf("%w: test", secmem.ErrNotLocked)
}

// every volume derives one pair the test knows
type knownPair struct {
	cheapStretch
	priv *secmem.Buffer
	pub  []byte
}

func (k knownPair) DerivePair(*secmem.Buffer, jcrypto.Context) (*secmem.Buffer, []byte, error) {
	priv, err := k.priv.Clone()
	return priv, bytes.Clone(k.pub), err
}

type vaultBed struct {
	p    jcrypto.CryptoProvider
	va   *vaultAdmin
	url  string
	out  *logBuffer
	path string

	mu    sync.Mutex
	lives []*live
}

// a -vault admin port whose open is attached to a conversation over first:
// by default a circuit that never answers and cannot be built again
func newVaultBed(t *testing.T, p jcrypto.CryptoProvider, path, mailboxAddr string, first, redial func() (conversation.Circuit, error)) *vaultBed {
	t.Helper()
	exists, err := vaultFileExists(path)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		first = func() (conversation.Circuit, error) { return &fakeCircuit{replies: make(chan []byte)}, nil }
	}
	if redial == nil {
		redial = func() (conversation.Circuit, error) { return nil, errEntryRefuses }
	}
	b := &vaultBed{p: p, out: &logBuffer{}, path: path}
	t.Cleanup(func() { checkVaultLines(t, b.out.String()) })
	f := peerFlags{mailbox: mailboxAddr, vault: path, rate: 50 * time.Millisecond, coverPuts: true, handshakeTimeout: time.Minute}
	b.va = newVaultAdmin(p, f, log.New(b.out, "", 0), exists)
	srv := httptest.NewServer(b.va.handler())
	b.url = srv.URL
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case req := <-b.va.opened:
				c, err := first()
				if err != nil {
					req.release()
					req.done <- openResult{http.StatusServiceUnavailable, "no circuit"}
					continue
				}
				if l, err := b.va.attach(req, c, redial); err == nil {
					b.mu.Lock()
					b.lives = append(b.lives, l)
					b.mu.Unlock()
				}
			case <-b.va.quit:
				return
			}
		}
	}()
	t.Cleanup(func() {
		srv.Close()
		b.va.drain()
		<-done
		for _, l := range b.lives {
			l.release()
		}
	})
	return b
}

func (b *vaultBed) call(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	return httpCall(t, method, b.url+path, body)
}

func (b *vaultBed) live(t *testing.T) *live {
	t.Helper()
	l := b.va.live.Load()
	if l == nil {
		t.Fatal("no volume open")
	}
	return l
}

func (b *vaultBed) lines() []string {
	out := strings.TrimSpace(b.out.String())
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// the lines that are no circuit line, in order
func (b *vaultBed) vaultLines() []string {
	var out []string
	for _, l := range b.lines() {
		if !strings.HasPrefix(l, "circuit ") {
			out = append(out, l)
		}
	}
	return out
}

func (b *vaultBed) card(t *testing.T) e2e.Card {
	t.Helper()
	code, text := b.call(t, http.MethodGet, "/card", "")
	if code != http.StatusOK {
		t.Fatalf("GET /card = %d %q", code, text)
	}
	c, err := e2e.ParseCard(strings.TrimSuffix(text, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (b *vaultBed) expect(t *testing.T, method, path, body string, want int) string {
	t.Helper()
	code, text := b.call(t, method, path, body)
	if code != want {
		t.Fatalf("%s %s = %d %q, want %d", method, path, code, text, want)
	}
	return text
}

// with -vault no line names a card, a role, a block, a password or the state
// of the session: every line is one of these or a line of the circuit
var vaultLineKinds = []string{
	"vault opened", "vault written", "contact pinned", "contact card changed, refusing",
	lineNoVolume, lineMailbox, lineContact, lineCorrupt, lineMemory, lineIO,
	notWritten + "write", notWritten + "link", notWritten + "sync", notWritten + "memory",
}

func checkVaultLines(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || slices.Contains(vaultLineKinds, line) || strings.HasPrefix(line, "circuit ") {
			continue
		}
		t.Errorf("a line outside the -vault classes: %q", line)
	}
}

type volumeSpec struct {
	password string
	fill     vault.Fill
}

func mustCreate(t *testing.T, p jcrypto.CryptoProvider, path string, specs ...volumeSpec) {
	t.Helper()
	var volumes []vault.Contents
	for _, s := range specs {
		pw, err := secmem.NewFrom([]byte(s.password))
		if err != nil {
			t.Fatal(err)
		}
		defer pw.Release()
		volumes = append(volumes, vault.Contents{Password: pw, Fill: s.fill})
	}
	if err := vault.Create(p, path, volumes...); err != nil {
		t.Fatal(err)
	}
}

// a volume whose content is the version byte and the bytes given
func rawContent(version byte, card []byte) vault.Fill {
	return func(_ *vault.Identity, buf []byte) (int, error) {
		buf[0] = version
		copy(buf[1:], card)
		return 1 + len(card), nil
	}
}

func vaultPath(t *testing.T) string { return filepath.Join(t.TempDir(), "client.vault") }

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// before an open every route of the running client is 503, and each of init
// and unlock is refused in the state of the other
func TestVaultLockedAnswers(t *testing.T) {
	p, _ := cheap(t)
	path := vaultPath(t)
	b := newVaultBed(t, p, path, testMailbox, nil, nil)
	peer := newPeerID(t, p, testMailbox)
	for _, req := range [][3]string{{http.MethodGet, "/card", ""}, {http.MethodPut, "/contact", peer.card.String()}, {http.MethodGet, "/status", ""}} {
		b.expect(t, req[0], req[1], req[2], http.StatusServiceUnavailable)
	}
	b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusConflict)

	mustCreate(t, p, path, volumeSpec{"pw", profile.New(p, testMailbox, &peer.card)})
	withFile := newVaultBed(t, p, path, testMailbox, nil, nil)
	withFile.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusConflict)
	withFile.expect(t, http.MethodGet, "/card", "", http.StatusServiceUnavailable)
	if lines := append(b.lines(), withFile.lines()...); len(lines) != 0 {
		t.Fatalf("lines while locked: %q", lines)
	}
}

// a file that is not a container stops the start before the listener
func TestVaultFileOfAnotherSizeIsRefused(t *testing.T) {
	path := vaultPath(t)
	if err := os.WriteFile(path, make([]byte, vault.FileSize-1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vaultFileExists(path); err == nil || err.Error() != lineNotVault {
		t.Fatalf("a short file: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := vaultFileExists(path); err == nil || err.Error() != lineNotVault {
		t.Fatalf("a directory: %v", err)
	}
	if ok, err := vaultFileExists(filepath.Join(t.TempDir(), "none")); ok || err != nil {
		t.Fatalf("no file: %v %v", ok, err)
	}
}

// every formal refusal of the body comes before the first stretch and leaves
// no line and no file; a refusal of the key comes after it, without a block
// number
func TestVaultInitBody(t *testing.T) {
	p, stretches := cheap(t)
	gost := provider(t, jcrypto.SuiteGOST)
	path := vaultPath(t)
	b := newVaultBed(t, p, path, testMailbox, nil, nil)
	one, two := newPeerID(t, p, testMailbox).card, newPeerID(t, p, testMailbox).card
	sameKey, sameQueue := two, two
	sameKey.Static = one.Static
	sameQueue.Queue = one.Queue
	otherMailbox := newPeerID(t, p, addrOf("relay-6")).card
	otherSuite := newPeerID(t, gost, testMailbox).card
	long := strings.Repeat("p", jcrypto.PasswordMax+1)

	for _, c := range []struct{ name, body string }{
		{"empty", ""},
		{"one line", "pw\n"},
		{"no line end", "pw\n" + one.String()},
		{"three lines", "pw\n\npw2\n"},
		{"five lines", "pw\n\npw2\n" + two.String() + "\nx\n"},
		{"no card in block 2", "pw\n\npw2\n\n"},
		{"no password", "\n\n"},
		{"a password of 257 bytes", long + "\n\n"},
		{"NUL in a password", "p\x00w\n\n"},
		{"CR in a password", "p\rw\n\n"},
		{"two CRs", "pw\r\r\n\n"},
		{"not a card", "pw\nsomething\n"},
		{"a card of another suite", "pw\n" + otherSuite.String() + "\n"},
		{"a card of another mailbox", "pw\n\npw2\n" + otherMailbox.String() + "\n"},
		{"two cards with one key", "pw\n" + one.String() + "\npw2\n" + sameKey.String() + "\n"},
		{"two cards with one queue", "pw\n" + one.String() + "\npw2\n" + sameQueue.String() + "\n"},
		{"equal passwords", "pw\n\npw\n" + two.String() + "\n"},
	} {
		code, text := b.call(t, http.MethodPut, "/vault/init", c.body)
		if code != http.StatusBadRequest || strings.Contains(text, "vault:") {
			t.Errorf("%s: %d %q", c.name, code, text)
		}
	}
	if code, _ := b.call(t, http.MethodPut, "/vault/init", strings.Repeat("p", maxInitBody+1)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("a long body: %d", code)
	}
	if n := stretches.Load(); n != 0 {
		t.Fatalf("%d stretches before a formal refusal", n)
	}

	bad := two
	bad.Static = make([]byte, len(two.Static))
	if code, text := b.call(t, http.MethodPut, "/vault/init", "pw\n\npw2\n"+bad.String()+"\n"); code != http.StatusBadRequest || text != keyRefused+"\n" {
		t.Fatalf("a key that does not pass: %d %q", code, text)
	}
	if stretches.Load() == 0 || exists(path) || len(b.lines()) != 0 {
		t.Fatalf("after the refusal of the key: %d stretches, file %v, lines %q", stretches.Load(), exists(path), b.lines())
	}

	// CR LF ends, a password of 256 bytes, the card of the second volume only
	pw := strings.Repeat("p", jcrypto.PasswordMax)
	b.expect(t, http.MethodPut, "/vault/init", pw+"\r\n\r\npw2\r\n"+two.String()+"\r\n", http.StatusNoContent)
	if exists(path) || stretches.Load() < 3 {
		t.Fatalf("file %v, %d stretches", exists(path), stretches.Load())
	}
	b.expect(t, http.MethodPut, "/contact", one.String(), http.StatusNoContent)
	if want := []string{"vault opened", "vault written", "contact pinned"}; !slices.Equal(b.vaultLines(), want) {
		t.Fatalf("lines %q, want %q", b.vaultLines(), want)
	}

	for _, pw := range []string{pw, "pw2"} {
		again := newVaultBed(t, p, path, testMailbox, nil, nil)
		again.expect(t, http.MethodPut, "/vault/unlock", pw+"\n", http.StatusNoContent)
	}
}

// the client's own card as the contact of a volume is refused once the
// stretch gives the identity
func TestVaultInitRefusesTheOwnCard(t *testing.T) {
	base, stretches := cheap(t)
	priv, pub, err := base.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	p := knownPair{cheapStretch: base, priv: priv, pub: pub}
	b := newVaultBed(t, p, vaultPath(t), testMailbox, nil, nil)
	own := newPeerID(t, p, testMailbox).card
	own.Static = pub
	if code, text := b.call(t, http.MethodPut, "/vault/init", "pw\n"+own.String()+"\n"); code != http.StatusBadRequest || text != keyRefused+"\n" {
		t.Fatalf("the own card: %d %q", code, text)
	}
	if stretches.Load() != 1 || len(b.lines()) != 0 {
		t.Fatalf("%d stretches, lines %q", stretches.Load(), b.lines())
	}
}

// the answers of unlock other than 204 leave the client locked, each with its
// one line; a 204 pins the volume's contact without a PUT
func TestVaultUnlockClasses(t *testing.T) {
	p, _ := cheap(t)
	peer := newPeerID(t, p, testMailbox)
	other := addrOf("relay-6")
	elsewhere := newPeerID(t, p, other).card
	badKey := peer.card
	badKey.Static = make([]byte, len(peer.card.Static))

	for _, c := range []struct {
		name   string
		fill   vault.Fill
		bed    jcrypto.CryptoProvider
		remove bool
		pw     string
		code   int
		line   string
	}{
		{name: "no volume", fill: profile.New(p, testMailbox, &peer.card), pw: "wrong", code: http.StatusForbidden, line: lineNoVolume},
		{name: "another mailbox", fill: profile.New(p, other, &elsewhere), pw: "pw", code: http.StatusConflict, line: lineMailbox},
		{name: "a contact whose key does not pass", fill: rawContent(1, badKey.Bytes()), pw: "pw", code: http.StatusConflict, line: lineContact},
		{name: "another version", fill: rawContent(2, peer.card.Bytes()), pw: "pw", code: http.StatusConflict, line: lineCorrupt},
		{name: "a card cut short", fill: rawContent(1, peer.card.Bytes()[:20]), pw: "pw", code: http.StatusConflict, line: lineCorrupt},
		{name: "memory", fill: profile.New(p, testMailbox, &peer.card), bed: unlockedPair{p}, pw: "pw", code: http.StatusInternalServerError, line: lineMemory},
		{name: "the file gone", fill: profile.New(p, testMailbox, &peer.card), remove: true, pw: "pw", code: http.StatusInternalServerError, line: lineIO},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := vaultPath(t)
			mustCreate(t, p, path, volumeSpec{"pw", c.fill})
			bp := c.bed
			if bp == nil {
				bp = p
			}
			b := newVaultBed(t, bp, path, testMailbox, nil, nil)
			if c.remove {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if text := b.expect(t, http.MethodPut, "/vault/unlock", c.pw+"\n", c.code); text != c.line+"\n" {
				t.Fatalf("body %q, want %q", text, c.line)
			}
			if lines := b.lines(); !slices.Equal(lines, []string{c.line}) {
				t.Fatalf("lines %q", lines)
			}
			b.expect(t, http.MethodGet, "/card", "", http.StatusServiceUnavailable)
			if b.va.live.Load() != nil || b.state() != lockedFile {
				t.Fatal("not locked after the refusal")
			}
		})
	}

	t.Run("opens", func(t *testing.T) {
		path := vaultPath(t)
		mustCreate(t, p, path, volumeSpec{"pw", profile.New(p, testMailbox, &peer.card)})
		before := fileBytes(t, path)
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		for _, body := range []string{"", "pw", "pw\nmore\n", "p\x00w\n"} {
			b.expect(t, http.MethodPut, "/vault/unlock", body, http.StatusBadRequest)
		}
		b.expect(t, http.MethodPut, "/vault/unlock", "pw\r\n", http.StatusNoContent)
		if want := []string{"vault opened", "contact pinned"}; !slices.Equal(b.vaultLines(), want) {
			t.Fatalf("lines %q, want %q", b.vaultLines(), want)
		}
		b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
		b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusConflict)
		b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusConflict)
		if !bytes.Equal(fileBytes(t, path), before) {
			t.Fatal("the file changed")
		}
	})
}

// one init or unlock at a time: a second one is 429 and the running routes
// stay 503 until the first ends
func TestVaultOneOperationAtATime(t *testing.T) {
	base, _ := cheap(t)
	p := blockingStretch{cheapStretch: base, entered: make(chan struct{}, 1), release: make(chan struct{})}
	b := newVaultBed(t, p, vaultPath(t), testMailbox, nil, nil)
	result := make(chan int, 1)
	go func() {
		code, _ := b.call(t, http.MethodPut, "/vault/init", "pw\n\n")
		result <- code
	}()
	<-p.entered
	b.expect(t, http.MethodPut, "/vault/init", "pw2\n\n", http.StatusTooManyRequests)
	b.expect(t, http.MethodPut, "/vault/unlock", "pw2\n", http.StatusTooManyRequests)
	b.expect(t, http.MethodGet, "/card", "", http.StatusServiceUnavailable)
	close(p.release)
	if code := <-result; code != http.StatusNoContent {
		t.Fatalf("the first init: %d", code)
	}
	b.expect(t, http.MethodPut, "/vault/init", "pw2\n\n", http.StatusConflict)
}

// the first PUT /contact writes the container once, before the pin; the same
// card again changes nothing, another one stops the client and leaves the file
// as it is
func TestVaultFirstPinWritesTheContainer(t *testing.T) {
	p, _ := cheap(t)
	path := vaultPath(t)
	b := newVaultBed(t, p, path, testMailbox, nil, nil)
	b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
	own := b.card(t)
	if exists(path) {
		t.Fatal("a file before the contact")
	}
	peer := newPeerID(t, p, testMailbox)
	b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
	written := fileBytes(t, path)
	b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
	if want := []string{"vault opened", "vault written", "contact pinned"}; !slices.Equal(b.vaultLines(), want) {
		t.Fatalf("lines %q, want %q", b.vaultLines(), want)
	}
	b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusConflict)
	for _, path := range []string{"/card", "/status"} {
		b.expect(t, http.MethodGet, path, "", http.StatusConflict)
	}
	b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusConflict)
	if !bytes.Equal(fileBytes(t, path), written) || exists(path+".tmp") {
		t.Fatal("the stop changed the file")
	}
	if last := b.vaultLines()[3]; last != "contact card changed, refusing" {
		t.Fatalf("the stop logged %q", last)
	}

	// the card that unlock builds is the one init built
	again := newVaultBed(t, p, path, testMailbox, nil, nil)
	again.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusNoContent)
	if got := again.card(t); !bytes.Equal(got.Bytes(), own.Bytes()) {
		t.Fatalf("the card after unlock %s, after init %s", got, own)
	}
	again.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
	if !bytes.Equal(fileBytes(t, path), written) {
		t.Fatal("a pin after unlock changed the file")
	}
	again.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusConflict)
	if !bytes.Equal(fileBytes(t, path), written) {
		t.Fatal("the stop after unlock changed the file")
	}
}

// a card in the first block is written before the chain, so a client that
// exits right after still has its container
func TestVaultInitWithACardWritesAtOnce(t *testing.T) {
	p, _ := cheap(t)
	path := vaultPath(t)
	peer := newPeerID(t, p, testMailbox)
	failing := func() (conversation.Circuit, error) { return nil, errEntryRefuses }
	b := newVaultBed(t, p, path, testMailbox, failing, nil)
	b.expect(t, http.MethodPut, "/vault/init", "pw\n"+peer.card.String()+"\n", http.StatusServiceUnavailable)
	if !exists(path) {
		t.Fatal("no file after the chain failed")
	}
	if want := []string{"vault opened", "vault written"}; !slices.Equal(b.vaultLines(), want) {
		t.Fatalf("lines %q, want %q", b.vaultLines(), want)
	}
	again := newVaultBed(t, p, path, testMailbox, nil, nil)
	again.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusNoContent)
	again.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
	if want := []string{"vault opened", "contact pinned"}; !slices.Equal(again.vaultLines(), want) {
		t.Fatalf("lines %q, want %q", again.vaultLines(), want)
	}
}

// a write that fails answers 500 with its class and pins the contact for the
// process; the same card again repeats the write, and only a write that
// succeeded logs vault written
func TestVaultFailedWriteIsRepeated(t *testing.T) {
	p, _ := cheap(t)
	missing := filepath.Join(t.TempDir(), "missing", "client.vault")
	for _, c := range []struct {
		class string
		// makes the next write fail and returns what undoes it
		fail func(t *testing.T, path string) func()
	}{
		{"link", func(t *testing.T, path string) func() {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return func() { _ = os.Remove(path) }
		}},
		{"write", func(t *testing.T, path string) func() {
			if err := os.MkdirAll(filepath.Join(path+".tmp", "x"), 0o700); err != nil {
				t.Fatal(err)
			}
			return func() { _ = os.RemoveAll(path + ".tmp") }
		}},
		{"memory", func(t *testing.T, _ string) func() {
			prev := writeDraft
			writeDraft = func(d *vault.Draft, _ string, fill vault.Fill) error {
				if err := d.Write(missing, fill); err == nil {
					t.Fatal("a write into a missing directory")
				}
				return fmt.Errorf("vault: seal: %w", secmem.ErrNotLocked)
			}
			return func() { writeDraft = prev }
		}},
	} {
		t.Run(c.class, func(t *testing.T) {
			path := vaultPath(t)
			b := newVaultBed(t, p, path, testMailbox, nil, nil)
			b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
			own := b.card(t)
			peer := newPeerID(t, p, testMailbox)
			undo := c.fail(t, path)
			if text := b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusInternalServerError); text != notWritten+c.class+"\n" {
				t.Fatalf("body %q", text)
			}
			undo()
			if want := []string{"vault opened", notWritten + c.class, "contact pinned"}; !slices.Equal(b.vaultLines(), want) {
				t.Fatalf("lines %q, want %q", b.vaultLines(), want)
			}
			b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
			b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
			if n := strings.Count(b.out.String(), "vault written\n"); n != 1 {
				t.Fatalf("%d vault written lines", n)
			}
			again := newVaultBed(t, p, path, testMailbox, nil, nil)
			again.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusNoContent)
			if !bytes.Equal(again.card(t).Bytes(), own.Bytes()) {
				t.Fatal("another card after the repeated write")
			}
		})
	}

	// a failure after the link spends the draft: the file goes and the pin
	// holds for the process only
	t.Run("sync", func(t *testing.T) {
		path := vaultPath(t)
		prev := writeDraft
		t.Cleanup(func() { writeDraft = prev })
		writeDraft = func(d *vault.Draft, path string, fill vault.Fill) error {
			if err := d.Write(path, fill); err != nil {
				t.Fatal(err)
			}
			return fmt.Errorf("%w, but %w", vault.ErrWritten, errors.New("sync failed"))
		}
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
		peer := newPeerID(t, p, testMailbox)
		b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusInternalServerError)
		if exists(path) || exists(path+".tmp") {
			t.Fatal("the file of a spent draft is left")
		}
		writeDraft = prev
		b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
		if exists(path) || strings.Contains(b.out.String(), "vault written") {
			t.Fatal("a spent draft was written")
		}
		if want := []string{"vault opened", notWritten + "sync", "contact pinned"}; !slices.Equal(b.vaultLines(), want) {
			t.Fatalf("lines %q, want %q", b.vaultLines(), want)
		}
	})

	// another card while the write waits stops the client and writes nothing
	t.Run("another card", func(t *testing.T) {
		path := vaultPath(t)
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
		peer := newPeerID(t, p, testMailbox)
		undo := func() func() {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return func() { _ = os.Remove(path) }
		}()
		b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusInternalServerError)
		undo()
		b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusConflict)
		b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusConflict)
		if exists(path) || b.live(t).writer.pending() {
			t.Fatal("the stop left a draft or a file")
		}
	})
}

// a key that does not pass is refused before the write and pins nothing
func TestVaultFirstPinRefusesABadKey(t *testing.T) {
	p, _ := cheap(t)
	path := vaultPath(t)
	b := newVaultBed(t, p, path, testMailbox, nil, nil)
	b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
	bad := newPeerID(t, p, testMailbox).card
	bad.Static = make([]byte, len(bad.Static))
	if text := b.expect(t, http.MethodPut, "/contact", bad.String(), http.StatusBadRequest); text != keyRefused+"\n" {
		t.Fatalf("body %q", text)
	}
	if exists(path) || isPaired(b.live(t).ct) {
		t.Fatal("a bad key was written or pinned")
	}
	b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusNoContent)
	if !exists(path) {
		t.Fatal("no file after a good card")
	}
}

// GET /status carries the counters of the minute line and the round trips
func TestVaultStatus(t *testing.T) {
	p, _ := cheap(t)
	b := newVaultBed(t, p, vaultPath(t), testMailbox, nil, nil)
	b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
	decode := func() map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(b.expect(t, http.MethodGet, "/status", "", http.StatusOK)), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := decode()
	if m["state"] != "unpaired" || m["round_trips"] != 0.0 || m["silent_for"] != nil || m["last_round_trip"] != nil {
		t.Fatalf("before the pin: %v", m)
	}
	for _, key := range []string{"requests", "puts", "put_refused", "window_full", "hits", "sent", "received", "dummies_sent",
		"dummies_received", "copies", "late", "lost", "window", "bad", "bad_replies", "handshakes", "refused_handshakes",
		"replayed_handshakes", "stale", "rebuilds", "refusals", "outbox_dropped", "held_dropped", "inbox_dropped", "unanswered"} {
		if _, ok := m[key]; !ok {
			t.Errorf("no %s in %v", key, m)
		}
	}
	b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusNoContent)
	l := b.live(t)
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	l.tk.lastAt.Store(at.UnixNano())
	l.tk.lastTook.Store(int64(1500 * time.Millisecond))
	l.tk.trips.Add(2)
	m = decode()
	if m["state"] == "unpaired" || m["round_trips"] != 2.0 || m["last_round_trip"] != "1.5s" ||
		m["last_round_trip_at"] != at.Format(time.RFC3339Nano) || m["silent_for"] == nil {
		t.Fatalf("after the pin: %v", m)
	}
}

// records the output of every call that gives a secret
type tracking struct {
	jcrypto.CryptoProvider
	mu      sync.Mutex
	secrets [][]byte
	noise   int
}

func (tr *tracking) keep(bufs ...*secmem.Buffer) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, b := range bufs {
		if b != nil && b.Len() >= 16 {
			tr.secrets = append(tr.secrets, bytes.Clone(b.Bytes()))
		}
	}
}

func (tr *tracking) recorded() ([][]byte, int) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return slices.Clone(tr.secrets), tr.noise
}

func (tr *tracking) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := tr.CryptoProvider.GenerateEphemeral()
	tr.keep(priv)
	return priv, pub, err
}

func (tr *tracking) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	out, err := tr.CryptoProvider.Agree(priv, pub, ctx)
	tr.keep(out)
	return out, err
}

func (tr *tracking) NoiseDH(priv *secmem.Buffer, pub []byte) (*secmem.Buffer, error) {
	out, err := tr.CryptoProvider.NoiseDH(priv, pub)
	tr.keep(out)
	tr.mu.Lock()
	tr.noise++
	tr.mu.Unlock()
	return out, err
}

func (tr *tracking) NoiseKDF2(ck, input *secmem.Buffer) (*secmem.Buffer, *secmem.Buffer, error) {
	a, b, err := tr.CryptoProvider.NoiseKDF2(ck, input)
	tr.keep(a, b)
	return a, b, err
}

func (tr *tracking) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	out, err := tr.CryptoProvider.MixKey(chain, secret, ctx)
	tr.keep(out)
	return out, err
}

func (tr *tracking) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	out, err := tr.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	tr.keep(out)
	return out, err
}

func (tr *tracking) DerivePair(secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, []byte, error) {
	priv, pub, err := tr.CryptoProvider.DerivePair(secret, ctx)
	tr.keep(priv)
	return priv, pub, err
}

func (tr *tracking) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	out, err := tr.CryptoProvider.PasswordKey(password, ctx)
	tr.keep(out)
	return out, err
}

// a KK handshake with a contact runs before the container is written: none of
// the secrets the client's provider gave, from the stretch to the session
// keys, is in the file or in the opened volume
func TestVaultSessionKeysNeverReachTheVolume(t *testing.T) {
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	tr := &tracking{CryptoProvider: cheapStretch{CryptoProvider: bed.p}}
	dial := func(p jcrypto.CryptoProvider) func() (conversation.Circuit, error) {
		return func() (conversation.Circuit, error) {
			c, err := client.Dial(client.Config{Provider: p, Chain: bed.nodes})
			if err != nil {
				return nil, err
			}
			return c, nil
		}
	}
	path := vaultPath(t)
	b := newVaultBed(t, tr, path, bed.addrs[2], dial(tr), dial(tr))
	b.va.f.rate = bed.rate
	b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
	own := b.card(t)

	peer := newPeerID(t, bed.p, bed.addrs[2])
	first, err := dial(bed.p)()
	if err != nil {
		t.Fatal(err)
	}
	conv, err := conversation.Start(conversation.Config{
		Provider: bed.p, Self: peer.id, Fetch: peer.f, First: first, Dial: dial(bed.p), Rate: bed.rate, CoverPuts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conv.Close)
	if err := conv.Pair(own); err != nil {
		t.Fatal(err)
	}

	// a file in the way holds the write back while the handshake runs
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusInternalServerError)
	l := b.live(t)
	running := func(s conversation.Stats) bool {
		return s.Paired && (s.State == e2e.StateEstablished || s.State == e2e.StateConfirmed)
	}
	for limit := time.Now().Add(time.Minute); !running(l.conv.Stats()) || !running(conv.Stats()); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(limit) {
			t.Fatalf("no session: %+v, %+v", l.conv.Stats(), conv.Stats())
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusNoContent)
	secrets, dh := tr.recorded()
	if dh == 0 || len(secrets) < 10 {
		t.Fatalf("%d secrets and %d noise agreements recorded", len(secrets), dh)
	}

	file := fileBytes(t, path)
	pw, err := secmem.NewFrom([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Release()
	v, err := vault.Open(cheapStretch{CryptoProvider: bed.p}, path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	content := v.Content()
	if !bytes.Contains(content, peer.card.Bytes()) {
		t.Fatal("the volume does not hold the contact")
	}
	for _, s := range secrets {
		if bytes.Contains(file, s) || bytes.Contains(content, s) {
			t.Fatalf("a secret of %d bytes is in the container", len(s))
		}
	}
}

func (b *vaultBed) state() vaultState {
	b.va.mu.Lock()
	defer b.va.mu.Unlock()
	return b.va.state
}

func (w *draftWriter) pending() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.draft != nil
}
