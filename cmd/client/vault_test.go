package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

// a client process started with this variable fails its first write of the
// container before the link, after the content took the contact
const failFirstWriteVar = "JIMICHI_TEST_FAIL_FIRST_WRITE"

func init() {
	if os.Getenv(failFirstWriteVar) != "" {
		var failed atomic.Bool
		writeDraft = func(d *vault.Draft, path string, fill vault.Fill) error {
			if failed.CompareAndSwap(false, true) {
				return d.Write(filepath.Join(path+".absent", "client.vault"), fill)
			}
			return d.Write(path, fill)
		}
	}
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
	// the SIGTERM of the process, and the codes it would exit with
	stop  chan os.Signal
	exits chan int

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
	b := &vaultBed{p: p, out: &logBuffer{}, path: path, stop: make(chan os.Signal, 1), exits: make(chan int, 4)}
	t.Cleanup(func() { checkVaultLines(t, b.out.String()) })
	f := peerFlags{mailbox: mailboxAddr, vault: path, hops: 3, rate: 50 * time.Millisecond, coverPuts: true, handshakeTimeout: time.Minute}
	b.va = newVaultAdmin(p, f, log.New(b.out, "", 0), exists)
	srv := httptest.NewServer(b.va.handler())
	b.url = srv.URL
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case req := <-b.va.opened:
				l, code := b.va.start(req, first, redial, b.stop)
				if l == nil {
					b.exits <- code
					continue
				}
				b.mu.Lock()
				b.lives = append(b.lives, l)
				b.mu.Unlock()
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
		if !circuitLine(l) {
			out = append(out, l)
		}
	}
	return out
}

func circuitLine(l string) bool {
	return strings.HasPrefix(l, "circuit ") || strings.HasPrefix(l, "refusing to build the circuit: ")
}

// the code the process would exit with: after an open that did not start, or
// after a pin that failed on a running client
func (b *vaultBed) exitCode(t *testing.T) int {
	t.Helper()
	select {
	case code := <-b.exits:
		return code
	case code := <-b.va.exit:
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("no exit")
		return 0
	}
}

// every request after an exit is decided waits for the end of the process
func (b *vaultBed) leaving(t *testing.T) {
	t.Helper()
	for _, req := range [][3]string{{http.MethodGet, "/card", ""}, {http.MethodGet, "/status", ""}, {http.MethodPut, "/contact", "x"},
		{http.MethodPut, "/vault/init", "pw\n\n"}, {http.MethodPut, "/vault/unlock", "pw\n"}} {
		if text := b.expect(t, req[0], req[1], req[2], http.StatusServiceUnavailable); text != leavingText+"\n" {
			t.Fatalf("%s %s after the exit: %q", req[0], req[1], text)
		}
	}
}

// what GET /status answers, field by field: PR5 reads these names and types
type statusFields struct {
	State              string  `json:"state"`
	Container          string  `json:"container"`
	Requests           uint64  `json:"requests"`
	Puts               uint64  `json:"puts"`
	PutRefused         uint64  `json:"put_refused"`
	WindowFull         uint64  `json:"window_full"`
	Hits               uint64  `json:"hits"`
	Sent               uint64  `json:"sent"`
	Received           uint64  `json:"received"`
	DummiesSent        uint64  `json:"dummies_sent"`
	DummiesReceived    uint64  `json:"dummies_received"`
	Copies             uint64  `json:"copies"`
	Late               uint64  `json:"late"`
	Lost               uint64  `json:"lost"`
	Window             uint64  `json:"window"`
	Bad                uint64  `json:"bad"`
	BadReplies         uint64  `json:"bad_replies"`
	Handshakes         uint64  `json:"handshakes"`
	RefusedHandshakes  uint64  `json:"refused_handshakes"`
	ReplayedHandshakes uint64  `json:"replayed_handshakes"`
	Stale              uint64  `json:"stale"`
	Rebuilds           uint64  `json:"rebuilds"`
	Refusals           uint64  `json:"refusals"`
	OutboxDropped      uint64  `json:"outbox_dropped"`
	HeldDropped        uint64  `json:"held_dropped"`
	InboxDropped       uint64  `json:"inbox_dropped"`
	Unanswered         uint64  `json:"unanswered"`
	RoundTrips         uint64  `json:"round_trips"`
	LastRoundTripAt    *string `json:"last_round_trip_at"`
	LastRoundTripMS    *int64  `json:"last_round_trip_ms"`
	SilentFor          *uint64 `json:"silent_for"`
}

var sessionStates = []string{"unpaired", "handshaking", "established", "confirmed", "stale"}

func decodeStatus(t *testing.T, text string) statusFields {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	var st statusFields
	if err := dec.Decode(&st); err != nil {
		t.Fatalf("GET /status %q: %v", text, err)
	}
	if !slices.Contains(sessionStates, st.State) {
		t.Fatalf("state %q", st.State)
	}
	return st
}

func (b *vaultBed) status(t *testing.T) statusFields {
	t.Helper()
	return decodeStatus(t, b.expect(t, http.MethodGet, "/status", "", http.StatusOK))
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
	"vault opened", "vault written", "contact pinned", "contact card changed, refusing", "shutting down", lineNoStart,
	lineNoVolume, lineMailbox, lineContact, lineCorrupt, lineMemory, lineIO,
	notWritten + "write", notWritten + "link", notWritten + "sync", notWritten + "memory",
	notPinned + "memory", notPinned + "closed", notPinned + "io",
}

func checkVaultLines(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || slices.Contains(vaultLineKinds, line) || circuitLine(line) {
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
	b.expect(t, http.MethodPut, "/vault/init", "pw2\n\n", http.StatusConflict)
	b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusConflict)
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
	text := b.expect(t, http.MethodPut, "/vault/init", "pw\n"+peer.card.String()+"\n", http.StatusServiceUnavailable)
	if want := notStarted + "circuit, " + onDisk + "\n"; text != want {
		t.Fatalf("body %q, want %q", text, want)
	}
	if code := b.exitCode(t); code != 1 {
		t.Fatalf("exit code %d", code)
	}
	if !exists(path) {
		t.Fatal("no file after the chain failed")
	}
	if want := []string{"vault opened", "vault written"}; !slices.Equal(b.vaultLines(), want) {
		t.Fatalf("lines %q, want %q", b.vaultLines(), want)
	}
	if !strings.Contains(b.out.String(), "refusing to build the circuit: ") {
		t.Fatalf("no line of the chain:\n%s", b.out.String())
	}
	b.leaving(t)
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

	// a failure after the link spends the draft and leaves the file as it is:
	// the same card again is the same 500 without another attempt, and the tmp
	// a failed settle leaves goes with the Clean of the next start
	for _, c := range []struct{ name, init string }{{"sync", "pw\n\n"}, {"sync of the first block", "pw\n%s\n"}} {
		t.Run(c.name, func(t *testing.T) {
			path := vaultPath(t)
			peer := newPeerID(t, p, testMailbox)
			attempts := failSettle(t)
			b := newVaultBed(t, p, path, testMailbox, nil, nil)
			if strings.Contains(c.init, "%s") {
				text := b.expect(t, http.MethodPut, "/vault/init", fmt.Sprintf(c.init, peer.card.String()), http.StatusInternalServerError)
				if text != notWritten+"sync\n" {
					t.Fatalf("body %q", text)
				}
			} else {
				b.expect(t, http.MethodPut, "/vault/init", c.init, http.StatusNoContent)
				if text := b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusInternalServerError); text != notWritten+"sync\n" {
					t.Fatalf("body %q", text)
				}
			}
			own := b.card(t)
			written := fileBytes(t, path)
			if !exists(path + ".tmp") {
				t.Fatal("no tmp left by the settle")
			}
			if text := b.expect(t, http.MethodPut, "/contact", peer.card.String(), http.StatusInternalServerError); text != notWritten+"sync\n" {
				t.Fatalf("the same card again: %q", text)
			}
			if n := attempts.Load(); n != 1 {
				t.Fatalf("%d writes", n)
			}
			if st := b.status(t); st.Container != containerUnsettled {
				t.Fatalf("container %q", st.Container)
			}
			if want := []string{"vault opened", notWritten + "sync", "contact pinned"}; !slices.Equal(b.vaultLines(), want) {
				t.Fatalf("lines %q, want %q", b.vaultLines(), want)
			}
			b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusConflict)
			if !bytes.Equal(fileBytes(t, path), written) {
				t.Fatal("the client changed a file it linked")
			}
			if err := vault.Clean(path); err != nil || exists(path+".tmp") {
				t.Fatalf("the Clean of the next start: %v", err)
			}
			again := newVaultBed(t, p, path, testMailbox, nil, nil)
			again.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusNoContent)
			if !bytes.Equal(again.card(t).Bytes(), own.Bytes()) {
				t.Fatal("another identity in the file")
			}
		})
	}

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

// GET /status carries the counters of the minute line, the round trips and
// the state of the file, under the names and types PR5 reads
func TestVaultStatus(t *testing.T) {
	p, _ := cheap(t)
	b := newVaultBed(t, p, vaultPath(t), testMailbox, nil, nil)
	b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
	st := b.status(t)
	if st.State != "unpaired" || st.Container != containerDraft || st.RoundTrips != 0 ||
		st.LastRoundTripAt != nil || st.LastRoundTripMS != nil || st.SilentFor != nil {
		t.Fatalf("before the pin: %+v", st)
	}
	b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusNoContent)
	l := b.live(t)
	at := time.Date(2026, 11, 26, 12, 0, 0, 700_000_000, time.UTC)
	l.tk.lastAt.Store(at.UnixNano())
	l.tk.lastTook.Store(int64(1500*time.Millisecond + 400*time.Microsecond))
	l.tk.trips.Add(2)
	st = b.status(t)
	if st.State == "unpaired" || st.Container != containerWritten || st.RoundTrips != 2 || st.SilentFor == nil ||
		st.LastRoundTripMS == nil || *st.LastRoundTripMS != 1500 ||
		st.LastRoundTripAt == nil || *st.LastRoundTripAt != "2026-11-26T12:00:00Z" {
		t.Fatalf("after the pin: %+v", st)
	}
}

// writes the container, then fails as a settle fails after the link: the tmp
// stays as a second name of the file
func failSettle(t *testing.T) *atomic.Int32 {
	t.Helper()
	n := new(atomic.Int32)
	prev := writeDraft
	t.Cleanup(func() { writeDraft = prev })
	writeDraft = func(d *vault.Draft, path string, fill vault.Fill) error {
		n.Add(1)
		if err := d.Write(path, fill); err != nil {
			return err
		}
		if err := os.Link(path, path+".tmp"); err != nil {
			return err
		}
		return fmt.Errorf("%w, but %w", vault.ErrWritten, errors.New("vault: remove: test"))
	}
	return n
}

// the next write fails before the link, as a tmp it cannot create
func failBeforeTheLink(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path+".tmp", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path + ".tmp") })
}

// a pin that always fails as locked memory runs short
type refusedPair struct{}

func (refusedPair) Pair(e2e.Card) error { return fmt.Errorf("%w: test", secmem.ErrNotLocked) }

func refusePins(*conversation.Conversation) pairing { return refusedPair{} }

// with -vault a contact the volume fixed is the only card of the process,
// and a client whose pin of it failed does not run on: an open answers 503
// and exits, a running client answers 500 and exits
func TestVaultFixedContact(t *testing.T) {
	p, _ := cheap(t)

	t.Run("unlock, the pin fails", func(t *testing.T) {
		path := vaultPath(t)
		mustCreate(t, p, path, volumeSpec{"pw", profile.New(p, testMailbox, cardOf(t, p, testMailbox))})
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		b.va.pairs = refusePins
		text := b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusServiceUnavailable)
		if want := notStarted + "pin, " + onDisk + "\n"; text != want {
			t.Fatalf("body %q, want %q", text, want)
		}
		if code := b.exitCode(t); code != 1 {
			t.Fatalf("exit code %d", code)
		}
		if want := []string{"vault opened", notPinned + "memory"}; !slices.Equal(b.vaultLines(), want) {
			t.Fatalf("lines %q, want %q", b.vaultLines(), want)
		}
		if b.va.live.Load() != nil {
			t.Fatal("a running client without its pin")
		}
		b.leaving(t)
	})

	t.Run("init with a card, the write and the pin fail", func(t *testing.T) {
		path := vaultPath(t)
		failBeforeTheLink(t, path)
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		b.va.pairs = refusePins
		text := b.expect(t, http.MethodPut, "/vault/init", "pw\n"+newPeerID(t, p, testMailbox).card.String()+"\n", http.StatusServiceUnavailable)
		if want := notStarted + "pin, " + noContainer + "\n"; text != want {
			t.Fatalf("body %q, want %q", text, want)
		}
		if code := b.exitCode(t); code != 1 || exists(path) {
			t.Fatalf("exit code %d, file %v", code, exists(path))
		}
		if want := []string{"vault opened", notWritten + "write", notPinned + "memory"}; !slices.Equal(b.vaultLines(), want) {
			t.Fatalf("lines %q, want %q", b.vaultLines(), want)
		}
		b.leaving(t)
	})

	t.Run("a first PUT, the write and the pin fail", func(t *testing.T) {
		path := vaultPath(t)
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		b.va.pairs = refusePins
		b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
		failBeforeTheLink(t, path)
		if text := b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusInternalServerError); text != notPinned+"memory\n" {
			t.Fatalf("body %q", text)
		}
		if code := b.exitCode(t); code != 1 {
			t.Fatalf("exit code %d", code)
		}
		if want := []string{"vault opened", notWritten + "write", notPinned + "memory"}; !slices.Equal(b.vaultLines(), want) {
			t.Fatalf("lines %q, want %q", b.vaultLines(), want)
		}
		b.leaving(t)
	})

	t.Run("a first PUT, the write fails and the pin holds", func(t *testing.T) {
		path := vaultPath(t)
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
		failBeforeTheLink(t, path)
		x := newPeerID(t, p, testMailbox).card
		b.expect(t, http.MethodPut, "/contact", x.String(), http.StatusInternalServerError)
		b.expect(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String(), http.StatusConflict)
		b.expect(t, http.MethodPut, "/contact", x.String(), http.StatusConflict)
		if exists(path) || b.live(t).writer.pending() {
			t.Fatal("the stop left a draft or a file")
		}
	})

	// the content took the card while its write failed: the card is fixed
	// before any pin, and a pin that failed after it lets no other card in
	t.Run("another card while the pin is out", func(t *testing.T) {
		path := vaultPath(t)
		b := newVaultBed(t, p, path, testMailbox, nil, nil)
		b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
		l := b.live(t)
		x := newPeerID(t, p, testMailbox).card
		failBeforeTheLink(t, path)
		if status, _, fixed := l.writer.first(x); status != http.StatusInternalServerError || !fixed {
			t.Fatalf("the write: %d, fixed %v", status, fixed)
		}
		if out := l.ct.pinCard(x); out.status != http.StatusServiceUnavailable || out.text != leavingText {
			t.Fatalf("the same card: %+v", out)
		}
		if out := l.ct.pinCard(newPeerID(t, p, testMailbox).card); !out.stop {
			t.Fatalf("another card: %+v", out)
		}
	})
}

// every cell of the running states: a draft, a written file, a file whose
// write did not settle, the stop of D-038 and an exit under way
func TestVaultRequestMatrix(t *testing.T) {
	p, _ := cheap(t)
	x, y := newPeerID(t, p, testMailbox).card, newPeerID(t, p, testMailbox).card
	other := newPeerID(t, provider(t, jcrypto.SuiteGOST), testMailbox).card
	type cell struct {
		method, path, body string
		code               int
	}
	opens := func(code int) []cell {
		return []cell{{http.MethodPut, "/vault/init", "pw2\n\n", code}, {http.MethodPut, "/vault/unlock", "pw\n", code}}
	}
	reads := func(code int) []cell {
		return []cell{{http.MethodGet, "/card", "", code}, {http.MethodGet, "/status", "", code}}
	}
	for _, c := range []struct {
		name  string
		reach func(t *testing.T, b *vaultBed)
		cells []cell
	}{
		{"draft", func(t *testing.T, b *vaultBed) {
			b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
		}, slices.Concat(opens(http.StatusConflict), reads(http.StatusOK),
			[]cell{{http.MethodPut, "/contact", other.String(), http.StatusBadRequest}})},
		{"written", func(t *testing.T, b *vaultBed) {
			b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
			b.expect(t, http.MethodPut, "/contact", x.String(), http.StatusNoContent)
		}, slices.Concat(opens(http.StatusConflict), reads(http.StatusOK),
			[]cell{{http.MethodPut, "/contact", x.String(), http.StatusNoContent}, {http.MethodPut, "/contact", y.String(), http.StatusConflict}})},
		{"unsettled", func(t *testing.T, b *vaultBed) {
			failSettle(t)
			b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
			b.expect(t, http.MethodPut, "/contact", x.String(), http.StatusInternalServerError)
		}, slices.Concat(opens(http.StatusConflict), reads(http.StatusOK),
			[]cell{{http.MethodPut, "/contact", x.String(), http.StatusInternalServerError}, {http.MethodPut, "/contact", y.String(), http.StatusConflict}})},
		{"stopped", func(t *testing.T, b *vaultBed) {
			b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
			b.expect(t, http.MethodPut, "/contact", x.String(), http.StatusNoContent)
			b.expect(t, http.MethodPut, "/contact", y.String(), http.StatusConflict)
		}, slices.Concat(opens(http.StatusConflict), reads(http.StatusConflict),
			[]cell{{http.MethodPut, "/contact", x.String(), http.StatusConflict}})},
		{"leaving", func(t *testing.T, b *vaultBed) {
			b.va.pairs = refusePins
			b.expect(t, http.MethodPut, "/vault/init", "pw\n\n", http.StatusNoContent)
			b.expect(t, http.MethodPut, "/contact", x.String(), http.StatusInternalServerError)
		}, slices.Concat(opens(http.StatusServiceUnavailable), reads(http.StatusServiceUnavailable),
			[]cell{{http.MethodPut, "/contact", x.String(), http.StatusServiceUnavailable}})},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newVaultBed(t, p, vaultPath(t), testMailbox, nil, nil)
			c.reach(t, b)
			for _, cl := range c.cells {
				b.expect(t, cl.method, cl.path, cl.body, cl.code)
			}
		})
	}
}

// the open waits for the first chain: meanwhile the routes of the running
// client say so, a second open is 429, and a SIGTERM ends the wait with an
// answer that tells whether the file is on disk, and code 0
func TestVaultOpening(t *testing.T) {
	p, _ := cheap(t)
	peer := newPeerID(t, p, testMailbox)
	for _, c := range []struct {
		name, body, where string
		stop              bool
	}{
		{"built", "pw\n\n", "", false},
		{"a stop without a container", "pw\n\n", noContainer, true},
		{"a stop with the container on disk", "pw\n" + peer.card.String() + "\n", onDisk, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			entered, release := make(chan struct{}, 1), make(chan struct{})
			first := func() (conversation.Circuit, error) {
				entered <- struct{}{}
				<-release
				return &fakeCircuit{replies: make(chan []byte)}, nil
			}
			b := newVaultBed(t, p, vaultPath(t), testMailbox, first, nil)
			var once sync.Once
			free := func() { once.Do(func() { close(release) }) }
			t.Cleanup(free)
			type answer struct {
				code int
				text string
			}
			result := make(chan answer, 1)
			go func() {
				code, text := b.call(t, http.MethodPut, "/vault/init", c.body)
				result <- answer{code, text}
			}()
			<-entered
			for _, req := range [][3]string{{http.MethodGet, "/card", ""}, {http.MethodGet, "/status", ""}, {http.MethodPut, "/contact", peer.card.String()}} {
				if text := b.expect(t, req[0], req[1], req[2], http.StatusServiceUnavailable); text != openingText+"\n" {
					t.Fatalf("%s %s: %q", req[0], req[1], text)
				}
			}
			b.expect(t, http.MethodPut, "/vault/init", "pw2\n\n", http.StatusTooManyRequests)
			b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusTooManyRequests)
			if !c.stop {
				free()
				if got := <-result; got.code != http.StatusNoContent {
					t.Fatalf("the init: %d %q", got.code, got.text)
				}
				b.expect(t, http.MethodGet, "/card", "", http.StatusOK)
				return
			}
			b.stop <- os.Interrupt
			got := <-result
			if want := notStarted + "shutdown, " + c.where + "\n"; got.code != http.StatusServiceUnavailable || got.text != want {
				t.Fatalf("the init: %d %q, want %q", got.code, got.text, want)
			}
			if code := b.exitCode(t); code != 0 {
				t.Fatalf("exit code %d", code)
			}
			b.leaving(t)
		})
	}
}

// after the third 403 in a row an unlock waits 1 s, then twice as long after
// every further 403 up to 64 s; a 400 or a 409 does not count, and a waiting
// unlock stretches nothing
func TestVaultUnlockPause(t *testing.T) {
	p, stretches := cheap(t)
	path := vaultPath(t)
	elsewhere := addrOf("relay-6")
	mustCreate(t, p, path, volumeSpec{"pw", profile.New(p, testMailbox, cardOf(t, p, testMailbox))},
		volumeSpec{"pw2", profile.New(p, elsewhere, cardOf(t, p, elsewhere))})
	b := newVaultBed(t, p, path, testMailbox, nil, nil)
	var mu sync.Mutex
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	b.va.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
	refused := func() {
		t.Helper()
		b.expect(t, http.MethodPut, "/vault/unlock", "wrong\n", http.StatusForbidden)
	}
	waits := func() {
		t.Helper()
		n := stretches.Load()
		if text := b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusTooManyRequests); text != pauseText+"\n" {
			t.Fatalf("body %q", text)
		}
		if stretches.Load() != n {
			t.Fatal("a stretch in the pause")
		}
	}
	for range freeUnlocks {
		refused()
	}
	waits()
	advance(time.Second - time.Millisecond)
	waits()
	advance(time.Millisecond)
	b.expect(t, http.MethodPut, "/vault/unlock", "", http.StatusBadRequest)
	b.expect(t, http.MethodPut, "/vault/unlock", "pw2\n", http.StatusConflict)
	b.expect(t, http.MethodPut, "/vault/unlock", "", http.StatusBadRequest)
	for k := freeUnlocks + 1; k <= 10; k++ {
		refused()
		pause := min(time.Second<<(k-freeUnlocks), maxUnlockPause)
		if k >= 9 && pause != 64*time.Second {
			t.Fatalf("the pause after %d refusals: %v", k, pause)
		}
		advance(pause - time.Millisecond)
		waits()
		advance(time.Millisecond)
	}
	b.expect(t, http.MethodPut, "/vault/unlock", "pw\n", http.StatusNoContent)
	if lines := strings.Count(b.out.String(), lineNoVolume+"\n"); lines != 10 {
		t.Fatalf("%d lines of a refusal, want one per 403", lines)
	}
}

// a body is taken only whole: one cut short, at the end of a block or
// anywhere, is refused before any stretch, whatever its framing
func TestVaultInitBodyArrivesWhole(t *testing.T) {
	p, stretches := cheap(t)
	b := newVaultBed(t, p, vaultPath(t), testMailbox, nil, nil)
	second := "pw2\n" + newPeerID(t, p, testMailbox).card.String() + "\n"
	for _, c := range []struct{ name, head, body string }{
		{"a length the body does not reach", fmt.Sprintf("Content-Length: %d\r\n", len("pw\n\n"+second)), "pw\n\n"},
		{"chunks without their end", "Transfer-Encoding: chunked\r\n", "4\r\npw\n\n\r\n"},
	} {
		code, text := rawPut(t, b.url, "/vault/init", c.head, c.body)
		if code != http.StatusBadRequest || text != "the body did not arrive\n" {
			t.Fatalf("%s: %d %q", c.name, code, text)
		}
	}
	if stretches.Load() != 0 || b.state() != lockedNoFile || len(b.lines()) != 0 {
		t.Fatalf("%d stretches, state %d, lines %q", stretches.Load(), b.state(), b.lines())
	}
	body := "pw\n\n" + second
	code, text := rawPut(t, b.url, "/vault/init", "Transfer-Encoding: chunked\r\n", fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body))
	if code != http.StatusNoContent {
		t.Fatalf("a whole chunked body: %d %q", code, text)
	}
}

// a request written by hand, whose sending side closes after the body
func rawPut(t *testing.T, url, path, head, body string) (int, string) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "PUT %s HTTP/1.1\r\nHost: admin\r\n%s\r\n%s", path, head, body); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(text)
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

func cardOf(t *testing.T, p jcrypto.CryptoProvider, mailboxAddr string) *e2e.Card {
	t.Helper()
	c := newPeerID(t, p, mailboxAddr).card
	return &c
}
