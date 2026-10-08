package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/noise"
)

const testMailbox = "relay-5.jimichi.svc.cluster.local:9000"

// the conversation as the admin port sees it: Pair records the cards and
// answers what the test sets
type fakePairing struct {
	mu    sync.Mutex
	cards []e2e.Card
	err   error
}

func (f *fakePairing) Pair(c e2e.Card) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cards = append(f.cards, c)
	return f.err
}

func (f *fakePairing) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cards)
}

type peerID struct {
	f    *secmem.Buffer
	id   *e2e.Identity
	card e2e.Card
	hash string
}

func newPeerID(t *testing.T, p jcrypto.CryptoProvider, mailboxAddr string) peerID {
	t.Helper()
	f, id, err := newPeerIdentity(p, mailboxAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		id.Close()
		f.Release()
	})
	card := id.Card()
	h, err := e2e.CardHash(p, card)
	if err != nil {
		t.Fatal(err)
	}
	return peerID{f: f, id: id, card: card, hash: hex.EncodeToString(h)}
}

type adminBed struct {
	ct     *contact
	conv   *fakePairing
	own    peerID
	url    string
	out    *logBuffer
	halts  int
	clock  time.Time
	haltMu sync.Mutex
}

type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newAdminBed(t *testing.T, p jcrypto.CryptoProvider) *adminBed {
	t.Helper()
	b := &adminBed{conv: &fakePairing{}, own: newPeerID(t, p, testMailbox), out: &logBuffer{}, clock: t0}
	b.ct = &contact{
		p: p, own: b.own.card, text: b.own.card.String(), conv: b.conv,
		logger: log.New(b.out, "", 0), now: func() time.Time { return b.clock },
		paired: make(chan struct{}),
		halt: func() {
			b.haltMu.Lock()
			b.halts++
			b.haltMu.Unlock()
		},
	}
	srv := httptest.NewServer(b.ct.handler())
	t.Cleanup(srv.Close)
	b.url = srv.URL
	return b
}

func (b *adminBed) call(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, b.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
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

func (b *adminBed) halted() int {
	b.haltMu.Lock()
	defer b.haltMu.Unlock()
	return b.halts
}

func isPaired(ct *contact) bool {
	select {
	case <-ct.paired:
		return true
	default:
		return false
	}
}

// the card goes out on GET /card and in no line of the log
func TestAdminHandsOutTheCard(t *testing.T) {
	b := newAdminBed(t, provider(t, jcrypto.SuiteC25519))
	code, text := b.call(t, http.MethodGet, "/card", "")
	if code != http.StatusOK || text != b.own.card.String()+"\n" {
		t.Fatalf("GET /card = %d %q", code, text)
	}
	if card, err := e2e.ParseCard(strings.TrimSpace(text)); err != nil || !bytes.Equal(card.Bytes(), b.own.card.Bytes()) {
		t.Fatalf("the card handed out does not parse back: %v", err)
	}
	if code, _ := b.call(t, http.MethodPost, "/card", ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /card = %d", code)
	}
	if b.out.String() != "" {
		t.Fatalf("GET /card logged %q", b.out.String())
	}
}

// the order of the checks: a body larger than a card is 413 and one that is
// not a canonical card 400, before and after pinning, and neither changes the
// state; a first card must be another client of the suite on the same mailbox
// whose key the conversation takes; the same card again is 204 without a
// second Pair
func TestPinningChecksInOrder(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	b := newAdminBed(t, p)
	peer := newPeerID(t, p, testMailbox)
	gost := newPeerID(t, provider(t, jcrypto.SuiteGOST), testMailbox)
	elsewhere := newPeerID(t, p, "relay-4.jimichi.svc.cluster.local:9000")

	garbage := []struct {
		body string
		code int
	}{
		{strings.Repeat("a", maxContactBody+1), http.StatusRequestEntityTooLarge},
		{"", http.StatusBadRequest},
		{"hello", http.StatusBadRequest},
		{peer.card.String() + "\n\n", http.StatusBadRequest},
		{" " + peer.card.String(), http.StatusBadRequest},
		{strings.Replace(peer.card.String(), "c25519:", "gost:", 1), http.StatusBadRequest},
	}
	for _, g := range garbage {
		if code, _ := b.call(t, http.MethodPut, "/contact", g.body); code != g.code {
			t.Fatalf("PUT %.20q = %d, want %d", g.body, code, g.code)
		}
	}
	ownStatic, ownQueue := peer.card, peer.card
	ownStatic.Static = b.own.card.Static
	ownQueue.Queue = b.own.card.Queue
	refused := []struct {
		name, card, why string
	}{
		{"another suite", gost.card.String(), "the card is of another suite\n"},
		{"another mailbox", elsewhere.card.String(), "the card names another mailbox\n"},
		{"its own card", b.own.card.String(), "the card is this client's own\n"},
		{"its own key with another queue", ownStatic.String(), "the card is this client's own\n"},
		{"its own queue with another key", ownQueue.String(), "the card is this client's own\n"},
	}
	for _, r := range refused {
		if code, why := b.call(t, http.MethodPut, "/contact", r.card); code != http.StatusBadRequest || why != r.why {
			t.Fatalf("%s: %d %q, want 400 %q", r.name, code, why, r.why)
		}
	}
	if b.conv.calls() != 0 || isPaired(b.ct) {
		t.Fatal("a refused card reached the conversation")
	}

	b.conv.err = e2e.ErrCard
	if code, _ := b.call(t, http.MethodPut, "/contact", peer.card.String()); code != http.StatusBadRequest {
		t.Fatalf("a key the conversation refuses: %d", code)
	}
	b.conv.err = conversation.ErrClosed
	if code, _ := b.call(t, http.MethodPut, "/contact", peer.card.String()); code != http.StatusServiceUnavailable {
		t.Fatalf("an ended conversation: %d", code)
	}
	if isPaired(b.ct) || b.out.String() != "" {
		t.Fatalf("a failed Pair pinned the card: %q", b.out.String())
	}

	b.conv.err = nil
	if code, _ := b.call(t, http.MethodPut, "/contact", peer.card.String()+"\n"); code != http.StatusNoContent {
		t.Fatalf("first card: %d", code)
	}
	if !isPaired(b.ct) {
		t.Fatal("not paired after 204")
	}
	role := e2e.RoleResponder
	if bytes.Compare(b.own.card.Static, peer.card.Static) < 0 {
		role = e2e.RoleInitiator
	}
	if want := "contact pinned card_hash=" + peer.hash + " role=" + role.String() + "\n"; b.out.String() != want {
		t.Fatalf("log %q, want %q", b.out.String(), want)
	}
	calls := b.conv.calls()
	if code, _ := b.call(t, http.MethodPut, "/contact", peer.card.String()); code != http.StatusNoContent || b.conv.calls() != calls {
		t.Fatalf("the same card again: %d, %d Pair calls", code, b.conv.calls())
	}
	for _, g := range garbage {
		if code, _ := b.call(t, http.MethodPut, "/contact", g.body); code != g.code {
			t.Fatalf("after pinning, PUT %.20q = %d, want %d", g.body, code, g.code)
		}
	}
	if b.ct.halted() || b.halted() != 0 {
		t.Fatal("a body that is no card stopped the client")
	}
	if code, text := b.call(t, http.MethodGet, "/card", ""); code != http.StatusOK || text != b.own.card.String()+"\n" {
		t.Fatalf("GET /card after pinning = %d %q", code, text)
	}
}

// any other card after pinning, even one the first check would have refused,
// stops the client: 409, the conversation and the keys go once, the line names
// the pinned card only, and from then on every request is 409 while the
// process lives on
func TestAnotherCardStopsTheClient(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	for _, c := range []struct {
		name  string
		other func(t *testing.T) string
	}{
		{"another client", func(t *testing.T) string { return newPeerID(t, p, testMailbox).card.String() }},
		{"another suite", func(t *testing.T) string {
			return newPeerID(t, provider(t, jcrypto.SuiteGOST), testMailbox).card.String()
		}},
		{"its own card", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newAdminBed(t, p)
			peer := newPeerID(t, p, testMailbox)
			if code, _ := b.call(t, http.MethodPut, "/contact", peer.card.String()); code != http.StatusNoContent {
				t.Fatalf("first card: %d", code)
			}
			other := b.own.card.String()
			if c.other != nil {
				other = c.other(t)
			}
			if code, _ := b.call(t, http.MethodPut, "/contact", other); code != http.StatusConflict {
				t.Fatalf("another card: %d", code)
			}
			if !b.ct.halted() || b.halted() != 1 {
				t.Fatalf("stopped %v, %d halts", b.ct.halted(), b.halted())
			}
			lines := strings.Split(strings.TrimSpace(b.out.String()), "\n")
			if len(lines) != 2 || lines[1] != "contact card changed, refusing: pinned card_hash="+peer.hash {
				t.Fatalf("log:\n%s", b.out.String())
			}
			for _, req := range []struct{ method, path, body string }{
				{http.MethodGet, "/card", ""},
				{http.MethodPut, "/contact", peer.card.String()},
				{http.MethodPut, "/contact", other},
				{http.MethodPut, "/contact", "hello"},
				{http.MethodGet, "/nothing", ""},
			} {
				if code, _ := b.call(t, req.method, req.path, req.body); code != http.StatusConflict {
					t.Fatalf("stopped: %s %s = %d", req.method, req.path, code)
				}
			}
			if b.halted() != 1 || len(strings.Split(strings.TrimSpace(b.out.String()), "\n")) != 2 {
				t.Fatalf("%d halts, log:\n%s", b.halted(), b.out.String())
			}
			if strings.Contains(b.out.String(), other) || strings.Contains(b.out.String(), b.own.card.String()) {
				t.Fatal("a card reached the log")
			}
		})
	}
}

// the 409 is written and flushed before the stop, which may wait for a rebuild
// under way
func TestAnotherCardIsAnsweredBeforeTheStop(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	b := newAdminBed(t, p)
	if code, _ := b.call(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String()); code != http.StatusNoContent {
		t.Fatalf("first card: %d", code)
	}
	rec := httptest.NewRecorder()
	var code int
	var flushed bool
	var body string
	b.ct.halt = func() { code, flushed, body = rec.Code, rec.Flushed, rec.Body.String() }
	req := httptest.NewRequest(http.MethodPut, "/contact", strings.NewReader(newPeerID(t, p, testMailbox).card.String()))
	b.ct.handler().ServeHTTP(rec, req)
	if code != http.StatusConflict || !flushed || !strings.HasPrefix(body, "stopped: ") {
		t.Fatalf("at the stop: %d, flushed %v, body %q; want the flushed 409", code, flushed, body)
	}
}

// the stop of the admin port ends the conversation, then releases the
// identity key and F
func TestStopReleasesTheConversationAndTheKeys(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	own, peer := newPeerID(t, p, testMailbox), newPeerID(t, p, testMailbox)
	conv, err := conversation.Start(conversation.Config{
		Provider: p, Self: own.id, Fetch: own.f,
		First: &fakeCircuit{replies: make(chan []byte)},
		Dial:  func() (conversation.Circuit, error) { return nil, errEntryRefuses },
		Rate:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conv.Close)
	ctx, err := jcrypto.NewContext(p, "test", []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	agree := func() error {
		k, err := own.id.Static().Agree(peer.card.Static, ctx)
		if err == nil {
			k.Release()
		}
		return err
	}
	if err := agree(); err != nil {
		t.Fatalf("the identity key before the stop: %v", err)
	}

	release(conv, own.id, own.f)()
	select {
	case <-conv.Done():
	default:
		t.Fatal("the conversation runs on after the stop")
	}
	if own.f.Bytes() != nil {
		t.Fatal("F is still held after the stop")
	}
	if err := agree(); !errors.Is(err, noise.ErrClosed) {
		t.Fatalf("the identity key after the stop: %v, want it released", err)
	}
}

// the line of every minute names the state and counts; a pinned peer silent
// for more than a minute gets the line that tells the operator to look at it
func TestReportLines(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	b := newAdminBed(t, p)
	b.ct.report(conversation.Stats{Requests: 7})
	if got := b.out.String(); !strings.HasPrefix(got, "e2e state=unpaired requests=7 puts=0 ") || strings.Count(got, "\n") != 1 {
		t.Fatalf("unpaired: %q", got)
	}
	for _, key := range []string{"put_refused=", "window_full=", "hits=", "sent=", "received=", "dummies_sent=", "dummies_received=",
		"copies=", "late=", "lost=", "window=", "bad=", "bad_replies=", "handshakes=", "refused_handshakes=", "replayed_handshakes=",
		"stale=", "rebuilds=", "refusals=", "outbox_dropped=", "held_dropped=", "inbox_dropped=", "unanswered="} {
		if !strings.Contains(b.out.String(), " "+key) {
			t.Fatalf("no %s in %q", key, b.out.String())
		}
	}

	peer := newPeerID(t, p, testMailbox)
	if code, _ := b.call(t, http.MethodPut, "/contact", peer.card.String()); code != http.StatusNoContent {
		t.Fatal(code)
	}
	b.out = &logBuffer{}
	b.ct.logger = log.New(b.out, "", 0)
	b.clock = t0.Add(50 * time.Second)
	b.ct.report(conversation.Stats{Paired: true, State: e2e.StateEstablished})
	if got := b.out.String(); !strings.HasPrefix(got, "e2e state=established ") || strings.Count(got, "\n") != 1 {
		t.Fatalf("paired: %q", got)
	}
	b.clock = t0.Add(3 * time.Minute)
	b.ct.report(conversation.Stats{Paired: true, State: e2e.StateStale, LastOpened: t0.Add(time.Minute)})
	lines := strings.Split(strings.TrimSpace(b.out.String()), "\n")
	if want := "e2e peer not reachable for 2m0s, pinned card_hash=" + peer.hash; len(lines) != 3 || lines[2] != want {
		t.Fatalf("silent peer:\n%s\nwant %q", b.out.String(), want)
	}

	if code, _ := b.call(t, http.MethodPut, "/contact", newPeerID(t, p, testMailbox).card.String()); code != http.StatusConflict {
		t.Fatal(code)
	}
	b.out = &logBuffer{}
	b.ct.logger = log.New(b.out, "", 0)
	b.ct.report(conversation.Stats{Paired: true, State: e2e.StateStale})
	if got := b.out.String(); !strings.HasPrefix(got, "e2e state=stopped ") || strings.Count(got, "\n") != 1 {
		t.Fatalf("stopped: %q", got)
	}
}

func TestPeerFlagsAreCheckedBeforeTheNetwork(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	nodes := []string{addrOf("relay-1"), addrOf("relay-2"), addrOf("relay-3"), addrOf("relay-4"), addrOf("relay-5")}
	good := func() peerFlags {
		return peerFlags{
			nodes: strings.Join(nodes, ","), mailbox: nodes[4], admin: "127.0.0.1:9201", infoPort: "9100",
			mode: "fixed", message: "hi", hops: 3, missing: 1, count: 0, rate: 200 * time.Millisecond,
			jitter: 0, interval: 2 * time.Second, handshakeTimeout: time.Minute,
		}
	}
	if _, exit, err := checkPeer(p, good()); err != nil || exit != 4 {
		t.Fatalf("good flags: exit %d, %v", exit, err)
	}
	for _, c := range []struct {
		name   string
		change func(*peerFlags)
	}{
		{"no mailbox", func(f *peerFlags) { f.mailbox = "" }},
		{"a mailbox off the list", func(f *peerFlags) { f.mailbox = addrOf("relay-6") }},
		{"one hop", func(f *peerFlags) { f.hops = 1 }},
		{"five hops", func(f *peerFlags) { f.hops = 5 }},
		{"immediate mode", func(f *peerFlags) { f.mode = "immediate" }},
		{"cover cells", func(f *peerFlags) { f.cover = time.Second }},
		{"a rate below the reply buffer", func(f *peerFlags) { f.rate = 39 * time.Millisecond }},
		{"jitter as long as the rate", func(f *peerFlags) { f.jitter = f.rate }},
		{"negative jitter", func(f *peerFlags) { f.jitter = -time.Millisecond }},
		{"admin on a name", func(f *peerFlags) { f.admin = "localhost:9201" }},
		{"admin on all addresses", func(f *peerFlags) { f.admin = ":9201" }},
		{"admin on another address", func(f *peerFlags) { f.admin = "10.0.0.1:9201" }},
		{"admin without a port", func(f *peerFlags) { f.admin = "127.0.0.1" }},
		{"a message longer than a record carries", func(f *peerFlags) { f.message = strings.Repeat("m", maxText+1) }},
		{"negative count", func(f *peerFlags) { f.count = -1 }},
		{"negative interval", func(f *peerFlags) { f.interval = -time.Second }},
		{"negative missing", func(f *peerFlags) { f.missing = -1 }},
		{"no handshake timeout", func(f *peerFlags) { f.handshakeTimeout = 0 }},
		{"a fixed chain that does not end on the mailbox", func(f *peerFlags) { f.fixed = true }},
		{"a node listed twice", func(f *peerFlags) { f.nodes += "," + nodes[0] }},
	} {
		f := good()
		c.change(&f)
		if _, _, err := checkPeer(p, f); err == nil {
			t.Errorf("%s: taken", c.name)
		} else if strings.Contains(err.Error(), "relay-") {
			t.Errorf("%s: the refusal names a node: %v", c.name, err)
		}
	}
	for _, f := range []func(*peerFlags){
		func(f *peerFlags) { f.message = strings.Repeat("m", maxText) },
		func(f *peerFlags) { f.admin = "[::1]:9201" },
		func(f *peerFlags) { f.admin = "127.0.0.1:0" },
		func(f *peerFlags) {
			f.rate, f.jitter = conversation.MinRate(conversation.DefaultReplyTimeout), time.Millisecond
		},
		func(f *peerFlags) { f.fixed, f.mailbox = true, nodes[2] },
		func(f *peerFlags) { f.hops = 2 },
		func(f *peerFlags) { f.hops = 4 },
	} {
		flags := good()
		f(&flags)
		if _, _, err := checkPeer(p, flags); err != nil {
			t.Errorf("%+v: %v", flags, err)
		}
	}
	gost := provider(t, jcrypto.SuiteGOST)
	f := good()
	f.hops = 4
	if _, _, err := checkPeer(gost, f); err == nil {
		t.Error("four hops on gost taken")
	}
}

// the design sets 96 KiB: a client at its peak locks about 19 pages of 4 KiB,
// and the limit leaves room for five more
func TestPeerMemlockMinimumIs96KiB(t *testing.T) {
	if minPeerMemlock != 98304 {
		t.Fatalf("minPeerMemlock is %d bytes, want 96 KiB", minPeerMemlock)
	}
	if err := memlockFits(98304, minPeerMemlock); err != nil {
		t.Fatalf("a limit of 96 KiB refused: %v", err)
	}
	err := memlockFits(98303, minPeerMemlock)
	if err == nil || err.Error() != "RLIMIT_MEMLOCK is 98303 bytes, need at least 98304 to lock key pages" {
		t.Fatalf("a limit one byte short: %v", err)
	}
}
