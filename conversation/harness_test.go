package conversation

import (
	"bytes"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

// the tests drive the loop's handlers by hand, one tick of a fake clock at a
// time, over fake circuits that hand each request to a real mailbox.Store a
// fixed number of ticks after it was sent and the reply back a fixed number
// later: every run of a test takes the same steps

const (
	testMailbox = "relay-5.jimichi.svc.cluster.local:9000"
	testRate    = 200 * time.Millisecond
	// the payload of a three-hop circuit
	testPayload = 444
)

// every test runs on a provider that fails it on a signing call
func eachSuite(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider)) {
	t.Helper()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(s.String(), func(t *testing.T) { run(t, noSigning{CryptoProvider: p, t: t}) })
	}
}

func c25519(t *testing.T) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	return noSigning{CryptoProvider: p, t: t}
}

// a client identity is an agreement key only: a signing call fails the test
type noSigning struct {
	jcrypto.CryptoProvider
	t testing.TB
}

func (p noSigning) GenerateSigning() (*secmem.Buffer, []byte, error) {
	p.t.Error("GenerateSigning called")
	return p.CryptoProvider.GenerateSigning()
}

func (p noSigning) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	p.t.Error("Sign called")
	return p.CryptoProvider.Sign(priv, msg)
}

func (p noSigning) Verify(pub, msg, sig []byte) bool {
	p.t.Error("Verify called")
	return p.CryptoProvider.Verify(pub, msg, sig)
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// the identity and fetch capability of one client
type party struct {
	f  *secmem.Buffer
	id *e2e.Identity
}

func newParty(t testing.TB, p jcrypto.CryptoProvider) party {
	t.Helper()
	f, err := secmem.New(mailbox.CapSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(f.Bytes()); err != nil {
		t.Fatal(err)
	}
	f.Bytes()[0] |= 1
	q, err := mailbox.QueueID(p, f.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	id, err := e2e.NewIdentity(p, testMailbox, q)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		id.Close()
		f.Release()
	})
	return party{f: f, id: id}
}

// two parties, the first the initiator: its key is the smaller one
func parties(t testing.TB, p jcrypto.CryptoProvider) (party, party) {
	t.Helper()
	for {
		a, b := newParty(t, p), newParty(t, p)
		if bytes.Compare(a.id.Card().Static, b.id.Card().Static) < 0 {
			return a, b
		}
	}
}

type deliverFunc func(circuit uint64, payload []byte) []byte

type flight struct {
	payload  []byte
	at, back int
	reached  bool
	reply    []byte
}

// a circuit whose requests reach the mailbox up ticks after they are sent and
// whose replies come back down ticks after that, strictly in order
type fakeCircuit struct {
	net      *testNet
	id       uint64
	up, down int
	payload  int
	flights  []*flight
	sent     []mailbox.Request
	closed   bool
	refused  error
	sendErr  error
}

func (f *fakeCircuit) Send(b []byte) error {
	if f.closed {
		return errors.New("fake circuit: closed")
	}
	if f.sendErr != nil {
		return f.sendErr
	}
	req, err := mailbox.ParseRequest(b)
	if err != nil {
		f.net.t.Errorf("a request of %d bytes: %v", len(b), err)
	}
	f.sent = append(f.sent, req)
	f.flights = append(f.flights, &flight{payload: bytes.Clone(b), at: f.net.tick + f.up, back: f.net.tick + f.up + f.down})
	return nil
}

func (f *fakeCircuit) Replies() <-chan []byte { return nil }
func (f *fakeCircuit) Refused() error         { return f.refused }
func (f *fakeCircuit) MaxPayload() int        { return f.payload }

func (f *fakeCircuit) Close() error {
	f.closed = true
	return nil
}

// the puts of the requests sent so far, nil for a request without one
func (f *fakeCircuit) puts() [][]byte {
	out := make([][]byte, len(f.sent))
	for i, r := range f.sent {
		if r.Puts() {
			out[i] = bytes.Clone(r.Record[:])
		}
	}
	return out
}

type testNet struct {
	t       *testing.T
	p       jcrypto.CryptoProvider
	clock   *testClock
	tick    int
	store   *mailbox.Store
	deliver deliverFunc
	nextID  uint64
	peers   []*testPeer
	// runs at the start of every step, before any request moves
	before []func()
}

func newNet(t *testing.T, p jcrypto.CryptoProvider, change func(*mailbox.Limits)) *testNet {
	t.Helper()
	clock := newTestClock()
	lim := mailbox.DefaultLimits()
	if change != nil {
		change(&lim)
	}
	store, err := mailbox.NewStore(p, lim, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return &testNet{t: t, p: p, clock: clock, store: store, deliver: store.Deliver}
}

func (n *testNet) wrap(w func(next deliverFunc) deliverFunc) { n.deliver = w(n.deliver) }

func (n *testNet) circuit(up, down int) *fakeCircuit {
	n.nextID++
	return &fakeCircuit{net: n, id: n.nextID, up: up, down: down, payload: testPayload}
}

type testPeer struct {
	name     string
	net      *testNet
	party    party
	c        *Conversation
	up, down int
	paused   bool
	got      []string
	events   []Event
	// the ticks Dial was called on, and what it answers
	dials   []int
	dialErr error
}

// a conversation over a fake circuit, CoverPuts on unless change says
// otherwise
func (n *testNet) join(name string, pt party, up, down int, change func(*Config)) *testPeer {
	n.t.Helper()
	pr := &testPeer{name: name, net: n, party: pt, up: up, down: down}
	first := n.circuit(up, down)
	cfg := Config{
		Provider:  n.p,
		Self:      pt.id,
		Fetch:     pt.f,
		First:     first,
		Dial:      pr.dial,
		Rate:      testRate,
		CoverPuts: true,
		Now:       n.clock.Now,
		Events:    func(ev Event) { pr.events = append(pr.events, ev) },
	}
	if change != nil {
		change(&cfg)
	}
	c, err := newConversation(cfg)
	if err != nil {
		n.t.Fatalf("%s: %v", name, err)
	}
	c.attach(cfg.First)
	pr.c = c
	n.t.Cleanup(c.teardown)
	n.peers = append(n.peers, pr)
	return pr
}

func (pr *testPeer) dial() (Circuit, error) {
	pr.dials = append(pr.dials, pr.net.tick)
	if pr.dialErr != nil {
		return nil, pr.dialErr
	}
	return pr.net.circuit(pr.up, pr.down), nil
}

func (pr *testPeer) circ() *fakeCircuit {
	f, _ := pr.c.circ.(*fakeCircuit)
	return f
}

func (pr *testPeer) reach() {
	f := pr.circ()
	if f == nil {
		return
	}
	for _, fl := range f.flights {
		if !fl.reached && fl.at <= pr.net.tick {
			fl.reached = true
			fl.reply = pr.net.deliver(f.id, bytes.Clone(fl.payload))
		}
	}
}

func (pr *testPeer) answer() {
	for {
		f := pr.circ()
		if f == nil || len(f.flights) == 0 || !f.flights[0].reached || f.flights[0].back > pr.net.tick {
			break
		}
		fl := f.flights[0]
		f.flights = f.flights[1:]
		pr.c.onReply(fl.reply)
	}
	pr.settle()
}

// takes the messages that came out and tears down a conversation that ended
func (pr *testPeer) settle() {
	for {
		select {
		case b, ok := <-pr.c.messages:
			if !ok {
				return
			}
			pr.got = append(pr.got, string(b))
			continue
		default:
		}
		if pr.c.finished && !pr.c.tornDown {
			pr.c.teardown()
		}
		return
	}
}

// one tick: requests due reach the mailbox, replies due come back, then every
// conversation that is not paused ticks
func (n *testNet) step() {
	n.tick++
	n.clock.Add(testRate)
	for _, f := range n.before {
		f()
	}
	for _, pr := range n.peers {
		if !pr.paused {
			pr.reach()
		}
	}
	for _, pr := range n.peers {
		if !pr.paused {
			pr.answer()
		}
	}
	for _, pr := range n.peers {
		if !pr.paused {
			pr.c.onTick()
			pr.settle()
		}
	}
}

func (n *testNet) run(ticks int) {
	for range ticks {
		n.step()
	}
}

// steps until cond holds and returns the number of steps it took
func (n *testNet) until(what string, limit int, cond func() bool) int {
	n.t.Helper()
	for i := 0; i <= limit; i++ {
		if cond() {
			return i
		}
		n.step()
	}
	n.t.Fatalf("%s: not within %d ticks", what, limit)
	return 0
}

func pair(t *testing.T, a, b *testPeer) {
	t.Helper()
	if err := a.c.onPair(b.party.id.Card()); err != nil {
		t.Fatalf("%s pairs: %v", a.name, err)
	}
	if err := b.c.onPair(a.party.id.Card()); err != nil {
		t.Fatalf("%s pairs: %v", b.name, err)
	}
}

func (pr *testPeer) state() e2e.State {
	if pr.c.session == nil {
		return 0
	}
	return pr.c.session.State()
}

func (pr *testPeer) session() e2e.Stats { return pr.c.session.Stats() }

func confirmed(ini, resp *testPeer) bool {
	return ini.state() == e2e.StateEstablished && resp.state() == e2e.StateConfirmed
}

// pairs both, runs until the responder is confirmed and returns how long it
// took
func (n *testNet) start(t *testing.T, ini, resp *testPeer) int {
	t.Helper()
	pair(t, ini, resp)
	return n.until("the session confirmed", 200, func() bool { return confirmed(ini, resp) })
}

func (pr *testPeer) send(t *testing.T, bodies ...string) {
	t.Helper()
	for _, b := range bodies {
		if err := pr.c.Send([]byte(b)); err != nil {
			t.Fatalf("%s sends: %v", pr.name, err)
		}
	}
}

func (pr *testPeer) count(body string) int {
	n := 0
	for _, g := range pr.got {
		if g == body {
			n++
		}
	}
	return n
}

func (pr *testPeer) outbox() []string {
	pr.c.mu.Lock()
	defer pr.c.mu.Unlock()
	out := make([]string, len(pr.c.outbox))
	for i, it := range pr.c.outbox {
		out[i] = string(it.body)
	}
	return out
}

// the bodies in the outbox themselves, not copies
func (pr *testPeer) queued() [][]byte {
	pr.c.mu.Lock()
	defer pr.c.mu.Unlock()
	out := make([][]byte, len(pr.c.outbox))
	for i, it := range pr.c.outbox {
		out[i] = it.body
	}
	return out
}

func zeroed(bufs [][]byte) bool {
	return !slices.ContainsFunc(bufs, func(b []byte) bool { return !allZero(b) })
}

// a record as a third party with nothing but the card makes it
func garbage(t testing.TB, kind byte) [mailbox.RecordSize]byte {
	t.Helper()
	var rec [mailbox.RecordSize]byte
	if _, err := rand.Read(rec[:]); err != nil {
		t.Fatal(err)
	}
	rec[0] = kind
	return rec
}

// puts rec into the queue of pr from a circuit of its own, fetching nothing
func (n *testNet) putFrom(circuit uint64, pr *testPeer, rec [mailbox.RecordSize]byte) byte {
	n.t.Helper()
	req := mailbox.Request{Put: pr.party.id.Card().Queue, Record: rec}
	reply, err := mailbox.ParseReply(n.deliver(circuit, req.Bytes()))
	if err != nil {
		n.t.Fatal(err)
	}
	return reply.Status & mailbox.PutMask
}

func dataRecord(r mailbox.Request) bool { return r.Puts() && r.Record[0] == 0x03 }

func mustSuite(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return noSigning{CryptoProvider: p, t: t}
}
