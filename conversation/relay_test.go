package conversation

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/relay"
)

// the conversation as a binary would run it: its own loop and ticker, the
// reply reader, circuits of three relays in this process with the mailbox
// Store as the Deliver of the exit, and real time

// relays that forward at once make the round trip of one request on an idle
// stand the work it costs along the chain, tens of times more with GOST in
// pure Go than with X25519 under the race detector. Conversations that send
// faster than the stand works queue their requests in the relays, and the
// round trip grows until replies time out; so the rate follows a measured
// round trip, and every wait counts the ticks the conversations ran against
// the ticks the protocol needs. Relays with a period of their own make the
// round trip mostly waiting, up to five periods for three hops, and a rate
// below it keeps several requests in flight
const (
	probes = 5
	// two conversations, each request about a round trip of work: a rate of
	// four round trips keeps the stand at half a core
	rateOverRoundTrip = 4
	// over paced relays the rate is a third of the round trip but above the
	// period, since a relay carries one cell per period on a circuit
	inFlight   = 3
	livePeriod = 10 * time.Millisecond
	// 200 rates of reply timeout must outlast a scheduler pause
	minRate         = 10 * time.Millisecond
	firstPauseTicks = 2
	// how many times the ticks a wait needs the test gives it before it calls
	// the conversation stuck, and the wall time no wait goes past
	slack   = 5
	maxWait = 2 * time.Minute
)

func startNode(t *testing.T, p jcrypto.CryptoProvider, period time.Duration, deliver relay.Deliver) client.Node {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	r, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, StaticPub: pub, Deliver: deliver, Period: period})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = r.Serve(ln) }()
	t.Cleanup(func() {
		r.Close()
		_ = ln.Close()
	})
	return client.Node{Addr: ln.Addr().String(), StaticPub: pub}
}

type relayNet struct {
	p     jcrypto.CryptoProvider
	store *mailbox.Store
	chain []client.Node
	// the period of the relays, zero when they forward at once
	period time.Duration
	// the slowest round trip of the probe and the slowest circuit build so
	// far, and the request period they give
	roundTrip, build, rate time.Duration
	peers                  []*livePeer
}

func newRelayNet(t *testing.T, p jcrypto.CryptoProvider, period time.Duration) *relayNet {
	t.Helper()
	store, err := mailbox.NewStore(p, mailbox.DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	exit := startNode(t, p, period, store.Deliver)
	r := &relayNet{p: p, store: store, period: period, chain: []client.Node{startNode(t, p, period, nil), startNode(t, p, period, nil), exit}}
	r.measure(t)
	return r
}

// a probe circuit sends one request at a time; a request that asks for
// nothing costs the mailbox the same hash as any other
func (r *relayNet) measure(t *testing.T) {
	t.Helper()
	start := time.Now()
	cl, err := client.Dial(client.Config{Provider: r.p, Chain: r.chain})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	r.build = time.Since(start)
	for i := range probes {
		req := mailbox.Request{Tag: uint16(i)}
		start := time.Now()
		if err := cl.Send(req.Bytes()); err != nil {
			t.Fatal(err)
		}
		select {
		case _, ok := <-cl.Replies():
			if !ok {
				t.Fatalf("the probe circuit ended: %v", cl.Refused())
			}
		case <-time.After(time.Minute):
			t.Fatal("no reply to the probe")
		}
		r.roundTrip = max(r.roundTrip, time.Since(start))
	}
	if r.period > 0 {
		r.rate = max(minRate, r.roundTrip/inFlight, r.period+r.period/4)
	} else {
		r.rate = max(minRate, rateOverRoundTrip*r.roundTrip)
	}
}

func ticksOf(d, rate time.Duration) uint64 { return uint64((d + rate - 1) / rate) }

// a leg takes a record from one side to the other: a tick for its sender to
// put it, a round trip, and a tick for the first fetch of the other side to
// pass it at the mailbox
func (r *relayNet) legs(n int) uint64 {
	return uint64(n) * (2 + ticksOf(r.roundTrip, r.rate))
}

// the end of a circuit is seen at once; the driver dials at its first tick
// after firstPause and counts the rebuild once the dial returns
func (r *relayNet) rebuildTicks() uint64 {
	return firstPauseTicks + 1 + ticksOf(r.build, r.rate)
}

// polls until done and returns the ticks it took, the most requests either
// conversation sent meanwhile; one without a circuit sends nothing, and the
// other one still counts. A starved runner drops ticks of the conversations'
// own tickers as it slows the stand, so wall time says little about the
// protocol, while a conversation that keeps sending past slack times the
// ticks it needs is stuck. A wait in which neither sends at all ends at slack
// squared times the ticks it needs in wall time, and none goes past maxWait,
// so a stuck conversation fails with the report before the test times out
func (r *relayNet) wait(t *testing.T, what string, need uint64, done func() bool) uint64 {
	t.Helper()
	from := make([]uint64, len(r.peers))
	for i, lp := range r.peers {
		from[i] = lp.c.Stats().Requests
	}
	start := time.Now()
	deadline := start.Add(min(time.Duration(slack*slack*need)*r.rate, maxWait))
	poll := time.NewTicker(r.rate)
	defer poll.Stop()
	for {
		var n uint64
		for i, lp := range r.peers {
			n = max(n, lp.c.Stats().Requests-from[i])
		}
		if done() {
			return n
		}
		if n > slack*need || time.Now().After(deadline) {
			t.Fatalf("%s: not in %d ticks and %v, %d ticks needed\n%s", what, n, time.Since(start).Round(time.Millisecond), need, r.report())
		}
		<-poll.C
	}
}

func (r *relayNet) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "relay period %v, rate %v, round trip %v, build %v", r.period, r.rate, r.roundTrip, r.build)
	for _, lp := range r.peers {
		fmt.Fprintf(&b, "\n%s: %d requests in flight at most, %+v", lp.name, lp.peak.Load(), lp.c.Stats())
	}
	fmt.Fprintf(&b, "\nmailbox: %+v", r.store.Stats())
	return b.String()
}

type livePeer struct {
	name  string
	party party
	r     *relayNet
	c     *Conversation
	// the most requests sent on one circuit and not yet answered
	peak atomic.Int64

	mu     sync.Mutex
	circs  []*countedCircuit
	events []Event
}

// a circuit that counts its requests and the replies that came back
type countedCircuit struct {
	*client.Client
	peak           *atomic.Int64
	sent, answered atomic.Int64
	replies        chan []byte
	done           chan struct{}
	closeOnce      sync.Once
}

func counted(cl *client.Client, peak *atomic.Int64) *countedCircuit {
	cc := &countedCircuit{Client: cl, peak: peak, replies: make(chan []byte, cap(cl.Replies())), done: make(chan struct{})}
	go cc.forward()
	return cc
}

func (cc *countedCircuit) forward() {
	defer close(cc.replies)
	for b := range cc.Client.Replies() {
		cc.answered.Add(1)
		select {
		case cc.replies <- b:
		case <-cc.done:
		}
	}
}

func (cc *countedCircuit) Send(b []byte) error {
	n := cc.sent.Add(1) - cc.answered.Load()
	for p := cc.peak.Load(); n > p; p = cc.peak.Load() {
		if cc.peak.CompareAndSwap(p, n) {
			break
		}
	}
	return cc.Client.Send(b)
}

func (cc *countedCircuit) Replies() <-chan []byte { return cc.replies }

func (cc *countedCircuit) Close() error {
	cc.closeOnce.Do(func() { close(cc.done) })
	return cc.Client.Close()
}

func (r *relayNet) join(t *testing.T, name string, pt party, change func(*Config)) *livePeer {
	t.Helper()
	lp := &livePeer{name: name, party: pt, r: r}
	start := time.Now()
	first, err := lp.dial()
	if err != nil {
		t.Fatal(err)
	}
	r.build = max(r.build, time.Since(start))
	cfg := Config{
		Provider:     r.p,
		Self:         pt.id,
		Fetch:        pt.f,
		First:        first,
		Dial:         lp.dial,
		Rate:         r.rate,
		CoverPuts:    true,
		ReplyTimeout: 200 * r.rate,
		Events: func(ev Event) {
			lp.mu.Lock()
			lp.events = append(lp.events, ev)
			lp.mu.Unlock()
		},
	}
	if change != nil {
		change(&cfg)
	}
	c, err := newConversation(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.firstPause = firstPauseTicks * r.rate
	c.launch()
	lp.c = c
	r.peers = append(r.peers, lp)
	t.Cleanup(c.Close)
	return lp
}

func (lp *livePeer) dial() (Circuit, error) {
	cl, err := client.Dial(client.Config{Provider: lp.r.p, Chain: lp.r.chain})
	if err != nil {
		return nil, err
	}
	cc := counted(cl, &lp.peak)
	lp.mu.Lock()
	lp.circs = append(lp.circs, cc)
	lp.mu.Unlock()
	return cc, nil
}

func (lp *livePeer) current() *countedCircuit {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	return lp.circs[len(lp.circs)-1]
}

func (lp *livePeer) expect(t *testing.T, body string, need uint64) {
	t.Helper()
	lp.r.wait(t, fmt.Sprintf("%s: %q", lp.name, body), need, func() bool {
		for {
			select {
			case m, ok := <-lp.c.Messages():
				if !ok {
					t.Fatalf("%s: the conversation ended with %v before %q", lp.name, lp.c.Err(), body)
				}
				if string(m) == body {
					return true
				}
			default:
				return false
			}
		}
	})
}

func (lp *livePeer) send(t *testing.T, body string) {
	t.Helper()
	if err := lp.c.Send([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

// the responder speaks first and the initiator only answers, with cover puts
// and without: the round trip needs the initiator's first record after kk2.
// Then the circuit of the initiator is closed under it, and the conversation
// goes on over a rebuilt one with the same session. X25519 runs over paced
// relays and must have kept two requests or more in flight on each side, GOST
// over relays that forward at once at a rate of several round trips
func TestConversationOverRelays(t *testing.T) {
	for _, s := range []struct {
		suite  jcrypto.Suite
		period time.Duration
	}{{jcrypto.SuiteC25519, livePeriod}, {jcrypto.SuiteGOST, 0}} {
		t.Run(s.suite.String(), func(t *testing.T) {
			p := mustSuite(t, s.suite)
			for _, cover := range []bool{true, false} {
				t.Run(fmt.Sprintf("cover puts %v", cover), func(t *testing.T) {
					conversationOverRelays(t, p, s.period, cover)
				})
			}
		})
	}
}

func conversationOverRelays(t *testing.T, p jcrypto.CryptoProvider, period time.Duration, cover bool) {
	r := newRelayNet(t, p, period)
	pi, pr := parties(t, p)
	change := func(c *Config) {
		c.CoverPuts = cover
		// a keepalive of the initiator would confirm the responder as well,
		// so none comes before a wait gives up
		c.Keepalive, c.StaleAfter = 2*maxWait, 3*maxWait
	}
	ini := r.join(t, "initiator", pi, change)
	resp := r.join(t, "responder", pr, change)
	if err := ini.c.Pair(resp.party.id.Card()); err != nil {
		t.Fatal(err)
	}
	resp.send(t, "ping")
	if err := resp.c.Pair(ini.party.id.Card()); err != nil {
		t.Fatal(err)
	}
	if err := resp.c.Pair(ini.party.id.Card()); err != nil {
		t.Fatalf("the same card again: %v", err)
	}
	// kk1, kk2 and the initiator's first record after it go first
	ini.expect(t, "ping", r.legs(4))
	if got := ini.c.Stats().Session.DummiesSent; !cover && got != 1 {
		t.Fatalf("the initiator sealed %d dummies by the time ping came, want the confirming record alone\n%s", got, r.report())
	}
	ini.send(t, "pong")
	resp.expect(t, "pong", r.legs(1))
	for _, lp := range []*livePeer{ini, resp} {
		if st := lp.c.Stats(); st.Unanswered != 0 || st.PutRefused != 0 || st.Rebuilds != 0 {
			t.Fatalf("%s before the close\n%s", lp.name, r.report())
		}
	}

	epoch := ini.c.Stats().Epoch
	_ = ini.current().Close()
	rebuilt := r.wait(t, "the rebuild", r.rebuildTicks(), func() bool { return ini.c.Stats().Rebuilds > 0 })
	// with cover puts the responder put a record on each of its ticks while
	// the initiator had no circuit, and they wait ahead
	resp.send(t, "after")
	ini.expect(t, "after", r.legs(1)+rebuilt)
	ini.send(t, "again")
	resp.expect(t, "again", r.legs(1))
	if period > 0 {
		for _, lp := range []*livePeer{ini, resp} {
			if lp.peak.Load() < 2 {
				t.Fatalf("%s kept no two requests in flight over paced relays\n%s", lp.name, r.report())
			}
		}
	}

	st := ini.c.Stats()
	ini.mu.Lock()
	events := append([]Event(nil), ini.events...)
	ini.mu.Unlock()
	if st.Epoch != epoch || st.BadReplies != 0 || st.Rebuilds != 1 || st.Refusals != 0 {
		t.Fatalf("initiator %+v, events %v", st, events)
	}
	if len(events) != 2 || events[0].Kind != CircuitEnded || events[1].Kind != CircuitRebuilt {
		t.Fatalf("events %v", events)
	}
	if s := r.store.Stats(); s.Bad != 0 || s.Puts == 0 || s.Hits == 0 {
		t.Fatalf("mailbox %+v", s)
	}

	ini.c.Close()
	select {
	case <-ini.c.Done():
	default:
		t.Fatal("Done is open after Close")
	}
	if ini.c.Err() != nil {
		t.Fatalf("Err after Close: %v", ini.c.Err())
	}
	if err := ini.c.Pair(resp.party.id.Card()); err != ErrClosed {
		t.Fatalf("Pair after Close: %v", err)
	}
	for range ini.c.Messages() {
	}
}

// a contact card that changes after pinning ends the conversation in its own
// loop: Pair answers ErrContactChanged and Done closes
func TestAnotherCardEndsTheLoop(t *testing.T) {
	p := c25519(t)
	r := newRelayNet(t, p, 0)
	pi, pr := parties(t, p)
	a := r.join(t, "a", pi, nil)
	if err := a.c.Pair(newParty(t, p).id.Card()); err != nil {
		t.Fatal(err)
	}
	if err := a.c.Pair(pr.id.Card()); err != ErrContactChanged {
		t.Fatalf("another card: %v", err)
	}
	select {
	case <-a.c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the conversation did not end")
	}
	if a.c.Err() != ErrContactChanged {
		t.Fatalf("Err %v", a.c.Err())
	}
}
