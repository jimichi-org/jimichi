package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/pki"
)

// the testbed of the stand: five nodes, chains of three, the mailbox on the
// last node. The rogue entry is node 0 and its colluder node 1, so the honest
// middle hops are nodes 2 and 3
const (
	bedNodes  = 5
	bedHops   = 3
	bedExit   = 4
	rogue     = 0
	colluder  = 1
	honestOne = 2
	honestTwo = 3
)

// a circuit whose replies the test hands in
type fakeCircuit struct{ replies chan []byte }

func (c *fakeCircuit) Send([]byte) error      { return nil }
func (c *fakeCircuit) Replies() <-chan []byte { return c.replies }
func (c *fakeCircuit) Refused() error         { return nil }
func (c *fakeCircuit) MaxPayload() int        { return mailbox.RequestSize }
func (c *fakeCircuit) Close() error           { return nil }

var errEntryRefuses = errors.New("the entry refuses the circuit")

// every chain a route dialled, as listed indices, and the circuits it got
type dialLog struct {
	addrs  []string
	chains [][]int
	circs  []*fakeCircuit
	// whether a dial of this chain succeeds
	takes func(chain []int) bool
}

// the rogue entry carries the first chain, since a client whose first chain
// fails exits, and closes it; from then on it carries only chains through its
// colluder
func (d *dialLog) rogue(chain []int) bool { return len(d.chains) == 1 || chain[1] == colluder }

func (d *dialLog) dial(chain []client.Node) (conversation.Circuit, error) {
	path := make([]int, len(chain))
	for i, node := range chain {
		path[i] = slices.Index(d.addrs, node.Addr)
	}
	d.chains = append(d.chains, path)
	if d.takes != nil && !d.takes(path) {
		return nil, errEntryRefuses
	}
	c := &fakeCircuit{replies: make(chan []byte, 1)}
	d.circs = append(d.circs, c)
	return c, nil
}

// one reply through the circuit dialled last, read the way the conversation
// reads it
func (d *dialLog) answer(t *testing.T, c conversation.Circuit) {
	t.Helper()
	d.circs[len(d.circs)-1].replies <- []byte{1}
	select {
	case <-c.Replies():
	case <-time.After(5 * time.Second):
		t.Fatal("the reply did not pass")
	}
}

// the conversation closes a circuit before it asks for the next
func end(c conversation.Circuit) {
	if c != nil {
		_ = c.Close()
	}
}

// the mirror of every node of the testbed holds all listed nodes but omit
func serveWithout(t *testing.T, tb *testbed, omit ...int) {
	t.Helper()
	var entries []pki.MirrorEntry
	for i, addr := range tb.addrs {
		if !slices.Contains(omit, i) {
			entries = append(entries, pki.MirrorEntry{Addr: addr, Bundle: tb.bundles[i]})
		}
	}
	raw, err := pki.MarshalMirror(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range tb.info {
		srv.mirror.Store(&raw)
	}
}

func newRoute(tb *testbed, rnd io.Reader, d *dialLog, out *bytes.Buffer) *route {
	d.addrs = tb.addrs
	sel := tb.selection(bedHops, rnd)
	// the default of the client and of the stand
	sel.missing = 1
	return &route{p: tb.p, sel: sel, exit: bedExit, dial: d.dial, logger: log.New(out, "", 0)}
}

// a draw among m nodes reads m+k for the k-th of them
func pick(m, k int) uint64 { return uint64(m + k) }

// a closed circuit, a timeout or a refused reply all bring the conversation
// back to Dial, and Dial takes the chain it had through a fresh mirror of the
// same entry: a chain that carries replies is never drawn again, whatever the
// number of rebuilds
func TestRebuildDialsTheChainItHad(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	tb.publish(t, tb.bundles)
	// the entry is node 2 of the others 0 1 2 3, the middle node 0 of 0 1 3
	stream := words(pick(4, 2), pick(3, 0))
	var d dialLog
	var out bytes.Buffer
	r := newRoute(tb, stream, &d, &out)
	c, err := r.first()
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		d.answer(t, c)
		end(c)
		if c, err = r.rebuild(); err != nil {
			t.Fatal(err)
		}
	}
	want := []int{2, 0, bedExit}
	for i, chain := range d.chains {
		if !slices.Equal(chain, want) {
			t.Fatalf("dial %d took %v, want %v", i, chain, want)
		}
	}
	if len(d.chains) != 11 || r.draws != 1 || stream.Len() != 0 {
		t.Fatalf("%d dials, %d draws, %d bytes of the stream left", len(d.chains), r.draws, stream.Len())
	}
	asked := make([]int32, bedNodes)
	asked[2] = 11
	if got := tb.requests(); !slices.Equal(got, asked) {
		t.Fatalf("mirror requests per node %v, want every one at the entry", got)
	}
	if out.Len() != 0 {
		t.Fatalf("rebuilds of the same chain logged %q", out.String())
	}
}

// a setup that the entry or a middle hop does not carry on shows to the
// client only as a circuit that closes: the same chain gets one more circuit,
// and after two in a row without a reply it counts as one that cannot be
// dialled. One reply in between starts the count over, and so does a draw: a
// fresh chain gets two silent circuits of its own
func TestSilentChainIsDrawnAgain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	tb.publish(t, tb.bundles)
	// entry node 0, middle node 1 of 1 2 3, then node 3 of 1 2 3
	stream := words(pick(4, 0), pick(3, 0), pick(3, 2))
	var d dialLog
	var out bytes.Buffer
	r := newRoute(tb, stream, &d, &out)
	c, err := r.first()
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		answered bool
		middle   int
	}{
		{false, 1}, // one silent circuit: the same chain again
		{true, 1},  // a reply: the count starts over
		{false, 1}, // one silent circuit again
		{false, 3}, // the second in a row: new middle hops
		{false, 3}, // the first silent circuit of the new chain
		{true, 3},
	}
	for i, s := range steps {
		if s.answered {
			d.answer(t, c)
		}
		end(c)
		if c, err = r.rebuild(); err != nil {
			t.Fatalf("rebuild %d: %v", i, err)
		}
		if got := d.chains[len(d.chains)-1]; got[0] != 0 || got[1] != s.middle {
			t.Fatalf("rebuild %d dialled %v, want the middle hop %d", i, got, s.middle)
		}
	}
	if r.draws != 2 || stream.Len() != 0 || strings.Count(out.String(), "new middle hops drawn") != 1 {
		t.Fatalf("%d draws, %d bytes left, log:\n%s", r.draws, stream.Len(), out.String())
	}
}

// the rogue entry closes every circuit whose middle hop is honest before any
// reply, and refuses to carry it again or leaves it out of its mirror, which
// -missing allows. Every chain it gets drawn has an honest middle here, so it
// would steer for ever if it could: the client draws the first chain and
// maxRedraws more, and after that dials its last chain whatever the mirror
// and however silent it is, never drawing again
func TestRogueEntryGetsAtMostTheBoundOfDraws(t *testing.T) {
	for _, c := range []struct {
		name string
		// what the entry does with a chain it wants gone
		refuse, omit bool
		// the draws are among the two nodes a mirror without one honest node
		// leaves, or among the three of a full one
		stream []uint64
	}{
		{"refused setups and mirrors without the middle hop", true, true,
			[]uint64{pick(4, rogue), pick(2, 1), pick(2, 1), pick(2, 1), pick(2, 0), pick(2, 0)}},
		{"silent circuits through a full mirror", false, false,
			[]uint64{pick(4, rogue), pick(3, 1), pick(3, 2), pick(3, 1), pick(3, 0), pick(3, 0)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
			if c.omit {
				serveWithout(t, tb, honestOne)
			} else {
				tb.publish(t, tb.bundles)
			}
			stream := words(c.stream...)
			var d dialLog
			if c.refuse {
				d.takes = d.rogue
			}
			var out bytes.Buffer
			r := newRoute(tb, stream, &d, &out)
			circ, err := r.first()
			if err != nil {
				t.Fatal(err)
			}
			// the dial that took the chain of the last draw
			lastDraw := -1
			for i := range 40 {
				end(circ)
				if c.omit {
					if i > maxRedraws && i%2 == 1 {
						// a full mirror changes nothing: the chain is refused on dial
						serveWithout(t, tb)
					} else {
						serveWithout(t, tb, r.path[1])
					}
				}
				draws := r.draws
				circ, err = r.rebuild()
				if c.refuse && err == nil {
					t.Fatalf("rebuild %d through the rogue entry succeeded", i)
				}
				// the entry closes every circuit but carries it: the client
				// dials its last chain on and on past the bound
				if !c.refuse && err != nil {
					t.Fatalf("rebuild %d: %v", i, err)
				}
				if r.draws > draws && r.draws == 1+maxRedraws {
					lastDraw = len(d.chains) - 1
				}
			}
			if r.draws != 1+maxRedraws || lastDraw < 0 {
				t.Fatalf("%d draws, want the first and %d redraws", r.draws, maxRedraws)
			}
			if left := stream.Len(); left != 16 {
				t.Fatalf("%d bytes of the stream left, want the two draws past the bound unread", left)
			}
			for i, chain := range d.chains {
				if chain[0] != rogue || chain[2] != bedExit || len(chain) != bedHops {
					t.Fatalf("dial %d took %v: another entry or another exit", i, chain)
				}
				if chain[1] == colluder {
					t.Fatal("the colluder was drawn although the stream never picked it")
				}
				if i > lastDraw && !slices.Equal(chain, d.chains[lastDraw]) {
					t.Fatalf("dial %d took %v past the bound, want the chain of the last draw %v", i, chain, d.chains[lastDraw])
				}
			}
			if !c.refuse && len(d.chains) != 41 {
				t.Fatalf("%d dials, want the first and one per rebuild", len(d.chains))
			}
			log := out.String()
			if got := strings.Count(log, "new middle hops drawn"); got != maxRedraws {
				t.Fatalf("%d redraws logged, want %d:\n%s", got, maxRedraws, log)
			}
			if namesAny(log, tb.addrs) {
				t.Fatalf("the log names a node:\n%s", log)
			}
		})
	}
}

// every sequence of draws, draw i taking each of its bounds[i] values once
func eachStream(bounds []int, visit func(values []uint64)) {
	values := make([]uint64, len(bounds))
	var walk func(i int)
	walk = func(i int) {
		if i == len(bounds) {
			visit(slices.Clone(values))
			return
		}
		for k := range bounds[i] {
			values[i] = pick(bounds[i], k)
			walk(i + 1)
		}
	}
	walk(0)
}

// the exact chance on the testbed that a rogue entry ends up with its colluder
// as the middle hop, over every outcome of a uniform source. The entry leaves
// one honest node out of each mirror, so every draw is between the colluder
// and one honest node, 1/2 each; a chain with an honest middle is closed and
// refused until the client draws again. With the first draw and maxRedraws =
// 2 redraws the colluder is missed only when all three draws miss it:
// 1 - (1/2)^3 = 7/8. Without the rebuild bound it would be reached with
// certainty
func TestSteeringOfTheMiddleHopIsBounded(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	bounds := []int{2, 2, 2}
	var steered, all int
	eachStream(bounds, func(values []uint64) {
		serveWithout(t, tb, honestOne)
		stream := words(append([]uint64{pick(4, rogue)}, values...)...)
		var d dialLog
		d.takes = d.rogue
		var out bytes.Buffer
		r := newRoute(tb, stream, &d, &out)
		c, err := r.first()
		if err != nil {
			t.Fatal(err)
		}
		for range 2 * len(bounds) {
			if r.path[1] == colluder {
				break
			}
			end(c)
			serveWithout(t, tb, r.path[1])
			c, err = r.rebuild()
			if err != nil && !errors.Is(err, errEntryRefuses) && !errors.Is(err, errNotServed) {
				t.Fatal(err)
			}
		}
		all++
		if last := d.chains[len(d.chains)-1]; last[1] == colluder {
			steered++
		}
	})
	if all != 8 || steered != 7 {
		t.Fatalf("the colluder ends up in the middle in %d of %d outcomes, want 7 of 8", steered, all)
	}
}

// the far side drives the redraws as well: a rogue mailbox leaves every
// request through an honest middle hop unanswered, and two silent circuits in
// a row count as a chain that cannot be dialled. Under an honest entry with a
// full mirror every draw is among the three other nodes, its colluder one of
// them, so with the first draw and maxRedraws = 2 redraws the colluder becomes
// the middle hop, and learns the entry, in 1 - (2/3)^3 = 19/27 of the outcomes
// instead of 1/3
func TestRogueMailboxSteersTheMiddleHopWithinTheBound(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	tb.publish(t, tb.bundles)
	bounds := []int{3, 3, 3}
	var steered, all int
	eachStream(bounds, func(values []uint64) {
		// the entry is node 2 of the others 0 1 2 3
		stream := words(append([]uint64{pick(4, honestOne)}, values...)...)
		var d dialLog
		var out bytes.Buffer
		r := newRoute(tb, stream, &d, &out)
		c, err := r.first()
		if err != nil {
			t.Fatal(err)
		}
		for range 2 * silentCircuits * len(bounds) {
			if r.path[1] == colluder {
				d.answer(t, c)
			}
			end(c)
			if c, err = r.rebuild(); err != nil {
				t.Fatal(err)
			}
		}
		all++
		if last := d.chains[len(d.chains)-1]; last[0] != honestOne || last[2] != bedExit {
			t.Fatalf("dialled %v: another entry or another exit", last)
		} else if last[1] == colluder {
			steered++
		}
	})
	if all != 27 || steered != 19 {
		t.Fatalf("the colluder ends up in the middle in %d of %d outcomes, want 19 of 27", steered, all)
	}
}

// a fixed chain is dialled as it is configured at every rebuild, whatever the
// entry does
func TestFixedChainIsNeverDrawn(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	tb.publish(t, tb.bundles)
	d := dialLog{takes: func([]int) bool { return false }}
	var out bytes.Buffer
	r := newRoute(tb, words(), &d, &out)
	r.sel.fixed, r.exit = true, bedHops-1
	if _, err := r.first(); !errors.Is(err, errEntryRefuses) {
		t.Fatalf("first dial: %v", err)
	}
	for range 5 {
		if _, err := r.rebuild(); !errors.Is(err, errEntryRefuses) {
			t.Fatalf("rebuild: %v", err)
		}
	}
	d.takes = nil
	for range 5 {
		c, err := r.rebuild()
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		end(c)
	}
	for _, chain := range d.chains {
		if !slices.Equal(chain, []int{0, 1, 2}) {
			t.Fatalf("a fixed chain dialled %v", chain)
		}
	}
	if r.draws != 0 || len(d.chains) != 11 {
		t.Fatalf("%d draws, %d dials", r.draws, len(d.chains))
	}
	serveWithout(t, tb, 1)
	var node *nodeError
	if _, err := r.rebuild(); !errors.As(err, &node) || namesAny(err.Error(), tb.addrs) {
		t.Fatalf("a fixed chain without its middle node: %v", err)
	}
}

// the mirror of the entry must hold the entry and the mailbox and lack at most
// -missing listed nodes; a refused mirror draws nothing, and no refusal names a
// node
func TestRouteRefusesAMirrorItCannotDrawFrom(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	for _, c := range []struct {
		name string
		omit []int
		want error
	}{
		{"without the mailbox", []int{bedExit}, errNoMailbox},
		{"without the entry", []int{rogue}, errNoBundle},
		{"without two nodes", []int{honestOne, honestTwo}, errTooFew},
	} {
		t.Run(c.name, func(t *testing.T) {
			serveWithout(t, tb, c.omit...)
			var d dialLog
			var out bytes.Buffer
			r := newRoute(tb, words(pick(4, rogue)), &d, &out)
			_, err := r.first()
			if !errors.Is(err, c.want) || r.draws != 0 || len(d.chains) != 0 {
				t.Fatalf("first: %v after %d draws and %d dials, want %v", err, r.draws, len(d.chains), c.want)
			}
			if text := peerCause(err); namesAny(text, tb.addrs) || text == "connection failed" {
				t.Fatalf("the refusal reads %q", text)
			}
		})
	}

	// a chain drawn once and a mirror refused later: no draw either
	tb.publish(t, tb.bundles)
	var d dialLog
	var out bytes.Buffer
	r := newRoute(tb, words(pick(4, rogue), pick(3, 0), pick(3, 0)), &d, &out)
	c, err := r.first()
	if err != nil {
		t.Fatal(err)
	}
	end(c)
	serveWithout(t, tb, bedExit)
	for range 3 {
		if _, err := r.rebuild(); !errors.Is(err, errNoMailbox) || r.draws != 1 {
			t.Fatalf("rebuild over a mirror without the mailbox: %v, %d draws", err, r.draws)
		}
	}
	if !strings.Contains(out.String(), "circuit rebuild failed: "+errNoMailbox.Error()) {
		t.Fatalf("log %q", out.String())
	}
}

// the first chain waits for an entry that is not ready yet, a rebuild asks
// once: the conversation spaces its attempts out itself
func TestRebuildAsksTheEntryOnce(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	tb.publish(t, tb.bundles)
	var d dialLog
	var out bytes.Buffer
	r := newRoute(tb, words(pick(4, rogue), pick(3, 0)), &d, &out)
	r.sel.attempts = 3
	tb.info[rogue].unready.Store(2)
	c, err := r.first()
	if err != nil {
		t.Fatalf("first after two unready answers: %v", err)
	}
	d.answer(t, c)
	end(c)
	asked := tb.info[rogue].requests.Load()
	tb.info[rogue].unready.Store(2)
	if _, err := r.rebuild(); err == nil {
		t.Fatal("a rebuild over an unready entry dialled")
	}
	if got := tb.info[rogue].requests.Load() - asked; got != 1 {
		t.Fatalf("a rebuild asked the entry %d times", got)
	}
	if _, err := r.rebuild(); err == nil {
		t.Fatal("a rebuild over an unready entry dialled")
	}
	if _, err := r.rebuild(); err != nil || r.draws != 1 || len(d.chains) != 2 {
		t.Fatalf("rebuild once the entry is ready: %v, %d draws, %d dials", err, r.draws, len(d.chains))
	}
}

// the watched circuit passes replies in order, ends when the circuit ends,
// and stops passing once closed, as the conversation stops reading then
func TestWatchedCircuitPassesReplies(t *testing.T) {
	inner := &fakeCircuit{replies: make(chan []byte, 3)}
	w := watch(inner)
	if w.answered.Load() {
		t.Fatal("answered before any reply")
	}
	inner.replies <- []byte{1}
	inner.replies <- []byte{2}
	for _, want := range []byte{1, 2} {
		if got := <-w.Replies(); len(got) != 1 || got[0] != want {
			t.Fatalf("reply %v, want %d", got, want)
		}
	}
	if !w.answered.Load() {
		t.Fatal("not answered after two replies")
	}
	close(inner.replies)
	if _, open := <-w.Replies(); open {
		t.Fatal("the replies stay open after the circuit ended")
	}

	inner = &fakeCircuit{replies: make(chan []byte, 1)}
	w = watch(inner)
	inner.replies <- []byte{1}
	_ = w.Close()
	_ = w.Close()
	select {
	case _, open := <-w.Replies():
		if open {
			// the reply may have passed before Close; the channel ends next
			if _, open := <-w.Replies(); open {
				t.Fatal("a closed circuit passes more than its last reply")
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a closed circuit did not end its replies")
	}
}

func TestPeerCauseNamesNoNode(t *testing.T) {
	addr := "relay-3.jimichi.svc.cluster.local:9000"
	for _, err := range []error{
		&entryError{fmt.Errorf("dial tcp %s: connection refused", addr)},
		&nodeError{fmt.Errorf("node %s: %w", addr, errNoBundle)},
		fmt.Errorf("dial tcp %s: i/o timeout", addr),
		fmt.Errorf("%w: 2 of 5 listed nodes, at most 1 may be", errTooFew),
		errNoMailbox, errNotServed, errSilent,
	} {
		if text := peerCause(err); strings.Contains(text, "relay-3") {
			t.Fatalf("%v reads %q", err, text)
		}
	}
}
