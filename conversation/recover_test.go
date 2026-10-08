package conversation

import (
	"fmt"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

// ticks of testRate
func ticks(n int) time.Duration { return time.Duration(n) * testRate }

// the mailbox answers 01 to the next count data records put through the
// circuit of from and keeps none of them, as a batch lost to eviction would
func (n *testNet) lose(from *testPeer, count int) *int {
	lost := new(int)
	n.wrap(func(next deliverFunc) deliverFunc {
		return func(circuit uint64, payload []byte) []byte {
			req, err := mailbox.ParseRequest(payload)
			if err != nil || *lost >= count || circuit != from.circ().id || !dataRecord(req) {
				return next(circuit, payload)
			}
			*lost++
			req.Put, req.Record = [mailbox.IDSize]byte{}, [mailbox.RecordSize]byte{}
			clear(payload)
			reply := next(circuit, req.Bytes())
			reply[3] |= mailbox.PutStored
			return reply
		}
	})
	return lost
}

// 65 records lost in a row put the next one past the window of the
// receiver, and the direction is wedged: nothing more of it opens. The stale
// bound is longer than the loss, so the receiver is not stale when the loss
// ends and the window refusals keep it from opening anything after it. A new
// handshake follows within 2 x StaleAfter plus HandshakeTimeout of the last
// record that opened, give or take a few round trips, and messages flow both
// ways again. First from the initiator to the responder, then back
func TestWedgedDirectionRecoversByANewHandshake(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		const staleAfter, hsTimeout = 100, 40
		change := func(c *Config) {
			c.StaleAfter = ticks(staleAfter)
			c.Keepalive = ticks(50)
			c.Session.HandshakeTimeout = ticks(hsTimeout)
		}
		n := newNet(t, p, nil)
		pi, pr := parties(t, p)
		ini := n.join("initiator", pi, 1, 1, change)
		resp := n.join("responder", pr, 1, 1, change)
		n.start(t, ini, resp)

		for round, dir := range [][2]*testPeer{{ini, resp}, {resp, ini}} {
			from, to := dir[0], dir[1]
			epoch, window, start := ini.c.epoch, to.session().Window, n.tick
			lost := n.lose(from, e2e.MaxSkip+1)
			n.until("the loss", 2*e2e.MaxSkip, func() bool { return *lost == e2e.MaxSkip+1 })
			if to.state() == e2e.StateStale {
				t.Fatalf("round %d: %s stale during the loss", round, to.name)
			}
			n.until("the wedge", 10, func() bool { return to.session().Window > window })

			const limit = 2*staleAfter + hsTimeout + 10
			n.until("a new confirmed session", limit, func() bool { return ini.c.epoch > epoch && confirmed(ini, resp) })
			if took := n.tick - start; took > limit {
				t.Fatalf("round %d: the session came back %d ticks after the loss began, over %d", round, took, limit)
			}
			there, back := fmt.Sprintf("there %d", round), fmt.Sprintf("back %d", round)
			from.send(t, there)
			to.send(t, back)
			n.until("messages both ways", 20, func() bool { return to.count(there) == 1 && from.count(back) == 1 })
		}
		if st := ini.session(); st.Stale == 0 || st.Handshakes < 3 {
			t.Fatalf("initiator %+v", st)
		}
	})
}

// a third party holding B's card puts garbage of every kind into B's queue:
// B refuses it record by record and the session goes on
func TestGarbageInTheQueueLeavesTheSessionAlive(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, nil)
		pi, pr := parties(t, p)
		a := n.join("a", pi, 1, 1, nil)
		b := n.join("b", pr, 1, 1, nil)
		n.start(t, a, b)
		epoch := b.c.epoch

		kinds := []byte{0x01, 0x02, 0x03, 0x03, 0x7f}
		for i := range 30 {
			if i%3 == 0 {
				n.putFrom(1<<40, b, garbage(t, kinds[i/3%len(kinds)]))
			}
			if i == 10 {
				a.send(t, "through")
			}
			n.step()
		}
		n.until("the message", 20, func() bool { return b.count("through") == 1 })
		if s := b.session(); s.Bad == 0 || b.state() != e2e.StateConfirmed || b.c.epoch != epoch {
			t.Fatalf("b in %v, epoch %d (was %d), %+v", b.state(), b.c.epoch, epoch, s)
		}
		b.send(t, "back")
		n.until("the answer", 10, func() bool { return a.count("back") == 1 })
	})
}

// records that wait in the queue past the TTL are gone when the owner fetches
// again: the receiver counts them lost and the session goes on
func TestRecordsPastTheTTLAreLost(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, func(l *mailbox.Limits) { l.TTL = ticks(5) })
	pi, pr := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	b := n.join("b", pr, 1, 1, nil)
	n.start(t, a, b)

	b.paused = true
	n.run(30)
	b.paused = false
	n.until("a record after the gap", 20, func() bool { return b.session().Lost > 0 })
	if n.store.Stats().Expired == 0 {
		t.Fatal("nothing expired")
	}
	if lost := b.session().Lost; lost > uint64(DefaultWindow+mailbox.DefaultLimits().Depth) {
		t.Fatalf("a gap of %d records", lost)
	}
	a.send(t, "after")
	n.until("a message after the gap", 20, func() bool { return b.count("after") == 1 })
	if b.state() != e2e.StateConfirmed {
		t.Fatalf("b in %v", b.state())
	}
}

// the initiator in stall mode goes stale while the peer is away and starts a
// new handshake: the probe of the old epoch is dropped and its body goes back
// with the bodies not yet sent, in their order, and kk1 is the next put. When
// the peer returns every message arrives exactly once
func TestEpochChangeDropsTheStickyRecordAndGivesTheBodiesBack(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		change := func(c *Config) {
			c.CoverPuts = false
			c.StaleAfter = ticks(40)
			c.Keepalive = ticks(20)
			c.Session.HandshakeTimeout = ticks(20)
		}
		n := newNet(t, p, func(l *mailbox.Limits) { l.Depth = 2 })
		pi, pr := parties(t, p)
		a := n.join("a", pi, 1, 1, change)
		b := n.join("b", pr, 1, 1, change)
		n.start(t, a, b)
		n.run(3)

		b.paused = true
		bodies := []string{"m1", "m2", "m3", "m4", "m5"}
		a.send(t, bodies...)
		n.until("stall mode with a real probe", 10, func() bool {
			return a.c.stall && a.c.sticky != nil && a.c.sticky.body != nil
		})
		probe := string(a.c.sticky.body.body)
		epoch := a.c.epoch
		n.until("a new epoch", 60, func() bool { return a.c.epoch > epoch })

		if a.c.sticky == nil || !a.c.sticky.handshake {
			t.Fatalf("the sticky record after the change: %+v", a.c.sticky)
		}
		puts := a.circ().puts()
		if last := puts[len(puts)-1]; last == nil || last[0] != 0x01 {
			t.Fatal("the first put of the new epoch is not kk1")
		}
		left := a.outbox()
		if len(left) == 0 || left[0] != probe {
			t.Fatalf("the outbox after the change is %q, the probe was %q", left, probe)
		}
		for i := 1; i < len(left); i++ {
			if left[i-1] >= left[i] {
				t.Fatalf("the outbox is out of order: %q", left)
			}
		}
		for _, r := range a.c.pending {
			if r.put != nil && r.put.body != nil {
				t.Fatal("a request of the old epoch still holds a body")
			}
		}

		b.paused = false
		n.until("every message at b", 400, func() bool {
			for _, s := range bodies {
				if b.count(s) == 0 {
					return false
				}
			}
			return true
		})
		n.run(20)
		for _, s := range bodies {
			if b.count(s) != 1 {
				t.Fatalf("b got %q", b.got)
			}
		}
	})
}

// the initiator restarts while real records are in flight: their bodies go
// back at once, before their outcomes are known, and the outcomes that come
// later change nothing
func TestEpochChangeGivesBackTheBodiesInFlight(t *testing.T) {
	p := c25519(t)
	change := func(c *Config) {
		c.CoverPuts = false
		c.StaleAfter = ticks(40)
		c.Keepalive = ticks(20)
		c.Session.HandshakeTimeout = ticks(20)
	}
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 3, 3, change)
	b := n.join("b", pr, 3, 3, change)
	n.start(t, a, b)
	n.run(10)

	a.send(t, "f1", "f2", "f3", "f4")
	n.run(3)
	inFlight := 0
	for _, r := range a.c.pending {
		if r.put != nil && r.put.body != nil {
			inFlight++
		}
	}
	if inFlight != 3 {
		t.Fatalf("%d bodies in flight", inFlight)
	}
	// the session goes stale and the next tick restarts it, before any reply
	// with a record of b can open
	for range a.c.opts.StaleFetches {
		a.c.session.Fetched()
	}
	epoch := a.c.epoch
	a.c.onTick()
	if a.c.epoch == epoch {
		t.Fatal("no new epoch")
	}
	if got := a.outbox(); len(got) != 4 || got[0] != "f1" || got[3] != "f4" {
		t.Fatalf("outbox %q after the change", got)
	}
	for _, r := range a.c.pending {
		if r.put != nil && r.put.body != nil {
			t.Fatal("a request of the old epoch still holds a body")
		}
	}
	n.run(10)
	if a.c.stall || len(a.outbox()) != 4 {
		t.Fatalf("the old outcomes changed the state: stall %v, outbox %q", a.c.stall, a.outbox())
	}
	n.until("every message at b", 200, func() bool {
		return b.count("f1") >= 1 && b.count("f2") >= 1 && b.count("f3") >= 1 && b.count("f4") == 1
	})
}
