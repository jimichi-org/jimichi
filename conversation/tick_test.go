package conversation

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

func coverPuts(on bool) func(*Config) { return func(c *Config) { c.CoverPuts = on } }

func TestHandshakeAndMessagesBothWays(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, cover := range []bool{true, false} {
			t.Run(fmt.Sprintf("cover puts %v", cover), func(t *testing.T) {
				n := newNet(t, p, nil)
				pi, pr := parties(t, p)
				a := n.join("a", pi, 1, 1, coverPuts(cover))
				b := n.join("b", pr, 1, 1, coverPuts(cover))
				n.start(t, a, b)

				a.send(t, "hello")
				n.until("hello at b", 10, func() bool { return b.count("hello") == 1 })
				b.send(t, "hi")
				n.until("hi at a", 10, func() bool { return a.count("hi") == 1 })
				n.run(20)
				for _, pr := range []*testPeer{a, b} {
					st, s := pr.c.Stats(), pr.session()
					if st.BadReplies != 0 || st.PutRefused != 0 || st.Unanswered != 0 || s.Bad != 0 || s.Lost != 0 || s.Window != 0 {
						t.Fatalf("%s: %+v, session %+v", pr.name, st, s)
					}
					if len(pr.got) != 1 {
						t.Fatalf("%s got %q", pr.name, pr.got)
					}
				}
			})
		}
	})
}

// without cover puts and with an initiator that has nothing to say, the
// responder may seal its message only once the initiator's first record after
// kk2 confirmed the session; that record comes at once, so the round trip
// does not wait for the initiator to speak
func TestSilentInitiatorConfirmsWithoutCoverPuts(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, nil)
		pi, pr := parties(t, p)
		ini := n.join("initiator", pi, 1, 1, coverPuts(false))
		resp := n.join("responder", pr, 1, 1, coverPuts(false))
		pair(t, ini, resp)
		resp.send(t, "ping")
		n.until("ping at the initiator", 40, func() bool {
			if resp.c.session.Stats().Sent > 0 && resp.state() != e2e.StateConfirmed {
				t.Fatalf("the responder sealed a message in %v", resp.state())
			}
			return ini.count("ping") == 1
		})
		s := ini.session()
		if s.DummiesSent != 1 || s.Sent != 0 {
			t.Fatalf("the silent initiator sealed %d dummies and %d messages, want the one confirming record", s.DummiesSent, s.Sent)
		}
		// beyond copies of kk1 and the one record, it put nothing
		for i, rec := range ini.circ().puts() {
			if rec != nil && rec[0] != 0x01 && rec[0] != 0x03 {
				t.Fatalf("put %d of kind %d", i, rec[0])
			}
		}
		ini.send(t, "pong")
		n.until("pong at the responder", 10, func() bool { return resp.count("pong") == 1 })
	})
}

// a round trip of three ticks and cover puts: after the session every request
// of each side carries a put, and the other side takes one record per tick
func TestPutOnEveryTickUnderThreeTickLatency(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, nil)
		pi, pr := parties(t, p)
		a := n.join("a", pi, 1, 2, nil)
		b := n.join("b", pr, 1, 2, nil)
		n.start(t, a, b)
		n.run(10)

		var requests, puts int
		n.wrap(func(next deliverFunc) deliverFunc {
			return func(circuit uint64, payload []byte) []byte {
				if req, err := mailbox.ParseRequest(payload); err == nil {
					requests++
					if req.Puts() {
						puts++
					}
				}
				return next(circuit, payload)
			}
		})
		sentA, sentB := len(a.circ().sent), len(b.circ().sent)
		hitsA, hitsB := a.c.Stats().Hits, b.c.Stats().Hits
		const ticks = 100
		n.run(ticks)
		for _, pr := range []*testPeer{a, b} {
			if st := pr.c.Stats(); st.WindowFull != 0 || st.PutRefused != 0 {
				t.Fatalf("%s: %+v", pr.name, st)
			}
		}
		for i, rec := range a.circ().puts()[sentA:] {
			if rec == nil {
				t.Fatalf("request %d of a without a put", sentA+i)
			}
		}
		for i, rec := range b.circ().puts()[sentB:] {
			if rec == nil {
				t.Fatalf("request %d of b without a put", sentB+i)
			}
		}
		if requests != 2*ticks || puts != requests {
			t.Fatalf("the mailbox saw %d requests, %d with a put, in %d ticks", requests, puts, ticks)
		}
		if got := a.c.Stats().Hits - hitsA; got != ticks {
			t.Fatalf("a took %d records in %d ticks", got, ticks)
		}
		if got := b.c.Stats().Hits - hitsB; got != ticks {
			t.Fatalf("b took %d records in %d ticks", got, ticks)
		}
		if recs := n.store.Stats().Records; recs > 2 {
			t.Fatalf("%d records wait in the mailbox", recs)
		}
	})
}

// a round trip of 20 ticks against a window of 16: no more than 16 puts are
// ever in flight, and the ticks the window keeps back are counted
func TestWindowBoundsThePutsInFlight(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 10, 10, nil)
	b := n.join("b", pr, 10, 10, nil)
	n.start(t, a, b)
	n.run(40)
	before := a.c.Stats()
	for range 100 {
		n.step()
		if a.c.inflight > DefaultWindow {
			t.Fatalf("%d puts in flight", a.c.inflight)
		}
	}
	st := a.c.Stats()
	full, puts := st.WindowFull-before.WindowFull, st.Puts-before.Puts
	// 16 puts in every 20 ticks
	if full != 20 || puts != 80 {
		t.Fatalf("in 100 ticks %d puts and %d ticks with the window full, want 80 and 20", puts, full)
	}
}

// the peer stops fetching and its queue of two fills: the puts are refused,
// one record goes on as copies of the same bytes, and when the peer is back
// every message arrives once and the gap stays within the window
func TestStallPutsTheProbeAsCopiesAndResumes(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, func(l *mailbox.Limits) { l.Depth = 2 })
		pi, pr := parties(t, p)
		a := n.join("a", pi, 1, 1, nil)
		b := n.join("b", pr, 1, 1, nil)
		n.start(t, a, b)

		b.paused = true
		bodies := make([]string, 10)
		for i := range bodies {
			bodies[i] = fmt.Sprintf("m%d", i)
		}
		a.send(t, bodies...)
		n.run(20)
		if !a.c.stall || a.c.sticky == nil || a.c.sticky.handshake {
			t.Fatalf("stall %v, sticky %+v", a.c.stall, a.c.sticky)
		}
		puts := a.circ().puts()
		probe := puts[len(puts)-1]
		for _, rec := range puts[len(puts)-8:] {
			if !bytes.Equal(rec, probe) {
				t.Fatal("the puts in stall mode are not copies of one record")
			}
		}
		if a.c.Stats().PutRefused < 8 {
			t.Fatalf("%d puts refused", a.c.Stats().PutRefused)
		}

		b.paused = false
		n.until("every message at b", 60, func() bool {
			return slices.IndexFunc(bodies, func(s string) bool { return b.count(s) == 0 }) < 0
		})
		n.run(10)
		for _, s := range bodies {
			if b.count(s) != 1 {
				t.Fatalf("b got %q", b.got)
			}
		}
		if a.c.stall {
			t.Fatal("a still in stall mode")
		}
		if lost := b.session().Lost; lost > DefaultWindow {
			t.Fatalf("a gap of %d records", lost)
		}
	})
}

// each way a reply can fail the strict parse: it is counted, the outcome of
// its put is unknown, so the body goes out again, and the circuit stays
func TestBadRepliesAreCountedAndTheBodySentAgain(t *testing.T) {
	for _, c := range []struct {
		name string
		// whether the reply spoilt is the one to a request with a put
		withPut bool
		bad     func(b []byte) []byte
	}{
		{"a byte short", true, func(b []byte) []byte { return b[:len(b)-1] }},
		{"a byte long", true, func(b []byte) []byte { return append(b, 0) }},
		{"another version", true, func(b []byte) []byte { b[0] = 2; return b }},
		{"another tag", true, func(b []byte) []byte { b[2]++; return b }},
		{"a reserved bit", true, func(b []byte) []byte { b[3] |= 0x08; return b }},
		{"bad request with a put outcome", true, func(b []byte) []byte { b[3] = 0x81; return b }},
		{"bad request alone", true, func(b []byte) []byte { b[3] = mailbox.StatusBad; clear(b[4:]); return b }},
		{"no put outcome for a put", true, func(b []byte) []byte { b[3] &^= mailbox.PutMask; return b }},
		{"a put outcome without a put", false, func(b []byte) []byte { b[3] |= mailbox.PutStored; return b }},
		{"a record without its bit", true, func(b []byte) []byte { b[3] &^= mailbox.StatusRecord; b[10] = 1; return b }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := c25519(t)
			n := newNet(t, p, nil)
			pi, pr := parties(t, p)
			a := n.join("a", pi, 1, 1, coverPuts(false))
			b := n.join("b", pr, 1, 1, coverPuts(false))
			n.start(t, a, b)
			n.run(4)

			hit := false
			n.wrap(func(next deliverFunc) deliverFunc {
				return func(circuit uint64, payload []byte) []byte {
					req, err := mailbox.ParseRequest(payload)
					reply := next(circuit, payload)
					if !hit && err == nil && circuit == a.circ().id && req.Puts() == c.withPut {
						hit = true
						return c.bad(reply)
					}
					return reply
				}
			})
			if c.withPut {
				a.send(t, "body")
			}
			n.until("the bad reply", 10, func() bool { return hit && a.c.Stats().BadReplies == 1 })
			n.run(10)
			st := a.c.Stats()
			if st.BadReplies != 1 || st.Unanswered != 0 || st.Rebuilds != 0 || len(a.events) != 0 || a.c.stall {
				t.Fatalf("after the bad reply: %+v, events %v, stall %v", st, a.events, a.c.stall)
			}
			// the mailbox did store the put, so the body sent again arrives twice
			if want := map[bool]int{true: 2, false: 0}[c.withPut]; b.count("body") != want {
				t.Fatalf("b got %q", b.got)
			}
			b.send(t, "still")
			n.until("a message after it", 10, func() bool { return a.count("still") == 1 })
		})
	}
}

// without cover puts an idle conversation puts a keepalive whenever it sealed
// nothing for Keepalive, and neither side goes stale
func TestKeepaliveKeepsAnIdleSessionFresh(t *testing.T) {
	p := c25519(t)
	change := func(c *Config) {
		c.CoverPuts = false
		c.StaleAfter = ticks(40)
		c.Keepalive = ticks(20)
	}
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 1, 1, change)
	b := n.join("b", pr, 1, 1, change)
	n.start(t, a, b)
	before := []uint64{a.session().DummiesSent, b.session().DummiesSent}
	n.run(200)
	for i, pr := range []*testPeer{a, b} {
		s := pr.session()
		if s.Stale != 0 || s.Handshakes != 1 {
			t.Fatalf("%s: %+v", pr.name, s)
		}
		if got := s.DummiesSent - before[i]; got < 9 || got > 11 {
			t.Fatalf("%s sealed %d keepalives in 200 ticks, want one every 20", pr.name, got)
		}
	}
}

// the responder stops putting kk2 once the initiator's first record opened,
// even when every reply to kk2 said the queue was full
func TestKK2CopiesStopOnceConfirmed(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	b := n.join("b", pr, 1, 1, nil)
	n.wrap(func(next deliverFunc) deliverFunc {
		return func(circuit uint64, payload []byte) []byte {
			req, err := mailbox.ParseRequest(payload)
			reply := next(circuit, payload)
			if err == nil && req.Puts() && req.Record[0] == 0x02 {
				reply[3] = reply[3]&^mailbox.PutMask | mailbox.PutFull
			}
			return reply
		}
	})
	n.start(t, a, b)
	n.run(2)
	sent := len(b.circ().sent)
	n.run(10)
	for _, rec := range b.circ().puts()[sent:] {
		if rec != nil && rec[0] == 0x02 {
			t.Fatal("kk2 put after the session was confirmed")
		}
	}
	if b.c.Stats().PutRefused == 0 {
		t.Fatal("no reply to kk2 was spoilt")
	}
}

// outcomes that no longer apply: a put of a past epoch, and a copy of a
// sticky record that is no longer the sticky one
func TestStaleOutcomesChangeNothing(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 1, 1, coverPuts(false))
	b := n.join("b", pr, 1, 1, coverPuts(false))
	n.start(t, a, b)

	current := &sticky{rec: []byte{3, 1}}
	a.c.sticky = current
	past := &put{rec: []byte{3, 2}, epoch: a.c.epoch + 1, body: &item{seq: 99, body: []byte("past")}}
	spent := &put{rec: []byte{3, 3}, epoch: a.c.epoch, sticky: &sticky{rec: []byte{3, 3}}}
	for _, status := range []byte{mailbox.PutStored, mailbox.PutFull, mailbox.PutRefused} {
		a.c.outcome(past, status)
		a.c.outcome(spent, status)
		if a.c.stall || a.c.sticky != current || len(a.outbox()) != 0 {
			t.Fatalf("status %d changed the state: stall %v, sticky %+v, outbox %q", status, a.c.stall, a.c.sticky, a.outbox())
		}
	}
	a.c.unknown(past)
	if len(a.outbox()) != 0 {
		t.Fatal("an unknown outcome of a past epoch gave a body back")
	}
}
