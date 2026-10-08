package conversation

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

var errRefusedReply = errors.New("client: reply refused: did not open")

// the far side closes the circuit while two messages are in flight: the
// conversation dials again after a second, through Dial, keeps its session
// and sends the two again on the new circuit, whose tags start from zero
func TestRebuildKeepsTheSessionAndSendsTheBodiesAgain(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, nil)
		pi, pr := parties(t, p)
		a := n.join("a", pi, 2, 2, coverPuts(false))
		b := n.join("b", pr, 2, 2, coverPuts(false))
		n.start(t, a, b)
		n.run(10)

		session, epoch := a.c.session, a.c.epoch
		a.send(t, "r0", "r1", "r2")
		n.run(2)
		old := a.circ()
		old.closed = true
		a.c.onEnd()
		ended := n.tick
		if a.c.circ != nil || !old.closed {
			t.Fatal("the circuit is still attached")
		}
		if len(a.events) != 1 || a.events[0] != (Event{Kind: CircuitEnded}) {
			t.Fatalf("events %v", a.events)
		}
		// a round trip of four ticks leaves the requests of the last four
		if st := a.c.Stats(); st.Unanswered != 4 || st.Refusals != 0 {
			t.Fatalf("%+v", st)
		}
		if got := a.outbox(); !slices.Equal(got, []string{"r0", "r1", "r2"}) {
			t.Fatalf("outbox %q", got)
		}

		n.until("the rebuild", 10, func() bool { return a.c.circ != nil })
		if len(a.dials) != 1 || a.dials[0] != ended+int(firstPause/testRate) {
			t.Fatalf("dialed on ticks %v, the circuit ended on %d", a.dials, ended)
		}
		if len(a.events) != 2 || a.events[1].Kind != CircuitRebuilt || a.c.Stats().Rebuilds != 1 {
			t.Fatalf("events %v", a.events)
		}
		n.until("the bodies at b", 20, func() bool { return b.count("r0") == 1 && b.count("r1") == 1 && b.count("r2") == 1 })
		if a.c.session != session || a.c.epoch != epoch || a.state() != e2e.StateEstablished {
			t.Fatal("the rebuild changed the session")
		}
		for i, req := range a.circ().sent {
			if req.Tag != uint16(i) {
				t.Fatalf("request %d on the new circuit has tag %d", i, req.Tag)
			}
		}
	})
}

// the circuit ends with the window full: the puts in flight end with it, so
// the next circuit puts on each of its first W ticks and the window keeps
// nothing back
func TestTheWindowReopensAfterARebuild(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 10, 10, nil)
	b := n.join("b", pr, 10, 10, nil)
	n.start(t, a, b)
	n.until("a full window", 40, func() bool { return a.c.inflight == DefaultWindow })
	a.circ().closed = true
	a.c.onEnd()
	n.until("the rebuild", 10, func() bool { return a.c.circ != nil })

	full := a.c.Stats().WindowFull
	n.run(DefaultWindow)
	puts := a.circ().puts()
	if len(puts) != DefaultWindow || slices.IndexFunc(puts, func(rec []byte) bool { return rec == nil }) >= 0 {
		t.Fatalf("the first %d requests of the new circuit: %d of them, a request without a put among them", DefaultWindow, len(puts))
	}
	if got := a.c.Stats().WindowFull; got != full {
		t.Fatalf("the window kept %d puts back on the new circuit", got-full)
	}
}

// the circuit ends in stall mode with a real probe in flight: the rebuilt
// circuit puts the same bytes first and the epoch stays, so a copy the old
// circuit may have left stored is never followed by the body sealed again,
// and each message arrives once
func TestTheProbeOutlivesTheCircuit(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, func(l *mailbox.Limits) { l.Depth = 2 })
		pi, pr := parties(t, p)
		a := n.join("a", pi, 1, 1, coverPuts(false))
		b := n.join("b", pr, 1, 1, coverPuts(false))
		n.start(t, a, b)
		n.run(3)

		b.paused = true
		bodies := []string{"m1", "m2", "m3", "m4", "m5"}
		a.send(t, bodies...)
		n.until("a real probe", 10, func() bool { return a.c.stall && a.c.sticky != nil && a.c.sticky.body != nil })
		probe, epoch := bytes.Clone(a.c.sticky.rec), a.c.epoch
		a.circ().closed = true
		a.c.onEnd()
		n.until("the rebuild", 10, func() bool { return a.c.circ != nil })
		if a.c.epoch != epoch || a.c.session.Epoch() != epoch {
			t.Fatalf("epoch %d, session epoch %d after the rebuild, was %d", a.c.epoch, a.c.session.Epoch(), epoch)
		}
		if !a.c.stall || a.c.sticky == nil || !bytes.Equal(a.c.sticky.rec, probe) {
			t.Fatalf("after the rebuild: stall %v, sticky %+v", a.c.stall, a.c.sticky)
		}
		n.step()
		if puts := a.circ().puts(); len(puts) != 1 || !bytes.Equal(puts[0], probe) {
			t.Fatal("the new circuit does not start with the probe")
		}

		b.paused = false
		n.until("every message at b", 100, func() bool {
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
	})
}

// a sticky record survives the end of its circuit and is put on the next
func TestTheStickyRecordOutlivesTheCircuit(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	b := n.join("b", pr, 1, 1, nil)
	pair(t, a, b)
	n.step()
	kk1 := a.c.sticky
	if kk1 == nil || !kk1.handshake {
		t.Fatal("kk1 is not sticky")
	}
	a.circ().closed = true
	a.c.onEnd()
	n.until("the rebuild", 10, func() bool { return a.c.circ != nil })
	n.step()
	if puts := a.circ().puts(); len(puts) == 0 || string(puts[0]) != string(kk1.rec) {
		t.Fatal("the new circuit does not start with the sticky kk1")
	}
	n.until("the session", 20, func() bool { return confirmed(a, b) })
}

// the oldest request waits 10 s for its reply: the conversation closes the
// circuit itself, counts every request in flight as unanswered, does not count
// a refusal and rebuilds
func TestReplyTimeoutClosesTheCircuit(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	a := n.join("a", pi, 1, 1<<20, nil)
	timeout := int(DefaultReplyTimeout / testRate)
	n.run(timeout)
	if a.c.circ == nil {
		t.Fatal("closed before the timeout")
	}
	first := a.circ()
	n.step()
	if a.c.circ != nil || !first.closed {
		t.Fatal("still open after the timeout")
	}
	if len(a.events) != 1 || a.events[0] != (Event{Kind: CircuitEnded, Cause: ErrReplyTimeout}) {
		t.Fatalf("events %v", a.events)
	}
	if st := a.c.Stats(); st.Unanswered != uint64(timeout) || st.Refusals != 0 {
		t.Fatalf("%+v", st)
	}
	n.until("the rebuild", 10, func() bool { return a.c.circ != nil })
}

// a send that fails ends the circuit with a class of its own
func TestFailedSendEndsTheCircuit(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	n.run(3)
	a.circ().sendErr = errors.New("write tcp 10.0.0.1:41000->10.0.0.2:9000: broken pipe")
	n.step()
	if len(a.events) != 1 || a.events[0] != (Event{Kind: CircuitEnded, Cause: ErrSendFailed}) {
		t.Fatalf("events %v", a.events)
	}
	// the reply to the first came back, the second and the one that failed
	// did not
	if st := a.c.Stats(); st.Unanswered != 2 || st.Requests != 3 {
		t.Fatalf("%+v", st)
	}
}

// three circuits that end in a refused reply within RebuildFor end the
// conversation with ErrRefused; a refusal older than that no longer counts
func TestRefusalLimit(t *testing.T) {
	p := c25519(t)
	refuse := func(pr *testPeer) {
		pr.circ().refused = errRefusedReply
		pr.c.onEnd()
		pr.settle()
		pr.net.until("the rebuild", 10, func() bool { return pr.c.circ != nil || pr.c.finished })
	}

	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	refuse(a)
	refuse(a)
	if a.c.finished || a.c.Stats().Refusals != 2 {
		t.Fatalf("finished %v after two refusals", a.c.finished)
	}
	if ev := a.events[0]; ev.Kind != CircuitEnded || !errors.Is(ev.Cause, errRefusedReply) {
		t.Fatalf("event %v", ev)
	}
	refuse(a)
	if !a.c.finished || a.c.Err() != ErrRefused {
		t.Fatalf("finished %v, %v after three refusals", a.c.finished, a.c.Err())
	}
	select {
	case <-a.c.Done():
	default:
		t.Fatal("Done is open")
	}

	n = newNet(t, p, nil)
	pi, _ = parties(t, p)
	a = n.join("a", pi, 1, 1, func(c *Config) { c.RebuildFor = ticks(100) })
	refuse(a)
	n.run(50)
	refuse(a)
	n.run(50)
	refuse(a)
	if a.c.finished || a.c.Stats().Refusals != 3 {
		t.Fatalf("finished %v: the first refusal is older than RebuildFor", a.c.finished)
	}
	refuse(a)
	if !a.c.finished || a.c.Err() != ErrRefused {
		t.Fatalf("finished %v, %v", a.c.finished, a.c.Err())
	}

	// a refusal exactly RebuildFor old no longer counts, one a tick younger
	// still does
	for _, last := range []struct {
		tick int
		ends bool
	}{{99, true}, {100, false}} {
		n := newNet(t, p, nil)
		pi, _ := parties(t, p)
		a := n.join("a", pi, 1, 1, func(c *Config) { c.RebuildFor = ticks(100) })
		start := n.tick
		refuse(a)
		n.run(start + 45 - n.tick)
		refuse(a)
		n.run(start + last.tick - n.tick)
		refuse(a)
		if a.c.finished != last.ends {
			t.Fatalf("refusals on ticks 0, 45 and %d of RebuildFor 100: finished %v, %v", last.tick, a.c.finished, a.c.Err())
		}
	}
}

// Dial fails every time: the pauses double from a second up to a minute, and
// ten minutes after the circuit ended the conversation gives up
func TestRebuildGivesUpAfterRebuildFor(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	a.dialErr = errors.New("dial: no route")
	n.step()
	a.circ().closed = true
	a.c.onEnd()
	ended := n.tick
	limit := int(DefaultRebuildFor / testRate)
	n.until("the end", limit+1, func() bool { return a.c.finished })
	if n.tick != ended+limit || a.c.Err() != ErrRebuild {
		t.Fatalf("ended on tick %d with %v, want %d", n.tick, a.c.Err(), ended+limit)
	}
	var gaps []int
	last := ended
	for _, d := range a.dials {
		gaps = append(gaps, d-last)
		last = d
	}
	// seconds in ticks of 200 ms: 1, 2, 4, 8, 16, 32, then 60 each time
	want := []int{5, 10, 20, 40, 80, 160}
	for len(want) < len(gaps) {
		want = append(want, 300)
	}
	if !slices.Equal(gaps, want) {
		t.Fatalf("pauses %v, want %v", gaps, want)
	}
}

// a circuit whose cell cannot carry a request is a failed attempt
func TestARebuiltCircuitTooSmallIsAFailure(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	var small *fakeCircuit
	a := n.join("a", pi, 1, 1, nil)
	a.c.cfg.Dial = func() (Circuit, error) {
		a.dials = append(a.dials, n.tick)
		if len(a.dials) == 1 {
			small = n.circuit(1, 1)
			small.payload = 426
			return small, nil
		}
		return n.circuit(1, 1), nil
	}
	n.step()
	a.circ().closed = true
	a.c.onEnd()
	n.until("the rebuild", 30, func() bool { return a.c.circ != nil })
	if !small.closed || len(a.dials) != 2 || a.dials[1]-a.dials[0] != 10 {
		t.Fatalf("the small circuit closed %v, dials %v", small.closed, a.dials)
	}
}
