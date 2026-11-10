package nodeview

import (
	"context"
	"math/rand"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/lab"
)

type workloadPlan struct {
	side                             uint16
	route                            [3]uint8
	gapSeed, lifetimeSeed, phaseSeed int64
	topology                         uint8
	contact                          []byte
	structural                       bool
	defaultsControl                  bool
	bodyArena                        *lockedArena
	bodies                           []arenaRef
	sourceLimit                      uint32
}

func echoWorkload(ctx context.Context, c *client.Client, p *privateCapture, w workloadPlan, epoch, cutoff int64, structural bool) error {
	if e := waitMonotonic(ctx, epoch); e != nil {
		return e
	}
	var lifetime int64 = cutoff - epoch
	if !structural {
		rng := rand.New(rand.NewSource(w.lifetimeSeed))
		if rng.Float64() >= .2 {
			lifetime = int64(10*time.Second) + rng.Int63n(int64(10*time.Second)+1)
		}
	}
	end := min(cutoff, epoch+lifetime)
	rng := rand.New(rand.NewSource(w.gapSeed))
	next := epoch
	for count := 0; next < end; count++ {
		if structural && count >= 1 {
			break
		}
		if count >= 1022 {
			return fail(ReasonLimit)
		}
		if e := waitMonotonic(ctx, next); e != nil {
			return e
		}
		p.mu.Lock()
		i, e := -1, error(nil)
		if structural && len(w.bodies) == 1 {
			i, e = p.sourceMessage(w.bodies[0])
		} else if p.err != ReasonNone {
			e = fail(p.err)
		} else {
			i, e = randomMessage(&p.truth, p.side)
			if e != nil {
				p.latch(reasonOf(e))
			}
		}
		if e != nil {
			p.mu.Unlock()
			return e
		}
		body := p.truth.arena.bytes(p.truth.messages[i].body)
		p.mu.Unlock()
		e = c.Send(body)
		p.mu.Lock()
		if e == nil {
			p.truth.messages[i].sent = true
		}
		p.mu.Unlock()
		if e != nil {
			return semanticFailure(e, ReasonBroken)
		}
		if structural {
			deadline := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				deadline.Stop()
				return fail(ReasonCancelled)
			case reply, ok := <-c.Replies():
				deadline.Stop()
				if !ok {
					return fail(ReasonBroken)
				}
				p.mu.Lock()
				found := false
				for j := range p.truth.messages {
					if equalBytes(p.truth.arena.bytes(p.truth.messages[j].body), reply) {
						p.truth.messages[j].replied = true
						found = true
						break
					}
				}
				p.mu.Unlock()
				clear(reply)
				if !found {
					return fail(ReasonLabel)
				}
			case <-deadline.C:
				return fail(ReasonBroken)
			}
		}
		var more bool
		next, more, e = sourceGapTime(next, end, rng.ExpFloat64()*float64(200*time.Millisecond))
		if e != nil {
			return e
		}
		if !more {
			break
		}
	}
	if !structural {
		if e := waitMonotonic(ctx, end); e != nil {
			return e
		}
		if end < cutoff {
			c.Close()
		}
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

var waitMonotonic = func(ctx context.Context, ns int64) error { return fail(ReasonUnsupported) }

func newGapRand(seed, segment int64) *rand.Rand {
	return rand.New(rand.NewSource(lab.Derive(seed, uint64(segment), 0, 0, 0)))
}

func defaultsOffsets() [100]int64 {
	var out [100]int64
	for segment := range 2 {
		base := int64(segment) * 20000000000
		for j := range 50 {
			out[segment*50+j] = base + 100000000 + int64(j)*200000000
		}
	}
	return out
}
