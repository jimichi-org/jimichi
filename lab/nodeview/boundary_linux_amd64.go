//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/e2e"
)

type boundaryClientState struct {
	mu                           sync.Mutex
	initialEnded, closeRequested bool
	current                      uint32
	initial                      uint32
	until                        int64
	ends                         circuitEnds
	dials, dialsAfter            dialCounts
	unanswered                   func() uint64
	windowUnanswered             uint64
}

type circuitEnds struct {
	replyTimeout, sendFailed, refused, farClose, after uint64
}
type dialCounts struct {
	attempts, failures uint64
}

// until stays zero before the workload begins, and an end before then is still inside the window
func (b *boundaryClientState) inWindow(now int64) bool { return b.until == 0 || now < b.until }

// the conversation adds an end's unanswered requests before it reports the end, so the
// count read here already holds this end
func (b *boundaryClientState) event(e conversation.Event) {
	if e.Kind == conversation.CircuitEnded {
		now := monotonicNS()
		b.mu.Lock()
		read := b.unanswered
		b.mu.Unlock()
		var unanswered uint64
		if read != nil {
			unanswered = read()
		}
		b.mu.Lock()
		b.initialEnded = true
		if b.inWindow(now) {
			b.windowUnanswered = max(b.windowUnanswered, unanswered)
		}
		switch {
		case !b.inWindow(now):
			b.ends.after++
		case errors.Is(e.Cause, conversation.ErrReplyTimeout):
			b.ends.replyTimeout++
		case errors.Is(e.Cause, conversation.ErrSendFailed):
			b.ends.sendFailed++
		case e.Cause == nil:
			b.ends.farClose++
		default:
			b.ends.refused++
		}
		b.mu.Unlock()
	}
}

func countedDial(b *boundaryClientState, dial func() (*client.Client, uint32, error)) (*client.Client, uint32, error) {
	next, generation, e := dial()
	now := monotonicNS()
	b.mu.Lock()
	defer b.mu.Unlock()
	counts := &b.dials
	if !b.inWindow(now) {
		counts = &b.dialsAfter
	}
	counts.attempts++
	if e != nil {
		counts.failures++
		return nil, 0, e
	}
	b.current = generation
	return next, generation, nil
}

func boundaryClientSettings(s Settings, side uint16, own, peer e2e.Card) (Settings, bool, error) {
	if s.ControlProfile == 0 {
		return s, false, nil
	}
	if side > 1 {
		return Settings{}, false, fail(ReasonIPC)
	}
	role := side
	responder := false
	if s.ControlProfile == 6 {
		order := bytes.Compare(own.Static, peer.Static)
		if order == 0 {
			return Settings{}, false, fail(ReasonContract)
		}
		responder = order > 0
		role = uint16(boolInt(responder))
	}
	cs, ok := boundaryProfileSideSettings(s.ControlProfile, role)
	if !ok || time.Duration(cs.RateNS) < conversation.MinRate(time.Duration(cs.ReplyTimeoutNS)) || cs.KeepaliveNS >= cs.StaleAfterNS {
		return Settings{}, false, fail(ReasonIPC)
	}
	return cs, responder, nil
}

func boundaryWorkload(ctx context.Context, c *childIO, conv *conversation.Conversation, initial *client.Client, b *boundaryClientState, peer e2e.Card, role e2e.Role, p *privateCapture, w workloadPlan, profile boundaryProfile, epoch, cutoff int64) error {
	if profile.actions[w.side] == boundaryPairAtTime {
		if e := waitUntil(ctx, epoch+profile.actionAtNS); e != nil {
			return e
		}
		if monotonicNS() >= cutoff || conv.Pair(peer) != nil {
			return fail(ReasonIncomplete)
		}
		if e := awaitPeerReady(ctx, conv, role, cutoff); e != nil {
			return e
		}
		if e := c.ready(3); e != nil {
			return e
		}
	}
	for i := 0; i < profile.sourceCount; i++ {
		if profile.actions[w.side] == boundaryCloseInitialAtTime && i == 1 {
			if e := closeBoundaryInitial(ctx, initial, b, conv, epoch+profile.actionAtNS, cutoff); e != nil {
				return e
			}
		}
		if e := waitUntil(ctx, epoch+profile.sourceOffsetsNS[i]); e != nil {
			return e
		}
		if monotonicNS() >= cutoff {
			return fail(ReasonIncomplete)
		}
		p.mu.Lock()
		at, e := p.sourceMessage(w.bodies[i])
		if e != nil {
			p.mu.Unlock()
			return e
		}
		e = conv.Send(p.truth.arena.bytes(w.bodies[i]))
		p.truth.messages[at].sent = e == nil
		p.mu.Unlock()
		if e != nil {
			return fail(ReasonBroken)
		}
	}
	return nil
}

func closeBoundaryInitial(ctx context.Context, initial *client.Client, b *boundaryClientState, conv *conversation.Conversation, at, cutoff int64) error {
	if e := waitUntil(ctx, at); e != nil {
		return e
	}
	b.mu.Lock()
	valid := !b.initialEnded && !b.closeRequested && b.current == b.initial
	if valid {
		b.closeRequested = true
	}
	b.mu.Unlock()
	if !valid || monotonicNS() >= cutoff || conv.Stats().Rebuilds != 0 {
		return fail(ReasonIncomplete)
	}
	if initial.Close() != nil {
		return fail(ReasonBroken)
	}
	return nil
}

func checkBoundaryClient(id uint8, side uint16, responder bool, st conversation.Stats, p *privateCapture, epoch, cutoff int64, b *boundaryClientState) error {
	if id == 1 && st.WindowFull == 0 || id == 7 && side == 0 && st.Rebuilds == 0 {
		return fail(ReasonIncomplete)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if id == 6 && responder {
		stale := false
		for _, req := range p.truth.requests {
			stale = stale || req.eligibility == 3
		}
		if st.Session.Stale == 0 || !stale {
			return fail(ReasonIncomplete)
		}
	}
	if id == 7 && side == 0 {
		b.mu.Lock()
		valid := b.closeRequested && b.initialEnded && b.initial != 0 && b.current > b.initial
		b.mu.Unlock()
		if !valid {
			return fail(ReasonIncomplete)
		}
	}
	return nil
}
