//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
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
}

func (b *boundaryClientState) event(e conversation.Event) {
	if e.Kind == conversation.CircuitEnded {
		b.mu.Lock()
		b.initialEnded = true
		b.mu.Unlock()
	}
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

func awaitPeerReady(ctx context.Context, conv *conversation.Conversation, until int64) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		st := conv.Stats()
		if st.State == e2e.StateConfirmed || st.State == e2e.StateEstablished && st.Session.DummiesReceived > 0 {
			return nil
		}
		if monotonicNS() >= until {
			return fail(ReasonIncomplete)
		}
		select {
		case <-ctx.Done():
			return fail(ReasonCancelled)
		case <-conv.Done():
			return fail(ReasonBroken)
		case <-tick.C:
		}
	}
}

func boundaryWorkload(ctx context.Context, c *childIO, conv *conversation.Conversation, initial *client.Client, b *boundaryClientState, peer e2e.Card, p *privateCapture, w workloadPlan, profile boundaryProfile, epoch, cutoff int64) error {
	if profile.actions[w.side] == boundaryPairAtTime {
		if e := waitUntil(ctx, epoch+profile.actionAtNS); e != nil {
			return e
		}
		if monotonicNS() >= cutoff || conv.Pair(peer) != nil {
			return fail(ReasonIncomplete)
		}
		if e := awaitPeerReady(ctx, conv, cutoff); e != nil {
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
		p.truth.messages = append(p.truth.messages, actualMessage{side: p.side, body: w.bodies[i]})
		at := len(p.truth.messages) - 1
		e := conv.Send(p.truth.arena.bytes(w.bodies[i]))
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
		closed, changed := b.closeRequested, b.current != b.initial
		b.mu.Unlock()
		if !closed || !changed {
			return fail(ReasonIncomplete)
		}
		for _, m := range p.truth.messages {
			if !m.replied {
				return fail(ReasonIncomplete)
			}
		}
	}
	return nil
}
