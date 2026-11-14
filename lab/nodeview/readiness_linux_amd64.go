//go:build linux && amd64

package nodeview

import (
	"context"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/e2e"
)

func awaitPeerReady(ctx context.Context, conv *conversation.Conversation, role e2e.Role, until int64) error {
	if ctx == nil || conv == nil || role != e2e.RoleInitiator && role != e2e.RoleResponder || until <= 0 {
		return fail(ReasonContract)
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return fail(ReasonCancelled)
		}
		select {
		case <-conv.Done():
			return fail(ReasonBroken)
		default:
		}
		now := monotonicNS()
		if now <= 0 {
			return fail(ReasonClock)
		}
		if now >= until {
			return fail(ReasonIncomplete)
		}
		st := conv.Stats()
		if peerSessionReady(role, st.Paired, st.State) {
			if ctx.Err() != nil {
				return fail(ReasonCancelled)
			}
			select {
			case <-conv.Done():
				return fail(ReasonBroken)
			default:
			}
			now = monotonicNS()
			if now <= 0 {
				return fail(ReasonClock)
			}
			if now >= until {
				return fail(ReasonIncomplete)
			}
			return nil
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
