package nodeview

import "github.com/jimichi-org/jimichi/mailbox"

func checkBoundaryEvaluation(id uint8, in evaluationInput) error {
	if id == 0 {
		return nil
	}
	profile, ok := boundaryProfileFor(id)
	if !ok || len(in.plans) != 2 || len(in.views.nodes) != 1 || in.views.nodes[0].position != 4 {
		return fail(ReasonContract)
	}
	for side := range 2 {
		own := 0
		for _, m := range in.truth.messages {
			if int(m.side) == side && m.sent {
				own++
			}
		}
		if own != profile.sourceCount {
			return fail(ReasonIncomplete)
		}
	}
	node := in.views.nodes[0]
	var requests [2]int
	noPut, preSession, stale, fullSticky := false, false, false, false
	for _, o := range node.mailbox {
		if o.CallNS < in.public.epochNS || o.CallNS >= in.public.cutoffNS {
			continue
		}
		_, eligible, side, valid := mailboxLabel(node, o, in.truth)
		if !valid || side > 1 {
			return fail(ReasonLabel)
		}
		requests[side]++
		noPut = noPut || eligible && !o.HasPut
		var owner setupOwnership
		for _, s := range node.setups {
			if s.hop == o.Circuit {
				owner, _ = ownerOf(in.truth, s.circuit, node.position)
			}
		}
		for _, q := range in.truth.requests {
			if q.side == side && q.generation == owner.group && q.tag == o.Tag {
				preSession = preSession || q.eligibility == 1
				stale = stale || q.eligibility == 3
			}
		}
		if id == 2 && o.HasPut && o.RecordKind == 3 && fullMailboxPut(o.ReplyStatus) {
			for _, next := range node.mailbox {
				if next.Circuit == o.Circuit && next.Order > o.Order && next.CallNS >= in.public.epochNS && next.CallNS < in.public.cutoffNS && next.HasPut && next.RecordAlias == o.RecordAlias && equalBytes(node.arena.bytes(next.record), node.arena.bytes(o.record)) {
					_, valid := matchRecordLabel(&in.truth, node.arena.bytes(o.record))
					fullSticky = fullSticky || valid
				}
			}
		}
	}
	if requests[0] == 0 || id != 4 && requests[1] == 0 || id == 4 && requests[1] != 0 || id == 1 && !noPut || id == 2 && !fullSticky || id == 5 && !preSession || id == 6 && !stale {
		return fail(ReasonIncomplete)
	}
	return nil
}

func fullMailboxPut(status byte) bool {
	return status&^(mailbox.PutMask|mailbox.StatusRecord) == 0 && status&mailbox.PutMask == mailbox.PutFull
}
