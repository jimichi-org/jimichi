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
	if id == 7 {
		if e := checkBoundaryPeerReceipts(in, profile.sourceCount); e != nil {
			return e
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

func checkBoundaryPeerReceipts(in evaluationInput, sourceCount int) error {
	if sourceCount != 2 || len(in.plans) != 2 || in.plans[0].side > 1 || in.plans[1].side > 1 || in.plans[0].side == in.plans[1].side {
		return mailboxControlContractError
	}
	for i := range in.plans {
		plan := &in.plans[i]
		if len(plan.bodies) != sourceCount {
			return mailboxControlContractError
		}
		for _, ref := range plan.bodies {
			if ref.size != payloadBytes || !plan.bodyArena.valid(ref) {
				return mailboxControlContractError
			}
		}
	}
	for i := range 4 {
		plan := &in.plans[i/2]
		body := plan.bodyArena.bytes(plan.bodies[i%2])
		for j := i + 1; j < 4; j++ {
			next := &in.plans[j/2]
			if equalBytes(body, next.bodyArena.bytes(next.bodies[j%2])) {
				return mailboxControlContractError
			}
		}
	}
	for _, message := range in.truth.messages {
		if message.side > 1 || message.body.size != payloadBytes || !in.truth.arena.valid(message.body) {
			return mailboxControlLabelError
		}
		matches := 0
		for i := range in.plans {
			plan := &in.plans[i]
			for _, ref := range plan.bodies {
				if equalBytes(in.truth.arena.bytes(message.body), plan.bodyArena.bytes(ref)) {
					if message.sent && message.side != plan.side || !message.sent && message.replied && message.side != plan.side^1 {
						return mailboxControlLabelError
					}
					matches++
				}
			}
		}
		if matches != 1 {
			return mailboxControlLabelError
		}
		if !message.sent && !message.replied {
			return mailboxControlIncompleteError
		}
	}
	for i := range in.plans {
		plan := &in.plans[i]
		for _, ref := range plan.bodies {
			body := plan.bodyArena.bytes(ref)
			sends, receives, resolved := 0, 0, false
			for _, message := range in.truth.messages {
				if !equalBytes(body, in.truth.arena.bytes(message.body)) {
					continue
				}
				if message.sent && message.side == plan.side {
					sends++
					resolved = message.replied
				} else if !message.sent && message.replied && message.side == plan.side^1 {
					receives++
				}
			}
			if sends > 1 {
				return mailboxControlLabelError
			}
			if sends != 1 || !resolved || receives == 0 {
				return mailboxControlIncompleteError
			}
		}
	}
	return nil
}

func fullMailboxPut(status byte) bool {
	return status&^(mailbox.PutMask|mailbox.StatusRecord) == 0 && status&mailbox.PutMask == mailbox.PutFull
}
