package nodeview

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/jimichi-org/jimichi/mailbox"
)

func boundaryReceiptInput(t *testing.T) evaluationInput {
	t.Helper()
	a := outcomeTestArena(t)
	in := evaluationInput{truth: privateTruth{arena: a}, public: publicConfig{epochNS: 100, cutoffNS: 200}, plans: []workloadPlan{{side: 0, bodyArena: a}, {side: 1, bodyArena: a}}}
	for side := range 2 {
		for source := range 2 {
			body := bytes.Repeat([]byte{byte(side*2 + source + 1)}, payloadBytes)
			ref := outcomeTestCopy(t, a, body)
			in.plans[side].bodies = append(in.plans[side].bodies, ref)
			in.truth.messages = append(in.truth.messages, actualMessage{side: uint16(side), body: outcomeTestCopy(t, a, body), sent: true})
		}
	}
	for i := range 4 {
		send := in.truth.messages[i]
		in.truth.messages = append(in.truth.messages, actualMessage{side: send.side ^ 1, body: outcomeTestCopy(t, a, a.bytes(send.body)), replied: true})
	}
	in.truth.ownership = setupOwnershipIndex{
		{id: setupIdentity{11, 4}, owner: setupOwnership{side: 0, group: 1, hop: 2, complete: true}},
		{id: setupIdentity{21, 4}, owner: setupOwnership{side: 1, group: 1, hop: 2, complete: true}},
	}
	in.truth.requests = []actualRequest{{side: 0, generation: 1, tag: 1, eligibility: 2, success: true}, {side: 1, generation: 1, tag: 1, eligibility: 2, success: true}}
	in.views.nodes = []nodeView{{position: 4, arena: a, setups: []setupView{{circuit: 11, hop: 101}, {circuit: 21, hop: 102}}, mailbox: []mailboxObservation{
		{Circuit: 101, Tag: 1, CallNS: 110, ReturnNS: 111, Complete: true},
		{Circuit: 102, Tag: 1, CallNS: 120, ReturnNS: 121, Complete: true},
	}}}
	return in
}

func TestBoundaryPeerReceiptsAllocationFreeOnEveryReturn(t *testing.T) {
	type allocationCase struct {
		name        string
		want        Reason
		sourceCount int
		edit        func(*evaluationInput)
	}
	cases := []allocationCase{
		{"resolved", ReasonNone, 2, func(in *evaluationInput) {}},
		{"swapped-plans", ReasonNone, 2, func(in *evaluationInput) { in.plans[0], in.plans[1] = in.plans[1], in.plans[0] }},
		{"repeated-receive", ReasonNone, 2, func(in *evaluationInput) { in.truth.messages = append(in.truth.messages, in.truth.messages[4]) }},
		{"source-count", ReasonContract, 1, func(in *evaluationInput) {}},
		{"no-plans", ReasonContract, 2, func(in *evaluationInput) { in.plans = nil }},
		{"one-plan", ReasonContract, 2, func(in *evaluationInput) { in.plans = in.plans[:1] }},
		{"three-plans", ReasonContract, 2, func(in *evaluationInput) { in.plans = append(in.plans, in.plans[0]) }},
		{"first-plan-side", ReasonContract, 2, func(in *evaluationInput) { in.plans[0].side = 2 }},
		{"second-plan-side", ReasonContract, 2, func(in *evaluationInput) { in.plans[1].side = 2 }},
		{"duplicate-plan-side", ReasonContract, 2, func(in *evaluationInput) { in.plans[1].side = 0 }},
		{"first-plan-body-count", ReasonContract, 2, func(in *evaluationInput) { in.plans[0].bodies = in.plans[0].bodies[:1] }},
		{"second-plan-body-count", ReasonContract, 2, func(in *evaluationInput) { in.plans[1].bodies = in.plans[1].bodies[:1] }},
		{"short-declared-body", ReasonContract, 2, func(in *evaluationInput) { in.plans[0].bodies[0].size-- }},
		{"long-declared-body", ReasonContract, 2, func(in *evaluationInput) { in.plans[0].bodies[0].size++ }},
		{"nil-plan-arena", ReasonContract, 2, func(in *evaluationInput) { in.plans[0].bodyArena = nil }},
		{"invalid-plan-arena", ReasonContract, 2, func(in *evaluationInput) { in.plans[0].bodyArena = &lockedArena{} }},
		{"invalid-plan-ref", ReasonContract, 2, func(in *evaluationInput) { in.plans[0].bodies[0].offset = -1 }},
		{"invalid-row-side", ReasonLabel, 2, func(in *evaluationInput) { in.truth.messages[0].side = 2 }},
		{"invalid-row-ref", ReasonLabel, 2, func(in *evaluationInput) { in.truth.messages[0].body.offset = -1 }},
		{"short-row-body", ReasonLabel, 2, func(in *evaluationInput) { in.truth.messages[0].body.size-- }},
		{"long-row-body", ReasonLabel, 2, func(in *evaluationInput) { in.truth.messages[0].body.size++ }},
		{"nil-truth-arena", ReasonLabel, 2, func(in *evaluationInput) { in.truth.arena = nil }},
		{"invalid-truth-arena", ReasonLabel, 2, func(in *evaluationInput) { in.truth.arena = &lockedArena{} }},
		{"wrong-side-send", ReasonLabel, 2, func(in *evaluationInput) { in.truth.messages[0].side = 1 }},
		{"same-side-receive", ReasonLabel, 2, func(in *evaluationInput) { in.truth.messages[4].side = 0 }},
		{"undeclared-body", ReasonLabel, 2, func(in *evaluationInput) {
			in.truth.messages[0].body = outcomeTestCopy(t, in.truth.arena, bytes.Repeat([]byte{99}, payloadBytes))
		}},
		{"duplicate-send", ReasonLabel, 2, func(in *evaluationInput) { in.truth.messages = append(in.truth.messages, in.truth.messages[0]) }},
		{"unsent-unreplied", ReasonIncomplete, 2, func(in *evaluationInput) {
			in.truth.messages = append(in.truth.messages, actualMessage{side: 0, body: in.truth.messages[0].body})
		}},
		{"manual-replied-without-receive", ReasonIncomplete, 2, func(in *evaluationInput) {
			in.truth.messages = in.truth.messages[:4]
			for i := range in.truth.messages {
				in.truth.messages[i].replied = true
			}
		}},
	}
	for first := range 4 {
		for second := first + 1; second < 4; second++ {
			cases = append(cases, allocationCase{"duplicate-declared-" + decimal(first) + "-" + decimal(second), ReasonContract, 2, func(in *evaluationInput) { in.plans[second/2].bodies[second%2] = in.plans[first/2].bodies[first%2] }})
		}
	}
	for source := range 4 {
		cases = append(cases,
			allocationCase{"missing-send-" + decimal(source), ReasonIncomplete, 2, func(in *evaluationInput) {
				in.truth.messages = append(in.truth.messages[:source], in.truth.messages[source+1:]...)
			}},
			allocationCase{"unresolved-send-" + decimal(source), ReasonIncomplete, 2, func(in *evaluationInput) { in.truth.messages[source].replied = false }},
			allocationCase{"missing-receive-" + decimal(source), ReasonIncomplete, 2, func(in *evaluationInput) {
				at := source + 4
				in.truth.messages = append(in.truth.messages[:at], in.truth.messages[at+1:]...)
			}},
		)
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			in := boundaryReceiptInput(t)
			if in.truth.resolveMessageReceipts() != 0 {
				t.Fatal("allocation base did not resolve its genuine receipt truth")
			}
			arena := in.truth.arena
			row.edit(&in)
			messagesBefore := append([]actualMessage(nil), in.truth.messages...)
			plansBefore := append([]workloadPlan(nil), in.plans...)
			for i := range plansBefore {
				plansBefore[i].bodies = append([]arenaRef(nil), plansBefore[i].bodies...)
			}
			bytesBefore := bytes.Clone(arena.buffer.Bytes())
			defer clear(bytesBefore)
			used, live, high := arena.used, arena.live, arena.high
			allocations := testing.AllocsPerRun(100, func() {
				mailboxControlAllocationErrorSink = checkBoundaryPeerReceipts(in, row.sourceCount)
			})
			if reasonOf(mailboxControlAllocationErrorSink) != row.want {
				t.Fatal("allocation path returned the wrong receipt reason")
			}
			if row.want != ReasonNone {
				if actual, ok := mailboxControlAllocationErrorSink.(failure); !ok || actual.reason != row.want {
					t.Fatal("allocation path changed the existing dynamic failure type")
				}
			}
			if !reflect.DeepEqual(messagesBefore, in.truth.messages) || !reflect.DeepEqual(plansBefore, in.plans) || !bytes.Equal(bytesBefore, arena.buffer.Bytes()) || used != arena.used || live != arena.live || high != arena.high {
				t.Fatal("allocation path mutated retained rows, plans or protected arena ownership")
			}
			if allocations != 0 {
				t.Errorf("helper allocated %.0f times on this return path, want 0", allocations)
			}
			mailboxControlAllocationErrorSink = nil
		})
	}
}

func TestBoundaryRebuildReceiptsRequireIndependentOppositePeer(t *testing.T) {
	in := boundaryReceiptInput(t)
	if reasonOf(checkBoundaryEvaluation(7, in)) != ReasonIncomplete {
		t.Fatal("unresolved own send passed the actual boundary evaluation path")
	}
	if unanswered := in.truth.resolveMessageReceipts(); unanswered != 0 {
		t.Fatal("complete genuine receives did not resolve all four sources")
	}
	before := append([]actualMessage(nil), in.truth.messages...)
	bytesBefore := bytes.Clone(in.truth.arena.buffer.Bytes())
	defer clear(bytesBefore)
	for range 2 {
		if e := checkBoundaryEvaluation(7, in); e != nil || in.truth.resolveMessageReceipts() != 0 {
			t.Fatal("resolved actual boundary evaluation or repeated resolution failed")
		}
	}
	if !reflect.DeepEqual(before, in.truth.messages) || !bytes.Equal(bytesBefore, in.truth.arena.buffer.Bytes()) {
		t.Fatal("receipt validation changed retained row ownership or bytes")
	}
	if allocations := testing.AllocsPerRun(10, func() { _ = checkBoundaryPeerReceipts(in, 2) }); allocations != 0 {
		t.Fatal("receipt helper allocated payload or control backing")
	}
	for removed := range 4 {
		t.Run("missing-"+decimal(removed), func(t *testing.T) {
			in := boundaryReceiptInput(t)
			at := 4 + removed
			in.truth.messages = append(in.truth.messages[:at], in.truth.messages[at+1:]...)
			in.truth.resolveMessageReceipts()
			if !oldBoundaryRebuildEvaluation(in) || reasonOf(checkBoundaryEvaluation(7, in)) != ReasonIncomplete {
				t.Fatal("missing independent receipt did not distinguish the old source-count decision")
			}
		})
	}
	for _, row := range []struct {
		name string
		want Reason
		edit func(*evaluationInput)
	}{
		{"manual-resolved", ReasonIncomplete, func(in *evaluationInput) {
			in.truth.messages = in.truth.messages[:4]
			for i := range in.truth.messages {
				in.truth.messages[i].replied = true
			}
		}},
		{"same-side", ReasonLabel, func(in *evaluationInput) { in.truth.messages[4].side ^= 1 }},
		{"wrong-body", ReasonLabel, func(in *evaluationInput) {
			in.truth.messages[4].body = outcomeTestCopy(t, in.truth.arena, bytes.Repeat([]byte{99}, payloadBytes))
		}},
		{"sent-only", ReasonIncomplete, func(in *evaluationInput) { in.truth.messages = in.truth.messages[:4] }},
		{"unattempted", ReasonIncomplete, func(in *evaluationInput) { in.truth.messages[4].replied = false }},
		{"echo-self", ReasonIncomplete, func(in *evaluationInput) {
			in.truth.messages = in.truth.messages[:4]
			for i := range in.truth.messages {
				in.truth.messages[i].replied = true
			}
		}},
		{"duplicate-send", ReasonLabel, func(in *evaluationInput) { in.truth.messages[1].body = in.truth.messages[0].body }},
		{"duplicate-declaration", ReasonContract, func(in *evaluationInput) { in.plans[1].bodies[1] = in.plans[0].bodies[0] }},
		{"invalid-side", ReasonLabel, func(in *evaluationInput) { in.truth.messages[4].side = 2 }},
		{"invalid-ref", ReasonLabel, func(in *evaluationInput) { in.truth.messages[4].body.offset = -1 }},
		{"wrong-width", ReasonLabel, func(in *evaluationInput) { in.truth.messages[4].body.size-- }},
		{"reused-receipt", ReasonIncomplete, func(in *evaluationInput) { in.truth.messages[5] = in.truth.messages[4] }},
		{"missing-send", ReasonIncomplete, func(in *evaluationInput) { in.truth.messages = in.truth.messages[1:] }},
		{"wrong-plan-side", ReasonContract, func(in *evaluationInput) { in.plans[1].side = 0 }},
		{"missing-plan-body", ReasonContract, func(in *evaluationInput) { in.plans[1].bodies = in.plans[1].bodies[:1] }},
		{"invalid-plan-arena", ReasonContract, func(in *evaluationInput) { in.plans[1].bodyArena = nil }},
		{"invalid-plan-ref", ReasonContract, func(in *evaluationInput) { in.plans[1].bodies[1].offset = -1 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			in := boundaryReceiptInput(t)
			in.truth.resolveMessageReceipts()
			row.edit(&in)
			if row.name == "manual-resolved" && (in.truth.resolveMessageReceipts() != 0 || !oldBoundaryRebuildEvaluation(in)) {
				t.Fatal("forged unanswered-zero counterexample did not pass the exact old rebuild decision")
			}
			if row.name == "same-side" && !oldBoundaryRebuildEvaluation(in) {
				t.Fatal("wrong-peer counterexample did not pass the exact old rebuild decision")
			}
			if reasonOf(checkBoundaryEvaluation(7, in)) != row.want {
				t.Fatalf("actual boundary evaluation accepted contradictory or missing evidence, want %s", row.want)
			}
		})
	}
	t.Run("repeated-real-receive", func(t *testing.T) {
		in := boundaryReceiptInput(t)
		in.truth.messages = append(in.truth.messages, in.truth.messages[4])
		in.truth.resolveMessageReceipts()
		if e := checkBoundaryEvaluation(7, in); e != nil {
			t.Fatal("a genuine repeated same-source receipt was rejected")
		}
	})
	for id := uint8(0); id <= 6; id++ {
		in := boundaryReceiptInput(t)
		profile, _ := boundaryProfileFor(id)
		in.truth.messages = nil
		for side := range 2 {
			for range profile.sourceCount {
				in.truth.messages = append(in.truth.messages, actualMessage{side: uint16(side), sent: true})
			}
		}
		if id == 6 {
			in.truth.requests[0].eligibility = 3
		}
		if id == 5 {
			in.truth.requests[0].eligibility = 1
		}
		if id == 4 {
			in.views.nodes[0].mailbox = in.views.nodes[0].mailbox[:1]
		}
		if id == 2 {
			record := outcomeTestCopy(t, in.truth.arena, bytes.Repeat([]byte{7}, 392))
			in.truth.seals = []actualSeal{{side: 0, generation: 1, record: record, real: true}}
			in.truth.requests[0].record = record
			in.truth.requests = append(in.truth.requests, actualRequest{side: 0, generation: 1, tag: 2, record: record, eligibility: 2, success: true})
			observation := &in.views.nodes[0].mailbox[0]
			observation.Order, observation.HasPut, observation.RecordKind, observation.RecordAlias, observation.ReplyStatus, observation.record = 1, true, 3, 1, mailbox.PutFull, record
			next := *observation
			next.Order, next.Tag, next.CallNS = 2, 2, 130
			in.views.nodes[0].mailbox = append(in.views.nodes[0].mailbox, next)
		}
		if e := checkBoundaryEvaluation(id, in); e != nil {
			t.Fatal("a pre-existing non-rebuild control acquired a peer receipt requirement")
		}
	}
}

func oldBoundaryRebuildEvaluation(in evaluationInput) bool {
	if len(in.plans) != 2 || len(in.views.nodes) != 1 || in.views.nodes[0].position != 4 {
		return false
	}
	for side := range 2 {
		count := 0
		for _, message := range in.truth.messages {
			if message.sent && int(message.side) == side {
				count++
			}
		}
		if count != 2 {
			return false
		}
	}
	var requests [2]int
	node := in.views.nodes[0]
	for _, observation := range node.mailbox {
		if observation.CallNS < in.public.epochNS || observation.CallNS >= in.public.cutoffNS {
			continue
		}
		_, _, side, valid := mailboxLabel(node, observation, in.truth)
		if !valid || side > 1 {
			return false
		}
		requests[side]++
	}
	return requests[0] > 0 && requests[1] > 0
}
