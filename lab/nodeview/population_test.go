package nodeview

import "testing"

func TestMailboxClassAndExclusionScopes(t *testing.T) {
	a := outcomeTestArena(t)
	in := evaluationInput{truth: privateTruth{arena: a, setups: outcomeTestGroup(0, [3]uint8{0, 1, 4}, 100)}, public: publicConfig{epochNS: 100, cutoffNS: 200}, views: viewSet{nodes: []nodeView{{position: 4, arena: a, setups: []setupView{{hop: 10, circuit: 102}}}}}}
	for i, eligibility := range []uint8{1, 3, 2, 2, 2, 2} {
		q := actualRequest{side: 0, generation: 1, tag: uint16(i), eligibility: eligibility, success: true}
		o := mailboxObservation{Circuit: 10, Tag: uint16(i), CallNS: 150, Complete: true}
		if i == 2 || i >= 4 {
			body := make([]byte, 392)
			body[0] = 3
			body[10] = byte(i)
			if i == 2 {
				body[0] = 1
			}
			q.record = outcomeTestCopy(t, a, body)
			o.record = q.record
			o.HasPut = true
			o.RecordKind = body[0]
			if i >= 4 {
				in.truth.seals = append(in.truth.seals, actualSeal{record: q.record, real: i == 4})
			}
		}
		in.truth.requests = append(in.truth.requests, q)
		in.views.nodes[0].mailbox = append(in.views.nodes[0].mailbox, o)
	}
	counts, excluded, records, e := mailboxPopulation(in)
	// Three eligible requests are one real put, one dummy put, and one no-put.
	if e != nil || counts.Eligible != 3 || counts.Positive != 1 || counts.Negative != 2 || records != [2]uint64{1, 1} || excluded != [4]uint64{1, 1, 1, 0} {
		t.Fatal("request and record populations conflated")
	}
	in.views.nodes[0].mailbox[0].CallNS = 200
	_, excluded, _, e = mailboxPopulation(in)
	if e != nil || excluded[0] != 0 {
		t.Fatal("cutoff exclusion scope changed")
	}
	in.truth.seals = nil
	counts, excluded, _, e = mailboxPopulation(in)
	if reasonOf(e) != ReasonLabel || counts.Unknown != 1 || excluded[3] != 1 {
		t.Fatal("unknown record became a negative")
	}
}
