package nodeview

func mailboxPopulation(in evaluationInput) (Counts, [4]uint64, [2]uint64, error) {
	var counts Counts
	var excluded [4]uint64
	var records [2]uint64
	for _, node := range in.views.nodes {
		for _, o := range node.mailbox {
			if o.CallNS < in.public.epochNS || o.CallNS >= in.public.cutoffNS {
				continue
			}
			positive, eligible, side, ok := mailboxLabel(node, o, in.truth)
			if !ok {
				counts.Unknown++
				excluded[3]++
				return counts, excluded, records, fail(ReasonLabel)
			}
			if eligible {
				counts.Eligible++
				if positive {
					counts.Positive++
				} else {
					counts.Negative++
				}
				if o.HasPut && o.RecordKind == 3 {
					records[boolInt(positive)]++
				}
				continue
			}
			var group uint32
			for _, s := range node.setups {
				if s.hop == o.Circuit {
					_, group, _ = setupOwner(in.truth, s.circuit, node.position)
				}
			}
			matched := 0
			var eligibility uint8
			for _, q := range in.truth.requests {
				if q.side == side && q.generation == group && q.tag == o.Tag {
					matched++
					eligibility = q.eligibility
				}
			}
			if matched != 1 {
				return counts, excluded, records, fail(ReasonLabel)
			}
			switch eligibility {
			case 1:
				excluded[0]++
			case 3:
				excluded[1]++
			case 2:
				excluded[2]++
			default:
				counts.Unknown++
				excluded[3]++
				return counts, excluded, records, fail(ReasonLabel)
			}
		}
	}
	return counts, excluded, records, nil
}
