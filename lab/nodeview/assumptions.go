package nodeview

import "sort"

func observedSetupOverlap(in evaluationInput) (uint64, error) {
	type interval struct{ start, end int64 }
	groups := make(map[[2]uint32]interval, maxClients)
	defer clear(groups)
	for _, node := range in.views.nodes {
		for _, s := range node.setups {
			owner, ok := ownerOf(in.truth, s.circuit, node.position)
			if !ok {
				return 0, fail(ReasonLabel)
			}
			if owner.group != 1 || !owner.complete || s.hop == 0 {
				continue
			}
			if s.opened <= 0 {
				return 0, fail(ReasonClock)
			}
			key := [2]uint32{uint32(owner.side), owner.group}
			value, present := groups[key]
			if !present {
				value = interval{s.opened, s.opened}
			} else {
				value.start = min(value.start, s.opened)
				value.end = max(value.end, s.opened)
			}
			groups[key] = value
		}
	}
	ordered := make([]interval, 0, len(groups))
	defer func() { clear(ordered) }()
	for _, value := range groups {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].start < ordered[j].start })
	var overlaps uint64
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].end >= ordered[i].start {
			overlaps++
		}
		ordered[i].end = max(ordered[i].end, ordered[i-1].end)
	}
	return overlaps, nil
}
