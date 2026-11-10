package nodeview

import "math"

func addCounterChecks(a *CounterChecks, b CounterChecks) error {
	dst := []*uint64{&a.Samples, &a.Transitions, &a.Advanced, &a.Gaps, &a.Repeats, &a.Invalid, &a.Matched, &a.ShiftChecks, &a.ShiftOK, &a.Missing, &a.DirectionOK, &a.IndexOK, &a.FirstOK, &a.FirstChecked, &a.FirstFailed}
	src := []uint64{b.Samples, b.Transitions, b.Advanced, b.Gaps, b.Repeats, b.Invalid, b.Matched, b.ShiftChecks, b.ShiftOK, b.Missing, b.DirectionOK, b.IndexOK, b.FirstOK, b.FirstChecked, b.FirstFailed}
	for i, p := range dst {
		if math.MaxUint64-*p < src[i] {
			return fail(ReasonLimit)
		}
		*p += src[i]
	}
	return nil
}

func selectedCaptureSummary(views viewSet, epoch, cutoff int64) (CaptureSummary, error) {
	var out CaptureSummary
	for _, node := range views.nodes {
		c := collector{view: nodeView{budget: node.budget, cells: node.cells, setups: node.setups}, start: epoch, cutoff: cutoff}
		if e := c.checkCounters(); e != nil {
			return out, e
		}
		if e := addCounterChecks(&out.Counters, c.summary.Counters); e != nil {
			return out, e
		}
		for _, s := range node.setups {
			if s.index >= 3 {
				return out, fail(ReasonContract)
			}
			if s.hop != 0 {
				out.Roles[s.index]++
			}
			if incoming, ok := connection(node, s.connection); ok && incoming.authenticated {
				if incoming.peer < 5 {
					out.NeighbourConfirmed++
				} else {
					out.NeighbourUnknown++
				}
			} else {
				out.NeighbourUnknown++
			}
			if s.nextPort != 0 {
				if _, ok := outgoing(node, s); ok {
					out.NeighbourConfirmed++
				} else {
					out.NeighbourUnknown++
				}
			}
		}
		for _, cell := range node.cells {
			if cell.hop == 0 || cell.localTime < epoch || cell.localTime >= cutoff {
				continue
			}
			for i, flag := range []uint16{stageInput, stageLocal, stageSealed, stagePartial, stageWritten} {
				if cell.stages&flag != 0 {
					out.Stages[i]++
				}
			}
			if cell.terminal > terminalAmbiguous {
				return out, fail(ReasonContract)
			}
			out.Lifecycle[cell.terminal]++
			index := int(cell.index)
			if index >= 3 {
				return out, fail(ReasonContract)
			}
			cipher := uint64(494 - index*16)
			plain := cipher - 16
			if cell.dir == 0 {
				out.OperationLengths[0] += cipher
				out.OperationLengths[1] += plain
			} else {
				out.OperationLengths[2] += plain
				out.OperationLengths[3] += cipher
			}
		}
	}
	return out, nil
}
