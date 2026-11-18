package nodeview

func wipeOwnedNumber(n *Number) {
	if n.Value != nil {
		*n.Value = 0
	}
	*n = Number{}
}

func wipeRejectedRun(row *RunResult) {
	for i := range row.Methods[:cap(row.Methods)] {
		m := &row.Methods[:cap(row.Methods)][i]
		for _, n := range []*Number{&m.AUC, &m.TopOne, &m.TPR, &m.BootstrapLow, &m.BootstrapHigh} {
			wipeOwnedNumber(n)
		}
	}
	for i := range row.LinkingTimes[:cap(row.LinkingTimes)] {
		wipeOwnedNumber(&row.LinkingTimes[:cap(row.LinkingTimes)][i].Seconds)
	}
	for _, n := range []*Number{&row.QueueJoined, &row.PutQ, &row.PutBaseline, &row.RequestLDA, &row.RecordLDA} {
		wipeOwnedNumber(n)
	}
	clear(row.Methods[:cap(row.Methods)])
	clear(row.LinkingTimes[:cap(row.LinkingTimes)])
	clear(row.RouteHistogram[:cap(row.RouteHistogram)])
	clear(row.Flags[:cap(row.Flags)])
	*row = RunResult{}
}

func validatedExecutionCounts(task executionTask, counts Counts) (Counts, error) {
	planned := uint64(max(len(task.routes), task.plannedSides))
	if task.membership {
		planned = 1
	}
	if counts.Planned != planned || counts.Attempted > planned || counts.Established > counts.Attempted || counts.PreflightOK > counts.Established || counts.MessageBearing > counts.PreflightOK || counts.Refused > counts.Attempted-counts.Established || counts.SetupFailed > counts.Attempted-counts.Established-counts.Refused {
		return Counts{}, fail(ReasonContract)
	}
	return Counts{Planned: planned, Attempted: counts.Attempted, Refused: counts.Refused, SetupFailed: counts.SetupFailed, Established: counts.Established, PreflightOK: counts.PreflightOK, MessageBearing: counts.MessageBearing, Unanswered: counts.Unanswered, Rebuilt: counts.Rebuilt, Missing: planned}, nil
}

func finalizeTaskOutput(c Config, task executionTask, row RunResult, audits []RankAudit, charge *resultCharge) (RunResult, []RankAudit, error) {
	err := charge.hold(runResultBacking(row))
	if err == nil {
		err = admitTaskOutput(c, task, row, audits, charge)
	}
	if err == nil {
		return row, audits, nil
	}
	var flags [128]Reason
	defer clear(flags[:])
	known := flags[:0]
	for _, reason := range row.Flags {
		if !validReason(reason) {
			reason = ReasonContract
		}
		known = appendRuntimeReason(known, reason)
	}
	known = appendRuntimeReason(known, reasonOf(err))
	known = appendRuntimeReason(known, ReasonIncomplete)
	counts, countErr := validatedExecutionCounts(task, row.Counts)
	wipeRejectedRun(&row)
	for i := range audits[:cap(audits)] {
		wipeRankAudit(&audits[:cap(audits)][i])
	}
	clear(audits[:cap(audits)])
	charge.discard()
	if countErr != nil {
		return RunResult{}, nil, mergeRuntimeFailure(err, countErr)
	}
	backing := runResultBacking(RunResult{})
	if e := c.outputBudget.reserve(backing); e != nil {
		return RunResult{}, nil, mergeRuntimeFailure(err, e)
	}
	if e := c.outputBudget.checkAllocation(backing); e != nil {
		c.outputBudget.release(backing)
		return RunResult{}, nil, mergeRuntimeFailure(err, e)
	}
	stub := unavailableTask(c, task, reasonOf(err))
	stub.Counts = counts
	clear(stub.Flags)
	stub.Flags = append([]Reason(nil), known...)
	return stub, nil, err
}
