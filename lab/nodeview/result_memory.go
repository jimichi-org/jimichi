package nodeview

import (
	"sync"
	"unsafe"
)

type resultCharge struct {
	mu                         sync.Mutex
	budget                     *memoryBudget
	bytes                      uint64
	proofs                     int
	clean, discarded, admitted bool
}

func (r *resultCharge) hold(n uint64) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.budget.reserve(n); e != nil {
		return e
	}
	r.bytes += n
	return nil
}
func (r *resultCharge) releasePart(n uint64) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > r.bytes {
		return fail(ReasonContract)
	}
	r.budget.release(n)
	r.bytes -= n
	return nil
}
func (r *resultCharge) cleaned() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clean = true
	if r.discarded {
		r.budget.release(r.bytes)
		r.bytes = 0
	}
}
func (r *resultCharge) discard() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.discarded = true
	if r.clean {
		r.budget.release(r.bytes)
		r.bytes = 0
	}
}
func (r *resultCharge) admit(audits int, output *memoryBudget) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.clean || r.discarded || r.admitted || r.proofs != audits {
		return fail(ReasonContract)
	}
	if e := output.reserve(r.bytes); e != nil {
		return e
	}
	r.budget.release(r.bytes)
	r.bytes = 0
	r.admitted = true
	return nil
}

func rankAuditBacking(a RankAudit) uint64 {
	n := uint64(cap(a.Groups))*24 + uint64(cap(a.TopOne))*16
	for _, group := range a.Groups {
		n += uint64(cap(group)) * uint64(unsafe.Sizeof(RankBucket{}))
	}
	return n
}

func runResultBacking(r RunResult) uint64 {
	n := uint64(cap(r.Methods))*uint64(unsafe.Sizeof(MethodResult{})) + uint64(cap(r.RouteHistogram))*8 + uint64(cap(r.LinkingTimes))*uint64(unsafe.Sizeof(LinkingTime{})) + uint64(max(256, cap(r.Flags)))*uint64(unsafe.Sizeof(Reason("")))
	n += uint64(5+5*len(r.Methods)+len(r.LinkingTimes)) * 8
	return n
}

func appendTaskOutput(r *Report, b *memoryBudget, row RunResult, audits []RankAudit) error {
	var e error
	r.Runs, e = appendCapacity(r.Runs, 1, b)
	if e != nil {
		return e
	}
	r.Audit, e = appendCapacity(r.Audit, len(audits), b)
	if e != nil {
		return e
	}
	r.Runs = append(r.Runs, row)
	r.Audit = append(r.Audit, audits...)
	clear(audits)
	return nil
}

func appendUnstartedTasks(r *Report, c Config, tasks []executionTask, reason Reason) error {
	for _, task := range tasks {
		if e := c.outputBudget.checkAllocation(4096); e != nil {
			return e
		}
		row := unavailableTask(c, task, reason)
		if e := c.outputBudget.reserve(runResultBacking(row)); e != nil {
			return e
		}
		if e := appendTaskOutput(r, c.outputBudget, row, nil); e != nil {
			return e
		}
	}
	return nil
}

func appendMissingTrainingTasks(r *Report, c Config, tasks []executionTask, reason Reason) error {
	type key struct {
		configuration string
		repeat        int
	}
	seen := make(map[key]bool, len(r.Runs))
	defer clear(seen)
	for _, row := range r.Runs {
		seen[key{row.Configuration, row.Repeat}] = true
	}
	for _, task := range tasks {
		if seen[key{task.coordinate.ID, task.repeat}] {
			continue
		}
		if e := appendUnstartedTasks(r, c, []executionTask{task}, reason); e != nil {
			return e
		}
	}
	return nil
}

func trainingBacking(rows []encodedTrainingRow) uint64 {
	return uint64(cap(rows)) * uint64(unsafe.Sizeof(encodedTrainingRow{}))
}

func wipeRankAudit(a *RankAudit) {
	groups := a.Groups[:cap(a.Groups)]
	for i := range groups {
		clear(groups[i][:cap(groups[i])])
		groups[i] = nil
	}
	clear(groups)
	clear(a.TopOne[:cap(a.TopOne)])
	a.Groups = nil
	a.TopOne = nil
}

func holdRankResult(in evaluationInput, m MethodResult, a RankAudit) error {
	if e := validateRankRelease(m, a, in.budget); e != nil {
		return e
	}
	if e := in.resultCharge.hold(rankAuditBacking(a)); e != nil {
		return e
	}
	if in.resultCharge != nil {
		in.resultCharge.mu.Lock()
		in.resultCharge.proofs++
		in.resultCharge.mu.Unlock()
	}
	return nil
}
