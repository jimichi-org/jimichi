package nodeview

import (
	"math"
	"unsafe"
)

func validateRankRelease(m MethodResult, a RankAudit, budgets ...*memoryBudget) error {
	if a.Method != m.Method || a.WindowNS != m.WindowNS || a.Repeat < 0 || !knownMethod(a.Method) || len(a.Groups) > 128 || m.Candidates < 0 || m.Candidates > maxSelectedCells || a.Made != m.Made || a.Wrong != m.Wrong || a.Wrong < 0 || a.Wrong > a.Made || a.Made > len(a.Groups) {
		return fail(ReasonContract)
	}
	type rank struct {
		positive, negative, category int
		present                      bool
	}
	var budget *memoryBudget
	if len(budgets) > 0 {
		budget = budgets[0]
	}
	if e := budget.checkAllocation(uint64(m.Candidates+1) * uint64(unsafe.Sizeof(rank{}))); e != nil {
		return e
	}
	ranks := make([]rank, m.Candidates+1)
	defer clear(ranks)
	total, positive, negative, maxRank, undefined, impossible := 0, 0, 0, 0, 0, 0
	classifier := m.Method == "request" || m.Method == "record"
	for _, group := range a.Groups {
		previous := 0
		for _, b := range group {
			if b.Rank <= previous || b.Rank > m.Candidates || b.Positive < 0 || b.Negative < 0 || b.Positive+b.Negative <= 0 || b.Positive+b.Negative > m.Candidates-total || b.Category != 0 && b.Category != 1 && b.Category != -2 && b.Category != -3 {
				return fail(ReasonContract)
			}
			previous = b.Rank
			maxRank = max(maxRank, b.Rank)
			r := &ranks[b.Rank]
			if r.present && r.category != b.Category {
				return fail(ReasonContract)
			}
			r.present = true
			r.category = b.Category
			r.positive += b.Positive
			r.negative += b.Negative
			total += b.Positive + b.Negative
			positive += b.Positive
			negative += b.Negative
			if !classifier {
				if b.Category == -2 {
					undefined += b.Positive + b.Negative
				}
				if b.Category == -3 {
					impossible += b.Positive + b.Negative
				}
			}
		}
	}
	if total != m.Candidates || undefined != m.Undefined || impossible != m.Impossible {
		return fail(ReasonContract)
	}
	var u2, below uint64
	previousCategory := -1
	for i := 1; i <= maxRank; i++ {
		r := ranks[i]
		if !r.present {
			return fail(ReasonContract)
		}
		category := map[int]int{-3: 0, -2: 1, 0: 2, 1: 3}[r.category]
		if category < previousCategory || (r.category == -2 || r.category == -3) && category == previousCategory || classifier && category < 2 {
			return fail(ReasonContract)
		}
		previousCategory = category
		u2 += uint64(r.positive) * (2*below + uint64(r.negative))
		below += uint64(r.negative)
	}
	if positive == 0 || negative == 0 {
		if m.AUC.Value != nil {
			return fail(ReasonContract)
		}
	} else {
		auc := float64(u2) / float64(2*uint64(positive)*uint64(negative))
		if m.AUC.Value == nil || math.Float64bits(auc) != math.Float64bits(*m.AUC.Value) {
			return fail(ReasonContract)
		}
		var fp, tp float64
		best := 0.0
		for i := maxRank; i > 0; i-- {
			beforeFP, beforeTP := fp/float64(negative), tp/float64(positive)
			fp += float64(ranks[i].negative)
			tp += float64(ranks[i].positive)
			afterFP, afterTP := fp/float64(negative), tp/float64(positive)
			if afterFP <= .01 {
				best = math.Max(best, afterTP)
			} else if beforeFP <= .01 {
				fraction := (.01 - beforeFP) / (afterFP - beforeFP)
				best = math.Max(best, beforeTP+fraction*(afterTP-beforeTP))
			}
		}
		if m.TPR.Value == nil || math.Float64bits(*m.TPR.Value) != math.Float64bits(best) {
			return fail(ReasonContract)
		}
	}
	if classifier {
		if len(a.TopOne) != 0 || a.Made != 0 || a.Wrong != 0 || m.Partners != 0 {
			return fail(ReasonContract)
		}
		return nil
	}
	if len(a.TopOne) != m.Partners {
		return fail(ReasonContract)
	}
	var top float64
	for _, v := range a.TopOne {
		if v[0] < 1 || v[0] > m.Candidates || v[1] < 0 || v[1] > 1 {
			return fail(ReasonContract)
		}
		if v[1] == 1 {
			top += 1 / float64(v[0])
		}
	}
	if m.Partners == 0 {
		if m.TopOne.Value != nil {
			return fail(ReasonContract)
		}
	} else if m.TopOne.Value == nil || math.Float64bits(top/float64(m.Partners)) != math.Float64bits(*m.TopOne.Value) {
		return fail(ReasonContract)
	}
	return nil
}
