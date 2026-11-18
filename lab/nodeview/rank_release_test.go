package nodeview

import "testing"

func releasedRankKnownAnswer() (MethodResult, RankAudit) {
	// Two positives at score1 each beat score0 and tie score1: (2 wins+2 half ties)/4=.75.
	m := MethodResult{Method: "request", WindowNS: 30000000000, Candidates: 4, AUC: number(.75, ReasonNone), TPR: number(.02, ReasonNone)}
	a := RankAudit{Configuration: "mail-P0-C0", Method: m.Method, WindowNS: m.WindowNS, Groups: [][]RankBucket{{{Rank: 1, Negative: 1, Category: 0}, {Rank: 2, Positive: 1, Category: 1}}, {{Rank: 2, Positive: 1, Negative: 1, Category: 1}}, nil}}
	return m, a
}

func TestRankReleaseChecksExactTieCategoriesAndROC(t *testing.T) {
	m, a := releasedRankKnownAnswer()
	if validateRankRelease(m, a) != nil {
		t.Fatal("rank known answer rejected")
	}
	for _, mutate := range []func(*MethodResult, *RankAudit){
		func(m *MethodResult, a *RankAudit) { m.AUC = number(.5, ReasonNone) },
		func(m *MethodResult, a *RankAudit) { m.TPR = number(.01, ReasonNone) },
		func(m *MethodResult, a *RankAudit) { a.Groups[1][0].Category = 0 },
		func(m *MethodResult, a *RankAudit) { a.Groups[1][0].Rank = 3 },
		func(m *MethodResult, a *RankAudit) { a.Groups[0][0].Negative = 0 },
		func(m *MethodResult, a *RankAudit) { a.Made = 1 },
	} {
		m, a := releasedRankKnownAnswer()
		mutate(&m, &a)
		if validateRankRelease(m, a) == nil {
			t.Fatal("malformed rank output released")
		}
	}
}

func TestCurrentWitnessRemainsRawUntilCleanAndAdmission(t *testing.T) {
	m, a := releasedRankKnownAnswer()
	raw := &memoryBudget{limit: 1 << 20}
	output := &memoryBudget{limit: 1 << 20}
	charge := &resultCharge{budget: raw}
	if e := holdRankResult(evaluationInput{resultCharge: charge}, m, a); e != nil {
		t.Fatal(e)
	}
	bytes := rankAuditBacking(a)
	if raw.used != bytes || charge.admit(1, output) == nil || raw.used != bytes || output.used != 0 {
		t.Fatal("current witness left raw before cleanup")
	}
	charge.cleaned()
	if charge.admit(1, output) != nil || raw.used != 0 || output.used != bytes {
		t.Fatal("exact ownership handoff failed")
	}
	if charge.admit(1, output) == nil || output.used != bytes {
		t.Fatal("repeat handoff accepted")
	}
}

func TestDiscardedWitnessStaysHeldUntilDefinitiveCleanup(t *testing.T) {
	_, a := releasedRankKnownAnswer()
	raw := &memoryBudget{limit: 1 << 20}
	charge := &resultCharge{budget: raw}
	if charge.hold(rankAuditBacking(a)) != nil {
		t.Fatal("hold")
	}
	backing := a.Groups[0]
	wipeRankAudit(&a)
	for _, v := range backing {
		if v != (RankBucket{}) {
			t.Fatal("rank backing not wiped")
		}
	}
	charge.discard()
	if raw.used == 0 {
		t.Fatal("unreaped ownership released")
	}
	charge.cleaned()
	if raw.used != 0 {
		t.Fatal("raw charge survived final cleanup")
	}
}
