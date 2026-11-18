package nodeview

import "testing"

func TestCohortTruthCapIsAtomicAcrossChildren(t *testing.T) {
	b := &memoryBudget{limit: 64 << 20}
	dst := privateTruth{budget: b, seals: make([]actualSeal, maxTruthRecords)}
	src := privateTruth{messages: []actualMessage{{side: 1}}, seals: []actualSeal{{side: 1}}}
	before := b.used
	if e := mergeTruth(&dst, src); e == nil || len(dst.messages) != 0 || len(dst.seals) != maxTruthRecords || b.used != before {
		t.Fatal("cohort overflow partially merged or allocated")
	}
}

func TestCohortTruthCapAcrossThirtyTwoChildren(t *testing.T) {
	dst := privateTruth{budget: &memoryBudget{limit: 64 << 20}}
	for side := range 32 {
		src := privateTruth{seals: make([]actualSeal, 1024)}
		for i := range src.seals {
			src.seals[i].side = uint16(side)
			src.seals[i].record = arenaRef{side*1024 + i, 1}
		}
		if e := mergeTruth(&dst, src); e != nil {
			t.Fatal(e)
		}
	}
	if len(dst.seals) != 32768 {
		t.Fatal("exact cohort cap not retained")
	}
	if e := mergeTruth(&dst, privateTruth{seals: []actualSeal{{side: 31}}}); e == nil || len(dst.seals) != 32768 {
		t.Fatal("next distinct seal admitted")
	}
	dst.wipeMetadata()
}

func TestStickyRequestCopiesDoNotConsumeDistinctSealCap(t *testing.T) {
	dst := privateTruth{seals: make([]actualSeal, maxTruthRecords)}
	if e := mergeTruth(&dst, privateTruth{requests: []actualRequest{{record: arenaRef{1, 392}}, {record: arenaRef{1, 392}}}}); e != nil || len(dst.seals) != maxTruthRecords || len(dst.requests) != 2 {
		t.Fatal("sticky copies changed original seal inventory")
	}
}
