package nodeview

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestBoundEvidenceCanonicalScalarCopiesAndReasonCarry(t *testing.T) {
	if unsafe.Sizeof(boundDetail{}) != 40 || unsafe.Sizeof(boundedFailure{}) != 56 {
		t.Fatal("bound control layout changed")
	}
	d := boundDetail{boundBudget, boundBytes, 10, 1, 10, 12}
	err := attachBound(fail(ReasonLimit), d)
	d.have = 0
	d.limit = 99
	want := boundDetail{boundBudget, boundBytes, 10, 1, 10, 12}
	if got, ok := boundEvidence(err); !ok || got != want || err.Error() != fail(ReasonLimit).Error() {
		t.Fatal("guard evidence retained a mutable source or changed its error")
	}
	var underlying failure
	if !errors.As(err, &underlying) || underlying.reason != ReasonLimit {
		t.Fatal("opaque error did not unwrap only its canonical failure")
	}
	merged := mergeRuntimeFailure(fail(ReasonIPC), err)
	merged = carryBoundReason(merged, ReasonIPC)
	if got, ok := boundEvidence(merged); !ok || got != want || reasonOf(merged) != ReasonIPC || merged.Error() != fail(ReasonIPC).Error() {
		t.Fatal("IPC priority discarded a valid guard example")
	}
	other := recordBound(boundViewCells, 20, 1, 20)
	if got, _ := boundEvidence(mergeRuntimeFailure(merged, other)); got != want {
		t.Fatal("later context replaced the first valid example")
	}
	if got, _ := boundEvidence(attachBound(err, boundDetail{boundArenaSpace, boundBytes, 16, 1, 16, 16})); got != want {
		t.Fatal("outer context replaced an inner denied guard")
	}
	plain := errors.New("private-unwrapped-sentinel")
	if attachBound(plain, boundDetail{}) != plain || mergeRuntimeFailure(nil, plain) != plain || mergeRuntimeFailure(plain, nil) != plain || carryBoundReason(nil, ReasonNone) != nil {
		t.Fatal("no-evidence or nil semantics changed")
	}
	if _, ok := boundEvidence(fail(ReasonLimit)); ok || formatBoundEvidence(fail(ReasonLimit)) != "bound=unknown" {
		t.Fatal("a child-only or untagged Limit gained guessed evidence")
	}
}

func TestBoundEvidenceRejectsMalformedMetadataAndFormatsWhitelist(t *testing.T) {
	valid := boundDetail{boundBudget, boundBytes, 10, 1, 10, 10}
	for _, bad := range []boundDetail{
		{boundOrigin(255), boundBytes, 10, 1, 10, 10},
		{boundBudget, boundUnit(255), 10, 1, 10, 10},
		{boundBudget, boundRecords, 10, 1, 10, 10},
		{boundViewCells, boundBytes, 10, 1, 10, 10},
		{boundViewCells, boundRecords, 9, 1, 10, 9},
		{boundHostHeadroom, boundBytes, 1, 11, 10, 0},
		{boundHostHeadroom, boundBytes, 0, 11, 10, 1},
	} {
		err := boundedFailure{ReasonLimit, bad}
		if _, ok := boundEvidence(err); ok || formatBoundEvidence(err) != "bound=unknown" || err.Error() != fail(ReasonLimit).Error() {
			t.Fatal("invalid origin/unit/applicability escaped as evidence")
		}
	}
	for _, reason := range []Reason{ReasonNone, Reason("private-bound-sentinel")} {
		err := boundedFailure{reason, valid}
		if _, ok := boundEvidence(err); ok || strings.Contains(err.Error(), "private-bound-sentinel") {
			t.Fatal("invalid carrier reason exposed a free-form string")
		}
	}
	host := attachBound(fail(ReasonLimit), boundDetail{origin: boundHostHeadroom, unit: boundBytes, need: 11, limit: 10})
	text := formatBoundEvidence(host)
	if text != "bound=supported-host-headroom unit=bytes need=11 limit=10" || strings.Contains(text, "have=") || strings.Contains(text, "high=") {
		t.Fatal("host formatting invented inapplicable zero measurements")
	}
	for origin := boundViewConnections; origin <= boundCohortFragments; origin++ {
		err := recordBound(origin, 10, 1, 10)
		if _, ok := boundEvidence(err); !ok || !strings.HasPrefix(formatBoundEvidence(err), "bound=parent-") || strings.Contains(formatBoundEvidence(err), "unknown") {
			t.Fatal("allowed inventory origin was not finitely formatted")
		}
	}
}

func TestBoundBudgetDenialAtomicStateAndExactBoundary(t *testing.T) {
	b := &memoryBudget{used: 7, high: 11, limit: 10}
	if e := b.reserve(3); e != nil {
		t.Fatal("exact budget equality rejected")
	}
	err := b.reserve(1)
	if reasonOf(err) != ReasonLimit || b.used != 10 || b.high != 11 {
		t.Fatal("denial changed budget state")
	}
	want := boundDetail{boundBudget, boundBytes, 10, 1, 10, 11}
	b.mu.Lock()
	b.used, b.high, b.limit = 0, 100, 100
	b.mu.Unlock()
	if d, ok := boundEvidence(err); !ok || d != want {
		t.Fatal("budget evidence was sampled after denial or retained a live budget")
	}
}

func TestBoundCohortInventoriesExactAndOneDeficit(t *testing.T) {
	for kind := byte(1); kind <= 5; kind++ {
		i := cohortInventory{}
		var count *int
		limit := 0
		origin := boundNone
		switch kind {
		case 1:
			count, limit, origin = &i.messages, maxMessages, boundCohortMessages
		case 2:
			count, limit, origin = &i.setups, maxContexts, boundCohortSetups
		case 3:
			count, limit, origin = &i.seals, maxTruthRecords, boundCohortSeals
		case 4:
			count, limit, origin = &i.requests, maxSelectedCells, boundCohortRequests
		case 5:
			count, limit, origin = &i.fragments, maxSelectedCells, boundCohortFragments
		}
		*count = limit - 1
		if e := i.reserveTruth(kind, 1); e != nil || *count != limit {
			t.Fatal("exact cohort inventory rejected")
		}
		err := i.reserveTruth(kind, 1)
		want := boundDetail{origin, boundRecords, uint64(limit), 1, uint64(limit), uint64(limit)}
		if d, ok := boundEvidence(err); !ok || d != want || *count != limit {
			t.Fatal("cohort denial lost its distinct bound or mutated state")
		}
		if e := i.reserveTruth(kind, 0); reasonOf(e) != ReasonIPC {
			t.Fatal("batch grammar became a count-quota failure")
		}
	}
}

func TestBoundArenaCheckedAndLegacyCopiesShareBytesAndFailures(t *testing.T) {
	budget := &memoryBudget{used: 16, high: 16, limit: 16}
	a := logicalChunkArena(t, 16, 8, 16, budget)
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	first, e := a.copyChecked(input)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := a.copy(input); !ok {
		t.Fatal("legacy exact-copy equality rejected")
	}
	_, err := a.copyChecked([]byte{9})
	if d, ok := boundEvidence(err); !ok || d.origin != boundArenaSpace || d.have != 16 || d.need != 1 || d.limit != 16 || reasonOf(err) != ReasonLimit {
		t.Fatal("arena extent denial lacks exact copied evidence")
	}
	if _, ok := a.copy([]byte{9}); ok || !reflect.DeepEqual(a.bytes(first), input) || a.used != 16 || budget.used != 16 {
		t.Fatal("checked/legacy failure changed borrowed bytes or allocation state")
	}
	if r, e := (&lockedArena{}).copyChecked(nil); e != nil || r != (arenaRef{}) {
		t.Fatal("empty-copy behavior changed")
	}
	if _, e := a.copyChecked(make([]byte, 9)); reasonOf(e) != ReasonLimit {
		t.Fatal("record-size failure changed class")
	}
	innerBudget := &memoryBudget{used: 8, high: 8, limit: 8}
	inner := logicalChunkArena(t, 16, 8, 8, innerBudget)
	if _, ok := inner.copy(make([]byte, 8)); !ok {
		t.Fatal("initial logical fill failed")
	}
	_, e = inner.copyChecked([]byte{1})
	if d, ok := boundEvidence(e); !ok || d.origin != boundBudget || d.have != 8 || d.need != 8 || innerBudget.used != 8 || inner.used != 8 {
		t.Fatal("outer arena context replaced the actual budget denial")
	}
}

func TestBoundOpaqueErrorDoesNotRetainWrappedSentinel(t *testing.T) {
	err := attachBound(fmt.Errorf("private-bound-sentinel: %w", fail(ReasonLimit)), boundDetail{boundBudget, boundBytes, 10, 1, 10, 10})
	if err.Error() != fail(ReasonLimit).Error() || strings.Contains(fmt.Sprintf("%#v", err), "private-bound-sentinel") {
		t.Fatal("opaque evidence kept an arbitrary wrapped error")
	}
}
