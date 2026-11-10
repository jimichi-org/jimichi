package nodeview

import "testing"

func TestMemoryBudgetChecksBeforeAllocation(t *testing.T) {
	b := &memoryBudget{limit: 32}
	if e := b.reserve(12); e != nil {
		t.Fatal(e)
	}
	if e := b.reserve(20); e != nil {
		t.Fatal(e)
	}
	if b.high != 32 {
		t.Fatal("exact boundary lost")
	}
	if e := b.reserve(1); e == nil || b.used != 32 {
		t.Fatal("overflow allocated or mutated state")
	}
	b.release(20)
	if e := b.reserve(20); e != nil {
		t.Fatal("released reservation not reusable")
	}
}

func TestAppendCapacityChargesTransientBacking(t *testing.T) {
	b := &memoryBudget{limit: 24}
	a, e := appendPrivate([]uint64(nil), 7, b)
	if e != nil {
		t.Fatal(e)
	}
	a, e = appendPrivate(a, 8, b)
	if e != nil || len(a) != 2 || a[0] != 7 || a[1] != 8 || b.high != 24 || b.used != 16 {
		t.Fatal("backing charge incorrect")
	}
	if _, e = appendPrivate(a, 9, b); e == nil {
		t.Fatal("old plus new backing exceeded cap")
	}
}

func TestAllocationHookRejectsGrowthWithoutChangingLiveBacking(t *testing.T) {
	values := []uint64{7, 8}
	b := &memoryBudget{limit: 40, used: 16}
	calls := 0
	b.beforeAllocation = func(n uint64) error {
		calls++
		b.mu.Lock()
		defer b.mu.Unlock()
		if n != 24 || b.used != 40 {
			t.Fatal("hook did not observe the old/new reservation")
		}
		return fail(ReasonLimit)
	}
	next, err := appendPrivate(values, 9, b)
	if reasonOf(err) != ReasonLimit || calls != 1 || b.used != 16 || len(next) != 2 || &next[0] != &values[0] || values[0] != 7 || values[1] != 8 {
		t.Fatal("rejected host admission changed or released live storage")
	}
}

func TestOwnershipReservationDoesNotInvokeAllocationHook(t *testing.T) {
	b := &memoryBudget{limit: 16}
	calls := 0
	b.beforeAllocation = func(uint64) error {
		calls++
		return fail(ReasonLimit)
	}
	if err := b.reserve(16); err != nil || calls != 0 || b.used != 16 {
		t.Fatal("ownership transfer was confused with an allocation")
	}
	if err := b.checkAllocation(0); err != nil || calls != 0 {
		t.Fatal("zero allocation invoked a host probe")
	}
	b.release(16)
}

func TestScratchHostRejectionRollsBackReservation(t *testing.T) {
	b := &memoryBudget{limit: 32, used: 8}
	b.beforeAllocation = func(n uint64) error {
		if n != 24 {
			t.Fatal("wrong prospective scratch cost")
		}
		return fail(ReasonUnsupported)
	}
	if release, err := scratchReservation(b, 24); reasonOf(err) != ReasonUnsupported || release != nil || b.used != 8 {
		t.Fatal("rejected scratch retained its reservation")
	}
}
