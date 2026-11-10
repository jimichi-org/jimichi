package nodeview

import (
	"bytes"
	"testing"
)

func TestBudgetedArenaUnlockFailureRollsBackReservation(t *testing.T) {
	budget := &memoryBudget{limit: 64}
	if a, err := newBudgetedArena(64, 32, budget); reasonOf(err) != ReasonUnsupported || a != nil || budget.used != 0 || budget.high != 32 {
		t.Fatal("unlocked allocation was accepted or retained its charge")
	}
}

func TestBudgetedArenaSecondChunkLockFailureKeepsFirst(t *testing.T) {
	budget := &memoryBudget{limit: 64, used: 32, high: 32}
	a := logicalChunkArena(t, 64, 32, 32, budget)
	r, ok := a.copy(bytes.Repeat([]byte{23}, 28))
	if !ok {
		t.Fatal("initial logical copy failed")
	}
	borrowed := a.bytes(r)
	if _, ok := a.copy(make([]byte, 8)); ok || a.used != 28 || a.live != 28 || a.high != 28 || a.allocated != 32 || a.chunks[1] != nil || budget.used != 32 || budget.high != 64 || len(a.free) != 0 {
		t.Fatal("second lock failure retained backing, padding or reservation")
	}
	if !a.valid(r) || !bytes.Equal(borrowed, bytes.Repeat([]byte{23}, 28)) {
		t.Fatal("failed second allocation changed live first-chunk data")
	}
}
