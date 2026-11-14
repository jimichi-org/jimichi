//go:build linux && amd64

package nodeview

import (
	"bytes"
	"testing"
)

func TestProtectedBudgetedArenaGrowthKeepsLockedBacking(t *testing.T) {
	budget := &memoryBudget{limit: 8192}
	a, err := newBudgetedArena(8192, 4096, budget)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	if budget.used != 4096 || a.allocated != 4096 || !a.chunks[0].Locked() || a.chunks[1] != nil {
		t.Fatal("uncommitted capacity was allocated or charged")
	}
	r1, ok := a.copy(bytes.Repeat([]byte{11}, 4090))
	if !ok {
		t.Fatal("initial chunk copy failed")
	}
	borrowed := a.bytes(r1)
	r2, ok := a.copy(bytes.Repeat([]byte{12}, 16))
	if !ok || r2.offset != 4096 || a.allocated != 8192 || budget.used != 8192 || budget.high != 8192 || !a.chunks[1].Locked() || !bytes.Equal(borrowed, bytes.Repeat([]byte{11}, 4090)) {
		t.Fatal("second chunk violated locking, stable references or reservation")
	}
	a.erase(&r1)
	if !bytes.Equal(borrowed, make([]byte, 4090)) {
		t.Fatal("owned locked contents were not erased")
	}
	a.erase(&r2)
	a.close()
	if budget.used != 0 {
		t.Fatal("committed locked backing was not released")
	}
}
