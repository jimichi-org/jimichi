package nodeview

import (
	"reflect"
	"testing"
	"unsafe"
)

func TestFragmentSourceExactLeaseAndLastConsumerWipe(t *testing.T) {
	if unsafe.Sizeof(fragmentSourceEntry{}) != 24 {
		t.Fatal("unexpected amd64 source-entry layout")
	}
	first, second := arenaRef{24, 8}, arenaRef{8, 4}
	groups := []fragmentSourceGroup{{2, []contentFragment{{data: first}, {data: second}, {data: first}}}}
	budget := &memoryBudget{limit: 72}
	index, release, err := buildFragmentSourceIndex(groups, budget)
	if err != nil || len(index) != 2 || cap(index) != 3 || budget.used != 72 {
		t.Fatal("source index shrank charge before last use")
	}
	backing := index[:cap(index)]
	if position, ok := index.lookup(first); !ok || position != 2 {
		t.Fatal("private lookup changed source association")
	}
	if _, ok := index.lookup(arenaRef{24, 9}); ok {
		t.Fatal("different source extent matched")
	}
	release()
	release()
	if budget.used != 0 || !reflect.DeepEqual(backing, make(fragmentSourceIndex, len(backing))) || groups[0].fragments[0].data != first {
		t.Fatal("source lease leaked or wiped borrowed references")
	}
}

func TestFragmentSourceAdmissionAndConflictAreTransactional(t *testing.T) {
	ref := arenaRef{1, 128}
	groups := []fragmentSourceGroup{{0, []contentFragment{{data: ref}}}, {4, []contentFragment{{data: ref}}}}
	for _, kind := range []string{"raw-limit", "host-limit", "conflict"} {
		budget := &memoryBudget{used: 17, limit: 1000}
		if kind == "raw-limit" {
			budget.limit = 17 + 48 - 1
		}
		if kind == "host-limit" {
			budget.beforeAllocation = func(uint64) error { return fail(ReasonLimit) }
		}
		index, release, err := buildFragmentSourceIndex(groups, budget)
		if err == nil || index != nil || release != nil || budget.used != 17 || groups[0].fragments[0].data != ref || groups[1].fragments[0].data != ref {
			t.Fatal("rejected source index partially committed or released prior storage")
		}
	}
}
