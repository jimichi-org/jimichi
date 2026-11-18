package nodeview

import (
	"math"
	"slices"
	"testing"
	"unsafe"
)

func TestUint32MembershipPreservesSparseKeysAndEnvelope(t *testing.T) {
	keys := []uint32{math.MaxUint32, 1, 0, 1, math.MaxUint32}
	original := slices.Clone(keys)
	charged := uint64(len(keys)) * 8
	budget := &memoryBudget{used: charged, high: charged, limit: charged + 8}
	var allocations []uint64
	budget.beforeAllocation = func(n uint64) error {
		allocations = append(allocations, n)
		return nil
	}
	var visited []int
	members, err := makeUint32Membership(len(keys), func(i int) uint32 {
		visited = append(visited, i)
		return keys[i]
	}, budget)
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.Sizeof(uint32Member{}) != 8 || cap(members) != len(keys) || !slices.Equal(allocations, []uint64{charged}) || budget.used != charged || budget.high != charged {
		t.Fatal("membership allocation changed its existing envelope or deduplicated capacity charge")
	}
	if !slices.Equal(members, uint32Membership{{key: 0}, {key: 1}, {key: math.MaxUint32}}) || !slices.Equal(visited, []int{0, 1, 2, 3, 4}) || !slices.Equal(keys, original) {
		t.Fatal("membership preparation changed borrowed keys, input traversal or inactive state")
	}
	before := slices.Clone(members)
	if previous, found := members.mark(17); previous || found || !slices.Equal(members, before) {
		t.Fatal("unknown key created or primed membership")
	}
	if previous, found := members.mark(0); previous || !found {
		t.Fatal("zero key lost its first observation")
	}
	if previous, found := members.mark(math.MaxUint32); previous || !found {
		t.Fatal("full-width key lost its first observation")
	}
	if previous, found := members.mark(math.MaxUint32); !previous || !found || members[1].seen {
		t.Fatal("repeat or future-key state differs")
	}
	backing := members[:cap(members)]
	backing[len(members)] = uint32Member{key: 99, seen: true}
	members.wipe()
	for _, member := range backing {
		if member != (uint32Member{}) {
			t.Fatal("membership retained owned backing beyond its last consumer")
		}
	}
	if !slices.Equal(keys, original) || budget.used != charged {
		t.Fatal("membership wipe changed borrowed keys or surrendered the caller's envelope")
	}
}

func TestUint32MembershipRejectsBeforeAllocation(t *testing.T) {
	budget := &memoryBudget{used: 64, high: 64, limit: 64}
	var requested uint64
	budget.beforeAllocation = func(n uint64) error {
		requested = n
		return fail(ReasonClock)
	}
	keyCalls := 0
	members, err := makeUint32Membership(3, func(int) uint32 {
		keyCalls++
		return 1
	}, budget)
	if members != nil || reasonOf(err) != ReasonClock || requested != 24 || keyCalls != 0 || budget.used != 64 || budget.high != 64 {
		t.Fatal("denied membership allocation changed ownership, invoked input or lost its cause")
	}
	requested = 0
	if members, err := makeUint32Membership(0, nil, budget); err != nil || members != nil || requested != 0 {
		t.Fatal("empty membership allocated or read an input")
	}
	for _, n := range []int{-1, math.MaxInt/8 + 1} {
		members, err := makeUint32Membership(n, func(int) uint32 { keyCalls++; return 0 }, budget)
		want := ReasonContract
		if n > 0 {
			want = ReasonLimit
		}
		if members != nil || reasonOf(err) != want || requested != 0 || keyCalls != 0 {
			t.Fatal("invalid membership extent reached allocation or input")
		}
	}
}
