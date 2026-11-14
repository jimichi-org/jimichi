package nodeview

import (
	"cmp"
	"math"
	"slices"
	"unsafe"
)

type uint32Member struct {
	key  uint32
	seen bool
}

type uint32Membership []uint32Member

func makeUint32Membership(n int, keyAt func(int) uint32, budget *memoryBudget) (uint32Membership, error) {
	if n < 0 || n > 0 && keyAt == nil {
		return nil, fail(ReasonContract)
	}
	if n == 0 {
		return nil, nil
	}
	const size = int(unsafe.Sizeof(uint32Member{}))
	if n > math.MaxInt/size {
		return nil, fail(ReasonLimit)
	}
	// the caller already holds the working envelope
	if err := budget.checkAllocation(uint64(n) * uint64(size)); err != nil {
		return nil, err
	}
	members := make(uint32Membership, n)
	for i := range members {
		members[i].key = keyAt(i)
	}
	slices.SortFunc(members, func(a, b uint32Member) int {
		return cmp.Compare(a.key, b.key)
	})
	unique := 0
	for i := range members {
		if unique == 0 || members[i].key != members[unique-1].key {
			members[unique] = members[i]
			unique++
		}
	}
	clear(members[unique:])
	return members[:unique], nil
}

func (m uint32Membership) mark(key uint32) (previous, found bool) {
	i, found := slices.BinarySearchFunc(m, key, func(member uint32Member, key uint32) int {
		return cmp.Compare(member.key, key)
	})
	if !found {
		return false, false
	}
	previous = m[i].seen
	m[i].seen = true
	return previous, true
}

func (m uint32Membership) wipe() {
	clear(m[:cap(m)])
}
