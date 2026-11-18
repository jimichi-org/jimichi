package nodeview

import (
	"slices"
	"sync"
	"unsafe"
)

type fragmentSourceEntry struct {
	ref      arenaRef
	position uint8
}
type fragmentSourceIndex []fragmentSourceEntry
type fragmentSourceGroup struct {
	position  uint8
	fragments []contentFragment
}

func compareFragmentRef(a, b arenaRef) int {
	if a.offset < b.offset {
		return -1
	}
	if a.offset > b.offset {
		return 1
	}
	if a.size < b.size {
		return -1
	}
	if a.size > b.size {
		return 1
	}
	return 0
}

func (index fragmentSourceIndex) lookup(ref arenaRef) (uint8, bool) {
	i, found := slices.BinarySearchFunc(index, ref, func(entry fragmentSourceEntry, ref arenaRef) int { return compareFragmentRef(entry.ref, ref) })
	if !found {
		return 0, false
	}
	return index[i].position, true
}

func buildFragmentSourceIndex(groups []fragmentSourceGroup, budget *memoryBudget) (fragmentSourceIndex, func(), error) {
	n := 0
	for _, group := range groups {
		if group.position >= 5 || len(group.fragments) > maxSelectedCells-n {
			return nil, nil, fail(ReasonContract)
		}
		n += len(group.fragments)
	}
	lease, err := scratchReservation(budget, uint64(n)*uint64(unsafe.Sizeof(fragmentSourceEntry{})))
	if err != nil {
		return nil, nil, err
	}
	entries := make(fragmentSourceIndex, 0, n)
	var once sync.Once
	release := func() { once.Do(func() { clear(entries[:cap(entries)]); entries = nil; lease() }) }
	for _, group := range groups {
		for _, fragment := range group.fragments {
			entries = append(entries, fragmentSourceEntry{fragment.data, group.position})
		}
	}
	slices.SortFunc(entries, func(a, b fragmentSourceEntry) int { return compareFragmentRef(a.ref, b.ref) })
	kept := 0
	for _, entry := range entries {
		if kept > 0 && entries[kept-1].ref == entry.ref {
			if entries[kept-1].position != entry.position {
				release()
				return nil, nil, fail(ReasonContract)
			}
			continue
		}
		entries[kept] = entry
		kept++
	}
	clear(entries[kept:])
	entries = entries[:kept]
	return entries, release, nil
}
