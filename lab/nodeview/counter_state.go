package nodeview

import (
	"slices"
	"sync"
	"unsafe"
)

type counterPrevious struct {
	input, output, shift                     uint64
	hasInput, hasOutput, hasShift, firstSeen bool
}
type counterScratch struct {
	keys   []uint64
	states []counterPrevious
}

func makeCounterScratch(cells []cellView, budget *memoryBudget) (*counterScratch, func(), error) {
	n := 0
	for _, v := range cells {
		if v.hop != 0 && v.kind == 1 {
			n++
		}
	}
	keyLease, e := scratchReservation(budget, uint64(n)*8)
	if e != nil {
		return nil, nil, e
	}
	keys := make([]uint64, 0, n)
	for _, v := range cells {
		if v.hop != 0 && v.kind == 1 {
			keys = append(keys, uint64(v.hop)<<1|uint64(v.dir))
		}
	}
	slices.Sort(keys)
	n = 0
	for _, key := range keys {
		if n == 0 || keys[n-1] != key {
			keys[n] = key
			n++
		}
	}
	clear(keys[n:])
	keys = keys[:n]
	stateLease, e := scratchReservation(budget, uint64(n)*uint64(unsafe.Sizeof(counterPrevious{})))
	if e != nil {
		clear(keys[:cap(keys)])
		keys = nil
		keyLease()
		return nil, nil, e
	}
	scratch := &counterScratch{keys: keys, states: make([]counterPrevious, n)}
	var once sync.Once
	release := func() {
		once.Do(func() {
			clear(scratch.keys[:cap(scratch.keys)])
			clear(scratch.states[:cap(scratch.states)])
			scratch.keys = nil
			scratch.states = nil
			stateLease()
			keyLease()
		})
	}
	return scratch, release, nil
}
