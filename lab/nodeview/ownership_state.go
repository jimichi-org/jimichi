package nodeview

import (
	"slices"
	"unsafe"
)

type setupGroupState struct {
	side, group uint32
	bits        uint8
}
type setupGroupStates []setupGroupState

func groupCompare(a, b setupGroupState) int {
	if a.side < b.side {
		return -1
	}
	if a.side > b.side {
		return 1
	}
	if a.group < b.group {
		return -1
	}
	if a.group > b.group {
		return 1
	}
	return 0
}
func makeSetupGroupStates(owners setupOwnershipIndex, b *memoryBudget) (setupGroupStates, error) {
	if e := b.checkAllocation(uint64(len(owners)) * uint64(unsafe.Sizeof(setupGroupState{}))); e != nil {
		return nil, e
	}
	out := make(setupGroupStates, len(owners))
	for i, entry := range owners {
		out[i] = setupGroupState{side: uint32(entry.owner.side), group: entry.owner.group}
	}
	slices.SortFunc(out, groupCompare)
	n := 0
	for _, entry := range out {
		if n == 0 || groupCompare(out[n-1], entry) != 0 {
			out[n] = entry
			n++
		}
	}
	clear(out[n:])
	return out[:n], nil
}
func (states setupGroupStates) add(owner setupOwnership, roster uint8) bool {
	i, ok := slices.BinarySearchFunc(states, setupGroupState{side: uint32(owner.side), group: owner.group}, groupCompare)
	if !ok {
		return false
	}
	bit := uint8(1) << roster
	if states[i].bits&bit != 0 {
		return false
	}
	states[i].bits |= bit
	return true
}

type hopOwnerEntry struct {
	hop        uint32
	ownerIndex int
}
type hopOwnerIndex []hopOwnerEntry

func makeHopOwnerIndex(setups []setupView, b *memoryBudget) (hopOwnerIndex, error) {
	n := 0
	for _, s := range setups {
		if s.hop != 0 {
			n++
		}
	}
	if e := b.checkAllocation(uint64(n) * uint64(unsafe.Sizeof(hopOwnerEntry{}))); e != nil {
		return nil, e
	}
	out := make(hopOwnerIndex, 0, n)
	for _, s := range setups {
		if s.hop != 0 {
			out = append(out, hopOwnerEntry{s.hop, -1})
		}
	}
	slices.SortFunc(out, func(a, b hopOwnerEntry) int {
		if a.hop < b.hop {
			return -1
		}
		if a.hop > b.hop {
			return 1
		}
		return 0
	})
	n = 0
	for _, entry := range out {
		if n == 0 || out[n-1].hop != entry.hop {
			out[n] = entry
			n++
		}
	}
	clear(out[n:])
	return out[:n], nil
}
func (index hopOwnerIndex) find(hop uint32) (int, bool) {
	return slices.BinarySearchFunc(index, hop, func(entry hopOwnerEntry, hop uint32) int {
		if entry.hop < hop {
			return -1
		}
		if entry.hop > hop {
			return 1
		}
		return 0
	})
}
func (index hopOwnerIndex) activate(hop uint32, owner int) bool {
	i, ok := index.find(hop)
	if !ok || index[i].ownerIndex >= 0 {
		return false
	}
	index[i].ownerIndex = owner
	return true
}
func (index hopOwnerIndex) lookup(hop uint32) (int, bool) {
	i, ok := index.find(hop)
	if !ok || index[i].ownerIndex < 0 {
		return 0, false
	}
	return index[i].ownerIndex, true
}
