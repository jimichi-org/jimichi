package nodeview

import (
	"math"
	"slices"
	"unsafe"
)

type constructionMark struct {
	ordinal uint32
	records int
}
type setupIdentity struct {
	circuit uint64
	roster  uint8
}
type setupOwnership struct {
	side     uint16
	group    uint32
	hop      uint8
	complete bool
}
type setupOwnerEntry struct {
	id    setupIdentity
	owner setupOwnership
}
type setupOwnershipIndex []setupOwnerEntry

func compareSetupIdentity(a, b setupIdentity) int {
	if a.circuit < b.circuit {
		return -1
	}
	if a.circuit > b.circuit {
		return 1
	}
	if a.roster < b.roster {
		return -1
	}
	if a.roster > b.roster {
		return 1
	}
	return 0
}
func (owners setupOwnershipIndex) find(id setupIdentity) (int, bool) {
	return slices.BinarySearchFunc(owners, id, func(entry setupOwnerEntry, id setupIdentity) int { return compareSetupIdentity(entry.id, id) })
}
func (owners setupOwnershipIndex) lookup(id setupIdentity) (setupOwnership, bool) {
	i, ok := owners.find(id)
	if !ok {
		return setupOwnership{}, false
	}
	return owners[i].owner, true
}

type setupGrammar struct {
	ordinal     uint32
	next        uint8
	has         bool
	members     [3]setupIdentity
	memberCount int
}

func (p *privateCapture) constructionMark() constructionMark {
	p.mu.Lock()
	defer p.mu.Unlock()
	return constructionMark{p.generation, len(p.truth.setups)}
}
func (p *privateCapture) completedSince(mark constructionMark) (uint32, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != ReasonNone {
		return 0, 0, fail(p.err)
	}
	if mark.ordinal == math.MaxUint32 || p.generation != mark.ordinal+1 || p.completeGeneration != p.generation || p.nextSetupHop != 255 || len(p.truth.setups) != mark.records+3 {
		return 0, 0, fail(ReasonLabel)
	}
	for i, want := range []uint8{2, 1, 0} {
		if p.truth.setups[mark.records+i].hop != want {
			return 0, 0, fail(ReasonLabel)
		}
	}
	return p.generation, p.truth.setups[len(p.truth.setups)-1].circuit, nil
}

func parseSetupOwnership(setups []actualSetup, budgets ...*memoryBudget) (setupOwnershipIndex, error) {
	var budget *memoryBudget
	if len(budgets) > 0 {
		budget = budgets[0]
	}
	if e := budget.checkAllocation(uint64(len(setups)) * uint64(unsafe.Sizeof(setupOwnerEntry{}))); e != nil {
		return nil, e
	}
	owners := make(setupOwnershipIndex, len(setups))
	if err := parseSetupOwnershipInto(setups, owners, budget); err != nil {
		return nil, err
	}
	return owners, nil
}

func parseSetupOwnershipInto(setups []actualSetup, owners setupOwnershipIndex, budgets ...*memoryBudget) (resultErr error) {
	defer func() {
		if resultErr != nil {
			clear(owners[:cap(owners)])
		}
	}()
	if len(owners) != len(setups) {
		return fail(ReasonLabel)
	}
	var budget *memoryBudget
	if len(budgets) > 0 {
		budget = budgets[0]
	}
	if e := budget.checkAllocation(uint64(len(setups)) * 9); e != nil {
		return e
	}
	var states [maxClients]setupGrammar
	circuits := make([]uint64, len(setups))
	seen := make([]bool, len(setups))
	defer clear(seen)
	for i, s := range setups {
		circuits[i] = s.circuit
		owners[i].id = setupIdentity{s.circuit, s.roster}
		owners[i].owner = setupOwnership{}
	}
	slices.Sort(circuits)
	slices.SortFunc(owners, func(a, b setupOwnerEntry) int { return compareSetupIdentity(a.id, b.id) })
	defer func() {
		clear(states[:])
		clear(circuits)
	}()
	for _, s := range setups {
		ci, _ := slices.BinarySearch(circuits, s.circuit)
		if s.hop >= 3 || s.roster >= 5 || s.side >= maxClients || seen[ci] {
			return fail(ReasonLabel)
		}
		seen[ci] = true
		state := states[s.side]
		if s.hop == 2 {
			if state.ordinal == math.MaxUint32 {
				return fail(ReasonLimit)
			}
			state.ordinal++
			state.next = 1
			state.has = true
			clear(state.members[:])
			state.memberCount = 0
		} else {
			if !state.has || s.hop != state.next {
				return fail(ReasonLabel)
			}
			if s.hop == 1 {
				state.next = 0
			} else {
				state.next = 255
			}
		}
		identity := setupIdentity{s.circuit, s.roster}
		oi, _ := owners.find(identity)
		owners[oi].owner = setupOwnership{s.side, state.ordinal, s.hop, false}
		if state.memberCount == len(state.members) {
			return fail(ReasonLabel)
		}
		state.members[state.memberCount] = identity
		state.memberCount++
		if s.hop == 0 {
			if state.memberCount != 3 {
				return fail(ReasonLabel)
			}
			for _, id := range state.members {
				i, _ := owners.find(id)
				owners[i].owner.complete = true
			}
		}
		states[s.side] = state
		state = setupGrammar{}
	}
	return nil
}

func ownerOf(t privateTruth, circuit uint64, position uint8) (setupOwnership, bool) {
	owners := t.ownership
	if owners == nil {
		var e error
		owners, e = parseSetupOwnership(t.setups, t.budget)
		if e != nil {
			return setupOwnership{}, false
		}
		defer clear(owners)
	}
	o, ok := owners.lookup(setupIdentity{circuit, position})
	return o, ok && o.complete
}
