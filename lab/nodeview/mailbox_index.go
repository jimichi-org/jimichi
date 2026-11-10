package nodeview

import (
	"cmp"
	"slices"
	"unsafe"
)

type mailboxFetchKey struct {
	queue, circuit uint32
}

type mailboxFetchEntry struct {
	key                      mailboxFetchKey
	latest, previous         int64
	hasPrevious, initialized bool
}

type mailboxFetchIndex []mailboxFetchEntry

func newPreparedMailboxExtractor(periodNS int64, observations []mailboxObservation, budget *memoryBudget) (*mailboxExtractor, error) {
	fetches, err := makeMailboxFetchIndex(observations, budget)
	if err != nil {
		return nil, err
	}
	// go1.27 map hint128 uses 10880 group bytes plus 48+32+8 header bytes
	const circuitMapBytes = 10968
	if err := budget.checkAllocation(circuitMapBytes + uint64(unsafe.Sizeof(mailboxExtractor{}))); err != nil {
		fetches.wipe()
		return nil, err
	}
	x := newMailboxExtractor(periodNS)
	x.fetches, x.prepared = fetches, true
	return x, nil
}

func compareMailboxFetchKey(a, b mailboxFetchKey) int {
	if c := cmp.Compare(a.queue, b.queue); c != 0 {
		return c
	}
	return cmp.Compare(a.circuit, b.circuit)
}

func makeMailboxFetchIndex(observations []mailboxObservation, budget *memoryBudget) (mailboxFetchIndex, error) {
	if len(observations) > 65536 {
		return nil, errMailboxLimit
	}
	if err := budget.checkAllocation(uint64(len(observations)) * uint64(unsafe.Sizeof(mailboxFetchEntry{}))); err != nil {
		return nil, err
	}
	index := make(mailboxFetchIndex, len(observations))
	for i, o := range observations {
		index[i].key = mailboxFetchKey{o.FetchQueue, o.Circuit}
	}
	slices.SortFunc(index, func(a, b mailboxFetchEntry) int {
		return compareMailboxFetchKey(a.key, b.key)
	})
	unique := 0
	for i := range index {
		if unique == 0 || index[i].key != index[unique-1].key {
			index[unique] = index[i]
			unique++
		}
	}
	clear(index[unique:])
	return index[:unique], nil
}

func (m mailboxFetchIndex) find(key mailboxFetchKey) (int, bool) {
	return slices.BinarySearchFunc(m, key, func(entry mailboxFetchEntry, key mailboxFetchKey) int {
		return compareMailboxFetchKey(entry.key, key)
	})
}

func (m mailboxFetchIndex) latestOther(queue, circuit uint32, when int64) int64 {
	start, _ := m.find(mailboxFetchKey{queue: queue})
	latest := int64(-1)
	for _, fetch := range m[start:] {
		if fetch.key.queue != queue {
			break
		}
		if !fetch.initialized || fetch.key.circuit == circuit {
			continue
		}
		t := fetch.latest
		if t == when && fetch.hasPrevious {
			t = fetch.previous
		}
		if t < when && t > latest {
			latest = t
		}
	}
	return latest
}

func (m mailboxFetchIndex) insert(key mailboxFetchKey) (mailboxFetchIndex, int) {
	at, found := m.find(key)
	if found {
		return m, at
	}
	next := make(mailboxFetchIndex, len(m)+1)
	copy(next, m[:at])
	next[at].key = key
	copy(next[at+1:], m[at:])
	m.wipe()
	return next, at
}

func (m mailboxFetchIndex) wipe() {
	clear(m[:cap(m)])
}
