package nodeview

import "github.com/jimichi-org/jimichi/crypto/secmem"

type arenaRef struct{ offset, size int }
type freeSpan struct{ offset, size int }

type lockedArena struct {
	buffer           *secmem.Buffer
	used, live, high int
	free             []freeSpan
	chunks           [8]*secmem.Buffer
	maximum, chunk   int
	allocated        int
	budget           *memoryBudget
}

func newArena(size int) (*lockedArena, error) {
	b, err := secmem.New(size)
	if err != nil {
		return nil, fail(ReasonUnsupported)
	}
	if !b.Locked() {
		b.Release()
		return nil, fail(ReasonUnsupported)
	}
	return &lockedArena{buffer: b, free: make([]freeSpan, 0, 1024)}, nil
}

func newBudgetedArena(maximum, chunk int, budget *memoryBudget) (*lockedArena, error) {
	if maximum <= 0 || chunk <= 0 || chunk > maximum || (maximum-1)/chunk >= 8 || budget == nil {
		return nil, ErrInvalid
	}
	a := &lockedArena{maximum: maximum, chunk: chunk, budget: budget, free: make([]freeSpan, 0, 1024)}
	if err := a.grow(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *lockedArena) grow() error {
	if a.maximum == 0 || a.allocated >= a.maximum {
		return attachBound(fail(ReasonLimit), boundDetail{boundArenaGrowth, boundBytes, uint64(a.allocated), uint64(a.chunk), uint64(a.maximum), uint64(a.allocated)})
	}
	size := min(a.chunk, a.maximum-a.allocated)
	if err := a.budget.reserve(uint64(size)); err != nil {
		return err
	}
	if err := a.budget.checkAllocation(uint64(size)); err != nil {
		a.budget.release(uint64(size))
		return err
	}
	b, err := secmem.New(size)
	if err != nil || !b.Locked() {
		if b != nil {
			b.Release()
		}
		a.budget.release(uint64(size))
		return attachBound(fail(ReasonUnsupported), boundDetail{boundArenaGrowth, boundBytes, uint64(a.allocated), uint64(size), uint64(a.maximum), uint64(a.allocated)})
	}
	a.chunks[a.allocated/a.chunk] = b
	a.allocated += size
	if a.buffer == nil {
		a.buffer = b
	}
	return nil
}

func (a *lockedArena) copy(b []byte) (arenaRef, bool) {
	r, e := a.copyChecked(b)
	return r, e == nil
}

func (a *lockedArena) copyChecked(b []byte) (arenaRef, error) {
	if len(b) == 0 {
		return arenaRef{}, nil
	}
	if a.buffer == nil {
		return arenaRef{}, attachBound(fail(ReasonLimit), boundDetail{origin: boundArenaUnavailable, unit: boundBytes, need: uint64(len(b))})
	}
	for i, s := range a.free {
		if s.size >= len(b) {
			r := arenaRef{s.offset, len(b)}
			a.free[i].offset += len(b)
			a.free[i].size -= len(b)
			if a.free[i].size == 0 {
				a.free = append(a.free[:i], a.free[i+1:]...)
			}
			copy(a.bytes(r), b)
			a.live += len(b)
			a.high = max(a.high, a.used)
			return r, nil
		}
	}
	offset := a.used
	if a.maximum == 0 {
		if len(b) > a.buffer.Len()-offset {
			return arenaRef{}, attachBound(fail(ReasonLimit), boundDetail{boundArenaSpace, boundBytes, uint64(a.used), uint64(len(b)), uint64(a.buffer.Len()), uint64(a.high)})
		}
	} else {
		if len(b) > a.chunk {
			return arenaRef{}, attachBound(fail(ReasonLimit), boundDetail{origin: boundArenaRecord, unit: boundBytes, need: uint64(len(b)), limit: uint64(a.chunk)})
		}
		if offset > a.maximum-len(b) {
			return arenaRef{}, attachBound(fail(ReasonLimit), boundDetail{boundArenaSpace, boundBytes, uint64(a.used), uint64(len(b)), uint64(a.maximum), uint64(a.high)})
		}
		remaining := a.chunk - offset%a.chunk
		if len(b) > remaining {
			offset += remaining
		}
		if offset > a.maximum-len(b) {
			return arenaRef{}, attachBound(fail(ReasonLimit), boundDetail{boundArenaSpace, boundBytes, uint64(a.used), uint64(offset - a.used + len(b)), uint64(a.maximum), uint64(a.high)})
		}
		if offset+len(b) > a.allocated {
			if err := a.grow(); err != nil {
				return arenaRef{}, attachBound(err, boundDetail{boundArenaGrowth, boundBytes, uint64(a.allocated), uint64(min(a.chunk, a.maximum-a.allocated)), uint64(a.maximum), uint64(a.allocated)})
			}
		}
		if offset > a.used {
			a.free = append(a.free, freeSpan{a.used, offset - a.used})
		}
	}
	r := arenaRef{offset, len(b)}
	a.used = offset + len(b)
	a.live += len(b)
	a.high = max(a.high, a.used)
	copy(a.bytes(r), b)
	return r, nil
}

func (a *lockedArena) valid(r arenaRef) bool {
	if a == nil || a.buffer == nil || r.offset < 0 || r.size <= 0 || r.offset > a.used || r.size > a.used-r.offset {
		return false
	}
	if a.maximum == 0 {
		return a.used <= a.buffer.Len()
	}
	i, offset := r.offset/a.chunk, r.offset%a.chunk
	if i >= len(a.chunks) || a.chunks[i] == nil || a.used > a.maximum {
		return false
	}
	return offset <= a.chunks[i].Len() && r.size <= a.chunks[i].Len()-offset
}

func (a *lockedArena) bytes(r arenaRef) []byte {
	if r.size == 0 {
		return nil
	}
	if !a.valid(r) {
		panic(ErrInvalid)
	}
	if a.maximum == 0 {
		return a.buffer.Bytes()[r.offset : r.offset+r.size]
	}
	offset := r.offset % a.chunk
	return a.chunks[r.offset/a.chunk].Bytes()[offset : offset+r.size]
}

func (a *lockedArena) erase(r *arenaRef) {
	if r.size == 0 {
		return
	}
	secmem.Zero(a.bytes(*r))
	a.live -= r.size
	span := freeSpan{r.offset, r.size}
	for i := 0; i < len(a.free); {
		other := a.free[i]
		if a.maximum != 0 && other.offset/a.chunk != span.offset/a.chunk {
			i++
			continue
		}
		if other.offset+other.size == span.offset {
			span.offset = other.offset
			span.size += other.size
		} else if span.offset+span.size == other.offset {
			span.size += other.size
		} else {
			i++
			continue
		}
		a.free = append(a.free[:i], a.free[i+1:]...)
		i = 0
	}
	a.free = append(a.free, span)
	*r = arenaRef{}
}

func (a *lockedArena) close() {
	if a.maximum == 0 {
		if a.buffer != nil {
			a.buffer.Release()
		}
	} else {
		for i, b := range a.chunks {
			if b != nil {
				b.Release()
				a.chunks[i] = nil
			}
		}
		a.budget.release(uint64(a.allocated))
		a.allocated = 0
	}
	a.buffer = nil
	clear(a.free[:cap(a.free)])
	a.free = nil
}
