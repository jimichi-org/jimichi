package nodeview

func declareSourceBody(arena *lockedArena, declared []arenaRef, read func([]byte) (int, error), body *[128]byte) (arenaRef, error) {
	defer clear(body[:])
	if n, e := read(body[:]); e != nil || n != len(body) {
		return arenaRef{}, fail(ReasonChild)
	}
	same := true
	for _, value := range body[1:] {
		if value != body[0] {
			same = false
			break
		}
	}
	if same {
		return arenaRef{}, fail(ReasonLabel)
	}
	for _, ref := range declared {
		if equalBytes(arena.bytes(ref), body[:]) {
			return arenaRef{}, fail(ReasonLabel)
		}
	}
	ref, ok := arena.copy(body[:])
	if !ok {
		return arenaRef{}, fail(ReasonLimit)
	}
	return ref, nil
}
