package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrChoice = errors.New("client: no such choice of nodes")

// Choose draws the path of a circuit as indices into a list of n nodes: the
// entry first, then the other hops in order, no node twice. Every ordered path
// is equally likely when rnd is uniform
func Choose(n, hops int, rnd io.Reader) ([]int, error) {
	if hops < 1 || hops > n {
		return nil, fmt.Errorf("%w: %d hops among %d nodes", ErrChoice, hops, n)
	}
	entry, err := ChooseEntry(n, rnd)
	if err != nil {
		return nil, err
	}
	return ChooseRest(entry, n, hops, rnd)
}

func ChooseEntry(n int, rnd io.Reader) (int, error) {
	if n < 1 {
		return 0, fmt.Errorf("%w: %d nodes", ErrChoice, n)
	}
	return below(rnd, n)
}

// the path that starts at entry: the other hops are drawn among the n-1 other
// nodes without replacement, by the first steps of a Fisher-Yates shuffle
func ChooseRest(entry, n, hops int, rnd io.Reader) ([]int, error) {
	if hops < 1 || hops > n || entry < 0 || entry >= n {
		return nil, fmt.Errorf("%w: %d hops among %d nodes", ErrChoice, hops, n)
	}
	others := make([]int, 0, n-1)
	for i := 0; i < n; i++ {
		if i != entry {
			others = append(others, i)
		}
	}
	path := make([]int, 1, hops)
	path[0] = entry
	for i := 0; i < hops-1; i++ {
		j, err := below(rnd, len(others)-i)
		if err != nil {
			return nil, err
		}
		others[i], others[i+j] = others[i+j], others[i]
		path = append(path, others[i])
	}
	return path, nil
}

// the entry of a chain whose exit is fixed: each of the other n-1 nodes with
// the same chance
func ChooseEntryExcept(n, except int, rnd io.Reader) (int, error) {
	if n < 2 || except < 0 || except >= n {
		return 0, fmt.Errorf("%w: an entry among %d nodes other than node %d", ErrChoice, n, except)
	}
	j, err := below(rnd, n-1)
	if err != nil {
		return 0, err
	}
	if j >= except {
		j++
	}
	return j, nil
}

// the path from entry to a fixed exit: the middle hops are drawn among the
// n-2 other nodes the way ChooseRest draws them, and exit comes last
func ChooseRestTo(entry, exit, n, hops int, rnd io.Reader) ([]int, error) {
	if hops < 2 || hops > n || entry < 0 || entry >= n || exit < 0 || exit >= n || entry == exit {
		return nil, fmt.Errorf("%w: %d hops among %d nodes from node %d to node %d", ErrChoice, hops, n, entry, exit)
	}
	others := make([]int, 0, n-2)
	for i := 0; i < n; i++ {
		if i != entry && i != exit {
			others = append(others, i)
		}
	}
	path := make([]int, 1, hops)
	path[0] = entry
	for i := 0; i < hops-2; i++ {
		j, err := below(rnd, len(others)-i)
		if err != nil {
			return nil, err
		}
		others[i], others[i+j] = others[i+j], others[i]
		path = append(path, others[i])
	}
	return append(path, exit), nil
}

// how many of the n listed nodes the mirror of an entry may lack for a chain
// of hops nodes: at most missing, and never so many that fewer than hops stay
func MaxAbsent(n, hops, missing int) int {
	return min(missing, n-hops)
}

// what a client that draws its chain makes of the mirror of the entry it drew
type MirrorVerdict int

const (
	MirrorTaken MirrorVerdict = iota
	// the mirror does not hold the entry that served it
	MirrorLacksEntry
	// the mirror lacks more listed nodes than MaxAbsent allows
	MirrorLacksTooMany
	// the mirror passes JudgeMirror but holds no exit a chain can end on: the
	// fixed exit is left out, outside the list or the entry itself
	MirrorLacksExit
)

// JudgeMirror is the rule by which a client that draws its chain takes or
// refuses the mirror of its entry; served[i] says whether the mirror holds
// listed node i. absent and allowed are the two numbers the rule compares
func JudgeMirror(served []bool, entry, hops, missing int) (verdict MirrorVerdict, absent, allowed int) {
	for _, held := range served {
		if !held {
			absent++
		}
	}
	allowed = MaxAbsent(len(served), hops, missing)
	switch {
	case entry < 0 || entry >= len(served) || !served[entry]:
		return MirrorLacksEntry, absent, allowed
	case absent > allowed:
		return MirrorLacksTooMany, absent, allowed
	}
	return MirrorTaken, absent, allowed
}

// JudgeMirrorTo is JudgeMirror for a chain whose exit is fixed: a mirror it
// takes is still refused when served[exit] is false or the exit is the entry,
// for which ChooseRestTo draws no chain
func JudgeMirrorTo(served []bool, entry, exit, hops, missing int) (verdict MirrorVerdict, absent, allowed int) {
	verdict, absent, allowed = JudgeMirror(served, entry, hops, missing)
	if verdict == MirrorTaken && (exit < 0 || exit >= len(served) || exit == entry || !served[exit]) {
		verdict = MirrorLacksExit
	}
	return verdict, absent, allowed
}

// a 64-bit value reduced modulo m favours the low remainders unless the first
// 2^64 mod m values are thrown away, which leaves a whole number of cycles
func below(rnd io.Reader, m int) (int, error) {
	bound := uint64(m)
	reject := -bound % bound
	var b [8]byte
	// a draw is rejected with probability below m/2^64, so a uniform source
	// never comes near this many; a stuck one must not hold the client forever
	for range maxDraws {
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return 0, fmt.Errorf("client: random choice: %w", err)
		}
		if v := binary.BigEndian.Uint64(b[:]); v >= reject {
			return int(v % bound), nil
		}
	}
	return 0, fmt.Errorf("%w: the random source gave no usable value in %d draws", ErrChoice, maxDraws)
}

const maxDraws = 128
