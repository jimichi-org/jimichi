package metrics

import (
	"bytes"
	"math"
)

// a position named wrong counts as unknown, so a wrong merge of two views
// raises the share only through an occupant both chains share
func RouteRecovered(path, claim []int) (recovered int, share float64) {
	if len(path) == 0 || len(claim) != len(path) {
		return -1, math.NaN()
	}
	for i, id := range path {
		if id < 0 {
			return -1, math.NaN()
		}
		if claim[i] == id {
			recovered++
		}
	}
	return recovered, float64(recovered) / float64(len(path))
}

type ExitChoice int

const (
	DrawnExit ExitChoice = iota
	PinnedHonestExit
	PinnedRogueExit
)

type Recovery struct {
	// Known[j] is the share of chains whose rogue nodes know j of the route positions: hops+1
	// with a drawn exit, hops with a pinned one, which is public and not a position
	Known     []float64
	Mean      float64
	StdDev    float64
	RogueExit float64
	Ends      float64
	Touched   float64
}

// the chain is drawn uniformly from full mirrors and the views of its rogue
// nodes are pooled; a pinned exit is public and not a position; beyond three
// hops a middle does not know its index, so there the model is an upper bound
// on what a position-wise claim can reach
func RecoveryModel(nodes, hops, rogue int, exit ExitChoice) Recovery {
	nan := math.NaN()
	none := Recovery{Mean: nan, StdDev: nan, RogueExit: nan, Ends: nan, Touched: nan}
	if hops < 1 || hops > nodes || rogue < 0 || rogue > nodes {
		return none
	}
	n, k := float64(nodes), float64(rogue)
	pool, kk, drawn, positions := nodes, rogue, hops, hops+1
	var out Recovery
	switch exit {
	case DrawnExit:
		out.RogueExit = k / n
		out.Ends, _ = CompromiseProbability(nodes, hops, rogue)
	case PinnedHonestExit:
		if hops < 2 || rogue == nodes {
			return none
		}
		pool, drawn, positions = nodes-1, hops-1, hops
	case PinnedRogueExit:
		if hops < 2 || rogue == 0 {
			return none
		}
		pool, kk, drawn, positions = nodes-1, rogue-1, hops-1, hops
		out.RogueExit = 1
		out.Ends = (k - 1) / (n - 1)
	default:
		return none
	}
	pinnedRogue := 0
	if exit == PinnedRogueExit {
		pinnedRogue = 1
	}

	// the chance of each state before node t: r rogue nodes drawn so far,
	// whether nodes t-2 and t-1 are rogue, and j of the elements before t-1
	// known; element t-1 is known when node t-2, t-1 or t is rogue
	width := hops + 1
	at := func(r, a, b, j int) int { return ((r*2+a)*2+b)*width + j }
	states := make([]float64, (kk+1)*4*width)
	states[at(0, 0, 0, 0)] = 1
	for t := 1; t <= hops; t++ {
		next := make([]float64, len(states))
		for r := 0; r <= kk; r++ {
			for a := 0; a < 2; a++ {
				for b := 0; b < 2; b++ {
					for j := 0; j < width; j++ {
						p := states[at(r, a, b, j)]
						if p == 0 {
							continue
						}
						move := func(x, rogueDrawn int, weight float64) {
							if weight != 0 {
								next[at(r+rogueDrawn, b, x, j+(a|b|x))] += p * weight
							}
						}
						if t > drawn {
							move(pinnedRogue, 0, 1)
							continue
						}
						left := float64(pool - (t - 1))
						move(1, 1, float64(kk-r)/left)
						move(0, 0, float64(pool-kk-(t-1-r))/left)
					}
				}
			}
		}
		states = next
	}

	// with a drawn exit the exit itself is a position, known when it or the
	// node before it is rogue
	out.Known = make([]float64, positions+1)
	for r := 0; r <= kk; r++ {
		for a := 0; a < 2; a++ {
			for b := 0; b < 2; b++ {
				for j := 0; j < width; j++ {
					known := j
					if exit == DrawnExit {
						known += a | b
					}
					out.Known[known] += states[at(r, a, b, j)]
				}
			}
		}
	}
	size := float64(positions)
	for j, p := range out.Known {
		out.Mean += float64(j) / size * p
	}
	var variance float64
	for j, p := range out.Known {
		d := float64(j)/size - out.Mean
		variance += d * d * p
	}
	out.StdDev = math.Sqrt(variance)
	out.Touched = 1 - out.Known[0]
	return out
}

// containment rather than equality, so a view that keeps a larger buffer
// cannot hide a plaintext; messages must be unique random bytes, and one whose
// bytes are all equal is refused, since it would be found in any buffer holding
// a run of that byte
func ContentShare(messages, view [][]byte) float64 {
	if len(messages) == 0 {
		return math.NaN()
	}
	for _, m := range messages {
		if len(m) == 0 || allEqual(m) {
			return math.NaN()
		}
	}
	found := 0
	for _, m := range messages {
		for _, v := range view {
			if bytes.Contains(v, m) {
				found++
				break
			}
		}
	}
	return float64(found) / float64(len(messages))
}

func allEqual(b []byte) bool {
	for _, c := range b[1:] {
		if c != b[0] {
			return false
		}
	}
	return true
}
