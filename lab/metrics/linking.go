package metrics

import (
	"maps"
	"math"
	"net/netip"
	"slices"
	"time"
)

// a pair the order of events rules out is certainly false, so it ranks below
// an undefined pair, which may be true
const ruledOut = -3

// the score is bounded so that no lag drops an admissible pair below a
// ruled-out one, and finite because a report cannot carry -Inf; minus the lag
// with the -2 floor would rank a true lag over 2 s below the ruled-out pairs.
// Equal lags give bit-equal scores, so no rounding
func SetupLagScores(first, second []time.Duration, truth map[int]int) []Score {
	return lagScores(first, second, truth, true)
}

// the close of a circuit travels both ways, so its order rules no pair out
func CloseLagScores(first, second []time.Duration, truth map[int]int) []Score {
	return lagScores(first, second, truth, false)
}

func lagScores(first, second []time.Duration, truth map[int]int, ordered bool) []Score {
	scores := make([]Score, 0, len(first)*len(second))
	for i, a := range first {
		for j, b := range second {
			v := float64(undefined)
			switch {
			case a < 0 || b < 0:
			case ordered && b < a:
				v = ruledOut
			default:
				v = 1 / (1 + (b - a).Abs().Seconds())
			}
			scores = append(scores, Score{Entry: i, Exit: j, Value: v, True: partner(truth, i, j)})
		}
	}
	return scores
}

type Link struct {
	Local, Remote string
}

// both ends are compared crosswise because one local port may serve links to
// two different nodes at once; addresses are compared parsed and unmapped
// because a dual-stack listener reports an IPv4 peer in IPv6 form
func SharedLinkScores(out, in []Link, truth map[int]int) []Score {
	type ends struct {
		local, remote netip.AddrPort
		ok            bool
	}
	parse := func(links []Link) []ends {
		parsed := make([]ends, len(links))
		for i, l := range links {
			local, okLocal := endpoint(l.Local)
			remote, okRemote := endpoint(l.Remote)
			parsed[i] = ends{local, remote, okLocal && okRemote}
		}
		return parsed
	}
	from, to := parse(out), parse(in)
	scores := make([]Score, 0, len(out)*len(in))
	for i, o := range from {
		for j, n := range to {
			v := float64(undefined)
			if o.ok && n.ok {
				v = 0
				if o.local == n.remote && o.remote == n.local {
					v = 1
				}
			}
			scores = append(scores, Score{Entry: i, Exit: j, Value: v, True: partner(truth, i, j)})
		}
	}
	return scores
}

func endpoint(s string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// a circuit pairs one to one, so a link needs the best of both sides; ties do
// not link
func BestMatches(scores []Score, flows int, floor float64) []int {
	var kept []Score
	exits := 0
	for _, s := range scores {
		if s.Entry >= 0 && s.Entry < flows && s.Exit >= 0 && s.Value > floor {
			kept = append(kept, s)
			exits = max(exits, s.Exit+1)
		}
	}
	rows := leaders(kept, flows, func(s Score) (int, int) { return s.Entry, s.Exit })
	columns := leaders(kept, exits, func(s Score) (int, int) { return s.Exit, s.Entry })
	links := make([]int, flows)
	for i, j := range rows {
		links[i] = -1
		if j >= 0 && columns[j] == i {
			links[i] = j
		}
	}
	return links
}

// for each of n indices the other side of its single highest score, -1 when
// it has no score or the highest is tied
func leaders(scores []Score, n int, sides func(Score) (own, other int)) []int {
	top := make([]float64, n)
	lead := make([]int, n)
	tied := make([]bool, n)
	for i := range lead {
		top[i], lead[i] = math.Inf(-1), -1
	}
	for _, s := range scores {
		own, other := sides(s)
		switch {
		case s.Value > top[own]:
			top[own], lead[own], tied[own] = s.Value, other, false
		case s.Value == top[own]:
			tied[own] = true
		}
	}
	for i := range lead {
		if tied[i] {
			lead[i] = -1
		}
	}
	return lead
}

// a first-node circuit whose exit is honest cannot be linked right, so
// counting it would put top-1 below 1 by construction
func Partnered(scores []Score, truth map[int]int) ([]Score, int) {
	keys := slices.Sorted(maps.Keys(truth))
	index := make(map[int]int, len(keys))
	for r, key := range keys {
		index[key] = r
	}
	var kept []Score
	for _, s := range scores {
		if r, ok := index[s.Entry]; ok {
			s.Entry = r
			kept = append(kept, s)
		}
	}
	return kept, len(keys)
}

// a circuit of the first node that never reached the second can still link to
// a circuit of an honest entry that passed the second; such a link names wrong
// positions, which RouteRecovered counts as unknown, so it is reported here
// and not in that share
func FalseLinks(links []int, truth map[int]int) (made, wrong int) {
	for i, j := range links {
		if j < 0 {
			continue
		}
		made++
		if !partner(truth, i, j) {
			wrong++
		}
	}
	return made, wrong
}

// a window followed by a miss on a larger one is not a time the adversary can
// rely on; the per-window top-1 is printed next to the value
func TimeToLink(windows []time.Duration, topOne []float64) float64 {
	n := len(windows)
	if n == 0 || len(topOne) != n {
		return math.NaN()
	}
	for i, w := range windows {
		if w < 0 || i > 0 && w <= windows[i-1] {
			return math.NaN()
		}
	}
	if topOne[n-1] != 1 {
		return math.NaN()
	}
	i := n - 1
	for i > 0 && topOne[i-1] == 1 {
		i--
	}
	return windows[i].Seconds()
}
