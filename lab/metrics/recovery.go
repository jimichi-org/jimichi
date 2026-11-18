package metrics

import "math"

type ViewClaim struct {
	Positions []int
	OnPath    bool
}

type ViewEdge struct {
	First, Second int
}

func RecoveredComponents(path []int, views []ViewClaim, links []ViewEdge) (int, float64) {
	invalid := func() (int, float64) { return -1, math.NaN() }
	if len(path) == 0 {
		return invalid()
	}
	for _, id := range path {
		if id < 0 {
			return invalid()
		}
	}
	for _, view := range views {
		if len(view.Positions) != len(path) {
			return invalid()
		}
		for _, id := range view.Positions {
			if id < -1 {
				return invalid()
			}
		}
	}
	partner := make([]int, len(views))
	defer clear(partner)
	for i := range partner {
		partner[i] = -1
	}
	for _, edge := range links {
		a, b := edge.First, edge.Second
		if a < 0 || b < 0 || a >= len(views) || b >= len(views) || a == b || partner[a] >= 0 || partner[b] >= 0 {
			return invalid()
		}
		partner[a], partner[b] = b, a
	}
	best := 0
	for i, view := range views {
		j := partner[i]
		if j < 0 {
			if view.OnPath {
				n, _ := RouteRecovered(path, view.Positions)
				best = max(best, n)
			}
			continue
		}
		if j < i || !view.OnPath && !views[j].OnPath {
			continue
		}
		best = max(best, recoveredMerge(path, view.Positions, views[j].Positions), recoveredMerge(path, views[j].Positions, view.Positions))
	}
	return best, float64(best) / float64(len(path))
}

func recoveredMerge(path, first, second []int) int {
	claim := make([]int, len(first))
	defer clear(claim)
	copy(claim, first)
	for i, id := range second {
		if claim[i] == -1 {
			claim[i] = id
		}
	}
	n, _ := RouteRecovered(path, claim)
	return n
}
