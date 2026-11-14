package metrics_test

import (
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func TestRecoveredComponentsRoleKnownAnswers(t *testing.T) {
	// echo has four positions including its client; peer omits its public mailbox
	// first, middle and last therefore recover 3/4, 3/4, 2/4 and 3/3, 2/3, 1/3
	for _, c := range []struct {
		name  string
		path  []int
		claim []int
		count int
		share float64
	}{
		{"echo first", []int{0, 1, 2, 3}, []int{0, 1, 2, -1}, 3, 3.0 / 4},
		{"echo middle", []int{0, 1, 2, 3}, []int{-1, 1, 2, 3}, 3, 3.0 / 4},
		{"echo last", []int{0, 1, 2, 3}, []int{-1, -1, 2, 3}, 2, 2.0 / 4},
		{"peer first", []int{0, 1, 2}, []int{0, 1, 2}, 3, 1},
		{"peer middle", []int{0, 1, 2}, []int{-1, 1, 2}, 2, 2.0 / 3},
		{"peer last", []int{0, 1, 2}, []int{-1, -1, 2}, 1, 1.0 / 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, share := metrics.RecoveredComponents(c.path, []metrics.ViewClaim{{Positions: c.claim, OnPath: true}}, nil)
			if got != c.count || share != c.share {
				t.Fatalf("recovery %d, %g, want %d, %g", got, share, c.count, c.share)
			}
		})
	}
}

func TestRecoveredComponentsKnownAnswers(t *testing.T) {
	path := []int{0, 1, 2, 3}
	for _, c := range []struct {
		name  string
		views []metrics.ViewClaim
		links []metrics.ViewEdge
		count int
	}{
		// disconnected 2/4 claims remain separate, rather than recovering 4/4
		{"unconnected", []metrics.ViewClaim{{Positions: []int{0, 1, -1, -1}, OnPath: true}, {Positions: []int{-1, -1, 2, 3}, OnPath: true}}, nil, 2},
		// exact joining fills the two missing positions and recovers all four
		{"joined", []metrics.ViewClaim{{Positions: []int{0, 1, -1, -1}, OnPath: true}, {Positions: []int{-1, -1, 2, 3}, OnPath: true}}, []metrics.ViewEdge{{First: 0, Second: 1}}, 4},
		// first order keeps two wrong occupants and recovers 2/4; reverse keeps one and recovers 3/4
		{"both orders", []metrics.ViewClaim{{Positions: []int{9, 1, 8, -1}, OnPath: true}, {Positions: []int{0, 7, 2, 3}}}, []metrics.ViewEdge{{First: 0, Second: 1}}, 3},
		// an unrelated exact claim is unavailable unless its component contains an actual view
		{"off path", []metrics.ViewClaim{{Positions: path}}, nil, 0},
		// a singleton with three correct occupants beats a different component with only two
		{"best component", []metrics.ViewClaim{{Positions: []int{0, -1, -1, -1}, OnPath: true}, {Positions: []int{-1, 1, -1, -1}}, {Positions: []int{0, 1, 2, -1}, OnPath: true}}, []metrics.ViewEdge{{First: 0, Second: 1}}, 3},
		{"no view", nil, nil, 0},
		{"unknown view", []metrics.ViewClaim{{Positions: []int{-1, -1, -1, -1}, OnPath: true}}, nil, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, share := metrics.RecoveredComponents(path, c.views, c.links)
			if got != c.count || share != float64(c.count)/4 {
				t.Fatalf("recovery %d, %g, want %d, %g", got, share, c.count, float64(c.count)/4)
			}
		})
	}
}

func TestRecoveredComponentsRejectsInvalid(t *testing.T) {
	views := []metrics.ViewClaim{
		{Positions: []int{0, -1}, OnPath: true},
		{Positions: []int{-1, 1}},
		{Positions: []int{0, 1}},
	}
	for _, c := range []struct {
		name  string
		path  []int
		views []metrics.ViewClaim
		links []metrics.ViewEdge
	}{
		{"empty path", nil, nil, nil},
		{"negative path", []int{-1, 1}, views, nil},
		{"wrong width", []int{0}, views, nil},
		{"invalid occupant", []int{0, 1}, []metrics.ViewClaim{{Positions: []int{-2, 1}}}, nil},
		{"negative edge", []int{0, 1}, views, []metrics.ViewEdge{{First: -1, Second: 1}}},
		{"absent edge", []int{0, 1}, views, []metrics.ViewEdge{{First: 0, Second: 3}}},
		{"self edge", []int{0, 1}, views, []metrics.ViewEdge{{First: 0, Second: 0}}},
		{"duplicate edge", []int{0, 1}, views, []metrics.ViewEdge{{First: 0, Second: 1}, {First: 0, Second: 1}}},
		{"reversed duplicate", []int{0, 1}, views, []metrics.ViewEdge{{First: 0, Second: 1}, {First: 1, Second: 0}}},
		{"three views", []int{0, 1}, views, []metrics.ViewEdge{{First: 0, Second: 1}, {First: 1, Second: 2}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, share := metrics.RecoveredComponents(c.path, c.views, c.links)
			if n != -1 || !math.IsNaN(share) {
				t.Fatalf("invalid recovery %d, %g", n, share)
			}
		})
	}
}

func TestRecoveredComponentsPermutation(t *testing.T) {
	path := []int{0, 1, 2, 3}
	views := []metrics.ViewClaim{
		{Positions: []int{0, 1, -1, -1}, OnPath: true},
		{Positions: []int{-1, -1, 2, 3}},
		{Positions: []int{0, -1, 2, -1}, OnPath: true},
	}
	want, share := metrics.RecoveredComponents(path, views, []metrics.ViewEdge{{First: 0, Second: 1}})
	permuted := []metrics.ViewClaim{views[2], views[1], views[0]}
	got, gotShare := metrics.RecoveredComponents(path, permuted, []metrics.ViewEdge{{First: 2, Second: 1}})
	if got != want || gotShare != share {
		t.Fatalf("permuted recovery %d, %g, want %d, %g", got, gotShare, want, share)
	}
}

func finiteRecoveryViews(path []int, selected, publicExit int) []metrics.ViewClaim {
	width := len(path)
	if publicExit >= 0 {
		width--
	}
	var views []metrics.ViewClaim
	for hop := 1; hop < len(path); hop++ {
		if path[hop] >= selected {
			continue
		}
		claim := make([]int, width)
		for j := range claim {
			claim[j] = -1
		}
		for j := max(0, hop-1); j <= min(width-1, hop+1); j++ {
			claim[j] = path[j]
		}
		views = append(views, metrics.ViewClaim{Positions: claim, OnPath: true})
	}
	return views
}

func TestRecoveredComponentsFiniteModels(t *testing.T) {
	// each of the 5*4*3=60 echo paths has weight 1/60
	// k=1 gives 24 absent and 12 at each role, total 12*(3+3+2)=96 known positions
	// k=2 gives 6 absent and 162 known positions, hence means 96/240=2/5 and 162/240=27/40
	// pinned peer has 4*3=12 paths and three private positions
	// their known-position totals H1,H2,M1,M2 are 15,26,12,21, giving 5/12,13/18,1/3,7/12
	for _, c := range []struct {
		name           string
		k, pin         int
		exit           metrics.ExitChoice
		total          int
		known          int
		absent         int
		controlledExit int
		ends           int
	}{
		{"E1", 1, -1, metrics.DrawnExit, 60, 96, 24, 12, 0},
		{"E2", 2, -1, metrics.DrawnExit, 60, 162, 6, 24, 6},
		{"H1", 1, 4, metrics.PinnedHonestExit, 12, 15, 6, 0, 0},
		{"H2", 2, 4, metrics.PinnedHonestExit, 12, 26, 2, 0, 0},
		{"M1", 1, 0, metrics.PinnedRogueExit, 12, 12, 0, 12, 0},
		{"M2", 2, 0, metrics.PinnedRogueExit, 12, 21, 0, 12, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			total, known, absent, controlledExit, ends, width := 0, 0, 0, 0, 0, 4
			for a := 0; a < 5; a++ {
				for b := 0; b < 5; b++ {
					for exit := 0; exit < 5; exit++ {
						if a == b || a == exit || b == exit || c.pin >= 0 && exit != c.pin {
							continue
						}
						path := []int{5, a, b, exit}
						views := finiteRecoveryViews(path, c.k, c.pin)
						if c.pin >= 0 {
							path = path[:3]
						}
						width = len(path)
						var links []metrics.ViewEdge
						if len(views) == 2 {
							links = []metrics.ViewEdge{{First: 0, Second: 1}}
						}
						n, _ := metrics.RecoveredComponents(path, views, links)
						if n < 0 {
							t.Fatal("valid finite path refused")
						}
						total++
						known += n
						if len(views) == 0 {
							absent++
						}
						if exit < c.k {
							controlledExit++
							if a < c.k {
								ends++
							}
						}
					}
				}
			}
			if total != c.total || known != c.known || absent != c.absent || controlledExit != c.controlledExit || ends != c.ends {
				t.Fatalf("counts total=%d known=%d absent=%d exit=%d ends=%d", total, known, absent, controlledExit, ends)
			}
			mean := float64(known) / float64(total*width)
			if model := metrics.RecoveryModel(5, 3, c.k, c.exit); !near(mean, model.Mean) {
				t.Fatalf("finite mean %g, model %g", mean, model.Mean)
			}
		})
	}
}
