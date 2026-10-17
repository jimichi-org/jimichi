package metrics_test

import (
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// counted by hand, position by position. An echo route is the client 10, then
// the entry 0, the middle 3 and the exit 2; a side of a -peer client is the
// client, the entry and the middle, the mailbox being public and not a
// position; a conversation is A, eA, mA, mB, eB, B, where a node may repeat
func TestRouteRecoveredKnownAnswer(t *testing.T) {
	echo := []int{10, 0, 3, 2}
	side := []int{10, 0, 3}
	for _, c := range []struct {
		name        string
		path, claim []int
		recovered   int
		share       float64
	}{
		// client, entry and middle named right, the exit unknown: 3 of 4
		{"rogue echo entry", echo, []int{10, 0, 3, -1}, 3, 0.75},
		// entry, middle and exit: 3 of 4
		{"rogue middle", echo, []int{-1, 0, 3, 2}, 3, 0.75},
		// the middle and itself; it echoes back, there is no next: 2 of 4
		{"rogue echo exit", echo, []int{-1, -1, 3, 2}, 2, 0.5},
		// position 2 is named 4 but holds 3, so it is unknown: 2 of 4
		{"a wrong name", echo, []int{10, 0, 4, -1}, 2, 0.5},
		// nothing named is a measured zero
		{"nothing named", echo, []int{-1, -1, -1, -1}, 0, 0},
		// client, entry and middle: 3 of 3
		{"rogue -peer entry", side, []int{10, 0, 3}, 3, 1},
		// the entry and itself: 2 of 3
		{"rogue -peer middle", side, []int{-1, 0, 3}, 2, 2.0 / 3},
		// the middle only: 1 of 3
		{"rogue mailbox", side, []int{-1, -1, 3}, 1, 1.0 / 3},
		// node 1 is mA and eB; positions 2 and 3 (mA, mB) are named, node 1 at
		// position 4 is not, although its id is in the claim: 2 of 6
		{"rogue mailbox on a conversation", []int{10, 0, 1, 2, 1, 11}, []int{-1, -1, 1, 2, -1, -1}, 2, 1.0 / 3},
	} {
		recovered, share := metrics.RouteRecovered(c.path, c.claim)
		if recovered != c.recovered || !near(share, c.share) {
			t.Errorf("%s: RouteRecovered = %d, %v, want %d, %v", c.name, recovered, share, c.recovered, c.share)
		}
	}
	// no route, lengths that differ, and a truth with an unknown in it
	for _, c := range []struct{ path, claim []int }{
		{nil, nil},
		{echo, []int{10, 0, 3}},
		{[]int{10, -1, 3, 2}, []int{10, 0, 3, 2}},
	} {
		if recovered, share := metrics.RouteRecovered(c.path, c.claim); recovered != -1 || !math.IsNaN(share) {
			t.Errorf("RouteRecovered(%v, %v) = %d, %v, want -1 and NaN", c.path, c.claim, recovered, share)
		}
	}
}

// worked by hand, N nodes with k rogue, chains of h. A rogue node knows the
// element before it (the client for the entry), itself and the next one; the
// rogue nodes of a chain pool their views. An echo route has h+1 positions,
// a -peer side h: the client, the entry and the middles, the pinned mailbox
// being public:
//
//	N=5 h=3 k=1 drawn: 60 chains. The rogue node is the entry in 12 (client,
//	entry, middle: 3), the middle in 12 (entry, middle, exit: 3), the exit in
//	12 (middle, exit: 2) and absent in 24. Known 24, 0, 12, 24, 0 of 60;
//	E[R] = (3/4 + 3/4 + 2/4)/5 = 2/5; E[R^2] = (2/5)(9/16) + (1/5)(1/4) =
//	11/40; var 11/40 - 4/25 = 23/200. The binomial error sqrt(0.4 x 0.6) =
//	0.490 would be 1.44 times this sqrt(23/200) = 0.339
//	N=5 h=3 k=2 drawn: no rogue node on 3*2*1 = 6 chains (0); exactly one on
//	2 nodes x 3 positions x 3*2 honest = 36, 12 per position (entry 3, middle
//	3, exit 2); both on 18: {entry, middle} 6 (4), {middle, exit} 6 (3),
//	{entry, exit} 6 (4, pooled). j = 0: 6, 2: 12, 3: 30, 4: 12 of 60;
//	E[R] = (12 x 1/2 + 30 x 3/4 + 12)/60 = 27/40; E[R^2] = 1/20 + 9/32 + 1/5
//	= 17/32; var 17/32 - 729/1600 = 121/1600, sd 11/40
//	N=5 h=3 k=1 pinned honest: 12 sides, positions A, e, m. The entry is rogue
//	1/4 (A, e, m: 3 of 3), the middle 3/4 x 1/3 = 1/4 (e, m: 2 of 3; the
//	mailbox it names is public), absent 1/2. E[R] = 1/4 + 1/6 = 5/12;
//	E[R^2] = 1/4 + (1/4)(4/9) = 13/36; var 13/36 - 25/144 = 3/16
//	N=5 h=3 k=2 pinned honest: the entry among 4 with 2 rogue, the middle
//	among 3: both 1/2 x 1/3 = 1/6 (3); the entry only 1/2 x 2/3 = 1/3 (3); the
//	middle only 1/2 x 2/3 = 1/3 (2); none 1/6. E[R] = 1/2 + 2/9 = 13/18;
//	E[R^2] = 1/2 + (1/3)(4/9) = 35/54; var 35/54 - 169/324 = 41/324. Touched
//	1 - 1/6 = 5/6, the share of the pinned-exit table of the experiment docs
//	N=5 h=3 k=1 pinned rogue: the mailbox always knows the middle, and itself
//	is public: 1 of 3 on every side, sd 0
//	N=5 h=3 k=2 pinned rogue: the other rogue node is the entry 1/4 ({A, e, m}
//	with {m}: 3), the middle 3/4 x 1/3 = 1/4 ({e, m}: 2), absent 1/2 ({m}:
//	1). E[R] = 1/4 + 1/6 + 1/6 = 7/12; E[R^2] = 1/4 + (1/4)(4/9) + (1/2)(1/9)
//	= 5/12; var 5/12 - 49/144 = 11/144. Ends (k-1)/(N-1) = 1/4
//	N=5 h=1 k=1 drawn: the route is the client and one node; a rogue node (1/5)
//	knows both: var (1/5)(4/5), sd 2/5
//	N=5 h=2 k=1 drawn: a rogue entry (1/5) knows all 3, a rogue exit (1/5)
//	knows 2. E[R] = 1/5 + 2/15 = 1/3; E[R^2] = 1/5 + 4/45 = 13/45; var 13/45 -
//	1/9 = 8/45
//	N=5 h=4 k=1 drawn: the entry and both middles know 3 of 5, the exit 2,
//	each position 1/5. E[R] = 9/25 + 2/25 = 11/25; E[R^2] = 27/125 + 4/125 =
//	31/125; var 31/125 - 121/625 = 34/625
//	N=3 h=2 k=1 drawn: 6 paths, a rogue entry in 2 (3 of 3), a rogue exit in 2
//	(2 of 3), absent in 2. E[R] = 1/3 + 2/9 = 5/9; E[R^2] = 1/3 + 4/27 =
//	13/27; var 13/27 - 25/81 = 14/81
//	N=4 h=4 k=1 drawn: a permutation, the rogue node is the exit 1/4 (2 of 5)
//	and elsewhere 3/4 (3 of 5). E[R] = 2/20 + 9/20 = 11/20; E[R^2] = 1/25 +
//	27/100 = 31/100; var 31/100 - 121/400 = 3/400
//	N=5 h=2 k=1 pinned honest: positions A, e; a rogue entry (1/4) knows both:
//	var (1/4)(3/4) = 3/16
//	N=5 h=2 k=1 pinned rogue: the mailbox knows the entry, 1 of 2
//	k=0: nothing known; every node rogue, or every node but an honest
//	mailbox: everything known
func TestRecoveryModelKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		nodes, hops, rogue int
		exit               metrics.ExitChoice
		want               metrics.Recovery
	}{
		{5, 3, 1, metrics.DrawnExit, metrics.Recovery{Known: []float64{0.4, 0, 0.2, 0.4, 0}, Mean: 0.4, StdDev: math.Sqrt(23.0 / 200), RogueExit: 0.2, Ends: 0, Touched: 0.6}},
		{5, 3, 2, metrics.DrawnExit, metrics.Recovery{Known: []float64{0.1, 0, 0.2, 0.5, 0.2}, Mean: 27.0 / 40, StdDev: 11.0 / 40, RogueExit: 0.4, Ends: 0.1, Touched: 0.9}},
		{5, 3, 1, metrics.PinnedHonestExit, metrics.Recovery{Known: []float64{0.5, 0, 0.25, 0.25}, Mean: 5.0 / 12, StdDev: math.Sqrt(3) / 4, RogueExit: 0, Ends: 0, Touched: 0.5}},
		{5, 3, 2, metrics.PinnedHonestExit, metrics.Recovery{Known: []float64{1.0 / 6, 0, 1.0 / 3, 0.5}, Mean: 13.0 / 18, StdDev: math.Sqrt(41) / 18, RogueExit: 0, Ends: 0, Touched: 5.0 / 6}},
		{5, 3, 1, metrics.PinnedRogueExit, metrics.Recovery{Known: []float64{0, 1, 0, 0}, Mean: 1.0 / 3, StdDev: 0, RogueExit: 1, Ends: 0, Touched: 1}},
		{5, 3, 2, metrics.PinnedRogueExit, metrics.Recovery{Known: []float64{0, 0.5, 0.25, 0.25}, Mean: 7.0 / 12, StdDev: math.Sqrt(11) / 12, RogueExit: 1, Ends: 0.25, Touched: 1}},
		{5, 1, 1, metrics.DrawnExit, metrics.Recovery{Known: []float64{0.8, 0, 0.2}, Mean: 0.2, StdDev: 0.4, RogueExit: 0.2, Ends: 0.2, Touched: 0.2}},
		{5, 2, 1, metrics.DrawnExit, metrics.Recovery{Known: []float64{0.6, 0, 0.2, 0.2}, Mean: 1.0 / 3, StdDev: math.Sqrt(8.0 / 45), RogueExit: 0.2, Ends: 0, Touched: 0.4}},
		{5, 4, 1, metrics.DrawnExit, metrics.Recovery{Known: []float64{0.2, 0, 0.2, 0.6, 0, 0}, Mean: 11.0 / 25, StdDev: math.Sqrt(34.0 / 625), RogueExit: 0.2, Ends: 0, Touched: 0.8}},
		{3, 2, 1, metrics.DrawnExit, metrics.Recovery{Known: []float64{1.0 / 3, 0, 1.0 / 3, 1.0 / 3}, Mean: 5.0 / 9, StdDev: math.Sqrt(14.0 / 81), RogueExit: 1.0 / 3, Ends: 0, Touched: 2.0 / 3}},
		{4, 4, 1, metrics.DrawnExit, metrics.Recovery{Known: []float64{0, 0, 0.25, 0.75, 0, 0}, Mean: 11.0 / 20, StdDev: math.Sqrt(3.0 / 400), RogueExit: 0.25, Ends: 0, Touched: 1}},
		{5, 2, 1, metrics.PinnedHonestExit, metrics.Recovery{Known: []float64{0.75, 0, 0.25}, Mean: 0.25, StdDev: math.Sqrt(3.0 / 16), RogueExit: 0, Ends: 0, Touched: 0.25}},
		{5, 2, 1, metrics.PinnedRogueExit, metrics.Recovery{Known: []float64{0, 1, 0}, Mean: 0.5, StdDev: 0, RogueExit: 1, Ends: 0, Touched: 1}},
		{5, 3, 0, metrics.DrawnExit, metrics.Recovery{Known: []float64{1, 0, 0, 0, 0}, Mean: 0, StdDev: 0, RogueExit: 0, Ends: 0, Touched: 0}},
		{5, 3, 0, metrics.PinnedHonestExit, metrics.Recovery{Known: []float64{1, 0, 0, 0}, Mean: 0, StdDev: 0, RogueExit: 0, Ends: 0, Touched: 0}},
		{5, 3, 5, metrics.DrawnExit, metrics.Recovery{Known: []float64{0, 0, 0, 0, 1}, Mean: 1, StdDev: 0, RogueExit: 1, Ends: 1, Touched: 1}},
		{5, 3, 4, metrics.PinnedHonestExit, metrics.Recovery{Known: []float64{0, 0, 0, 1}, Mean: 1, StdDev: 0, RogueExit: 0, Ends: 0, Touched: 1}},
		{5, 3, 5, metrics.PinnedRogueExit, metrics.Recovery{Known: []float64{0, 0, 0, 1}, Mean: 1, StdDev: 0, RogueExit: 1, Ends: 1, Touched: 1}},
	} {
		got := metrics.RecoveryModel(c.nodes, c.hops, c.rogue, c.exit)
		if !sameRecovery(got, c.want) {
			t.Errorf("RecoveryModel(%d, %d, %d, %d) = %+v, want %+v", c.nodes, c.hops, c.rogue, c.exit, got, c.want)
		}
		// a degenerate row has a deviation of exactly 0, never -0, and a share
		// of chains with a rogue node of exactly 0 or 1
		if c.want.StdDev == 0 && (got.StdDev != 0 || math.Signbit(got.StdDev)) {
			t.Errorf("RecoveryModel(%d, %d, %d, %d): StdDev %v, want exactly 0", c.nodes, c.hops, c.rogue, c.exit, got.StdDev)
		}
		if (c.want.Touched == 0 || c.want.Touched == 1) && got.Touched != c.want.Touched {
			t.Errorf("RecoveryModel(%d, %d, %d, %d): Touched %v, want exactly %v", c.nodes, c.hops, c.rogue, c.exit, got.Touched, c.want.Touched)
		}
	}
}

func sameRecovery(a, b metrics.Recovery) bool {
	if len(a.Known) != len(b.Known) {
		return false
	}
	for j := range a.Known {
		if !near(a.Known[j], b.Known[j]) {
			return false
		}
	}
	return near(a.Mean, b.Mean) && near(a.StdDev, b.StdDev) && near(a.RogueExit, b.RogueExit) && near(a.Ends, b.Ends) && near(a.Touched, b.Touched)
}

func TestRecoveryModelUndefined(t *testing.T) {
	for _, c := range []struct {
		nodes, hops, rogue int
		exit               metrics.ExitChoice
	}{
		{5, 0, 1, metrics.DrawnExit}, {5, 6, 1, metrics.DrawnExit}, {5, 3, -1, metrics.DrawnExit}, {5, 3, 6, metrics.DrawnExit},
		{5, 1, 1, metrics.PinnedHonestExit}, {5, 1, 1, metrics.PinnedRogueExit},
		{5, 3, 5, metrics.PinnedHonestExit}, {5, 3, 0, metrics.PinnedRogueExit},
		{5, 3, 1, metrics.ExitChoice(3)},
	} {
		got := metrics.RecoveryModel(c.nodes, c.hops, c.rogue, c.exit)
		if got.Known != nil || !math.IsNaN(got.Mean) || !math.IsNaN(got.StdDev) || !math.IsNaN(got.RogueExit) || !math.IsNaN(got.Ends) || !math.IsNaN(got.Touched) {
			t.Errorf("RecoveryModel(%d, %d, %d, %d) = %+v, want no distribution and NaN", c.nodes, c.hops, c.rogue, c.exit, got)
		}
	}
}

// every chain with the exit pinned to node exit: an ordered choice of hops-1
// distinct nodes among the others, then exit
func pinnedPaths(n, hops, exit int) [][]int {
	var out [][]int
	var extend func(path []int)
	extend = func(path []int) {
		if len(path) == hops-1 {
			out = append(out, append(append([]int(nil), path...), exit))
			return
		}
	next:
		for node := 0; node < n; node++ {
			if node == exit {
				continue
			}
			for _, taken := range path {
				if taken == node {
					continue next
				}
			}
			extend(append(path, node))
		}
	}
	extend(nil)
	return out
}

// what the pooled views of the rogue nodes of a chain name: the elements are
// the client, then the nodes, and element t is named when a rogue node sits at
// t-1, t or t+1 (never the client, which is not rogue); the first positions
// elements are positions
func pooledClaim(elements []int, rogue map[int]bool, positions int) []int {
	last := len(elements) - 1
	claim := make([]int, positions)
	for t := range claim {
		claim[t] = -1
		for _, at := range []int{t - 1, t, t + 1} {
			if at >= 1 && at <= last && rogue[elements[at]] {
				claim[t] = elements[t]
			}
		}
	}
	return claim
}

// the model agrees with every chain counted one by one, for every
// configuration of up to six nodes and four hops and each exit choice: the
// first k nodes are rogue, the client is node N, a pinned rogue exit is node
// 0 and a pinned honest one node N-1
func TestRecoveryModelAgreesWithEveryChain(t *testing.T) {
	checked := 0
	for nodes := 1; nodes <= 6; nodes++ {
		for hops := 1; hops <= min(nodes, 4); hops++ {
			for k := 0; k <= nodes; k++ {
				for _, exit := range []metrics.ExitChoice{metrics.DrawnExit, metrics.PinnedHonestExit, metrics.PinnedRogueExit} {
					var paths [][]int
					positions := hops
					switch {
					case exit == metrics.DrawnExit:
						paths, positions = orderedPaths(nodes, hops), hops+1
					case hops < 2:
						continue
					case exit == metrics.PinnedHonestExit && k < nodes:
						paths = pinnedPaths(nodes, hops, nodes-1)
					case exit == metrics.PinnedRogueExit && k > 0:
						paths = pinnedPaths(nodes, hops, 0)
					default:
						continue
					}
					rogue := make(map[int]bool, k)
					for node := 0; node < k; node++ {
						rogue[node] = true
					}
					counts := make([]float64, positions+1)
					shares := make([]float64, 0, len(paths))
					rogueExits := 0
					for _, path := range paths {
						elements := append([]int{nodes}, path...)
						recovered, share := metrics.RouteRecovered(elements[:positions], pooledClaim(elements, rogue, positions))
						counts[recovered]++
						shares = append(shares, share)
						if rogue[path[len(path)-1]] {
							rogueExits++
						}
					}
					chains := float64(len(paths))
					var mean, variance float64
					for _, s := range shares {
						mean += s
					}
					mean /= chains
					for _, s := range shares {
						variance += (s - mean) * (s - mean)
					}
					want := metrics.Recovery{Known: counts, Mean: mean, StdDev: math.Sqrt(variance / chains), RogueExit: float64(rogueExits) / chains}
					for j := range want.Known {
						want.Known[j] /= chains
					}
					want.Ends, want.Touched = metrics.CompromiseFraction(paths, rogue)
					got := metrics.RecoveryModel(nodes, hops, k, exit)
					if !sameRecovery(got, want) {
						t.Errorf("RecoveryModel(%d, %d, %d, %d) = %+v, every chain gives %+v", nodes, hops, k, exit, got, want)
					}
					if exit == metrics.DrawnExit {
						ends, touched := metrics.CompromiseProbability(nodes, hops, k)
						if !near(got.Ends, ends) || !near(got.Touched, touched) {
							t.Errorf("RecoveryModel(%d, %d, %d, drawn): Ends %v, Touched %v, CompromiseProbability gives %v, %v", nodes, hops, k, got.Ends, got.Touched, ends, touched)
						}
					}
					checked++
				}
			}
		}
	}
	if checked != 198 {
		t.Fatalf("%d configurations checked, want 198", checked)
	}
}

// m1 is inside a larger buffer, m2 is a whole entry, m3 appears only as its
// first 7 bytes: 2 of 3 found
func TestContentShareKnownAnswer(t *testing.T) {
	m1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	m2 := []byte{10, 11, 12, 13, 14, 15, 16, 17}
	m3 := []byte{20, 21, 22, 23, 24, 25, 26, 27}
	larger := append(append([]byte{0, 0, 0}, m1...), 0xff, 0xff)
	view := [][]byte{larger, append([]byte(nil), m2...), append([]byte(nil), m3[:7]...)}
	messages := [][]byte{m1, m2, m3}
	if got := metrics.ContentShare(messages, view); !near(got, 2.0/3) {
		t.Fatalf("ContentShare = %v, want 2/3", got)
	}
	if got := metrics.ContentShare(messages, nil); got != 0 {
		t.Fatalf("ContentShare with nothing recorded = %v, want 0", got)
	}
	// no messages, or an empty one, leave nothing to find
	for _, msgs := range [][][]byte{nil, {m1, {}}} {
		if got := metrics.ContentShare(msgs, view); !math.IsNaN(got) {
			t.Errorf("ContentShare(%v) = %v, want NaN", msgs, got)
		}
	}
	// bytes.Contains alone would find 16 zero bytes in the 392 zero bytes of a
	// mailbox record and report 1, a reveal where the -peer model is 0 by
	// construction; a message of equal bytes is refused
	if got := metrics.ContentShare([][]byte{make([]byte, 16)}, [][]byte{make([]byte, 392)}); !math.IsNaN(got) {
		t.Fatalf("ContentShare of a message of zeros = %v, want NaN", got)
	}
}
