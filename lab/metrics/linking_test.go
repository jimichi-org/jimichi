package metrics_test

import (
	"math"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func ms(v ...int) []time.Duration {
	out := make([]time.Duration, len(v))
	for i, x := range v {
		out[i] = time.Duration(x) * time.Millisecond
	}
	return out
}

type linkCase struct {
	name          string
	first, second []time.Duration
	truth         map[int]int
	auc, topOne   float64
	partnered     float64
	undefined     int
	links         []int
}

// AUC and UndefinedPairs over all pairs, top-1 over the raw rows with flows =
// len(first), partnered top-1 over Partnered, and the mutual links
func checkLinking(t *testing.T, name string, scores []metrics.Score, flows int, truth map[int]int, c linkCase) {
	t.Helper()
	kept, partners := metrics.Partnered(scores, truth)
	auc, topOne, partnered := metrics.AUC(scores), metrics.TopOneAccuracy(scores, flows), metrics.TopOneAccuracy(kept, partners)
	undefined, links := metrics.UndefinedPairs(scores), metrics.BestMatches(scores, flows, 0)
	if !near(auc, c.auc) || !near(topOne, c.topOne) || !near(partnered, c.partnered) || undefined != c.undefined || !slices.Equal(links, c.links) {
		t.Errorf("%s: AUC %v, top-1 %v, partnered %v, undefined %d, links %v; want %v, %v, %v, %d, %v",
			name, auc, topOne, partnered, undefined, links, c.auc, c.topOne, c.partnered, c.undefined, c.links)
	}
}

func TestSetupLagScoresKnownAnswer(t *testing.T) {
	identity := map[int]int{0: 0, 1: 1, 2: 2}
	for _, c := range []linkCase{
		// positives 1/1.002, 1/1.003, 1/1.001; admissible negatives (0,1)
		// 1/1.103, (0,2) 1/1.201, (1,2) 1/1.101; (1,0), (2,0), (2,1) ruled out
		// at -3. The lowest positive 0.99701 is above the highest negative
		// 1/1.101 = 0.90826. Each exit's best entry is its own (column 2:
		// 1/1.201, 1/1.101, 1/1.001), so every link is mutual. Minus the lag in
		// ms with -2 for a ruled-out pair would score the true 2 ms pair -2,
		// equal to undefined, and the 3 ms pair below the ruled-out pairs: AUC
		// 3/4, top-1 2/3
		{"three circuits", ms(0, 100, 200), ms(2, 103, 201), identity, 1, 1, 1, 0, []int{0, 1, 2}},
		// (0,0) 1/1.5 = 2/3, (0,1) 1/2.2 = 5/11, (0,2) 1/6.5 = 2/13, (1,1) 1/1.2
		// = 5/6, (1,2) 1/5.5 = 2/11, (2,2) 1/3.5 = 2/7; (1,0), (2,0), (2,1) = -3.
		// 2/3 and 5/6 beat all 6 negatives (12), 2/7 beats 2/13, 2/11 and the
		// three -3 and loses to 5/11 (5): 17/18. Each row's and each column's
		// maximum is its own pair. Minus the lag with -2 would put (2,2) = -2.5
		// below its row's two -2: AUC 7/9, top-1 2/3
		{"lags over 2 s", ms(0, 1000, 3000), ms(500, 1200, 5500), identity, 17.0 / 18, 1, 1, 0, []int{0, 1, 2}},
		// true lags 300, 5, 5 ms; negatives (0,1) 1/1.315, (0,2) 1/1.325, (1,2)
		// 1/1.015, and (1,0), (2,0), (2,1) = -3. Each entry's own exit is the
		// first exit event after it: top-1 1. 1/1.3 loses only to 1/1.015 (5 of
		// 6), the two 1/1.005 beat all 6: 17/18. Column 0 holds only (0,0) above
		// 0, column 1 is led by (1,1), column 2 by (2,2): all mutual
		{"serial setup, a slow first flow", ms(0, 310, 320), ms(300, 315, 325), identity, 17.0 / 18, 1, 1, 0, []int{0, 1, 2}},
		// row 0 ties 101 and 101 ms, row 1 ties 1 and 1 ms; each positive ties
		// one negative and beats or loses to the other: (1/2 + 0 + 1 + 1/2)/4
		{"two exit setups in one millisecond", ms(0, 100), ms(101, 101), map[int]int{0: 0, 1: 1}, 0.5, 0.5, 0.5, 0, []int{-1, -1}},
		// row 1 (3 pairs) and column 2 (2 more) undefined at -2; (2,0) and (2,1)
		// ruled out at -3. Positives 1/1.002, -2, -2; negatives 1/1.103, -2 x 3,
		// -3 x 2. 1/1.002 beats all 6; each -2 positive loses to 1/1.103, ties
		// three -2 (1.5) and beats the two -3 (2): 6 + 3.5 + 3.5 = 13 of 18.
		// top-1: flow 0 hit; flow 1 three-way tie with its own (1/3); flow 2:
		// its undefined own pair -2 is above the two ruled-out -3: hit.
		// (1 + 1/3 + 1)/3 = 7/9. Ruled out at 0 would give AUC 1/2 and top-1
		// 4/9; ruled out equal to undefined 11/18, 5/9 and 7 undefined pairs
		{"unrecorded events", ms(0, -1, 200), ms(2, 103, -1), identity, 13.0 / 18, 7.0 / 9, 7.0 / 9, 5, []int{0, -1, -1}},
		// (2,0) and (2,1) are ruled out at -3 and not true; with a missing key
		// read as exit 0, (2,0) would be true. Flow 2 has no partner, so the raw
		// top-1 counts it as a miss although both linkable circuits are linked:
		// 2/3 over 3 flows, 1 over the 2 partnered ones
		{"partial truth", ms(0, 100, 200), ms(2, 103), map[int]int{0: 0, 1: 1}, 1, 2.0 / 3, 1, 0, []int{0, 1, -1}},
		// circuit 1 ends at an honest exit. Row 1: (1,0) -3, (1,1) 103 ms =
		// 1/1.103, its unique best above 0; column 1: (0,1) 1/1.203, (1,1)
		// 1/1.103, (2,1) 1/1.003 is led by entry 2, so the link 1 -> 1 is not
		// mutual. A one-sided best would give [0, 1, 1] and a false link.
		// Positives 1/1.002 and 1/1.003 beat all four negatives: AUC 1
		{"a partnerless entry", ms(0, 100, 200), ms(2, 203), map[int]int{0: 0, 2: 1}, 1, 2.0 / 3, 1, 0, []int{0, -1, 1}},
	} {
		scores := metrics.SetupLagScores(c.first, c.second, c.truth)
		checkLinking(t, c.name, scores, len(c.first), c.truth, c)
		for _, s := range scores {
			if s.Value != -3 && s.Value != -2 && !(s.Value > 0 && s.Value <= 1) {
				t.Errorf("%s: score %v outside -3, -2 and (0, 1]", c.name, s.Value)
			}
		}
	}

	scores := metrics.SetupLagScores(ms(0, 100, 200), ms(2, 103, 201), identity)
	if !near(scores[0].Value, 500.0/501) {
		t.Errorf("(0,0) = %v, want 1/1.002 = 500/501", scores[0].Value)
	}
	// 1/1.3 is the only positive below a negative, 1/1.015: the two 1/1.005
	// are above every negative, TPR 2/3 at FPR 0, and the next group is a
	// negative, so the curve stays at 2/3 up to FPR 1/6
	scores = metrics.SetupLagScores(ms(0, 310, 320), ms(300, 315, 325), identity)
	if got := metrics.TPRAtFPR(scores, 0.01); !near(got, 2.0/3) {
		t.Errorf("serial setup: TPR at FPR 0.01 = %v, want 2/3", got)
	}
	scores = metrics.SetupLagScores(ms(0, 100, 200), ms(2, 103), map[int]int{0: 0, 1: 1})
	for _, s := range scores {
		if s.Entry == 2 && s.True {
			t.Errorf("partial truth: %+v is true, entry 2 has no partner", s)
		}
	}
	scores = metrics.SetupLagScores(ms(0, 100, 200), ms(2, 203), map[int]int{0: 0, 2: 1})
	if made, wrong := metrics.FalseLinks(metrics.BestMatches(scores, 3, 0), map[int]int{0: 0, 2: 1}); made != 2 || wrong != 0 {
		t.Errorf("a partnerless entry: FalseLinks = %d, %d, want 2 and 0", made, wrong)
	}

	// 1/(1 + 2) and 1/(1 + 0)
	if s := metrics.SetupLagScores(ms(0), ms(2000), map[int]int{0: 0}); len(s) != 1 || !near(s[0].Value, 1.0/3) {
		t.Errorf("one pair 2 s apart: %+v, want 1/3", s)
	}
	if s := metrics.SetupLagScores(ms(5), ms(5), map[int]int{0: 0}); len(s) != 1 || s[0].Value != 1 {
		t.Errorf("one pair without lag: %+v, want 1", s)
	}
	if s := metrics.SetupLagScores(nil, ms(5), nil); len(s) != 0 || !math.IsNaN(metrics.AUC(s)) {
		t.Errorf("no circuits at the first node: %+v, want no scores", s)
	}
}

func TestCloseLagScoresKnownAnswer(t *testing.T) {
	identity := map[int]int{0: 0, 1: 1, 2: 2}
	for _, c := range []linkCase{
		// true lags 1 ms each, 1/1.001; negatives at 99, 101, 199, 201 ms, all
		// below
		{"exits close first", ms(100, 200, 300), ms(99, 199, 299), identity, 1, 1, 1, 0, []int{0, 1, 2}},
		// (0,0) and (1,0) both 1/1.1: a tie; column 0 is shared, so no link. A
		// one-sided best would link both entries to exit 0
		{"100 ms before and after", ms(100, 300), ms(200), map[int]int{0: 0}, 0.5, 0.5, 1, 0, []int{-1, -1}},
		// row 0 at -2; (1,0) 1 ms = 1/1.001, (1,1) 150 ms = 1/1.15. Positives -2
		// and 1/1.15, negatives -2 and 1/1.001: 1/2 + 0 + 1 + 0 = 3/2 of 4.
		// Row 0 ties its two -2 (1/2), row 1 misses: 1/4
		{"an unrecorded close", ms(-1, 200), ms(201, 50), map[int]int{0: 0, 1: 1}, 3.0 / 8, 0.25, 0.25, 2, []int{-1, 0}},
	} {
		checkLinking(t, c.name, metrics.CloseLagScores(c.first, c.second, c.truth), len(c.first), c.truth, c)
	}

	// entry 1 links to exit 0, whose own entry was not recorded: a false link
	scores := metrics.CloseLagScores(ms(-1, 200), ms(201, 50), map[int]int{0: 0, 1: 1})
	if made, wrong := metrics.FalseLinks(metrics.BestMatches(scores, 2, 0), map[int]int{0: 0, 1: 1}); made != 1 || wrong != 1 {
		t.Errorf("an unrecorded close: FalseLinks = %d, %d, want 1 and 1", made, wrong)
	}

	// the setup rule would rule out every true pair of the first case: they sit
	// at -3, lose to the three admissible negatives (0,1) 1/1.099, (0,2)
	// 1/1.199, (1,2) 1/1.099 and tie the three ruled-out ones, 4.5/18 = 1/4;
	// rows 0 and 1 pick a wrong exit and row 2 ties three ways, 1/9; entry 0
	// links to 1 and entry 1 to 2, both false
	setup := linkCase{"exits close first under the setup rule", nil, nil, nil, 0.25, 1.0 / 9, 1.0 / 9, 0, []int{1, 2, -1}}
	scores = metrics.SetupLagScores(ms(100, 200, 300), ms(99, 199, 299), identity)
	checkLinking(t, setup.name, scores, 3, identity, setup)
	if made, wrong := metrics.FalseLinks(metrics.BestMatches(scores, 3, 0), identity); made != 2 || wrong != 2 {
		t.Errorf("%s: FalseLinks = %d, %d, want 2 and 2", setup.name, made, wrong)
	}
}

func TestSharedLinkScoresKnownAnswer(t *testing.T) {
	a := func(port int) string { return "127.0.0.11:" + strconv.Itoa(port) }
	b, c := "127.0.0.12:7000", "127.0.0.13:7000"
	for _, k := range []struct {
		linkCase
		out, in []metrics.Link
	}{
		// each circuit matches exactly one accepted link; the order of the two
		// lists does not matter
		{linkCase{"permuted", nil, nil, map[int]int{0: 1, 1: 0, 2: 2}, 1, 1, 1, 0, []int{1, 0, 2}},
			[]metrics.Link{{a(40001), b}, {a(40002), b}, {a(40003), b}}, []metrics.Link{{b, a(40002)}, {b, a(40001)}, {b, a(40003)}}},
		// positives (0,0) = 1 and (1,1) = -2, negatives (0,1) = 0 and (1,0) =
		// -2: 1 > 0, 1 > -2, -2 < 0, -2 = -2 (1/2): 2.5/4. Row 1 ties its two
		// -2: (1 + 1/2)/2
		{linkCase{"an unrecorded link", nil, nil, map[int]int{0: 0, 1: 1}, 5.0 / 8, 0.75, 0.75, 2, []int{0, -1}},
			[]metrics.Link{{a(40001), b}, {"", ""}}, []metrics.Link{{b, a(40001)}, {b, a(40009)}}},
		// one local port serves links to two nodes: (1,0) matches on the local
		// end only and scores 0. Comparing only out.Local with in.Remote would
		// score it 1, a tie with the true pair, AUC 1/2. Flow 1 has no partner:
		// top-1 1/2 over 2 flows, 1 over the partnered one
		{linkCase{"crosswise", nil, nil, map[int]int{0: 0}, 1, 0.5, 1, 0, []int{0, -1}},
			[]metrics.Link{{a(40001), b}, {a(40001), c}}, []metrics.Link{{b, a(40001)}}},
		// (0,0) = 1, the mapped form being 127.0.0.11:40001, (0,1) = 0, and row
		// 1 undefined, a hostname does not parse: as the unrecorded link
		{linkCase{"parsing", nil, nil, map[int]int{0: 0, 1: 1}, 5.0 / 8, 0.75, 0.75, 2, []int{0, -1}},
			[]metrics.Link{{"[::ffff:127.0.0.11]:40001", b}, {"localhost:40002", b}}, []metrics.Link{{b, a(40001)}, {b, a(40002)}}},
	} {
		scores := metrics.SharedLinkScores(k.out, k.in, k.truth)
		checkLinking(t, k.name, scores, len(k.out), k.truth, k.linkCase)
		if k.name == "parsing" && (scores[0].Value != 1 || scores[1].Value != 0) {
			t.Errorf("parsing: (0,0) = %v and (0,1) = %v, want 1 and 0", scores[0].Value, scores[1].Value)
		}
	}
}

func TestBestMatchesKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		name  string
		m     [][]float64
		floor float64
		want  []int
	}{
		// row 0 ties; row 1's best exit 1 has entry 0 above it in its column
		// (0.9). A one-sided best would give [-1, 1]
		{"a tie and a column led by another row", [][]float64{{0.9, 0.9}, {0.2, 0.8}}, 0, []int{-1, -1}},
		// row 2 has nothing above 0
		{"floor 0", [][]float64{{0.9, 0.1, -0.4}, {0.2, 0.8, -0.2}, {-0.5, -0.3, -0.1}}, 0, []int{0, 1, -1}},
		// column 2 is led by row 2 at -0.1
		{"floor -1", [][]float64{{0.9, 0.1, -0.4}, {0.2, 0.8, -0.2}, {-0.5, -0.3, -0.1}}, -1, []int{0, 1, 2}},
		// each row's best is exit 0, which the two rows tie
		{"a column tie", [][]float64{{0.7, 0.1}, {0.7, 0.2}}, 0, []int{-1, -1}},
		// the two values are distinct under ==; the tolerance of the rank tests
		// would tie them
		{"1e-10 apart", [][]float64{{0.5, 0.5 + 1e-10}}, 0, []int{1}},
	} {
		if got := metrics.BestMatches(matrixScores(c.m), len(c.m), c.floor); !slices.Equal(got, c.want) {
			t.Errorf("%s: BestMatches = %v, want %v", c.name, got, c.want)
		}
	}
	// the NaN is skipped, and entry 5 lies outside [0, 2), so it does not lead
	// column 0
	scores := []metrics.Score{
		{Entry: 0, Exit: 0, Value: 0.6, True: true},
		{Entry: 0, Exit: 1, Value: math.NaN()},
		{Entry: 5, Exit: 0, Value: 0.9},
		{Entry: 1, Exit: 1, Value: 0.4, True: true},
	}
	if got := metrics.BestMatches(scores, 2, 0); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("NaN and an entry out of range: BestMatches = %v, want [0 1]", got)
	}
	if got := metrics.BestMatches(scores, 0, 0); len(got) != 0 {
		t.Errorf("no flows: BestMatches = %v, want empty", got)
	}
}

// the partnerless-entry case of the setup lag: keys 0 and 2 become entries 0
// and 1, and the pair of entry 2 with exit 1, 1/1.003, is kept as (1, 1)
func TestPartneredKnownAnswer(t *testing.T) {
	truth := map[int]int{0: 0, 2: 1}
	scores := metrics.SetupLagScores(ms(0, 100, 200), ms(2, 203), truth)
	kept, partners := metrics.Partnered(scores, truth)
	if partners != 2 || len(kept) != 4 {
		t.Fatalf("Partnered kept %d scores of %d entries, want 4 and 2", len(kept), partners)
	}
	for _, s := range kept {
		if s.Entry == 1 && s.Exit == 1 && (!s.True || !near(s.Value, 1/1.003)) {
			t.Errorf("(1, 1) = %+v, want true at 1/1.003", s)
		}
	}
	if got := metrics.TopOneAccuracy(kept, partners); !near(got, 1) {
		t.Errorf("partnered top-1 = %v, want 1", got)
	}
	if scores[5].Entry != 2 || scores[5].Exit != 1 {
		t.Errorf("Partnered changed its input: %+v", scores[5])
	}
	kept, partners = metrics.Partnered(metrics.SetupLagScores(ms(0, 100, 200), ms(2, 103), map[int]int{0: 0, 1: 1}), map[int]int{0: 0, 1: 1})
	if got := metrics.TopOneAccuracy(kept, partners); partners != 2 || !near(got, 1) {
		t.Errorf("partial truth: %d partnered, top-1 %v, want 2 and 1", partners, got)
	}
	// no partner at all: nothing to score, and top-1 is undefined
	kept, partners = metrics.Partnered(scores, map[int]int{})
	if partners != 0 || len(kept) != 0 || !math.IsNaN(metrics.TopOneAccuracy(kept, partners)) {
		t.Errorf("no partners: %d scores of %d entries, want none", len(kept), partners)
	}
}

// links made are the non-negative ones; a link is wrong when its entry has no
// partner or another one
func TestFalseLinksKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		links       []int
		truth       map[int]int
		made, wrong int
	}{
		{[]int{0, -1, 1}, map[int]int{0: 0, 2: 1}, 2, 0},
		// entry 1 has no partner
		{[]int{0, 1, 1}, map[int]int{0: 0, 2: 1}, 3, 1},
		{[]int{1, 2, -1}, map[int]int{0: 0, 1: 1, 2: 2}, 2, 2},
		{nil, map[int]int{}, 0, 0},
	} {
		if made, wrong := metrics.FalseLinks(c.links, c.truth); made != c.made || wrong != c.wrong {
			t.Errorf("FalseLinks(%v, %v) = %d, %d, want %d and %d", c.links, c.truth, made, wrong, c.made, c.wrong)
		}
	}
}

func TestTimeToLinkKnownAnswer(t *testing.T) {
	grid := ms(0, 500, 1000, 2000, 5000, 10000, 20000, 30000)
	short := ms(0, 500, 1000)
	for _, c := range []struct {
		name    string
		windows []time.Duration
		topOne  []float64
		want    float64
	}{
		// 1 at 1 s is followed by 0.9 at 2 s; from 5 s on every window gives 1
		{"a miss after a hit", grid, []float64{0.1, 0.3, 1, 0.9, 1, 1, 1, 1}, 5},
		// the setup matcher with top-1 1: the score does not depend on the window
		{"linked at every window", grid, []float64{1, 1, 1, 1, 1, 1, 1, 1}, 0},
		// the first hit at 0 is not kept
		{"a first hit not kept", short, []float64{1, 5.0 / 6, 1}, 1},
	} {
		if got := metrics.TimeToLink(c.windows, c.topOne); !near(got, c.want) {
			t.Errorf("%s: TimeToLink = %v, want %v", c.name, got, c.want)
		}
	}
	for _, c := range []struct {
		name    string
		windows []time.Duration
		topOne  []float64
	}{
		{"below 1 at the largest window", short, []float64{1, 1, 0.95}},
		{"undefined at the largest window", short, []float64{1, 1, math.NaN()}},
		{"no grid", nil, nil},
		{"lengths differ", ms(0, 500), []float64{1}},
		{"a window repeats", ms(0, 1000, 1000), []float64{1, 1, 1}},
		{"a negative window", ms(-1000, 0), []float64{1, 1}},
	} {
		if got := metrics.TimeToLink(c.windows, c.topOne); !math.IsNaN(got) {
			t.Errorf("%s: TimeToLink = %v, want NaN", c.name, got)
		}
	}
}

// two flows, the entry trace equal to the exit trace of each, bins of 100 ms.
// Flow 0 has cells at 0, 200, 400 and 500 ms, flow 1 at 0, 200, 600 and 700 ms:
//
//	w = 0: no bins, every Pearson NaN, all four pairs -2: top-1 1/2
//	w = 0.4 s: both flows (1, 0, 1, 0); every pair has Pearson 1 (mean 1/2,
//	deviations +-1/2, num = da = db = 1): top-1 1/2
//	w = 0.8 s: flow 0 (1, 0, 1, 0, 1, 1, 0, 0), flow 1 (1, 0, 1, 0, 0, 0, 1, 1).
//	Own pairs 1; cross pairs: means 1/2, products +1/4 in bins 0-3 and -1/4 in
//	bins 4-7, num 0, Pearson 0: top-1 1
//
// the flows diverge at 400 ms, and the first window that sees the divergence
// links them: 0.8 s
func TestTimeToLinkOnTraces(t *testing.T) {
	traces := [][]time.Duration{ms(0, 200, 400, 500), ms(0, 200, 600, 700)}
	windows := ms(0, 400, 800)
	want := []float64{0.5, 0.5, 1}
	topOne := make([]float64, len(windows))
	for i, w := range windows {
		bins := make([][]float64, len(traces))
		for f, events := range traces {
			bins[f] = metrics.Bin(events, w, 100*time.Millisecond)
		}
		topOne[i] = metrics.TopOneAccuracy(metrics.ScorePairs(bins, bins, map[int]int{0: 0, 1: 1}), 2)
		if !near(topOne[i], want[i]) {
			t.Errorf("window %v: top-1 = %v, want %v", w, topOne[i], want[i])
		}
	}
	if got := metrics.TimeToLink(windows, topOne); !near(got, 0.8) {
		t.Fatalf("TimeToLink = %v, want 0.8", got)
	}
}
