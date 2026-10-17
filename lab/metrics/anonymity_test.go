package metrics_test

import (
	"math"
	"slices"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// one exit per row, the true entry first
func exitRows(rows ...[]float64) []metrics.Score {
	var out []metrics.Score
	for x, r := range rows {
		for e, v := range r {
			out = append(out, metrics.Score{Entry: e, Exit: x, Value: v, True: e == 0})
		}
	}
	return out
}

func nearAll(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !near(a[i], b[i]) {
			return false
		}
	}
	return true
}

func nearAnonymity(a metrics.Anonymity, entropy, degree, size float64) bool {
	return near(a.Entropy, entropy) && near(a.Degree, degree) && near(a.Size, size)
}

func allNaN(a metrics.Anonymity) bool {
	return math.IsNaN(a.Entropy) && math.IsNaN(a.Degree) && math.IsNaN(a.Size)
}

var fourExits = exitRows(
	[]float64{0.9, 0.1, 0.2, 0.3},
	[]float64{0.7, 0.5, 0.4, 0.6},
	[]float64{0.9, 0.95, 0.9, 0.3},
	[]float64{0.5, 0.8, 0.5, 0.1},
)

func TestRankCountsKnownAnswer(t *testing.T) {
	unpartnered := append(append([]metrics.Score(nil), fourExits...),
		metrics.Score{Entry: 0, Exit: 4, Value: 0.4},
		metrics.Score{Entry: 1, Exit: 4, Value: 0.2},
		metrics.Score{Entry: 2, Exit: 4, Value: 0.9},
		metrics.Score{Entry: 3, Exit: 4, Value: 0.1},
	)
	for _, c := range []struct {
		name   string
		scores []metrics.Score
		want   []float64
	}{
		// targets 1 and 2 are first. Target 3: a = 1 (0.95), t = 1 (0.9),
		// places 2 and 3 get 1/2 each. Target 4: a = 1 (0.8), t = 1 (0.5),
		// places 2 and 3 get 1/2 each. [2, 1, 1, 0], q = (1/2, 1/4, 1/4, 0) of
		// the worked example in EXPERIMENT
		{"four exits", fourExits, []float64{2, 1, 1, 0}},
		// an exit with no True score has no partner and is skipped
		{"an exit without a partner", unpartnered, []float64{2, 1, 1, 0}},
		// a = 0, t = 3: each of the places 1..4 gets 1/4
		{"all undefined", exitRows([]float64{-2, -2, -2, -2}), []float64{0.25, 0.25, 0.25, 0.25}},
		// 0.999999999 is within 1e-9 of the true 1, but scores compare exactly:
		// a = 0, t = 0, place 1; merged by same() it would be [1/2, 1/2, 0]
		{"a competitor within 1e-9", exitRows([]float64{1, 0.999999999, 0.3}), []float64{1, 0, 0}},
	} {
		if got := metrics.RankCounts(c.scores); !nearAll(got, c.want) {
			t.Errorf("%s: RankCounts = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRankCountsUndefined(t *testing.T) {
	twoTrue := exitRows([]float64{0.9, 0.1, 0.2})
	twoTrue[1].True = true
	mixed := exitRows([]float64{0.9, 0.1, 0.2}, []float64{0.9, 0.1, 0.2, 0.3}, []float64{0.9, 0.1, 0.2, 0.3})
	noTrue := exitRows([]float64{0.9, 0.1, 0.2})
	noTrue[0].True = false
	for _, c := range []struct {
		name   string
		scores []metrics.Score
	}{
		{"an exit with two True scores", twoTrue},
		{"3 candidates next to 4", mixed},
		{"no score", nil},
		{"no True score", noTrue},
		{"a NaN value", exitRows([]float64{0.9, math.NaN(), 0.2})},
		{"one candidate", exitRows([]float64{0.9})},
	} {
		if got := metrics.RankCounts(c.scores); got != nil {
			t.Errorf("%s: RankCounts = %v, want nil", c.name, got)
		}
	}
}

func TestTrueRankKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		name   string
		scores []metrics.Score
		want   float64
	}{
		// 0.95, 0.9 and the true 0.9 are >= 0.9
		{"worked example", exitRows([]float64{0.9, 0.95, 0.9, 0.3}), 3},
		// per target 1, 1, 3, 3; mean 8/4 (random tie breaking would give 2.5
		// for target 3)
		{"four exits", fourExits, 2},
		{"all tied", exitRows([]float64{-2, -2, -2, -2}), 4},
		// only the true 1 is >= 1; merged by same() 0.999999999 would count too
		{"a competitor within 1e-9", exitRows([]float64{1, 0.999999999, 0.3}), 1},
	} {
		if got := metrics.TrueRank(c.scores); !near(got, c.want) {
			t.Errorf("%s: TrueRank = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTrueRankUndefined(t *testing.T) {
	noTrue := exitRows([]float64{0.9, 0.1, 0.2})
	noTrue[0].True = false
	twoTrue := exitRows([]float64{0.9, 0.1, 0.2})
	twoTrue[2].True = true
	for _, c := range []struct {
		name   string
		scores []metrics.Score
	}{
		{"no True score", noTrue},
		{"an exit with two True scores", twoTrue},
		{"a NaN value", exitRows([]float64{0.9, math.NaN(), 0.2})},
	} {
		if got := metrics.TrueRank(c.scores); !math.IsNaN(got) {
			t.Errorf("%s: TrueRank = %v, want NaN", c.name, got)
		}
	}
}

// q = counts/N, H = -sum q log2 q, Degree H/log2 F, Size 2^H; Miller-Madow
// adds (K - 1)/(2 N ln 2), K the counts above 0, capped at log2 F:
//
//	[2, 1, 1, 0]: H = 1/2*1 + 1/4*2 + 1/4*2 = 3/2, log2 4 = 2, Size 2 sqrt 2 =
//	2.8284271. K = 3, N = 4, correction 2/(8 ln 2) = 1/(4 ln 2) = 0.3606738 <
//	2 - 3/2: corrected {1.8606738, 0.9303369, 2^1.8606738 = 3.6317723}
//	[1/4, 1/4, 1/4, 1/4]: H = 2, Degree 1, Size 4; raw Miller-Madow
//	2 + 3/(2 ln 2) = 4.164 exceeds log2 4, so the corrected value is 2 as well
//	[5, 0, 0, 0]: H = 0, Degree 0, Size 1, with Entropy +0; K = 1 adds nothing
//	[20, 10, 10, 0], the docs example pooled over runs: the q of the first
//	case; K = 3, N = 40, correction 2/(80 ln 2) = 1/(40 ln 2) = 0.0360674:
//	corrected {1.5360674, 0.7680337, 2^1.5360674 = 2.9000291}
//	[60, 61, 59]: H = 1.5848289 below log2 3; K = 3, N = 180, correction
//	2/(360 ln 2) = 0.0080150 takes it past log2 3, so the corrected value is
//	exactly {log2 3, 1, 3}
//	F equal counts: H = log2 F, Degree 1, Size F; the plug-in sum lands within
//	rounding of log2 F, at times a few ulps above it, and the cap holds both
//	values at log2 F
func TestRankAnonymityKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		name              string
		counts            []float64
		plugIn, corrected [3]float64
	}{
		{"four exits", []float64{2, 1, 1, 0}, [3]float64{1.5, 0.75, 2.8284271}, [3]float64{1.8606738, 0.9303369, 3.6317723}},
		{"uniform", []float64{0.25, 0.25, 0.25, 0.25}, [3]float64{2, 1, 4}, [3]float64{2, 1, 4}},
		{"point mass", []float64{5, 0, 0, 0}, [3]float64{0, 0, 1}, [3]float64{0, 0, 1}},
		{"pooled over runs", []float64{20, 10, 10, 0}, [3]float64{1.5, 0.75, 2.8284271}, [3]float64{1.5360674, 0.7680337, 2.9000291}},
	} {
		plugIn, corrected := metrics.RankAnonymity(c.counts)
		for _, r := range []struct {
			kind string
			got  metrics.Anonymity
			want [3]float64
		}{{"plug-in", plugIn, c.plugIn}, {"corrected", corrected, c.corrected}} {
			if !toSeven(r.got.Entropy, r.want[0]) || !toSeven(r.got.Degree, r.want[1]) || !toSeven(r.got.Size, r.want[2]) {
				t.Errorf("%s: %s %+v, want %v", c.name, r.kind, r.got, r.want)
			}
		}
	}
	plugIn, corrected := metrics.RankAnonymity([]float64{2, 1, 1, 0})
	mm := 1.5 + 1/(4*math.Ln2)
	if !nearAnonymity(plugIn, 1.5, 0.75, 2*math.Sqrt2) || !nearAnonymity(corrected, mm, mm/2, math.Exp2(mm)) {
		t.Errorf("RankAnonymity(2, 1, 1, 0) = %+v, %+v, want {3/2, 3/4, 2 sqrt 2} and {%v, %v, 2^%v}", plugIn, corrected, mm, mm/2, mm)
	}
	plugIn, corrected = metrics.RankAnonymity([]float64{5, 0, 0, 0})
	if math.Signbit(plugIn.Entropy) || math.Signbit(corrected.Entropy) {
		t.Errorf("a point mass gives Entropy %v and %v, want +0", plugIn.Entropy, corrected.Entropy)
	}
	_, corrected = metrics.RankAnonymity([]float64{60, 61, 59})
	if corrected != (metrics.Anonymity{Entropy: math.Log2(3), Degree: 1, Size: 3}) {
		t.Errorf("RankAnonymity(60, 61, 59) corrected = %+v, want exactly {log2 3, 1, 3}", corrected)
	}
	for f := 2; f <= 200; f++ {
		top, size := math.Log2(float64(f)), float64(f)
		for _, c := range []float64{0.25, 1, 3, 7, 10} {
			plugIn, corrected := metrics.RankAnonymity(slices.Repeat([]float64{c}, f))
			if !near(plugIn.Entropy, top) || plugIn.Entropy > top || !near(plugIn.Degree, 1) || plugIn.Degree > 1 || !near(plugIn.Size, size) || plugIn.Size > size {
				t.Errorf("%d counts of %v: plug-in %+v, want {log2 F, 1, F} and none above", f, c, plugIn)
			}
			if corrected != (metrics.Anonymity{Entropy: top, Degree: 1, Size: size}) {
				t.Errorf("%d counts of %v: corrected %+v, want exactly {log2 F, 1, F}", f, c, corrected)
			}
		}
	}
}

// the sum of 1.7e308 and 1.7e308 overflows, which would give q = 0 and a
// misleading H = 0
func TestRankAnonymityUndefined(t *testing.T) {
	for _, counts := range [][]float64{
		{}, {3}, {1, -1}, {1, math.NaN()}, {1, math.Inf(1)}, {0, 0}, {1.7e308, 1.7e308},
	} {
		if plugIn, corrected := metrics.RankAnonymity(counts); !allNaN(plugIn) || !allNaN(corrected) {
			t.Errorf("RankAnonymity(%v) = %+v, %+v, want NaN", counts, plugIn, corrected)
		}
	}
}

// isotonic regression of True on Value over the training pairs with a pseudo
// True below all and a pseudo False above all; odds pos/(total - pos) of the
// block of the greatest training value <= s; p_i = o_i / sum o
func TestPosteriorAnonymityKnownAnswer(t *testing.T) {
	train := scored([]float64{0.3, 0.6, 0.8}, []float64{0.1, 0.2, 0.4})
	eleven := make([]float64, 11)
	for i := range eleven {
		eleven[i] = 0.02 * float64(i)
	}
	for _, c := range []struct {
		name                         string
		train, test                  []metrics.Score
		entropy, degree, size, cross float64
	}{
		// PAV on 1(pseudo) 0 0 1 0 1 1 0(pseudo): [1,0] pools to 1/2, the next
		// 0 joins, 1/3; 1 stands; 0 pools with it, 1/2 >= 1/3; 1 and 1 stand;
		// the pseudo 0 pools with 0.8 to 1/2 < 1, so the three pool to 2/3.
		// Blocks (pos, total): (1, 3) for s < 0.3, odds 1/2; (1, 2) for
		// 0.3 <= s < 0.6 (0.5 takes 0.4's block), odds 1; (2, 3) for s >= 0.6,
		// odds 2. Exit 1: odds 2, 1, 1/2, sum 7/2, p = (4/7, 2/7, 1/7),
		// H = log2 7 - (4/7*2 + 2/7*1) = log2 7 - 10/7, -log2 p_true =
		// log2(7/4). Exit 2: odds 1, 2, 1/2, the same H, -log2 p_true =
		// log2(7/2). Means: H = 1.3787835 and (2 log2 7 - 3)/2 = 1.3073549;
		// Degree H/log2 3 = 0.8699155, Size 7*2^(-10/7) = 2.6004900. Here the
		// cross-entropy is below the entropy: the bound degree is
		// 1.3073549/log2 3 = 0.8248491
		{
			"two exits", train, exitRows([]float64{0.8, 0.3, 0.1}, []float64{0.5, 0.6, 0.2}),
			math.Log2(7) - 10.0/7, (math.Log2(7) - 10.0/7) / math.Log2(3), 7 * math.Exp2(-10.0/7), math.Log2(7) - 1.5,
		},
		// all candidates fall in the lowest block, equal odds
		{
			"below all training values", train, exitRows([]float64{0.05, 0.1, 0.2}),
			math.Log2(3), 1, 3, math.Log2(3),
		},
		// blocks (1, 3) (pseudo T with 0.1, 0.2) and (2, 3) (0.9, 0.95 with
		// pseudo F): odds 2, 2, 1/2, p = (4/9, 4/9, 1/9), Entropy
		// 2*(4/9) log2(9/4) + (1/9) log2 9 = log2 9 - 16/9 = 1.3921472, Degree
		// 0.8783471, Size 9*2^(-16/9) = 2.6246903, cross-entropy log2(9/4) =
		// 1.1699250. Without the pseudo pairs c would be 1 and the odds infinite
		{
			"separated training", scored([]float64{0.9, 0.95}, []float64{0.1, 0.2}), exitRows([]float64{0.9, 0.95, 0.1}),
			math.Log2(9) - 16.0/9, (math.Log2(9) - 16.0/9) / math.Log2(3), 9 * math.Exp2(-16.0/9), math.Log2(9.0 / 4),
		},
		// True {1, 1} against False {0.999999999, 0.999999999}, kept apart as
		// scores compare exactly: on 1(pseudo) 0 0 1 1 0(pseudo) the 0s pool with
		// the pseudo 1 to (1, 3), the 1s stand at 2/2, the pseudo 0 pools with
		// them to (2, 3): odds 1/2 below 1 and 2 from 1 up. Exit (1;
		// 0.999999999, 0.3): odds 2, 1/2, 1/2, p = (2/3, 1/6, 1/6), H =
		// 2/3 log2(3/2) + 1/3 log2 6 = log2 3 - 1/3, cross-entropy log2(3/2).
		// Merged by same() the four would form one block, equal odds, H = log2 3
		{
			"a training value within 1e-9", scored([]float64{1, 1}, []float64{0.999999999, 0.999999999}), exitRows([]float64{1, 0.999999999, 0.3}),
			math.Log2(3) - 1.0/3, (math.Log2(3) - 1.0/3) / math.Log2(3), 3 * math.Exp2(-1.0/3), math.Log2(1.5),
		},
		// eleven candidates below 0.3, all in the lowest block: p = 1/11 each,
		// H = log2 11, Degree 1, Size 11, although the summed entropy comes out
		// two ulps above log2 11
		{
			"eleven candidates", train, exitRows(eleven),
			math.Log2(11), 1, 11, math.Log2(11),
		},
	} {
		a, cross := metrics.PosteriorAnonymity(c.train, c.test)
		if !nearAnonymity(a, c.entropy, c.degree, c.size) || !near(cross, c.cross) {
			t.Errorf("%s: PosteriorAnonymity = %+v, %v, want {%v, %v, %v}, %v", c.name, a, cross, c.entropy, c.degree, c.size, c.cross)
		}
	}
	a, cross := metrics.PosteriorAnonymity(train, exitRows([]float64{0.8, 0.3, 0.1}, []float64{0.5, 0.6, 0.2}))
	if !toSeven(a.Entropy, 1.3787835) || !toSeven(a.Degree, 0.8699155) || !toSeven(a.Size, 2.6004900) || !toSeven(cross, 1.3073549) || !toSeven(cross/math.Log2(3), 0.8248491) {
		t.Errorf("two exits: PosteriorAnonymity = %+v, %v, want {1.3787835, 0.8699155, 2.6004900}, 1.3073549", a, cross)
	}
	a, cross = metrics.PosteriorAnonymity(scored([]float64{0.9, 0.95}, []float64{0.1, 0.2}), exitRows([]float64{0.9, 0.95, 0.1}))
	if !toSeven(a.Entropy, 1.3921472) || !toSeven(a.Degree, 0.8783471) || !toSeven(a.Size, 2.6246903) || !toSeven(cross, 1.1699250) {
		t.Errorf("separated training: PosteriorAnonymity = %+v, %v, want {1.3921472, 0.8783471, 2.6246903}, 1.1699250", a, cross)
	}
	if a, _ = metrics.PosteriorAnonymity(train, exitRows(eleven)); a != (metrics.Anonymity{Entropy: math.Log2(11), Degree: 1, Size: 11}) {
		t.Errorf("eleven candidates: PosteriorAnonymity = %+v, want exactly {log2 11, 1, 11}", a)
	}
}

func TestPosteriorAnonymityUndefined(t *testing.T) {
	train := scored([]float64{0.3, 0.6, 0.8}, []float64{0.1, 0.2, 0.4})
	test := exitRows([]float64{0.8, 0.3, 0.1})
	noTrue := exitRows([]float64{0.8, 0.3, 0.1})
	noTrue[0].True = false
	twoTrue := exitRows([]float64{0.8, 0.3, 0.1})
	twoTrue[1].True = true
	for _, c := range []struct {
		name        string
		train, test []metrics.Score
	}{
		{"train without a False score", scored([]float64{0.3, 0.6}, nil), test},
		{"train without a True score", scored(nil, []float64{0.3, 0.6}), test},
		{"train with NaN", scored([]float64{0.3, math.NaN()}, []float64{0.1}), test},
		{"test with +Inf", train, exitRows([]float64{0.8, math.Inf(1), 0.1})},
		{"test without a True score", train, noTrue},
		{"a test exit with two True scores", train, twoTrue},
		{"3 candidates next to 2", train, exitRows([]float64{0.8, 0.3, 0.1}, []float64{0.5, 0.6})},
		{"one candidate", train, exitRows([]float64{0.8})},
	} {
		if a, cross := metrics.PosteriorAnonymity(c.train, c.test); !allNaN(a) || !math.IsNaN(cross) {
			t.Errorf("%s: PosteriorAnonymity = %+v, %v, want NaN", c.name, a, cross)
		}
	}
}
