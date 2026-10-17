package metrics_test

import (
	"math"
	"slices"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// computed at run time: the constant expression 0.1 + 0.2 is exactly 0.3
var tenth, fifth = 0.1, 0.2

func rows(v ...[]float64) [][]float64 { return v }

func times(rows [][]float64, k float64) [][]float64 {
	out := make([][]float64, len(rows))
	for i, r := range rows {
		for _, v := range r {
			out[i] = append(out[i], v*k)
		}
	}
	return out
}

func classes(payload, cover [][]float64) ([][]float64, []bool) {
	train := append(append([][]float64(nil), payload...), cover...)
	truth := make([]bool, len(train))
	for i := range payload {
		truth[i] = true
	}
	return train, truth
}

func meanRow(rows [][]float64) []float64 {
	out := make([]float64, len(rows[0]))
	for _, r := range rows {
		for j, v := range r {
			out[j] += v / float64(len(rows))
		}
	}
	return out
}

// each test cell its own flow, as RequestScores takes the scores of a run
func cellAUC(values []float64, truth []bool) float64 {
	flows := make([]int, len(values))
	for i := range flows {
		flows[i] = i
	}
	return metrics.AUC(metrics.RequestScores(flows, len(values), values, truth))
}

// the scores are w·(x - m)/(w·d) with m = (mu1 + mu0)/2 and d = mu1 - mu0, so
// the zero row and the unit rows give the direction w/(w·d) as score(e_j) -
// score(0), and the training class means score +1/2 and -1/2 in every case
type discriminantCase struct {
	name           string
	payload, cover [][]float64
	test           [][]float64
	truth          []bool
	want           []float64
	dir            []float64
	auc            float64
}

func discriminantCases() []discriminantCase {
	nan := math.NaN()
	case1 := rows([]float64{2, 0}, []float64{4, 0})
	cover1 := rows([]float64{0, 1}, []float64{0, 3})
	test1 := rows([]float64{3, 1}, []float64{1, 1}, []float64{1, 0}, []float64{0, 2})
	truth1 := []bool{true, true, false, false}
	scores1 := []float64{9.0 / 26, -3.0 / 26, 1.0 / 26, -0.5}
	return []discriminantCase{
		// mu = (3/2, 1), deviations (1/2,-1), (5/2,-1), (-3/2,0), (-3/2,2):
		// S_t = [[1/4+25/4+9/4+9/4, -1/2-5/2+0-3], [., 1+1+0+4]] = [[11,-6],[-6,6]],
		// det 30, S_t^-1 = (1/30)[[6,6],[6,11]]. d = (3,0) - (0,2) = (3,-2),
		// w = (1/30)(18-12, 18-22) = (1/5, -2/15). Fisher: S_w = diag(2,2)
		// (payload deviations (-1,0), (1,0); cover (0,-1), (0,1)), w_F = (3/2, -1);
		// c = 2*2/4 = 1, d^T S_w^-1 d = 13/2, so w = w_F/(1 + 13/2) = (2/15) w_F.
		// m = (3/2, 1), w·m = 3/10 - 2/15 = 1/6, w·d = 3/5 + 4/15 = 13/15. Raw
		// w·x = 7/15, 1/15, 1/5, -4/15; score (w·x - 1/6)*15/13:
		// (14/30-5/30)*15/13 = 9/26, (2/30-5/30)*15/13 = -3/26, (1/30)*15/13 =
		// 1/26, (-13/30)*15/13 = -1/2. Pairs: 9/26 > 1/26, 9/26 > -1/2,
		// -3/26 < 1/26, -3/26 > -1/2: 3 of 4. w/(w·d) = (3/13, -2/13)
		{"two-feature worked case", case1, cover1, test1, truth1, scores1, []float64{3.0 / 13, -2.0 / 13}, 0.75},
		// feature 1 times 1e9, feature 2 plus 7: x -> Ax + b maps w to A^-T w =
		// (2e-10, -2/15) and leaves w·(x - m)/(w·d) unchanged, so the scores and
		// the AUC of the two-feature worked case
		{
			"affine invariance",
			rows([]float64{2e9, 7}, []float64{4e9, 7}), rows([]float64{0, 8}, []float64{0, 10}),
			rows([]float64{3e9, 8}, []float64{1e9, 8}, []float64{1e9, 7}, []float64{0, 9}), truth1,
			scores1, nil, 0.75,
		},
		// a third value 7 in every training row: same(7, 7), so the column is
		// dropped with weight 0 and its test values 0, 100, -5, 3 do not matter;
		// weights (1/5, -2/15, 0), the scores of the two-feature worked case
		{
			"constant column",
			rows([]float64{2, 0, 7}, []float64{4, 0, 7}), rows([]float64{0, 1, 7}, []float64{0, 3, 7}),
			rows([]float64{3, 1, 0}, []float64{1, 1, 100}, []float64{1, 0, -5}, []float64{0, 2, 3}), truth1,
			scores1, []float64{3.0 / 13, -2.0 / 13, 0}, 0.75,
		},
		// mu = (1/2, 11/2), deviations (1/2,-1/2), (1/2,3/2), (-1/2,-3/2),
		// (-1/2,1/2): S_t = [[1,1],[1,5]], det 4, S_t^-1 = (1/4)[[5,-1],[-1,1]],
		// d = (1,1), w = (1/4)(5-1, -1+1) = (1,0); S_w = [[0,0],[0,4]] and
		// S_w w = 0. m = (1/2, 11/2), w·d = 1, score x_1 - 1/2. The
		// pseudo-inverse of S_w would give w = (0, 1/4), raw scores 0 against
		// 9/4, AUC 0; dropping feature 1 for zero within-class variance gives
		// the same AUC 0
		{
			"separator",
			rows([]float64{1, 5}, []float64{1, 7}), rows([]float64{0, 4}, []float64{0, 6}),
			rows([]float64{1, 0}, []float64{0, 9}), []bool{true, false},
			[]float64{0.5, -0.5}, []float64{1, 0}, 1,
		},
		// x2 = 2 x1 + 1: column 2's pivot is 0 <= 1e-9 (exactly affine; float
		// residual about 1e-16), so it is dropped; d_1 = 2 - 1 = 1, S_t,11 =
		// 1/4+9/4+9/4+1/4 = 5, w_1 = 1/5; m_1 = 3/2, w·d = 1/5, score x_1 - 3/2;
		// the 100 is ignored
		{
			"collinear, test outside the dependency",
			rows([]float64{1, 3}, []float64{3, 7}), rows([]float64{0, 1}, []float64{2, 5}),
			rows([]float64{2, 5}, []float64{1, 3}, []float64{2, 0}, []float64{1, 100}), nil,
			[]float64{0.5, -0.5, 0.5, -0.5}, []float64{1, 0}, nan,
		},
		// columns (a+b, a, b) over the rows (a, b) of the two-feature worked
		// case: b = (a+b) - a is dropped; -2/15 (a+b) + 1/3 a = a/5 - 2b/15, its
		// discriminant, with the same m and w·d = 13/15: raw -2/15 and 1/5 give
		// (-2/15 - 1/6)*15/13 = -9/26 and (1/5 - 1/6)*15/13 = 1/26. Weights
		// (-2/15, 1/3, 0), w/(w·d) = (-2/13, 5/13, 0): which dependent column
		// goes does not change the scores while the test respects the dependency
		{
			"dependent column first",
			rows([]float64{2, 2, 0}, []float64{4, 4, 0}), rows([]float64{1, 0, 1}, []float64{3, 0, 3}),
			rows([]float64{1, 0, 1}, []float64{1, 1, 0}), nil,
			[]float64{-9.0 / 26, 1.0 / 26}, []float64{-2.0 / 13, 5.0 / 13, 0}, nan,
		},
		// S_t = [[2,4],[4,8]] has rank one, column 2's pivot is 8 - 16/2 = 0,
		// dropped; d_1 = -2, w_1 = -2/2 = -1; m_1 = 2, w·d = 2, score
		// -(x_1 - 2)/2
		{
			"two rows",
			rows([]float64{1, 2}), rows([]float64{3, 6}),
			rows([]float64{1, 0}, []float64{3, 0}), nil,
			[]float64{0.5, -0.5}, []float64{-0.5, 0}, nan,
		},
		// mu = 3/2, S_t = 1/4+25/4+9/4+9/4 = 11, d = 3, w = 3/11; one column
		// scores (x - m)/d = (x - 3/2)/3: 1/2 and -1/6
		{
			"one column",
			rows([]float64{2}, []float64{4}), rows([]float64{0}, []float64{0}),
			rows([]float64{3}, []float64{1}), []bool{true, false},
			[]float64{0.5, -1.0 / 6}, []float64{1.0 / 3}, 1,
		},
		// the same with the test swapped, payload {1} and cover {3}: AUC 0, not
		// folded
		{
			"one column, test swapped",
			rows([]float64{2}, []float64{4}), rows([]float64{0}, []float64{0}),
			rows([]float64{1}, []float64{3}), []bool{true, false},
			[]float64{-1.0 / 6, 0.5}, []float64{1.0 / 3}, 0,
		},
		// mu = 9/4, S_t = (81+25+9+121)/16 = 59/4, d = 1/2 - 4 = -7/2 < 0,
		// w = -14/59; score (x - 9/4)/(-7/2) falls with the value: 2 gives 1/14,
		// 1 gives 5/14, 4 gives -1/2, so the payload 2 is above 4 and below 1
		// in score, 1 of 2
		{
			"one column, falling direction",
			rows([]float64{0}, []float64{1}), rows([]float64{3}, []float64{5}),
			rows([]float64{2}, []float64{1}, []float64{4}), []bool{true, false, false},
			[]float64{1.0 / 14, 5.0 / 14, -0.5}, []float64{-2.0 / 7}, 0.5,
		},
		// 0.30000000000000004 is within 1e-9 of 0.3, so column 2 is constant
		// and the scores are those of the one column case
		{
			"float constant",
			rows([]float64{2, 0.3}, []float64{4, tenth + fifth}), rows([]float64{0, 0.3}, []float64{0, 0.3}),
			rows([]float64{3, 0.3}, []float64{1, tenth + fifth}), []bool{true, false},
			[]float64{0.5, -1.0 / 6}, []float64{1.0 / 3, 0}, 1,
		},
		// e = 0.01: mu = (1, 1 + e/2), deviations of column 2 -1 + e/2, 1 + e/2,
		// -1 - e/2, 1 - e/2: S_t = [[4, 4], [4, 4 + e^2]], column 2's pivot
		// 1 - 16/(4(4 + e^2)) = e^2/(4 + e^2) = 2.5e-5 > 1e-9, kept. d = (0, e),
		// S_t^-1 = (1/(4e^2))[[4 + e^2, -4], [-4, 4]], w = (1/e)(-1, 1), w·d = 1,
		// m = (1, 1 + e/2): (1, 1 + e) scores 1/2, (1, 1) -1/2, (5, 5 + e)
		// (1/e)(-4 + 4 + e/2) = 1/2, AUC 1. A tolerance above 2.5e-5 would drop
		// column 2, leave equal means on column 1 and give nil
		{
			"just above the pivot tolerance",
			rows([]float64{0, 0.01}, []float64{2, 2.01}), rows([]float64{0, 0}, []float64{2, 2}),
			rows([]float64{1, 1.01}, []float64{1, 1}, []float64{5, 5.01}), []bool{true, false, true},
			[]float64{0.5, -0.5, 0.5}, []float64{-100, 100}, 1,
		},
		// payload {0}, {1}, {2} against cover {5}: mu1 = 1, mu0 = 5, d = -4,
		// m = 3, mu = 2; S_t = 4 + 1 + 0 + 9 = 14, w = -2/7, w·d = 8/7, score
		// (x - 3)/(-4): 1 gives 1/2, 5 -1/2, 0 3/4, 3 0, AUC 1. Centring at mu
		// would give the class means 1/4 and -3/4
		{
			"unbalanced training",
			rows([]float64{0}, []float64{1}, []float64{2}), rows([]float64{5}),
			rows([]float64{1}, []float64{5}, []float64{0}, []float64{3}), []bool{true, false, true, false},
			[]float64{0.5, -0.5, 0.75, 0}, []float64{-0.25}, 1,
		},
		// the two-feature worked case times 1e-150: S_t,jj about 1e-299 is a
		// normal float, so the scores and the AUC of that case
		{
			"small units",
			times(case1, 1e-150), times(cover1, 1e-150), times(test1, 1e-150), truth1,
			scores1, nil, 0.75,
		},
	}
}

// the probe of the zero row and the unit rows
func directionProbe(width int) [][]float64 {
	probe := rows(make([]float64, width))
	for j := range width {
		e := make([]float64, width)
		e[j] = 1
		probe = append(probe, e)
	}
	return probe
}

func TestDiscriminantScoresKnownAnswer(t *testing.T) {
	for _, c := range discriminantCases() {
		train, truth := classes(c.payload, c.cover)
		got := metrics.DiscriminantScores(train, truth, c.test)
		if len(got) != len(c.want) {
			t.Errorf("%s: scores %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if !near(got[i], c.want[i]) {
				t.Errorf("%s: scores %v, want %v", c.name, got, c.want)
				break
			}
		}
		if c.truth != nil {
			if auc := cellAUC(got, c.truth); !near(auc, c.auc) {
				t.Errorf("%s: AUC %v, want %v", c.name, auc, c.auc)
			}
		}
		if means := metrics.DiscriminantScores(train, truth, rows(meanRow(c.payload), meanRow(c.cover))); len(means) != 2 || !near(means[0], 0.5) || !near(means[1], -0.5) {
			t.Errorf("%s: the training class means score %v, want 1/2 and -1/2", c.name, means)
		}
		if c.dir == nil {
			continue
		}
		width := len(train[0])
		s := metrics.DiscriminantScores(train, truth, directionProbe(width))
		for j := range width {
			if !near(s[j+1]-s[0], c.dir[j]) {
				t.Errorf("%s: direction w/(w·d) %v at column %d, want %v", c.name, s[j+1]-s[0], j, c.dir)
			}
		}
	}
	if tenth+fifth == 0.3 {
		t.Fatal("0.1 + 0.2 came out as 0.3; the float constant case does not exercise the rule")
	}
}

// the underflowing column: payload {2e-200}, {4e-200}, cover {0}, {1e-200}
// is not constant by same(), but every squared deviation underflows, so
// S_t,11 = 0 and s_1 = 0. The two-feature worked case times 1e-160 has S_t,11 = 11e-320,
// a subnormal float that has lost its digits. The pivot case of the known
// answers at e = 1e-5: e^2/(4 + e^2) = 2.5e-11 <= 1e-9 drops column 2 and the
// means of column 1 are equal, so a leak of 1e-5 is lost to the tolerance
func TestDiscriminantScoresUndefined(t *testing.T) {
	payload, cover := rows([]float64{2, 0}, []float64{4, 0}), rows([]float64{0, 1}, []float64{0, 3})
	train, truth := classes(payload, cover)
	test := rows([]float64{3, 1}, []float64{1, 0})
	equalTrain, equalTruth := classes(rows([]float64{1, 2}, []float64{3, 4}), rows([]float64{1, 4}, []float64{3, 2}))
	constant := rows([]float64{5, 1}, []float64{5, 1}, []float64{5, 1}, []float64{5, 1})
	tinyTrain, tinyTruth := classes(rows([]float64{2e-200}, []float64{4e-200}), rows([]float64{0}, []float64{1e-200}))
	subnormal := times(train, 1e-160)
	pivotTrain, pivotTruth := classes(rows([]float64{0, 1e-5}, []float64{2, 2 + 1e-5}), rows([]float64{0, 0}, []float64{2, 2}))
	for _, c := range []struct {
		name  string
		train [][]float64
		truth []bool
		test  [][]float64
	}{
		{"equal means", equalTrain, equalTruth, test},
		{"payload only", payload, []bool{true, true}, test},
		{"every column constant", constant, truth, test},
		{"NaN in train", rows([]float64{2, 0}, []float64{4, math.NaN()}, []float64{0, 1}, []float64{0, 3}), truth, test},
		{"+Inf in test", train, truth, rows([]float64{3, math.Inf(1)})},
		{"ragged rows", rows([]float64{2, 0}, []float64{4}, []float64{0, 1}, []float64{0, 3}), truth, test},
		{"test narrower than train", train, truth, rows([]float64{3})},
		{"truth of another length", train, truth[:3], test},
		{"empty train", nil, nil, test},
		{"empty test", train, truth, nil},
		{"underflowing column", tinyTrain, tinyTruth, rows([]float64{3e-200})},
		{"subnormal scatter", subnormal, truth, times(test, 1e-160)},
		{"just below the pivot tolerance", pivotTrain, pivotTruth, rows([]float64{1, 1 + 1e-5}, []float64{1, 1})},
	} {
		if got := metrics.DiscriminantScores(c.train, c.truth, c.test); got != nil {
			t.Errorf("%s: scores %v, want nil", c.name, got)
		}
	}
}

func TestKSDistanceKnownAnswer(t *testing.T) {
	var odd, even, halves []float64
	for k := 1; k <= 16; k++ {
		odd, even = append(odd, float64(2*k-1)), append(even, float64(2*k))
	}
	for k := 0; k < 40; k++ {
		halves = append(halves, 0.5+float64(k))
	}
	for _, c := range []struct {
		name string
		a, b []float64
		want float64
	}{
		// after 1: 1/4; after 2: 2/4; after 3: 3/4 - 1/4; after 4: 1 - 2/4;
		// after 5: 1/4; after 6: 0
		{"shifted", seq(1, 4), seq(3, 6), 0.5},
		// after 1: 1/4; after the group of 2s: 3/4 - 1/4; after 3: 1 - 3/4;
		// after 4: 0. A walk that took a's 2s first would report 3/4
		{"ties", []float64{1, 2, 2, 3}, []float64{2, 3, 3, 4}, 0.5},
		// F_a(4) - F_b(4) = 4/8. No p is given: the exact permutation p is
		// 1 - (paths inside |i - j| < 4)/C(16,8) = 1819/6435 = 0.2827, Stephens'
		// asymptotic p with lambda = (sqrt 4 + 0.12 + 0.11/2) 0.5 = 1.0875 gives
		// 0.1877; at 20 and 20, D = 2/5: exact 55309/682341 = 0.0811 against
		// 0.0591; at 8 and 9, D = 5/9: exact 191/2431 = 0.0786 against 0.0925,
		// above the exact value
		{"8 and 8", seq(1, 8), seq(5, 12), 0.5},
		// at 10: 1 - 10/40
		{"10 and 40", seq(1, 10), halves, 0.75},
		// at 2k-1: k/16 - (k-1)/16
		{"interleaved", odd, even, 1.0 / 16},
		// n = 2, m = 3, |i m - j n|/(n m): after 1: |3 - 0|/6; after 2:
		// |3 - 2|/6; after 3: |3 - 4|/6; after 4: |6 - 4|/6; after 5: 0
		{"unequal sizes", []float64{1, 4}, []float64{2, 3, 5}, 0.5},
		// one tie group; a bitwise comparison would give 1
		{"float tie", []float64{tenth + fifth}, []float64{0.3}, 0},
		{"same values", []float64{1, 2, 3}, []float64{3, 2, 1}, 0},
		{"separated", []float64{1, 2}, []float64{3, 4}, 1},
		// all pooled values equal: identical empirical distributions
		{"all equal", []float64{5, 5}, []float64{5, 5, 5}, 0},
	} {
		if got := metrics.KSDistance(c.a, c.b); !near(got, c.want) {
			t.Errorf("%s: D = %v, want %v", c.name, got, c.want)
		}
		if got := metrics.KSDistance(c.b, c.a); !near(got, c.want) {
			t.Errorf("%s swapped: D = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestKSDistanceUndefined(t *testing.T) {
	for _, c := range []struct{ a, b []float64 }{
		{nil, []float64{1}}, {[]float64{1}, nil}, {[]float64{1, math.NaN()}, []float64{2}}, {[]float64{1, math.Inf(1)}, []float64{2}},
	} {
		if got := metrics.KSDistance(c.a, c.b); !math.IsNaN(got) {
			t.Errorf("KSDistance(%v, %v) = %v, want NaN", c.a, c.b, got)
		}
	}
}

// a tie group whose smallest zero-based pooled rank is r goes whole into bin
// floor(bins r / N), N = n + m; TV = sum |ca_k m - cb_k n| / (2 n m)
func TestTotalVariationKnownAnswer(t *testing.T) {
	var odd, even []float64
	for k := 1; k <= 16; k++ {
		odd, even = append(odd, float64(2*k-1)), append(even, float64(2*k))
	}
	for _, c := range []struct {
		name string
		a, b []float64
		bins int
		want float64
	}{
		// N = 6, ranks 0..5 go to floor(3r/6) = 0,0,1,1,2,2: p = (1/2, 1/2, 0),
		// q = (1/4, 1/4, 1/2), TV = 1/2 (1/4 + 1/4 + 1/2)
		{"worked example", []float64{1, 3}, []float64{2, 4, 5, 6}, 3, 0.5},
		// N = 8, bin floor(r/2): the three 1s (r = 0) to bin 0, 2 (r = 3) to 1,
		// 3 (r = 4) and 4 (r = 5) to 2, 5 and 6 to 3; p = (1/2, 1/4, 1/4, 0),
		// q = (1/4, 0, 1/4, 1/2), TV = 1/2 (1/4 + 1/4 + 0 + 1/2)
		{"ties", []float64{1, 1, 2, 3}, []float64{1, 4, 5, 6}, 4, 0.5},
		// each bin holds 2j-1 and 2j: the supports are disjoint (KS 1/16), and
		// binning hides everything
		{"interleaved", odd, even, 16, 0},
		{"separated", seq(1, 16), seq(17, 32), 16, 1},
		// 1..8 only in a (bins 0..3, mass 1/2 of a), 9..16 one of each per bin
		// (bins 4..11), 17..24 only in b (bins 12..15, mass 1/2 of b)
		{"half overlap", seq(1, 16), seq(9, 24), 16, 0.5},
		// floor(16r/6) = 0,2,5,8,10,13: every value its own bin
		{"fewer values than bins", []float64{1, 3}, []float64{2, 4, 5, 6}, 16, 1},
		// bins past N = 6 change nothing, so every value its own bin as at 16
		{"bins at the int limit", []float64{1, 3}, []float64{2, 4, 5, 6}, math.MaxInt, 1},
		// groups at r = 0, 2, 4 go to bins 0, 5, 10: p = (1/2, 1/2, 0),
		// q = (1/4, 1/4, 1/2)
		{"tie groups across bins", []float64{1, 2}, []float64{1, 2, 3, 3}, 16, 0.5},
		{"two groups", []float64{1, 1}, []float64{2, 2, 2}, 16, 1},
		{"all equal", []float64{5, 5}, []float64{5, 5, 5}, 16, 0},
	} {
		if got := metrics.TotalVariation(c.a, c.b, c.bins); !near(got, c.want) {
			t.Errorf("%s: TV = %v, want %v", c.name, got, c.want)
		}
	}
}

// one bin can separate nothing, and its 0 would read as measured
func TestTotalVariationUndefined(t *testing.T) {
	for _, c := range []struct {
		a, b []float64
		bins int
	}{
		{nil, []float64{1}, 16}, {[]float64{math.NaN()}, []float64{1}, 16}, {[]float64{1}, []float64{2}, 1}, {[]float64{1}, []float64{2}, 0},
	} {
		if got := metrics.TotalVariation(c.a, c.b, c.bins); !math.IsNaN(got) {
			t.Errorf("TotalVariation(%v, %v, %d) = %v, want NaN", c.a, c.b, c.bins, got)
		}
	}
}

// the training rows of the DiscriminantScores cases: a constant column and a
// column that is an affine function of the ones before it are left out, the
// two-feature worked, separator, one column and pivot cases keep every
// column; in the two row case S_t has rank one and the second column's pivot
// is 8 - 16/2 = 0; one row makes every column constant
func TestUnusedColumnsKnownAnswer(t *testing.T) {
	nan := math.NaN()
	for _, c := range []struct {
		name  string
		train [][]float64
		want  []int
	}{
		{"two-feature worked case", rows([]float64{2, 0}, []float64{4, 0}, []float64{0, 1}, []float64{0, 3}), []int{}},
		{"constant column", rows([]float64{2, 0, 7}, []float64{4, 0, 7}, []float64{0, 1, 7}, []float64{0, 3, 7}), []int{2}},
		{"separator", rows([]float64{1, 5}, []float64{1, 7}, []float64{0, 4}, []float64{0, 6}), []int{}},
		{"collinear", rows([]float64{1, 3}, []float64{3, 7}, []float64{0, 1}, []float64{2, 5}), []int{1}},
		{"dependent column first", rows([]float64{2, 2, 0}, []float64{4, 4, 0}, []float64{1, 0, 1}, []float64{3, 0, 3}), []int{2}},
		{"two rows", rows([]float64{1, 2}, []float64{3, 6}), []int{1}},
		{"one column", rows([]float64{2}, []float64{4}, []float64{0}, []float64{0}), []int{}},
		{"float constant", rows([]float64{2, 0.3}, []float64{4, tenth + fifth}, []float64{0, 0.3}, []float64{0, 0.3}), []int{1}},
		{"just above the pivot tolerance", rows([]float64{0, 0.01}, []float64{2, 2.01}, []float64{0, 0}, []float64{2, 2}), []int{}},
		{"just below the pivot tolerance", rows([]float64{0, 1e-5}, []float64{2, 2 + 1e-5}, []float64{0, 0}, []float64{2, 2}), []int{1}},
		{"every column constant", rows([]float64{5, 1}, []float64{5, 1}, []float64{5, 1}, []float64{5, 1}), []int{0, 1}},
		{"one row", rows([]float64{3, 4}), []int{0, 1}},
	} {
		got := metrics.UnusedColumns(c.train)
		if got == nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: unused %v, want %v", c.name, got, c.want)
		}
	}
	for _, c := range []struct {
		name  string
		train [][]float64
	}{
		{"empty", nil},
		{"ragged", rows([]float64{2, 0}, []float64{4}, []float64{0, 1})},
		{"NaN", rows([]float64{2, 0}, []float64{4, nan})},
		{"width zero", rows([]float64{}, []float64{})},
		{"underflowing column", rows([]float64{2e-200}, []float64{4e-200}, []float64{0}, []float64{1e-200})},
		{"subnormal scatter", times(rows([]float64{2, 0}, []float64{4, 0}, []float64{0, 1}, []float64{0, 3}), 1e-160)},
	} {
		if got := metrics.UnusedColumns(c.train); got != nil {
			t.Errorf("%s: unused %v, want nil", c.name, got)
		}
	}
	// the two share one rule: every column UnusedColumns lists has weight 0,
	// so its unit row scores exactly as the zero row
	for _, c := range discriminantCases() {
		train, truth := classes(c.payload, c.cover)
		unused := metrics.UnusedColumns(train)
		if unused == nil {
			t.Errorf("%s: no columns, though DiscriminantScores scores it", c.name)
			continue
		}
		s := metrics.DiscriminantScores(train, truth, directionProbe(len(train[0])))
		for _, j := range unused {
			if s[j+1]-s[0] != 0 {
				t.Errorf("%s: column %d is unused but moves the score by %v", c.name, j, s[j+1]-s[0])
			}
		}
	}
}

// truth [T, F, F, T | F, T] over flows 0 and 1: row j of a flow takes the
// label of row (j + k) mod n of that flow. Offsets 1 and 1 turn flow 0 into
// F, F, T, T and flow 1 into T, F; 3 and 0 give T, T, F, F and F, T; 5 and -1
// equal 1 and 1 modulo 4 and 2
func TestCircularShiftKnownAnswer(t *testing.T) {
	truth := []bool{true, false, false, true, false, true}
	flow := []int{0, 0, 0, 0, 1, 1}
	before := slices.Clone(truth)
	for _, c := range []struct {
		name    string
		truth   []bool
		flow    []int
		offsets []int
		want    []bool
	}{
		{"one each", truth, flow, []int{1, 1}, []bool{false, false, true, true, true, false}},
		{"three and none", truth, flow, []int{3, 0}, []bool{true, true, false, false, false, true}},
		{"beyond the flow and negative", truth, flow, []int{5, -1}, []bool{false, false, true, true, true, false}},
		{"identity", truth, flow, []int{0, 0}, truth},
		// flow 0 holds rows 0 and 2, T and F; flow 1 rows 1 and 3, F and T
		{"interleaved flows", []bool{true, false, false, true}, []int{0, 1, 0, 1}, []int{1, 1}, []bool{false, true, true, false}},
	} {
		got := metrics.CircularShift(c.truth, c.flow, c.offsets)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		for f := range c.offsets {
			in, out := 0, 0
			for i := range c.flow {
				if c.flow[i] == f && c.truth[i] {
					in++
				}
				if c.flow[i] == f && got[i] {
					out++
				}
			}
			if in != out {
				t.Errorf("%s: flow %d holds %d true labels after the shift, %d before", c.name, f, out, in)
			}
		}
	}
	if !slices.Equal(truth, before) {
		t.Fatalf("the input changed to %v", truth)
	}
	if got := metrics.CircularShift(truth, []int{0, 0, 0, 0, 1, 2}, []int{1, 1}); got != nil {
		t.Errorf("a flow without an offset: %v, want nil", got)
	}
	if got := metrics.CircularShift(truth, flow[:5], []int{1, 1}); got != nil {
		t.Errorf("truth and flow of different lengths: %v, want nil", got)
	}
}
