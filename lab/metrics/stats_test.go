package metrics_test

import (
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func seq(from, to int) []float64 {
	out := make([]float64, 0, to-from+1)
	for v := from; v <= to; v++ {
		out = append(out, float64(v))
	}
	return out
}

func repeat(v float64, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func concat(parts ...[]float64) []float64 {
	var out []float64
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// relative, for p-values far below the absolute eps
func closeTo(a, b float64) bool { return math.Abs(a-b) <= 1e-9*math.Abs(b) }

func checkTest(t *testing.T, name string, got metrics.Test, stat, p, effect float64, method string) {
	t.Helper()
	if !near(got.Statistic, stat) || !closeTo(got.P, p) || !near(got.Effect, effect) || got.Method != method {
		t.Errorf("%s: got statistic %v, p %v, effect %v, %s; want %v, %v, %v, %s",
			name, got.Statistic, got.P, got.Effect, got.Method, stat, p, effect, method)
	}
}

func TestMannWhitneyExactKnownAnswer(t *testing.T) {
	cases := []struct {
		name         string
		x, y         []float64
		u, p, effect float64
	}{
		// every x below every y, so U = 0, nm/2 = 4.5 and delta = 2U/(nm) - 1 = -1.
		// of the C(6,3) = 20 splits only x = {1,2,3} (U = 0) and x = {4,5,6}
		// (U = 9) lie 4.5 from the mean: p = 2/20
		{"separated 3 and 3", seq(1, 3), seq(4, 6), 0, 0.1, -1},
		// U = 0, nm/2 = 3. of the C(5,3) = 10 splits only U = 0 and U = 6 lie 3
		// from the mean: p = 2/10. the normal approximation would give 0.149
		// here (z = 2.5/sqrt(3))
		{"separated 3 and 2", seq(1, 3), seq(4, 5), 0, 0.2, -1},
		// pooled 1 2 2 2 3 has midranks 1 3 3 3 5; R of x = 1+3+3 = 7, U = 7 - 6 = 1
		// (pairs: 1<2, 1<3, 2=2, 2<3, 2=2, 2<3 gives 0.5+0.5), delta = 2/6 - 1.
		// nm/2 = 3, so the observed U lies 2 away. the 10 splits of size 3:
		//   1, 5 and one 3: R = 9, U = 3, three splits, 0 away
		//   1 and two 3s:   R = 7, U = 1, three splits, 2 away
		//   5 and two 3s:   R = 11, U = 5, three splits, 2 away
		//   three 3s:       R = 9, U = 3, one split, 0 away
		// six splits lie at least 2 away: p = 6/10
		{"ties", []float64{1, 2, 2}, []float64{2, 3}, 1, 0.6, -2.0 / 3},
		// midranks 1.5 1.5 3; the three splits of size 2 give U = 0 once and
		// U = 1.5 twice, nm/2 = 1. only U = 0 lies 1 away: p = 1/3. the null
		// distribution is not symmetric, and doubling the lower tail would give 2/3
		{"ties, asymmetric null", []float64{1, 1}, []float64{2}, 0, 1.0 / 3, -1},
	}
	for _, c := range cases {
		checkTest(t, c.name, metrics.MannWhitney(c.x, c.y), c.u, c.p, c.effect, "exact")
	}
}

func TestMannWhitneyExactWithHeavyTies(t *testing.T) {
	// n = m = 7, x: one 0 and six 1s; y: five 0s and two 1s. with a 1s among
	// the 7 in x (and 8 - a in y), U = a(a-1) + (a(8-a) + (7-a)(a-1))/2 = 7a - 3.5,
	// so the observed a = 6 gives U = 38.5 and delta = 77/49 - 1 = 28/49. nm/2 =
	// 24.5 is a = 4, and |U - 24.5| >= 14 means a in {1, 2, 6, 7}. a is
	// hypergeometric: C(8,a) C(6,7-a) splits of C(14,7) = 3432, that is
	// 8 + 168 + 168 + 8 = 352: p = 352/3432 = 0.1026. the normal approximation
	// with tie and continuity corrections would give 0.0447 here
	x := []float64{0, 1, 1, 1, 1, 1, 1}
	y := []float64{0, 0, 0, 0, 0, 1, 1}
	checkTest(t, "binary 7 and 7", metrics.MannWhitney(x, y), 38.5, 352.0/3432, 28.0/49, "exact")

	// a series-sized case, 30 runs a side: x all at AUC 1, y 26 at 1 and 4 at
	// 0.9. with a of the four 0.9 values in x,
	// U = (30-a)(4-a) + ((30-a)(26+a) + a(4-a))/2 = 510 - 30a, the mean 450 is
	// a = 2, and only a = 0 or a = 4 lie the observed 60 away. P(a = 0) = P(a = 4) = C(56,30)/C(60,30) =
	// (30*29*28*27)/(60*59*58*57), so p = 2 * 657720/11703240 = 0.1124.
	// delta = 120/900 = 2/15, negligible. the normal approximation would give 0.0418
	y = concat(repeat(1, 26), repeat(0.9, 4))
	want := 2 * 657720.0 / 11703240
	checkTest(t, "30 and 30", metrics.MannWhitney(repeat(1, 30), y), 510, want, 2.0/15, "exact")
}

func TestMannWhitneyExactBound(t *testing.T) {
	// n = m = 50: min(n,m)(n+m) = 5000, the last exact size. every x below every
	// y, so U = 0, and only the lowest fifty and the highest fifty lie nm/2 =
	// 1250 away: p = 2/C(100,50)
	c := 1.0
	for i := 1; i <= 50; i++ {
		c = c * float64(50+i) / float64(i)
	}
	checkTest(t, "50 and 50", metrics.MannWhitney(seq(1, 50), seq(51, 100)), 0, 2/c, -1, "exact")

	// n = 50, m = 51: 50*101 = 5050, normal. U = 0, nm/2 = 1275, no ties, so the
	// variance is nm(n+m+1)/12 = 2550*102/12 = 21675 and z = 1274.5/sqrt(21675)
	want := math.Erfc(1274.5 / math.Sqrt(21675) / math.Sqrt2)
	checkTest(t, "50 and 51", metrics.MannWhitney(seq(1, 50), seq(51, 101)), 0, want, -1, "normal")
}

func TestMannWhitneyNormalWithTies(t *testing.T) {
	// n = m = 51, 51*102 = 5202, normal. x: 26 ones and 25 zeros; y: 20 ones
	// and 31 zeros. pooled 46 ones and 56 zeros. U = 26*31 + (26*20 + 25*31)/2
	// = 806 + 647.5 = 1453.5, nm/2 = 1300.5, so 153 away; delta = 306/2601.
	// ties: (46^3 - 46) + (56^3 - 56) = 97290 + 175560 = 272850, N(N-1) = 10302.
	// variance = 2601/12 * (103 - 272850/10302) = 16584.6, z = 152.5/128.78 =
	// 1.184, p about 0.236
	x := concat(repeat(1, 26), repeat(0, 25))
	y := concat(repeat(1, 20), repeat(0, 31))
	want := math.Erfc(152.5 / math.Sqrt(2601.0/12*(103-272850.0/10302)) / math.Sqrt2)
	checkTest(t, "binary 51 and 51", metrics.MannWhitney(x, y), 1453.5, want, 306.0/2601, "normal")

}

func TestMannWhitneyDegenerate(t *testing.T) {
	// one tie group: every split gives U = nm/2 (3 here, 1300.5 for 51 and 51),
	// so p = 1 and delta 0, and the comparison is marked to stay out of Holm
	checkTest(t, "small", metrics.MannWhitney(repeat(5, 2), repeat(5, 3)), 3, 1, 0, "degenerate")
	checkTest(t, "large", metrics.MannWhitney(repeat(0.5, 51), repeat(0.5, 51)), 1300.5, 1, 0, "degenerate")
	// 0.1 + 0.2 = 0.30000000000000004 in float64 is within 1e-9 of 0.3, so the
	// three values are one group: U = 1 = nm/2 (bit for bit it would be 1.5)
	a, b := 0.1, 0.2
	checkTest(t, "within 1e-9", metrics.MannWhitney([]float64{a + b, 0.3}, []float64{0.3}), 1, 1, 0, "degenerate")
}

func TestMannWhitneySymmetric(t *testing.T) {
	// swapping the samples turns U into nm - U = 6 - 1 = 5, flips delta, keeps p
	checkTest(t, "swapped ties", metrics.MannWhitney([]float64{2, 3}, []float64{1, 2, 2}), 5, 0.6, 2.0/3, "exact")
}

func TestMannWhitneyEffectIsCliffsDelta(t *testing.T) {
	// pairs counted one by one: x 4 6 9 against y 5 6 1 has above 4>1, 6>5,
	// 6>1, 9>5, 9>6, 9>1 (six), below 4<5, 4<6 (two), one tie 6=6: (6 - 2)/9
	got := metrics.MannWhitney([]float64{4, 6, 9}, []float64{5, 6, 1}).Effect
	if !near(got, 4.0/9) {
		t.Fatalf("delta = %v, want 4/9", got)
	}
}

func TestMannWhitneyUndefined(t *testing.T) {
	for name, got := range map[string]metrics.Test{
		"empty x": metrics.MannWhitney(nil, []float64{1}),
		"empty y": metrics.MannWhitney([]float64{1}, nil),
		"NaN":     metrics.MannWhitney([]float64{math.NaN(), 1}, []float64{2}),
	} {
		if !math.IsNaN(got.P) || !math.IsNaN(got.Statistic) || !math.IsNaN(got.Effect) {
			t.Errorf("%s: got %+v, want NaN", name, got)
		}
	}
}

func TestWilcoxonExactKnownAnswer(t *testing.T) {
	cases := []struct {
		name         string
		x, y         []float64
		w, p, effect float64
	}{
		// d = 1 2 3 4 5, all positive: W = 15 of the rank total 15, so the
		// rank-biserial (W - W-)/(W + W-) = 1; mean n(n+1)/4 = 7.5. of the 2^5 = 32
		// sign assignments only all plus (15) and all minus (0) lie 7.5 away:
		// p = 2/32
		{"all positive", seq(2, 6), repeat(1, 5), 15, 2.0 / 32, 1},
		// d = 0 1 -1 2 2 3; the zero is dropped, n' = 5. |d| = 1 1 2 2 3 gets
		// midranks 1.5 1.5 3.5 3.5 5, so W = 1.5 + 3.5 + 3.5 + 5 = 13.5, W- = 1.5,
		// effect 12/15; mean 5*6/4 = 7.5, 6 away. subsets of the ranks with sum
		// at most 1.5 are {}, {1.5}, {1.5}: three; their complements have sum at
		// least 13.5: three more. p = 6/32
		{"zero and ties", []float64{5, 6, 4, 7, 7, 8}, repeat(5, 6), 13.5, 6.0 / 32, 0.8},
		// eleven differences of one size, nine positive: every rank is 6, so
		// W = 6k with k the number of plus signs, binomial(11, 1/2). W = 54,
		// mean 33, and |6k - 33| >= 21 means k >= 9 or k <= 2:
		// 2 (C(11,9) + C(11,10) + C(11,11)) / 2048 = 134/2048 = 0.0654.
		// effect (54 - 12)/66 = 7/11. the normal approximation would give 0.039
		{"one size", concat(repeat(1, 9), repeat(-1, 2)), repeat(0, 11), 54, 134.0 / 2048, 7.0 / 11},
	}
	for _, c := range cases {
		checkTest(t, c.name, metrics.Wilcoxon(c.x, c.y), c.w, c.p, c.effect, "exact")
	}
}

func TestWilcoxonExactBound(t *testing.T) {
	// n' = 100, the last exact size. d = 1..100, all positive, W = 5050; only all
	// plus and all minus lie 2525 from the mean: p = 2/2^100
	checkTest(t, "100 pairs", metrics.Wilcoxon(seq(2, 101), repeat(1, 100)), 5050, math.Ldexp(2, -100), 1, "exact")

	// n' = 101, normal. d = 1..101, W = 5151, mean 101*102/4 = 2575.5, variance
	// 101*102*203/24 = 2091306/24 = 87137.75, z = (2575.5 - 0.5)/sqrt(87137.75)
	want := math.Erfc(2575 / math.Sqrt(87137.75) / math.Sqrt2)
	checkTest(t, "101 pairs", metrics.Wilcoxon(seq(2, 102), repeat(1, 101)), 5151, want, 1, "normal")
}

func TestWilcoxonNormalWithTies(t *testing.T) {
	// n' = 101, normal. fifty differences of size 1 (30 plus, 20 minus) take
	// ranks 1..50, midrank 25.5; fifty-one of size 2 (30 plus, 21 minus) take
	// 51..101, midrank 76. W = 30*25.5 + 30*76 = 3045 of the total 5151, effect
	// (2*3045 - 5151)/5151 = 939/5151; mean 2575.5, 469.5 away. variance
	// 87137.75 - ((50^3 - 50) + (51^3 - 51))/48 = 87137.75 - 5365.625 =
	// 81772.125, z = 469/285.96 = 1.640, p about 0.101
	d := concat(repeat(1, 30), repeat(-1, 20), repeat(2, 30), repeat(-2, 21))
	want := math.Erfc(469 / math.Sqrt(81772.125) / math.Sqrt2)
	checkTest(t, "two sizes", metrics.Wilcoxon(d, repeat(0, 101)), 3045, want, 939.0/5151, "normal")
}

func TestWilcoxonEqualWithin1e9(t *testing.T) {
	// 0.7 - 0.6 = 0.09999999999999998 and 0.7 - 0.8 = -0.10000000000000009 in
	// float64, within 1e-9 of each other, so they tie at rank 1.5 below the
	// third difference, 1, at rank 3: W = 1.5 + 3 = 4.5, W- = 1.5, effect 3/6
	// (with ranks 1, 2, 3 W would be 4). ranks 1.5 1.5 3, mean 3: the sums 0 1.5
	// 1.5 3 3 4.5 4.5 6 lie 3 1.5 1.5 0 0 1.5 1.5 3 away; six of eight at least
	// 1.5: p = 6/8
	checkTest(t, "tie", metrics.Wilcoxon([]float64{0.7, 0.7, 2}, []float64{0.6, 0.8, 1}), 4.5, 0.75, 0.5, "exact")

	// equal within 1e-9 of their size: 1 + 5e-10 against 1 and 1e6 + 5e-4
	// against 1e6 are dropped, 1 + 2e-9 against 1 and 1e6 + 2e-3 against 1e6 are
	// kept, so d is about 2e-9, 2e-3 and 1, ranks 1 2 3, all plus: W = 6, p = 2/8.
	// an absolute step of 1e-9 would keep 5e-4 and give n' = 4
	x := []float64{1 + 5e-10, 1e6 + 5e-4, 1 + 2e-9, 1e6 + 2e-3, 5}
	y := []float64{1, 1e6, 1, 1e6, 4}
	checkTest(t, "relative", metrics.Wilcoxon(x, y), 6, 0.25, 1, "exact")

	// equal infinities are a zero difference; Inf - 0 ranks above 1 - 0: W = 3
	// of 3, mean 1.5; the sums 0 1 2 3 lie 1.5 0.5 0.5 1.5 away: p = 2/4
	inf := math.Inf(1)
	checkTest(t, "infinite", metrics.Wilcoxon([]float64{inf, inf, 1}, []float64{inf, 0, 0}), 3, 0.5, 1, "exact")
}

func TestWilcoxonDegenerate(t *testing.T) {
	// no difference is left: W = 0, p = 1, effect 0, marked to stay out of Holm
	checkTest(t, "all zero", metrics.Wilcoxon(seq(1, 4), seq(1, 4)), 0, 1, 0, "degenerate")
}

func TestWilcoxonUndefined(t *testing.T) {
	for name, got := range map[string]metrics.Test{
		"empty":    metrics.Wilcoxon(nil, nil),
		"unpaired": metrics.Wilcoxon([]float64{1, 2}, []float64{1}),
		"NaN":      metrics.Wilcoxon([]float64{math.NaN(), 1}, []float64{0, 0}),
	} {
		if !math.IsNaN(got.P) || !math.IsNaN(got.Statistic) || !math.IsNaN(got.Effect) {
			t.Errorf("%s: got %+v, want NaN", name, got)
		}
	}
}

func TestEffectMagnitudeThresholds(t *testing.T) {
	cases := []struct {
		e    float64
		want string
	}{
		{0, "negligible"},
		{0.146, "negligible"},
		{0.147, "small"},
		{-0.329, "small"},
		{0.33, "medium"},
		{-0.473, "medium"},
		{0.474, "large"},
		{-1, "large"},
		// the effects above: 2/15 = 0.133, 939/5151 = 0.182, 28/49 = 0.571
		{2.0 / 15, "negligible"},
		{939.0 / 5151, "small"},
		{28.0 / 49, "large"},
	}
	for _, c := range cases {
		if got := metrics.EffectMagnitude(c.e); got != c.want {
			t.Errorf("magnitude of %v = %q, want %q", c.e, got, c.want)
		}
	}
	if got := metrics.EffectMagnitude(math.NaN()); got != "" {
		t.Errorf("magnitude of NaN = %q, want empty", got)
	}
}

func TestHolmKnownAnswer(t *testing.T) {
	cases := []struct {
		name    string
		p, want []float64
	}{
		// sorted: 0.005 (4th), 0.01 (1st), 0.03 (3rd), 0.04 (2nd), k = 4.
		// 4*0.005 = 0.02, 3*0.01 = 0.03, 2*0.03 = 0.06, 1*0.04 = 0.04 raised to
		// the running maximum 0.06. back in the given order: 0.03 0.06 0.06 0.02.
		// at 0.05 the step-down stops at 0.03 > 0.05/2, so 0.04 is kept although
		// it is below 0.05/1
		{"order", []float64{0.01, 0.04, 0.03, 0.005}, []float64{0.03, 0.06, 0.06, 0.02}},
		// 2*0.6 = 1.2 capped to 1, then 1*0.7 raised to 1
		{"cap", []float64{0.6, 0.7}, []float64{1, 1}},
		// 2*0.02 = 0.04, then 1*0.02 raised to 0.04: equal p get equal adjustments
		{"ties", []float64{0.02, 0.02}, []float64{0.04, 0.04}},
		{"single", []float64{0.03}, []float64{0.03}},
		{"empty", nil, nil},
	}
	for _, c := range cases {
		got := metrics.Holm(c.p)
		if len(got) != len(c.want) {
			t.Fatalf("%s: %d values, want %d", c.name, len(got), len(c.want))
		}
		for i := range got {
			if !near(got[i], c.want[i]) {
				t.Errorf("%s: adjusted %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestHolmUndefined(t *testing.T) {
	for _, v := range metrics.Holm([]float64{0.01, math.NaN()}) {
		if !math.IsNaN(v) {
			t.Fatal("a family with an undefined p has no defined correction")
		}
	}
}
