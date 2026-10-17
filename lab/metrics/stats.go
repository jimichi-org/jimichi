package metrics

import (
	"math"
	"sort"
)

// Effect is Cliff's delta for MannWhitney and the matched-pairs rank-biserial
// correlation for Wilcoxon, both from -1 to 1
type Test struct {
	Statistic float64
	P         float64
	Effect    float64
	Method    string
}

// up to these sizes the null distribution is counted exactly; with the heavy
// ties of per-run metrics the normal approximation gives too small a p
const (
	exactMannWhitney = 5000 // min(n, m) * (n + m)
	exactWilcoxon    = 100  // nonzero differences
)

func undefinedTest() Test {
	return Test{Statistic: math.NaN(), P: math.NaN(), Effect: math.NaN()}
}

func hasNaN(v []float64) bool {
	for _, x := range v {
		if math.IsNaN(x) {
			return true
		}
	}
	return false
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// the same number reached by different arithmetic differs in the last bits, so
// values within 1e-9 of the larger count as equal; this is not transitive, and
// a tie group starts at its smallest value
func same(a, b float64) bool {
	if a == b {
		return true
	}
	if math.IsInf(a, 0) || math.IsInf(b, 0) {
		return false
	}
	return math.Abs(a-b) <= 1e-9*math.Max(math.Abs(a), math.Abs(b))
}

// midranks doubled so that tied ranks stay integers and sums compare exactly;
// ties is the sum of t^3 - t over groups of t equal values
func doubledRanks(v []float64) (ranks []int, ties float64) {
	order := make([]int, len(v))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return v[order[a]] < v[order[b]] })

	ranks = make([]int, len(v))
	for i := 0; i < len(order); {
		j := i
		for j+1 < len(order) && same(v[order[j+1]], v[order[i]]) {
			j++
		}
		for k := i; k <= j; k++ {
			ranks[order[k]] = i + j + 2
		}
		t := float64(j - i + 1)
		ties += t*t*t - t
		i = j + 1
	}
	return ranks, ties
}

// how many subsets of k ranks reach each sum; float64 because the counts
// outgrow int64 from about thirty-four values a side
func subsetSums(ranks []int, k int) []float64 {
	top := append([]int(nil), ranks...)
	sort.Sort(sort.Reverse(sort.IntSlice(top)))
	limit := 0
	for _, r := range top[:k] {
		limit += r
	}
	f := make([][]float64, k+1)
	for j := range f {
		f[j] = make([]float64, limit+1)
	}
	f[0][0] = 1
	for i, r := range ranks {
		for j := min(i+1, k); j >= 1; j-- {
			prev, cur := f[j-1], f[j]
			for s := limit; s >= r; s-- {
				cur[s] += prev[s-r]
			}
		}
	}
	return f[k]
}

// a single tie group: nothing can separate the samples, and the comparison
// stays out of the Holm family
func degenerate(ranks []int) bool {
	for _, r := range ranks {
		if r != len(ranks)+1 {
			return false
		}
	}
	return true
}

// two-sided p of a statistic dev away from its mean, with the 0.5 continuity
// correction; without spread every relabelling gives the observed value
func normalTail(dev, variance float64) float64 {
	if variance <= 0 {
		return 1
	}
	z := math.Max(dev-0.5, 0) / math.Sqrt(variance)
	return math.Erfc(z / math.Sqrt2)
}

// Statistic is U of x: pairs with x above y plus half the tied pairs. the
// two-sided p counts splits at least as far from nm/2 as the observed U; with
// ties the null distribution need not be symmetric, and doubling one tail would
// disagree with the |z| of the normal branch
func MannWhitney(x, y []float64) Test {
	n, m := len(x), len(y)
	if n == 0 || m == 0 || hasNaN(x) || hasNaN(y) {
		return undefinedTest()
	}
	pooled := make([]float64, 0, n+m)
	pooled = append(append(pooled, x...), y...)
	ranks, ties := doubledRanks(pooled)

	// 2U = 2R - n(n+1), with R the rank sum of x
	r := 0
	for _, v := range ranks[:n] {
		r += v
	}
	u2 := r - n*(n+1)
	dev := absInt(u2 - n*m)
	out := Test{
		Statistic: float64(u2) / 2,
		Effect:    float64(u2-n*m) / float64(n*m),
	}
	if degenerate(ranks) {
		out.P = 1
		out.Method = "degenerate"
		return out
	}

	// the smaller group gives the same distances from nm/2 with a smaller table
	if k := min(n, m); k*(n+m) <= exactMannWhitney {
		var hits, total float64
		for s, c := range subsetSums(ranks, k) {
			total += c
			if absInt(s-k*(k+1)-n*m) >= dev {
				hits += c
			}
		}
		out.P = hits / total
		out.Method = "exact"
		return out
	}
	size := float64(n + m)
	variance := float64(n*m) / 12 * (size + 1 - ties/(size*(size-1)))
	out.P = normalTail(float64(dev)/2, variance)
	out.Method = "normal"
	return out
}

// Statistic is W, the rank sum of the positive differences x - y. pairs with
// equal values are dropped; with none left the comparison is degenerate
func Wilcoxon(x, y []float64) Test {
	if len(x) == 0 || len(x) != len(y) || hasNaN(x) || hasNaN(y) {
		return undefinedTest()
	}
	var d []float64
	for i := range x {
		if !same(x[i], y[i]) {
			d = append(d, x[i]-y[i])
		}
	}
	n := len(d)
	magnitudes := make([]float64, n)
	for i, v := range d {
		magnitudes[i] = math.Abs(v)
	}
	ranks, ties := doubledRanks(magnitudes)

	w2 := 0
	for i, v := range d {
		if v > 0 {
			w2 += ranks[i]
		}
	}
	// the doubled ranks sum to n(n+1), so 2W has mean n(n+1)/2
	total2 := n * (n + 1)
	mean2 := total2 / 2
	dev := absInt(w2 - mean2)
	out := Test{Statistic: float64(w2) / 2}
	if n == 0 {
		out.P = 1
		out.Method = "degenerate"
		return out
	}
	out.Effect = float64(2*w2-total2) / float64(total2)

	if n <= exactWilcoxon {
		counts := make([]float64, total2+1)
		counts[0] = 1
		reach := 0
		for _, r := range ranks {
			reach += r
			for s := reach; s >= r; s-- {
				counts[s] += counts[s-r]
			}
		}
		var hits, all float64
		for s, c := range counts {
			all += c
			if absInt(s-mean2) >= dev {
				hits += c
			}
		}
		out.P = hits / all
		out.Method = "exact"
		return out
	}
	k := float64(n)
	variance := k*(k+1)*(2*k+1)/24 - ties/48
	out.P = normalTail(float64(dev)/2, variance)
	out.Method = "normal"
	return out
}

// thresholds of Romano et al. (2006) for Cliff's delta, used for the paired
// rank-biserial as well; empty for an undefined effect
func EffectMagnitude(e float64) string {
	switch a := math.Abs(e); {
	case math.IsNaN(a):
		return ""
	case a < 0.147:
		return "negligible"
	case a < 0.33:
		return "small"
	case a < 0.474:
		return "medium"
	default:
		return "large"
	}
}

func twoSided(level float64) float64 { return math.Sqrt2 * math.Erfinv(level) }

// unlike p +- z sqrt(p(1-p)/n) it keeps a width at x = 0 and x = n and stays in
// [0, 1] (Brown, Cai and DasGupta, 2001); rounding leaves the raw bound up to
// about 1e-16 off 0 or 1, either way, so both are set exactly
func WilsonInterval(x, n int, level float64) Interval {
	nan := math.NaN()
	if n < 1 || x < 0 || x > n {
		return Interval{Point: nan, Low: nan, High: nan, Method: "wilson"}
	}
	p := float64(x) / float64(n)
	out := Interval{Point: p, Low: nan, High: nan, Method: "wilson"}
	if !(level > 0 && level < 1) {
		return out
	}
	z, size := twoSided(level), float64(n)
	d := 1 + z*z/size
	center := (p + z*z/(2*size)) / d
	half := z / d * math.Sqrt(p*(1-p)/size+z*z/(4*size*size))
	out.Low, out.High = 0, 1
	if x > 0 {
		out.Low = math.Max(center-half, 0)
	}
	if x < n {
		out.High = math.Min(center+half, 1)
	}
	return out
}

// the quantile is normal, not Student's: at the block 3 sizes (533 and more) t
// is wider by under half a percent (0.45 percent at n = 533, 0.24 at n = 1000,
// at the level for 14 claims); it is not meant for the 30 runs of a point,
// where t is wider by 8.8 percent at that level and 4.4 at 0.95. Constant
// input is returned as is, since a two-pass mean of equal values can miss them
// by an ulp ({0.2} x 7 gives 0.19999999999999998)
func MeanInterval(values []float64, level float64) Interval {
	nan := math.NaN()
	undefinedMean := Interval{Point: nan, Low: nan, High: nan, Method: "normal"}
	if len(values) == 0 {
		return undefinedMean
	}
	var sum float64
	constant := true
	for _, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return undefinedMean
		}
		sum += v
		constant = constant && v == values[0]
	}
	n := float64(len(values))
	mean := sum / n
	if constant {
		mean = values[0]
	}
	if math.IsInf(mean, 0) {
		return undefinedMean
	}
	out := Interval{Point: mean, Low: nan, High: nan, Method: "normal"}
	if len(values) == 1 || !(level > 0 && level < 1) {
		return out
	}
	if constant {
		out.Low, out.High = mean, mean
		return out
	}
	var squares float64
	for _, v := range values {
		squares += (v - mean) * (v - mean)
	}
	s := math.Sqrt(squares / (n - 1))
	if math.IsInf(s, 0) {
		return undefinedMean
	}
	half := twoSided(level) * s / math.Sqrt(n)
	out.Low, out.High = mean-half, mean+half
	return out
}

// a bound no order statistic reaches at this n is NaN, not an infinite bound
func QuantileInterval(values []float64, q, level float64) Interval {
	nan := math.NaN()
	undefinedQuantile := Interval{Point: nan, Low: nan, High: nan, Method: "order"}
	if len(values) == 0 || !(q > 0 && q < 1) {
		return undefinedQuantile
	}
	for _, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return undefinedQuantile
		}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	var point float64
	if q == 0.5 {
		// computed as Median computes it, so a summary median does not move by an ulp
		point = middle(sorted)
	} else {
		point = quantile(sorted, q)
	}
	if math.IsNaN(point) || math.IsInf(point, 0) {
		return undefinedQuantile
	}
	out := Interval{Point: point, Low: nan, High: nan, Method: "order"}
	if !(level > 0 && level < 1) {
		return out
	}
	n := len(sorted)
	// the tails from Lgamma and Exp are a few ulp off, and a tail exactly at
	// alpha/2 must not fall on the wrong side by rounding
	half := (1 - level) / 2 * (1 + 1e-12)
	pmf := binomialPMF(n, q)
	below := 0.0
	for l := 1; l <= n; l++ {
		below += pmf[l-1]
		if below > half {
			break
		}
		out.Low = sorted[l-1]
	}
	above := 0.0
	for u := n; u >= 1; u-- {
		above += pmf[u]
		if above > half {
			break
		}
		out.High = sorted[u-1]
	}
	return out
}

func binomialPMF(n int, q float64) []float64 {
	pmf := make([]float64, n+1)
	all, _ := math.Lgamma(float64(n + 1))
	for k := range pmf {
		a, _ := math.Lgamma(float64(k + 1))
		b, _ := math.Lgamma(float64(n - k + 1))
		pmf[k] = math.Exp(all - a - b + float64(k)*math.Log(q) + float64(n-k)*math.Log1p(-q))
	}
	return pmf
}

// "not shown" says only that agreement was not shown, not that the value
// differs
func Equivalence(iv Interval, model, margin float64) string {
	if math.IsNaN(iv.Low) || math.IsNaN(iv.High) || math.IsNaN(model) || math.IsNaN(margin) || margin < 0 || math.IsInf(margin, 0) {
		return ""
	}
	if model-margin <= iv.Low && iv.High <= model+margin {
		return "equivalent"
	}
	return "not shown"
}

// the model sd is known before the series, so the size needs no pilot; a
// normal approximation, and near 0 or 1 the exact power of the Wilson claim
// falls a few points short
func EquivalenceSize(sd, margin float64, claims int, power float64) (int, bool) {
	if !(sd > 0) || !(margin > 0) || math.IsInf(margin, 0) || claims < 1 || !(power > 0 && power < 1) {
		return 0, false
	}
	z := twoSided(1-0.05/float64(claims)) + twoSided(power)
	n := math.Ceil(math.Pow(sd*z/margin, 2))
	if !(n < 1<<53) {
		return 0, false
	}
	return max(30, int(n)), true
}

// adjusted p-values in the order given. a family holding an undefined p has
// no defined correction, so every value is NaN then
func Holm(p []float64) []float64 {
	k := len(p)
	out := make([]float64, k)
	if hasNaN(p) {
		for i := range out {
			out[i] = math.NaN()
		}
		return out
	}
	order := make([]int, k)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return p[order[a]] < p[order[b]] })

	running := 0.0
	for j, i := range order {
		running = math.Max(running, math.Min(float64(k-j)*p[i], 1))
		out[i] = running
	}
	return out
}

// Holm over the comparisons that can be tested: a degenerate or undefined one
// gets NaN and does not count in the size of the family
func HolmTests(tests []Test) []float64 {
	out := make([]float64, len(tests))
	var members []int
	var p []float64
	for i, t := range tests {
		out[i] = math.NaN()
		if t.Method == "degenerate" || math.IsNaN(t.P) {
			continue
		}
		members = append(members, i)
		p = append(p, t.P)
	}
	for k, adjusted := range Holm(p) {
		out[members[k]] = adjusted
	}
	return out
}
