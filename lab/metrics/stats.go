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
