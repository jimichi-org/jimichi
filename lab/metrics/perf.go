package metrics

import (
	"math"
	"math/rand/v2"
	"time"
)

// events per second inside [from, to), the half-open window of CellsWithin;
// NaN for an empty or reversed window
func RateWithin(times []time.Duration, from, to time.Duration) float64 {
	if to <= from {
		return math.NaN()
	}
	n := 0
	for _, t := range times {
		if t >= from && t < to {
			n++
		}
	}
	return float64(n) / (to - from).Seconds()
}

// a counter that went backwards was reset or belongs to another process
func CounterRate(before, after uint64, wall time.Duration) float64 {
	if wall <= 0 || after < before {
		return math.NaN()
	}
	return float64(after-before) / wall.Seconds()
}

// per flow 0..n-1, the times inside [from, to); flows[i] is the flow of
// times[i], and nil comes back when the two do not pair up
func CountsWithin(times []time.Duration, flows []int, n int, from, to time.Duration) []int {
	if len(times) != len(flows) || n < 0 {
		return nil
	}
	counts := make([]int, n)
	for i, t := range times {
		if f := flows[i]; f >= 0 && f < n && t >= from && t < to {
			counts[f]++
		}
	}
	return counts
}

// payload bytes per second per flow, as the mean over flows and the slowest
// flow; an echo carries the same bytes back and is not counted twice
func Goodput(counts []int, payload int, window time.Duration) (mean, min float64) {
	if len(counts) == 0 || window <= 0 {
		return math.NaN(), math.NaN()
	}
	sum, low := 0, counts[0]
	for _, c := range counts {
		sum += c
		low = minInt(low, c)
	}
	s := window.Seconds()
	return float64(sum*payload) / (s * float64(len(counts))), float64(low*payload) / s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// the share of cores busy, 1 when every core ran the whole time
func Utilisation(cpu, wall time.Duration, cores int) float64 {
	if wall <= 0 || cores < 1 {
		return math.NaN()
	}
	return float64(cpu) / (float64(wall) * float64(cores))
}

// core-nanoseconds per cell
func CostPerCell(cpu time.Duration, cells uint64) float64 {
	if cells == 0 {
		return math.NaN()
	}
	return float64(cpu) / float64(cells)
}

// which side ran out of processor first: the node when its CPUs are busy,
// otherwise the generator when its are; "other" names neither, since a node
// held by a lock and a generator held by a serial step look alike from here
func Bound(node, parent, threshold float64) string {
	switch {
	case math.IsNaN(node) || math.IsNaN(parent) || math.IsNaN(threshold):
		return ""
	case node >= threshold:
		return "node_cpu"
	case parent >= threshold:
		return "generator"
	}
	return "other"
}

// throughput on n cores against n times that on one; 1 is linear
func Scaling(x1, xn float64, n int) float64 {
	if !(x1 > 0) || n < 1 || math.IsNaN(xn) {
		return math.NaN()
	}
	return xn / (float64(n) * x1)
}

// pairwise num[i]/den[i]; a pair with an undefined side or a denominator that
// is not positive is dropped and counted
func Ratios(num, den []float64) (r []float64, dropped int) {
	n := minInt(len(num), len(den))
	dropped = max(len(num), len(den)) - n
	for i := 0; i < n; i++ {
		if math.IsNaN(num[i]) || math.IsNaN(den[i]) || !(den[i] > 0) {
			dropped++
			continue
		}
		r = append(r, num[i]/den[i])
	}
	return r, dropped
}

// pairwise x[i]-y[i], dropping and counting pairs with an undefined side
func Differences(x, y []float64) (d []float64, dropped int) {
	n := minInt(len(x), len(y))
	dropped = max(len(x), len(y)) - n
	for i := 0; i < n; i++ {
		if math.IsNaN(x[i]) || math.IsNaN(y[i]) {
			dropped++
			continue
		}
		d = append(d, x[i]-y[i])
	}
	return d, dropped
}

// the last step of a ladder is a plateau when it stays within tol of the step
// before, in either direction: a fall at the last step is a decline, not
// saturation. The last step and not the maximum is taken, since the maximum
// of noisy medians is biased upwards
func Plateau(medians []float64, tol float64) (ok bool, reason string) {
	k := len(medians)
	if k < 2 {
		return false, "short"
	}
	last, prev := medians[k-1], medians[k-2]
	if math.IsNaN(last) || math.IsNaN(prev) || !(last > 0) || !(prev > 0) || math.IsNaN(tol) {
		return false, "undefined"
	}
	switch {
	case math.Abs(last-prev) <= tol*prev:
		return true, ""
	case last > prev:
		return false, "rising"
	}
	return false, "declined"
}

// a quantile q is reported only with at least ceil(10/(1-q)) samples, so on
// average ten order statistics lie above it. The quotient in float64 can land
// just above an integer, 10/(1-0.9) is 100.00000000000003, and ceil would
// then ask for one sample more
func TailPercentile(samples []time.Duration, q float64) (time.Duration, bool) {
	if !(q > 0 && q < 1) {
		return 0, false
	}
	if float64(len(samples)) < math.Ceil(10/(1-q)-1e-9) {
		return 0, false
	}
	return Percentile(samples, q)
}

// cores of work on the run's CPUs that its own processes did not account for
func ForeignCores(busy, own, wall time.Duration) float64 {
	if wall <= 0 {
		return math.NaN()
	}
	return float64(max(0, busy-own)) / float64(wall)
}

// the share of time a node holds two onion keys
func DutyCycle(hold, period time.Duration) float64 {
	if !(hold > 0 && hold <= period) {
		return math.NaN()
	}
	return float64(hold) / float64(period)
}

// mean setup cost when setups arrive evenly over the rotation period; a model,
// not a measurement
func ExpectedSetup(one, two, duty float64) float64 {
	return (1-duty)*one + duty*two
}

// the share of resamples of size n in which the claim of no effect is made:
// the pilot is centred on its median, so the power is that at no effect with
// the spread of the pilot, and every resample is judged by the order interval
// of the median and Equivalence with model 1. NaN when it cannot be computed
func EquivalencePower(pilot []float64, n int, level, margin float64, draws int, seed uint64) float64 {
	if len(pilot) == 0 || n < 1 || draws < 1 || !(level > 0 && level < 1) || !(margin >= 0) || math.IsInf(margin, 0) {
		return math.NaN()
	}
	for _, v := range pilot {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return math.NaN()
		}
	}
	centre := Median(pilot)
	if !(centre > 0) {
		return math.NaN()
	}
	// the interval takes the order statistics at positions that depend only on
	// n and the level, so a resample is equivalent exactly when fewer than low
	// of its values fall under the corridor and no more than n-high over it;
	// counting decides what sorting every resample would, at a fraction of the
	// cost
	low, high, defined := orderPositions(n, level)
	if !defined {
		return 0
	}
	lo, hi := 1-margin, 1+margin
	side := make([]int8, len(pilot))
	for i, v := range pilot {
		switch c := v / centre; {
		case c < lo:
			side[i] = -1
		case c > hi:
			side[i] = 1
		}
	}
	r := rand.New(rand.NewPCG(seed, 0))
	hits := 0
	for range draws {
		under, over := 0, 0
		for range n {
			switch side[r.IntN(len(side))] {
			case -1:
				under++
			case 1:
				over++
			}
		}
		if under < low && over <= n-high {
			hits++
		}
	}
	return float64(hits) / float64(draws)
}

// the 1-based positions QuantileInterval takes for the median of n values at
// this level, read off the interval of the ranks 1..n
func orderPositions(n int, level float64) (low, high int, defined bool) {
	ranks := make([]float64, n)
	for i := range ranks {
		ranks[i] = float64(i + 1)
	}
	iv := QuantileInterval(ranks, 0.5, level)
	if math.IsNaN(iv.Low) || math.IsNaN(iv.High) {
		return 0, 0, false
	}
	return int(iv.Low), int(iv.High), true
}

// the smallest number of repeats in 1..max whose EquivalencePower reaches
// power; the caller takes the larger of it and the 30 repeats of a series
func RepeatsForPower(pilot []float64, level, margin, power float64, draws, max int, seed uint64) (int, bool) {
	if !(power > 0 && power <= 1) || max < 1 {
		return 0, false
	}
	for n := 1; n <= max; n++ {
		p := EquivalencePower(pilot, n, level, margin, draws, seed)
		if math.IsNaN(p) {
			return 0, false
		}
		if p >= power {
			return n, true
		}
	}
	return 0, false
}
