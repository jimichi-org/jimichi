package metrics_test

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// {0.5, 1, 1.5, 2, 2.5} s in [1 s, 2 s): 1 and 1.5 are inside, 2 is on the
// open end; 2 events over 1 s is 2 per second
func TestRateWithinKnownAnswer(t *testing.T) {
	s := time.Second
	times := []time.Duration{s / 2, s, 3 * s / 2, 2 * s, 5 * s / 2}
	if got := metrics.RateWithin(times, s, 2*s); !near(got, 2) {
		t.Fatalf("RateWithin = %v, want 2", got)
	}
	if got := metrics.RateWithin(times, 2*s, 2*s); !math.IsNaN(got) {
		t.Fatalf("RateWithin of an empty window = %v, want NaN", got)
	}
}

// 1000 to 31000 over 2 s is 30000/2 = 15000 per second; a counter that went
// down or no time between the readings is undefined
func TestCounterRateKnownAnswer(t *testing.T) {
	if got := metrics.CounterRate(1000, 31000, 2*time.Second); !near(got, 15000) {
		t.Fatalf("CounterRate = %v, want 15000", got)
	}
	if got := metrics.CounterRate(31000, 1000, 2*time.Second); !math.IsNaN(got) {
		t.Fatalf("CounterRate backwards = %v, want NaN", got)
	}
	if got := metrics.CounterRate(1000, 31000, 0); !math.IsNaN(got) {
		t.Fatalf("CounterRate at no wall = %v, want NaN", got)
	}
}

// times {1, 1.5, 2.5} s of flows {0, 1, 0} in [1 s, 2 s): flow 0 keeps 1 s,
// flow 1 keeps 1.5 s, 2.5 s is outside: {1, 1}
func TestCountsWithinKnownAnswer(t *testing.T) {
	s := time.Second
	got := metrics.CountsWithin([]time.Duration{s, 3 * s / 2, 5 * s / 2}, []int{0, 1, 0}, 2, s, 2*s)
	if !slices.Equal(got, []int{1, 1}) {
		t.Fatalf("CountsWithin = %v, want [1 1]", got)
	}
	if got := metrics.CountsWithin([]time.Duration{s}, nil, 1, 0, 2*s); got != nil {
		t.Fatalf("CountsWithin of unpaired slices = %v, want nil", got)
	}
}

// counts {100, 150, 200} of 444 bytes over 2 s: 22200, 33300 and 44400 B/s per
// flow; mean 450*444/(2*3) = 33300, min 22200
func TestGoodputKnownAnswer(t *testing.T) {
	mean, low := metrics.Goodput([]int{100, 150, 200}, 444, 2*time.Second)
	if !near(mean, 33300) || !near(low, 22200) {
		t.Fatalf("Goodput = %v, %v, want 33300, 22200", mean, low)
	}
	if mean, low := metrics.Goodput(nil, 444, 2*time.Second); !math.IsNaN(mean) || !math.IsNaN(low) {
		t.Fatalf("Goodput of no flow = %v, %v, want NaN", mean, low)
	}
	if mean, _ := metrics.Goodput([]int{1}, 444, 0); !math.IsNaN(mean) {
		t.Fatalf("Goodput of no window = %v, want NaN", mean)
	}
}

// 3.6 s of processor over 1 s on 4 cores is 3.6/4 = 0.9
func TestUtilisationKnownAnswer(t *testing.T) {
	if got := metrics.Utilisation(3600*time.Millisecond, time.Second, 4); !near(got, 0.9) {
		t.Fatalf("Utilisation = %v, want 0.9", got)
	}
	if got := metrics.Utilisation(time.Second, time.Second, 0); !math.IsNaN(got) {
		t.Fatalf("Utilisation on no core = %v, want NaN", got)
	}
	if got := metrics.Utilisation(time.Second, 0, 1); !math.IsNaN(got) {
		t.Fatalf("Utilisation over no wall = %v, want NaN", got)
	}
}

// 1.5 s over 300000 cells is 1.5e9/3e5 = 5000 ns per cell
func TestCostPerCellKnownAnswer(t *testing.T) {
	if got := metrics.CostPerCell(1500*time.Millisecond, 300000); !near(got, 5000) {
		t.Fatalf("CostPerCell = %v, want 5000", got)
	}
	if got := metrics.CostPerCell(time.Second, 0); !math.IsNaN(got) {
		t.Fatalf("CostPerCell of no cell = %v, want NaN", got)
	}
}

// threshold 0.9: the node at 0.95 and at exactly 0.9 is node_cpu, the edge is
// in; the node at 0.5 with the parent at 0.95 is generator; both at 0.5 is
// other; an undefined node is ""
func TestBoundKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		node, parent float64
		want         string
	}{
		{0.95, 0.5, "node_cpu"},
		{0.9, 0.2, "node_cpu"},
		{0.5, 0.95, "generator"},
		{0.5, 0.5, "other"},
		{math.NaN(), 0.5, ""},
	} {
		if got := metrics.Bound(c.node, c.parent, 0.9); got != c.want {
			t.Fatalf("Bound(%v, %v) = %q, want %q", c.node, c.parent, got, c.want)
		}
	}
}

// 36000 on 4 cores against 10000 on one: 36000/(4*10000) = 0.9
func TestScalingKnownAnswer(t *testing.T) {
	if got := metrics.Scaling(10000, 36000, 4); !near(got, 0.9) {
		t.Fatalf("Scaling = %v, want 0.9", got)
	}
	if got := metrics.Scaling(0, 36000, 4); !math.IsNaN(got) {
		t.Fatalf("Scaling from zero = %v, want NaN", got)
	}
}

// {2, 3, NaN, 4} over {1, 0, 1, 2}: 2/1 = 2, 3/0 dropped, NaN dropped,
// 4/2 = 2: {2, 2} and 2 dropped
func TestRatiosKnownAnswer(t *testing.T) {
	r, dropped := metrics.Ratios([]float64{2, 3, math.NaN(), 4}, []float64{1, 0, 1, 2})
	if !nearAll(r, []float64{2, 2}) || dropped != 2 {
		t.Fatalf("Ratios = %v, %d dropped, want [2 2], 2", r, dropped)
	}
}

// {150, 170, NaN} - {100, 110, 120}: {50, 60} and 1 dropped
func TestDifferencesKnownAnswer(t *testing.T) {
	d, dropped := metrics.Differences([]float64{150, 170, math.NaN()}, []float64{100, 110, 120})
	if !nearAll(d, []float64{50, 60}) || dropped != 1 {
		t.Fatalf("Differences = %v, %d dropped, want [50 60], 1", d, dropped)
	}
}

// tol 0.05: |204-200| = 4 <= 10 is a plateau; 200-180 = 20 > 9 is rising;
// |190-200| = 10 <= 10 is a plateau, the edge is in; 1200 < 0.95*1900 = 1805
// and 50 < 190 are declines; one step is short; NaN is undefined
func TestPlateauKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		medians []float64
		ok      bool
		reason  string
	}{
		{[]float64{100, 180, 200, 204}, true, ""},
		{[]float64{100, 180, 200}, false, "rising"},
		{[]float64{100, 200, 190}, true, ""},
		{[]float64{1000, 1900, 1200}, false, "declined"},
		{[]float64{100, 200, 50}, false, "declined"},
		{[]float64{100}, false, "short"},
		{[]float64{100, math.NaN()}, false, "undefined"},
	} {
		ok, reason := metrics.Plateau(c.medians, 0.05)
		if ok != c.ok || reason != c.reason {
			t.Fatalf("Plateau(%v) = %v, %q, want %v, %q", c.medians, ok, reason, c.ok, c.reason)
		}
	}
}

// the rule asks for ceil(10/(1-q)) samples: 1000 at q 0.99, 20 at q 0.5. At
// q 0.9 the quotient is 100.00000000000003 in float64, and with the 1e-9
// correction the bound is 100, not 101. 1..20 ms at q 0.5: position
// 19*0.5 = 9.5 counted from 0, half way between 10 and 11 ms, 10.5 ms
func TestTailPercentileKnownAnswer(t *testing.T) {
	ms := func(n int) []time.Duration {
		out := make([]time.Duration, n)
		for i := range out {
			out[i] = time.Duration(i+1) * time.Millisecond
		}
		return out
	}
	q := 0.9
	if v := 10 / (1 - q); v != 100.00000000000003 {
		t.Fatalf("10/(1-0.9) = %v in float64, the case this test pins", v)
	}
	for _, c := range []struct {
		q    float64
		n    int
		want bool
	}{
		{0.99, 999, false}, {0.99, 1000, true},
		{0.5, 19, false}, {0.5, 20, true},
		{0.9, 99, false}, {0.9, 100, true},
	} {
		if _, ok := metrics.TailPercentile(ms(c.n), c.q); ok != c.want {
			t.Fatalf("TailPercentile(n %d, q %v) defined = %v, want %v", c.n, c.q, ok, c.want)
		}
	}
	if got, ok := metrics.TailPercentile(ms(20), 0.5); !ok || got != 10500*time.Microsecond {
		t.Fatalf("TailPercentile(1..20 ms, 0.5) = %v, %v, want 10.5ms", got, ok)
	}
}

// busy 5.5 s, own 5.0 s over 2 s: 0.5/2 = 0.25 cores; own 6.0 s leaves
// nothing: 0; no wall is undefined
func TestForeignCoresKnownAnswer(t *testing.T) {
	s := time.Second
	if got := metrics.ForeignCores(5500*time.Millisecond, 5*s, 2*s); !near(got, 0.25) {
		t.Fatalf("ForeignCores = %v, want 0.25", got)
	}
	if got := metrics.ForeignCores(5500*time.Millisecond, 6*s, 2*s); got != 0 {
		t.Fatalf("ForeignCores under own = %v, want 0", got)
	}
	if got := metrics.ForeignCores(s, 0, 0); !math.IsNaN(got) {
		t.Fatalf("ForeignCores over no wall = %v, want NaN", got)
	}
}

// 22 min of 60 is 22/60; a hold longer than the period, or none, is undefined
func TestDutyCycleKnownAnswer(t *testing.T) {
	if got := metrics.DutyCycle(22*time.Minute, time.Hour); !near(got, 22.0/60) {
		t.Fatalf("DutyCycle = %v, want 22/60", got)
	}
	if got := metrics.DutyCycle(2*time.Hour, time.Hour); !math.IsNaN(got) {
		t.Fatalf("DutyCycle over the period = %v, want NaN", got)
	}
	if got := metrics.DutyCycle(0, time.Hour); !math.IsNaN(got) {
		t.Fatalf("DutyCycle of no hold = %v, want NaN", got)
	}
}

// 100 and 200 at duty 22/60: 100 + (22/60)*100 = 136.67
func TestExpectedSetupKnownAnswer(t *testing.T) {
	if got := metrics.ExpectedSetup(100, 200, 22.0/60); math.Abs(got-136.6666666) > 1e-6 {
		t.Fatalf("ExpectedSetup = %v, want 136.67", got)
	}
}

// level 0.995 is alpha/2 = 0.0025. A pilot {2, 2, 2} centres on its median to
// {1, 1, 1}: at n 9, P(K <= 0) = 0.5^9 = 0.00195 <= 0.0025, the interval
// [x(1), x(9)] = [1, 1] is inside [0.95, 1.05] in every resample, power 1; at
// n 8, 0.5^8 = 0.0039 > 0.0025 and no interval exists, power 0
func TestEquivalencePowerKnownAnswer(t *testing.T) {
	flat := []float64{2, 2, 2}
	if got := metrics.EquivalencePower(flat, 9, 0.995, 0.05, 1000, 1); got != 1 {
		t.Fatalf("power at n 9 = %v, want 1", got)
	}
	if got := metrics.EquivalencePower(flat, 8, 0.995, 0.05, 1000, 1); got != 0 {
		t.Fatalf("power at n 8 = %v, want 0", got)
	}
	// {1, 1.02, 1.04} has median 1.02 and centres to {0.9804, 1, 1.0196}, all
	// inside [0.95, 1.05]: power 1
	if got := metrics.EquivalencePower([]float64{1, 1.02, 1.04}, 9, 0.995, 0.05, 1000, 1); got != 1 {
		t.Fatalf("power of a narrow pilot = %v, want 1", got)
	}
	for name, got := range map[string]float64{
		"empty pilot": metrics.EquivalencePower(nil, 9, 0.995, 0.05, 1000, 1),
		"n 0":         metrics.EquivalencePower(flat, 0, 0.995, 0.05, 1000, 1),
		"NaN":         metrics.EquivalencePower([]float64{1, math.NaN()}, 9, 0.995, 0.05, 1000, 1),
	} {
		if !math.IsNaN(got) {
			t.Fatalf("%s: power %v, want NaN", name, got)
		}
	}
}

// {0.9, 1, 1, 1.1} has median 1; 0.9 and 1.1 lie outside [0.95, 1.05], so at
// n 9 the interval [x(1), x(9)] is inside only if all nine draws are 1:
// 0.5^9 = 1/512 = 0.001953. 200000 draws give a standard error of
// sqrt(p(1-p)/200000) = 0.0000987; three of them is 0.000296
func TestEquivalencePowerByResampling(t *testing.T) {
	got := metrics.EquivalencePower([]float64{0.9, 1, 1, 1.1}, 9, 0.995, 0.05, 200000, 7)
	if math.Abs(got-1.0/512) > 0.000296 {
		t.Fatalf("power = %v, want 1/512 = 0.001953 within 0.000296", got)
	}
}

// EquivalencePower judges a resample by counting values outside the corridor
// against the positions of the order interval; on random samples that rule
// must agree with sorting, QuantileInterval and Equivalence
func TestEquivalencePowerCountsAsTheIntervalJudges(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for trial := 0; trial < 300; trial++ {
		n := 9 + r.IntN(40)
		sample := make([]float64, n)
		for i := range sample {
			sample[i] = 1 + (r.Float64()-0.5)*0.14
		}
		want := metrics.Equivalence(metrics.QuantileInterval(sample, 0.5, 0.995), 1, 0.05) == "equivalent"
		under, over := 0, 0
		for _, v := range sample {
			switch {
			case v < 0.95:
				under++
			case v > 1.05:
				over++
			}
		}
		ranks := make([]float64, n)
		for i := range ranks {
			ranks[i] = float64(i + 1)
		}
		iv := metrics.QuantileInterval(ranks, 0.5, 0.995)
		got := under < int(iv.Low) && over <= n-int(iv.High)
		if got != want {
			t.Fatalf("trial %d, n %d: counting says %v, the interval says %v", trial, n, got, want)
		}
	}
}

// {2, 2, 2}: power 0 for n 1..8 and 1 at n 9, so 9; the caller takes
// max(30, 9) = 30. {1, 1.2} centres to {0.909, 1.091}, both outside the
// corridor, so no n reaches any power
func TestRepeatsForPowerKnownAnswer(t *testing.T) {
	if n, ok := metrics.RepeatsForPower([]float64{2, 2, 2}, 0.995, 0.05, 0.8, 1000, 1000, 1); !ok || n != 9 {
		t.Fatalf("RepeatsForPower = %d, %v, want 9, true", n, ok)
	}
	if n, ok := metrics.RepeatsForPower([]float64{1, 1.2}, 0.995, 0.05, 0.8, 1000, 40, 1); ok {
		t.Fatalf("RepeatsForPower of a wide pilot = %d, true, want false", n)
	}
}
