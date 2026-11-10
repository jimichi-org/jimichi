package nodeview

import (
	"context"
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func TestNodeStatisticalRegistryKnownAnswer(t *testing.T) {
	// E1 has 3, E2 4, H1 2, H2 2, M2 2 claims: 3+4+2+2+2=13
	model, difference := ModelRegistry(), DifferenceRegistry()
	if len(model) != 13 || len(difference) != 13 || model[0].ID != "E1.touched" || model[12].ID != "M2.R" || difference[8] != "node-F20-L2" || difference[12] != "mail-P33250000-record" {
		t.Fatal("registered families changed")
	}
	seen := map[string]bool{}
	for _, c := range model {
		if seen[c.ID] || c.Row == "M1" {
			t.Fatal("structural claim added")
		}
		seen[c.ID] = true
	}
	if nodeDelta != .05 || nodePower != .8 || nodeAlpha != .05 || nodePowerSimulations != 10000 || nodeBootstrapResamples != 2000 || nodeMaxPairs != 512 {
		t.Fatal("registration constants changed")
	}
}

func TestExactWilsonPowerKnownAnswer(t *testing.T) {
	// at n=2,p=1/2,margin=.4,level=.5 only k=1 contains its Wilson interval, with probability 2/4
	p, ok := ExactWilsonPower(2, .5, .4, .5)
	if !ok || p != .5 {
		t.Fatalf("power %v", p)
	}
	for n := 1; n <= 12; n++ {
		for _, p := range []float64{.2, .5, .75} {
			got, ok := ExactWilsonPower(n, p, .3, .8)
			if !ok {
				t.Fatal("power rejected")
			}
			want := 0.0
			choose := 1.0
			for k := 0; k <= n; k++ {
				if k > 0 {
					choose *= float64(n-k+1) / float64(k)
				}
				iv := metrics.WilsonInterval(k, n, .8)
				if iv.Low >= p-.3 && iv.High <= p+.3 {
					want += choose * math.Pow(p, float64(k)) * math.Pow(1-p, float64(n-k))
				}
			}
			if math.Abs(got-want) > 1e-14 {
				t.Fatal("exact binomial enumeration disagrees")
			}
		}
	}
	for _, n := range []int{0, 1048577} {
		if _, ok := ExactWilsonPower(n, .5, .05, .95); ok {
			t.Fatal("invalid count accepted")
		}
	}
}

func TestNodeModelSamplePlan(t *testing.T) {
	plans, err := PlanModelSlots(context.Background())
	if err != nil || len(plans) != 6 {
		t.Fatal("model planning failed")
	}
	for _, p := range plans {
		if p.Row == "M1" {
			if p.Slots != 32 {
				t.Fatal("structural slots changed")
			}
			continue
		}
		if p.Slots < 2048 || p.Slots > 1048576 || p.Slots%32 != 0 {
			t.Fatal("invalid planned slots")
		}
		for _, power := range p.Power {
			if power.Power < .8 {
				t.Fatal("underpowered exact Wilson claim")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanModelSlots(ctx); err == nil {
		t.Fatal("cancelled model planning succeeded")
	}
}

func TestPairedPowerConstantKnownAnswer(t *testing.T) {
	// centered identical pilot differences become +.05; all 30 signs agree, so p=2/2^30=2^-29
	x, y := []float64{.5, .5, .5, .5, .5}, []float64{.5, .5, .5, .5, .5}
	plan, err := PlanPairedPower(context.Background(), x, y, 11721)
	if err != nil || plan.SelectedN != 30 || len(plan.Search) != 1 || plan.Search[0].Successes != 10000 || plan.Search[0].Power != 1 {
		t.Fatal("constant paired planning changed")
	}
	final, err := PairedPowerAtN(context.Background(), x, y, 11721, 128)
	if err != nil || final.Successes != 10000 {
		t.Fatal("final-count recomputation changed")
	}
	if plan.Estimate.MaximumDPBytes != 2101256 || plan.Estimate.Candidates != 483 || plan.Estimate.PrefixBytes != 5120000 {
		t.Fatal("planning resource estimate changed")
	}
	if plan.SubsetAdditions != 0 {
		t.Fatal("all-sign exact tail did unnecessary subset work")
	}
}

func TestPairedPowerCancellationAndPilotValidation(t *testing.T) {
	x := []float64{.5, .5, .5, .5, .5}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := PlanPairedPower(ctx, x, x, 11721)
	if err == nil || out.SelectedN != 0 || out.Reason != ReasonPlanning {
		t.Fatal("cancelled planning passed")
	}
	if _, err := PlanPairedPower(context.Background(), x[:4], x, 0); err == nil {
		t.Fatal("incomplete pilot accepted")
	}
	bad := append([]float64(nil), x...)
	bad[2] = math.NaN()
	if _, err := PlanPairedPower(context.Background(), bad, x, 0); err == nil {
		t.Fatal("undefined pilot accepted")
	}
}

func TestPlanningExactTailMatchesRegisteredTest(t *testing.T) {
	// ranks 1,2,3 with signs +,-,+ have W=4; of eight sign choices six are as far from mean 3
	p := pairedPlanner{}
	got, ok := p.tail(context.Background(), [5]uint16{1, 1, 1}, [5]int{2, 4, 6}, 3, 8)
	if !ok || got != .75 {
		t.Fatal("signed-rank known answer changed")
	}
	for n := 2; n <= 40; n++ {
		var counts [5]uint16
		var positives [5]uint16
		x := make([]float64, n)
		y := make([]float64, n)
		for i := range x {
			g := i % 5
			counts[g]++
			x[i] = float64(g + 1)
			if i%3 == 0 {
				x[i] = -x[i]
			} else {
				positives[g]++
			}
		}
		var ranks [5]int
		below, sum := 0, 0
		for g := range 5 {
			ranks[g] = 2*below + int(counts[g]) + 1
			sum += int(positives[g]) * ranks[g]
			below += int(counts[g])
		}
		got, ok := p.tail(context.Background(), counts, ranks, n, sum)
		want, valid := metrics.WilcoxonExact(x, y, 512)
		if !ok || !valid || got != want.P {
			t.Fatal("planner and registered exact test differ")
		}
	}
	// all 128 positive differences have two extreme assignments among 2^128
	got, ok = p.tail(context.Background(), [5]uint16{128}, [5]int{129}, 128, 128*129)
	if !ok || got != math.Ldexp(1, -127) {
		t.Fatal("128-pair exact tail changed")
	}
}

func TestAnalyzePairedExactAboveLegacyCap(t *testing.T) {
	x, y := make([]float64, 128), make([]float64, 128)
	for i := range x {
		x[i] = .05
	}
	out, err := AnalyzePaired(x, y)
	if err != nil || out.Test.Method != "exact" || out.Test.P != math.Ldexp(1, -127) || out.MedianDelta != .05 {
		t.Fatal("exact analysis silently changed method")
	}
}

func TestPairedPowerRanksOnlyOccupiedAtoms(t *testing.T) {
	x := []float64{.47500000000000003, .4750000000375, .475000000075, .4125, .4124999998875}
	y := []float64{.425, .42499999996250004, .42499999992500004, .48750000000000004, .4875000001125}
	p, ok := newPairedPlanner(x, y, 11721)
	if !ok {
		t.Fatal("valid pilot rejected")
	}
	defer p.release()
	indices := make([]byte, 0, 30)
	for i, count := range []int{0, 12, 12, 6, 0} {
		for range count {
			indices = append(indices, byte(i))
		}
	}
	for simulation := range nodePowerSimulations {
		copy(p.prefixes[simulation*nodeMaxPairs:], indices)
	}
	if _, ok := p.point(context.Background(), 30, 0); !ok || len(p.memo) != 1 {
		t.Fatal("identical resamples did not share an exact result")
	}
	// the six negative ranks are 7 and the 24 tied positive ranks are 37, doubled
	// lower sums <=42 have 2^6+24=88 assignments; both tails have 176 of 2^30
	want := math.Ldexp(176, -30)
	for _, got := range p.memo {
		if got != want {
			t.Fatalf("omitted pilot atom changed sampled ties: got %.17g, want %.17g", got, want)
		}
	}
}
