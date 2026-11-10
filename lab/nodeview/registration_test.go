package nodeview

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func planningTestSeal(t *testing.T, p Plan) Plan {
	t.Helper()
	p, err := sealPlanningTestPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sealPlanningTestPlan(p Plan) (Plan, error) {
	p.Digest = ""
	b, err := json.Marshal(p)
	if err != nil {
		return Plan{}, err
	}
	p.Digest = publicHash(b)
	return p, nil
}

func planningTestPilots(t *testing.T) (Plan, Plan) {
	t.Helper()
	left, right, err := makePlanningTestPilots()
	if err != nil {
		t.Fatal(err)
	}
	return left, right
}

func makePlanningTestPilots() (Plan, Plan, error) {
	left, right := testNodeviewPlan(Collude), testNodeviewPlan(Mailbox)
	sealedLeft, err := sealPlanningTestPlan(left)
	if err != nil {
		return Plan{}, Plan{}, err
	}
	sealedRight, err := sealPlanningTestPlan(right)
	if err != nil {
		return Plan{}, Plan{}, err
	}
	left.ParentDigest, right.ParentDigest = sealedLeft.Digest, sealedRight.Digest
	left.Phase, right.Phase = Pilot, Pilot
	for _, row := range canonicalCoordinates(Mailbox) {
		if row.Population == "classifier" {
			for _, population := range []string{"request", "record"} {
				right.FrozenModels = append(right.FrozenModels, ModelReference{row.ID, population, publicHash([]byte(row.ID + "/" + population))})
			}
		}
	}
	right.TrainingReady = true
	interval := metrics.WilsonInterval(10000, 10000, .95)
	for i, id := range differenceIDs() {
		input := PowerCalculation{ID: id, N: 30, Seed: int64(11700 + i), Successes: 10000, Simulations: 10000, PilotX: []float64{0, 0, 0, 0, 0}, PilotY: []float64{0, 0, 0, 0, 0}, Low: interval.Low, High: interval.High}
		if i < 9 {
			left.Powers = append(left.Powers, input)
		} else {
			right.Powers = append(right.Powers, input)
		}
	}
	left, err = sealPlanningTestPlan(left)
	if err != nil {
		return Plan{}, Plan{}, err
	}
	right, err = sealPlanningTestPlan(right)
	if err != nil {
		return Plan{}, Plan{}, err
	}
	return left, right, nil
}

func TestRegistrationModelPlanningKnownRows(t *testing.T) {
	input := planningTestSeal(t, testNodeviewPlan(Compromise))
	before := clonePlanningPlan(input)
	p, err := PrepareModelPlan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input, before) || p.Phase != Pilot || !p.ModelReady || p.PilotReady || p.ParentDigest != input.Digest || p.Digest == input.Digest || len(p.Samples) != 13 {
		t.Fatal("model successor changed its input or registration")
	}
	// the largest model variance is 1/4; its equivalence lower bound is below
	// 2048, and exact Wilson containment passes at the registered 2048 floor
	for i, row := range p.Configurations {
		if i >= 6 {
			if !reflect.DeepEqual(row, input.Configurations[i]) {
				t.Fatal("model planning changed a structural trust coordinate")
			}
			continue
		}
		want := 2048
		if row.ID == "M1" {
			want = 32
		}
		if row.Slots != want {
			t.Fatalf("%s slots = %d, want %d", row.ID, row.Slots, want)
		}
	}
	for i, sample := range p.Samples {
		claim := ModelRegistry()[i]
		if sample.ID != modelIDs()[i] || sample.Expected != claim.Mean || sample.SD != math.Sqrt(claim.Variance) || sample.Slots != 2048 || sample.Power < .8 || sample.Power > 1 {
			t.Fatalf("invalid claim calculation: %+v", sample)
		}
	}
	if err := ValidatePlan(p); err != nil {
		t.Fatal(err)
	}
	p.Phase, p.Digest = Primary, ""
	if err := validateRegisteredPlanning(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Plan){
		"missing":   func(p *Plan) { p.Samples = p.Samples[:12] },
		"duplicate": func(p *Plan) { p.Samples[1] = p.Samples[0] },
		"mean":      func(p *Plan) { p.Samples[0].Expected = .5 },
		"sd":        func(p *Plan) { p.Samples[0].SD = 0 },
		"power":     func(p *Plan) { p.Samples[0].Power = 1 },
		"count":     func(p *Plan) { p.Configurations[0].Slots = 2016 },
		"m1":        func(p *Plan) { p.Configurations[4].Slots = 64 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clonePlanningPlan(p)
			mutate(&bad)
			if err := validateRegisteredPlanning(context.Background(), bad); err == nil {
				t.Fatal("tampered model calculation accepted")
			}
		})
	}
}

func TestRegistrationModelRequiresFrozenStructuralPredecessor(t *testing.T) {
	base := testNodeviewPlan(Compromise)
	for name, input := range map[string]Plan{
		"unsealed": base,
		"opened-successor": func() Plan {
			p := clonePlanningPlan(base)
			p.ParentDigest = strings.Repeat("d", 64)
			return p
		}(),
		"mismatched-digest": func() Plan {
			p := clonePlanningPlan(base)
			p.Digest = strings.Repeat("d", 64)
			return p
		}(),
		"pilot": func() Plan {
			p := clonePlanningPlan(base)
			p.Phase = Pilot
			return planningTestSeal(t, p)
		}(),
		"primary": func() Plan {
			p := clonePlanningPlan(base)
			p.Phase = Primary
			return planningTestSeal(t, p)
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			before := clonePlanningPlan(input)
			if _, err := PrepareModelPlan(context.Background(), input); err == nil {
				t.Fatal("missing or wrong predecessor accepted")
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("rejected predecessor was changed")
			}
		})
	}
}

func TestRegistrationCombinesAllPairedPositions(t *testing.T) {
	left, right := planningTestPilots(t)
	leftBefore, rightBefore := clonePlanningPlan(left), clonePlanningPlan(right)
	a, b, err := CombinePilotPlans(context.Background(), left, right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, leftBefore) || !reflect.DeepEqual(right, rightBefore) {
		t.Fatal("combination mutated a pilot input")
	}
	// all five paired differences are zero; centering and the registered shift
	// make every synthetic difference +.05, so p=2/2^30 and all 10000 pass
	z := math.Sqrt2 * math.Erfinv(.95)
	wantLow := 10000 / (10000 + z*z)
	for _, p := range []Plan{a, b} {
		if !p.PilotReady || !p.TrainingReady || len(p.Powers) != 13 || len(p.PowerSearch) != 13 || !reflect.DeepEqual(p.FrozenModels, right.FrozenModels) {
			t.Fatal("combined family or model references incomplete")
		}
		for i, power := range p.Powers {
			search := p.PowerSearch[i]
			if power.ID != differenceIDs()[i] || power.N != 30 || power.Successes != 10000 || power.Simulations != 10000 || len(search.Search) != 1 || search.Search[0].N != 30 || search.SelectedN != 30 || search.Search[0].Power != 1 || math.Abs(power.Low-wantLow) > 1e-15 || math.Abs(power.High-1) > 1e-15 {
				t.Fatalf("wrong exact constant-pilot answer: %+v", power)
			}
		}
		if err := ValidatePlan(p); err != nil {
			t.Fatal(err)
		}
	}
	if a.ParentDigest != left.Digest || b.ParentDigest != right.Digest || a.Digest == left.Digest || b.Digest == right.Digest {
		t.Fatal("successor digest chain lost")
	}
	primary := clonePlanningPlan(a)
	primary.Phase, primary.Digest = Primary, ""
	if err := validateRegisteredPlanning(context.Background(), primary); err != nil {
		t.Fatal(err)
	}
	bad := clonePlanningPlan(primary)
	bad.PowerSearch[0].Search[0].Successes--
	if err := validateRegisteredPlanning(context.Background(), bad); err == nil {
		t.Fatal("altered search audit accepted")
	}
	bad = clonePlanningPlan(primary)
	bad.Powers[0].High = math.Nextafter(bad.Powers[0].High, 0)
	if err := validateRegisteredPlanning(context.Background(), bad); err == nil {
		t.Fatal("altered exact final interval accepted")
	}
	a.Powers[0].PilotX[0] = 1
	a.PowerSearch[0].Search[0].N = 512
	a.FrozenModels[0].Digest = strings.Repeat("f", 64)
	a.Configurations[0].Controlled[0] = 4
	if b.Powers[0].PilotX[0] != 0 || b.PowerSearch[0].Search[0].N != 30 || reflect.DeepEqual(a.FrozenModels, b.FrozenModels) || left.Configurations[0].Controlled[0] != 0 {
		t.Fatal("successors or input share mutable backing slices")
	}
}

func TestRegistrationKeepsBoundaryCoordinatesStructuralOnly(t *testing.T) {
	left, right := planningTestPilots(t)
	_, combined, err := CombinePilotPlans(context.Background(), left, right)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	first := -1
	for i, row := range combined.Configurations {
		if row.Population != "boundary" {
			continue
		}
		if first < 0 {
			first = i
		}
		seen++
		if !planningBoundaryCoordinate(row) || row.Main != 0 || row.Pilots != 0 || row.Training != 0 || !reflect.DeepEqual(row, right.Configurations[i]) {
			t.Fatal("combination changed a structural boundary recipe")
		}
	}
	if seen != 7 || len(combined.Powers) != 13 || len(combined.PowerSearch) != 13 {
		t.Fatal("boundary controls changed the registered family")
	}
	for _, change := range []string{"main", "pilots", "settings", "population"} {
		bad := clonePlanningPlan(combined)
		switch change {
		case "main":
			bad.Configurations[first].Main = 30
		case "pilots":
			bad.Configurations[first].Pilots = 5
		case "settings":
			bad.Configurations[first].Settings.Window++
		case "population":
			bad.Configurations[first].Population = "classifier"
		}
		if err := validateRegisteredPlanning(context.Background(), bad); err == nil {
			t.Fatalf("changed boundary %s accepted", change)
		}
	}
}

func TestRegistrationRejectsIncompleteOrUnboundPilots(t *testing.T) {
	left, right := planningTestPilots(t)
	for name, mutate := range map[string]func(*Plan, *Plan){
		"source":             func(a, b *Plan) { b.Tree = strings.Repeat("d", 40) },
		"revision":           func(a, b *Plan) { b.Revision = strings.Repeat("d", 40) },
		"binary":             func(a, b *Plan) { b.BinarySHA256 = strings.Repeat("d", 64) },
		"feature":            func(a, b *Plan) { b.FeatureVersion = "other" },
		"config":             func(a, b *Plan) { b.Configurations[0].Settings.CoverPuts = true },
		"missing-position":   func(a, b *Plan) { a.Powers = a.Powers[:8] },
		"duplicate-position": func(a, b *Plan) { a.Powers[1].ID = a.Powers[0].ID },
		"missing-repeat":     func(a, b *Plan) { a.Powers[0].PilotY = a.Powers[0].PilotY[:4] },
		"nonfinite":          func(a, b *Plan) { a.Powers[0].PilotX[0] = math.Inf(1) },
		"out-of-domain":      func(a, b *Plan) { a.Powers[0].PilotX[0] = -1 },
		"duplicate-seed":     func(a, b *Plan) { b.Powers[0].Seed = a.Powers[0].Seed },
		"unreleased":         func(a, b *Plan) { b.TrainingReady = false; b.FrozenModels = nil },
		"missing-model":      func(a, b *Plan) { b.FrozenModels = b.FrozenModels[:7] },
		"duplicate-model":    func(a, b *Plan) { b.FrozenModels[1] = b.FrozenModels[0] },
		"previous-ready":     func(a, b *Plan) { a.PilotReady = true },
	} {
		t.Run(name, func(t *testing.T) {
			a, b := clonePlanningPlan(left), clonePlanningPlan(right)
			mutate(&a, &b)
			if name != "nonfinite" {
				a, b = planningTestSeal(t, a), planningTestSeal(t, b)
			}
			if _, _, err := CombinePilotPlans(context.Background(), a, b); err == nil {
				t.Fatal("incomplete or unbound pilot accepted")
			}
		})
	}
	a := clonePlanningPlan(left)
	a.Digest = ""
	if _, _, err := CombinePilotPlans(context.Background(), a, right); err == nil {
		t.Fatal("unsealed pilot accepted")
	}
}

func TestRegistrationIncidentMaximaAndDescriptions(t *testing.T) {
	search := make([]PairedPowerPlan, 13)
	for i := range search {
		search[i].SelectedN = 30 + i
	}
	counts := plannedIncidentCounts(search)
	// request/record need 39/40 at period zero and 41/42 at period 33250000
	// both covers therefore need 40 and 42 respectively; controls stay separate
	for _, row := range canonicalCoordinates(Mailbox) {
		n, incident := configurationIncidentCount(row, counts)
		if row.Population != "classifier" {
			if incident {
				t.Fatalf("descriptive control %s entered inference", row.ID)
			}
			continue
		}
		want := 40
		if strings.Contains(row.ID, "33250000") {
			want = 42
		}
		if !incident || n != want {
			t.Fatalf("%s count = %d, want %d", row.ID, n, want)
		}
	}
	for i, row := range canonicalCoordinates(Collude)[:9] {
		if n, incident := configurationIncidentCount(row, counts); !incident || n != 30+i {
			t.Fatal("linking coordinate lost its own count")
		}
	}
}

func TestRegistrationCancellationAndNoGOSTFamily(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	left, right := planningTestPilots(t)
	if _, _, err := CombinePilotPlans(ctx, left, right); reasonOf(err) != ReasonPlanning {
		t.Fatal("cancelled pilot planning accepted")
	}
	if _, err := PrepareModelPlan(ctx, testNodeviewPlan(Compromise)); reasonOf(err) != ReasonPlanning {
		t.Fatal("cancelled model planning accepted")
	}
	if err := validateRegisteredPlanning(ctx, left); reasonOf(err) != ReasonPlanning {
		t.Fatal("cancelled registration validation accepted")
	}
	gost := testNodeviewPlan(Compromise)
	gost.Suite = "gost"
	if _, err := PrepareModelPlan(context.Background(), gost); err == nil {
		t.Fatal("GOST inferential model family created")
	}
	if err := validateRegisteredPlanning(context.Background(), gost); err != nil {
		t.Fatal("descriptive GOST plan rejected")
	}
	gost.ModelReady = true
	if err := validateRegisteredPlanning(context.Background(), gost); err == nil {
		t.Fatal("GOST inferential readiness accepted")
	}
}
