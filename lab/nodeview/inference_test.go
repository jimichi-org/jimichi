package nodeview

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func inferenceTestPlan(set Set) Plan {
	p := testNodeviewPlan(set)
	p.Phase = Primary
	if set != Compromise {
		for _, id := range differenceIDs() {
			p.Powers = append(p.Powers, PowerCalculation{ID: id, N: 30})
		}
	}
	return p
}

func inferenceTestCounts(n int) Counts {
	return Counts{Planned: uint64(n), Attempted: uint64(n), Established: uint64(n), PreflightOK: uint64(n), MessageBearing: uint64(n)}
}

func inferenceTestModels() []RunResult {
	var runs []RunResult
	for _, row := range canonicalCoordinates(Compromise) {
		for repeat := range row.Slots / 32 {
			histogram := []uint64{32, 0, 0, 0, 0}
			if row.Topology == "peer" {
				histogram = histogram[:4]
			}
			run := RunResult{Configuration: row.ID, Phase: Primary, Repeat: repeat, ModelComplete: true, Counts: inferenceTestCounts(32), RouteHistogram: histogram}
			if row.ID == "E1" {
				run.RouteHistogram = []uint64{8, 0, 8, 16, 0}
				run.Touched, run.ContentFound = 24, 8
			}
			if row.ID == "H1" {
				run.RouteHistogram = []uint64{16, 0, 16, 0}
				run.Touched = 16
			}
			if row.ID == "E2" || row.ID == "M2" {
				run.Touched, run.Ends = 16, 8
			}
			runs = append(runs, run)
		}
	}
	return runs
}

func inferenceTestLinking() []RunResult {
	var runs []RunResult
	for _, coordinate := range canonicalCoordinates(Collude)[:9] {
		for repeat := range 30 {
			runs = append(runs, RunResult{Configuration: coordinate.ID, Phase: Primary, Repeat: repeat, Counts: inferenceTestCounts(coordinate.Flows), Methods: []MethodResult{
				{Method: "cells", WindowNS: 20000000000, AUC: number(.75, ReasonNone)},
				{Method: "frames", WindowNS: 20000000000, AUC: number(.5, ReasonNone)},
			}})
		}
	}
	return runs
}

func inferenceTestMailbox() []RunResult {
	var runs []RunResult
	for _, coordinate := range canonicalCoordinates(Mailbox) {
		if coordinate.Population != "classifier" {
			continue
		}
		request, record := .25, .75
		if coordinate.Settings.CoverPuts {
			request, record = .75, .25
		}
		for repeat := range 30 {
			runs = append(runs, RunResult{Configuration: coordinate.ID, Phase: Primary, Repeat: repeat, Counts: inferenceTestCounts(2 * coordinate.Conversations), RequestLDA: number(request, ReasonNone), RecordLDA: number(record, ReasonNone)})
		}
	}
	return runs
}

func inferenceTestValue(t *testing.T, value Number) float64 {
	t.Helper()
	if value.Value == nil || value.Reason != ReasonNone {
		t.Fatalf("undefined number: %+v", value)
	}
	return *value.Value
}

func inferenceTestNull(t *testing.T, item Inference) {
	t.Helper()
	if item.Defined || item.Verdict != "" || item.Point.Value != nil || item.Low.Value != nil || item.High.Value != nil || item.P.Value != nil || item.AdjustedP.Value != nil || item.Effect.Value != nil || item.MedianDelta.Value != nil {
		t.Fatalf("unavailable comparison released inference: %+v", item)
	}
}

func TestInferenceModelKnownAnswers(t *testing.T) {
	p := inferenceTestPlan(Compromise)
	runs := inferenceTestModels()
	model, difference, err := summarizeInferences(p, runs)
	if err != nil || len(model) != 13 || len(difference) != 13 {
		t.Fatalf("families: %v", err)
	}
	// each E1 cohort has eight R=0, eight R=1/2 and sixteen R=3/4 units
	// over 2048 units sum=1024, sum of squares=704 and centered sum=192
	z := math.Sqrt2 * math.Erfinv(1-.05/13)
	half := z * math.Sqrt(192.0/(2047*2048))
	route := model[2]
	if !route.Defined || route.Method != "normal" || math.Abs(inferenceTestValue(t, route.Point)-.5) > 1e-15 || math.Abs(inferenceTestValue(t, route.Low)-(.5-half)) > 1e-14 || math.Abs(inferenceTestValue(t, route.High)-(.5+half)) > 1e-14 {
		t.Fatalf("E1 route mean: %+v", route)
	}
	// touched is 24/32=3/4; Wilson bounds use the simultaneous 13-claim level
	n, share := 2048.0, .75
	d := 1 + z*z/n
	center := (share + z*z/(2*n)) / d
	radius := z / d * math.Sqrt(share*(1-share)/n+z*z/(4*n*n))
	touched := model[0]
	if touched.Method != "wilson" || inferenceTestValue(t, touched.Point) != share || math.Abs(inferenceTestValue(t, touched.Low)-(center-radius)) > 1e-15 || math.Abs(inferenceTestValue(t, touched.High)-(center+radius)) > 1e-15 || inferenceTestValue(t, model[1].Point) != .25 {
		t.Fatal("binary chain counts did not use Wilson intervals")
	}
	// H1 has sixteen R=0 and sixteen R=2/3, hence mean 1/3, using four bins
	if math.Abs(inferenceTestValue(t, model[8].Point)-1.0/3) > 1e-13 {
		t.Fatal("peer histogram divided by its bin count")
	}
	// explicit endpoint counts are eight per cohort, hence 1/4, independent of R
	if inferenceTestValue(t, model[3].Point) != .25 || inferenceTestValue(t, model[11].Point) != .25 {
		t.Fatal("endpoint counts were omitted or inferred from route bins")
	}
	for i, item := range model {
		if item.ID != modelIDs()[i] || !item.Defined || item.Planned != 2048 || item.Usable != 2048 || item.Failures != 0 || item.P.Value != nil || item.MedianDelta.Value != nil {
			t.Fatalf("model family changed: %+v", item)
		}
	}
	for _, item := range difference {
		inferenceTestNull(t, item)
	}
}

func TestInferenceStructuralTrustExtrasDoNotCreateModelClaims(t *testing.T) {
	p := inferenceTestPlan(Compromise)
	if len(p.Configurations) != 25 {
		t.Fatal("missing structural trust and membership coordinates")
	}
	base := inferenceTestModels()
	want, _, err := summarizeInferences(p, base)
	if err != nil || len(want) != 13 {
		t.Fatalf("model family: %v", err)
	}
	for _, row := range p.Configurations[6:] {
		runs := append(append([]RunResult(nil), base...), RunResult{Configuration: row.ID, Phase: Structural})
		got, _, err := summarizeInferences(p, runs)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("structural coordinate %s changed model inference: %v", row.ID, err)
		}
		runs[len(runs)-1].Phase = Primary
		if _, _, err := summarizeInferences(p, runs); err == nil {
			t.Fatalf("structural coordinate %s entered primary inference", row.ID)
		}
	}
	bad := clonePlanningPlan(p)
	bad.Configurations[6].Slots = 32
	if _, _, err := summarizeInferences(bad, nil); err == nil {
		t.Fatal("tampered structural coordinate accepted")
	}
	bad = clonePlanningPlan(p)
	bad.Configurations[6].ForeignPositions = []int{4}
	if _, _, err := summarizeInferences(bad, nil); err == nil {
		t.Fatal("changed foreign membership accepted")
	}
}

func TestInferenceModelMissingAndUnstartedSlots(t *testing.T) {
	p := inferenceTestPlan(Compromise)
	runs := inferenceTestModels()
	model, _, err := summarizeInferences(p, runs[1:])
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1, 2} {
		inferenceTestNull(t, model[index])
		if model[index].Planned != 2048 || model[index].Usable != 2016 || model[index].Failures != 32 || model[index].Reason != ReasonIncomplete {
			t.Fatal("missing cohort shrank the planned denominator")
		}
	}
	runs = inferenceTestModels()
	runs[0].ModelComplete = false
	runs[0].Flags = []Reason{ReasonCancelled}
	model, _, err = summarizeInferences(p, runs)
	if err != nil || model[0].Usable != 2016 || model[0].Failures != 32 {
		t.Fatal("cancelled cohort entered inference")
	}
	model, _, err = summarizeInferences(p, nil)
	if err != nil || model[0].Planned != 2048 || model[0].Usable != 0 || model[0].Failures != 2048 {
		t.Fatal("unstarted slots disappeared")
	}
	inferenceTestNull(t, model[0])
	// pilot rows carry no main observations, even when their values are complete
	runs = inferenceTestModels()
	for i := range runs {
		runs[i].Phase = Pilot
	}
	model, _, err = summarizeInferences(p, runs)
	if err != nil || model[0].Usable != 0 {
		t.Fatal("pilot rows entered main")
	}
}

func TestInferenceJointPairedKnownAnswers(t *testing.T) {
	p := inferenceTestPlan(Collude)
	runs := append(inferenceTestLinking(), inferenceTestMailbox()...)
	// an intended unanswered terminal cell does not invalidate an otherwise clean run
	runs[0].Counts.Unanswered = 128
	runs[0].Counts.Missing = 10
	model, difference, err := summarizeInferences(p, runs)
	if err != nil {
		t.Fatal(err)
	}
	// all 30 nonzero differences have the same sign, so two-sided p=2/2^30
	// all 13 equal p-values receive Holm adjustment 13*2^-29
	wantP := math.Ldexp(1, -29)
	for i, item := range difference {
		wantDelta, wantEffect := .25, 1.0
		if i >= 9 {
			wantDelta = .5
			if strings.HasSuffix(item.ID, "-record") {
				wantDelta, wantEffect = -.5, -1
			}
		}
		if item.ID != differenceIDs()[i] || !item.Defined || item.Method != "exact" || item.Planned != 30 || item.Usable != 30 || item.Failures != 0 || inferenceTestValue(t, item.Point) != wantDelta || inferenceTestValue(t, item.MedianDelta) != wantDelta || inferenceTestValue(t, item.Low) != wantDelta || inferenceTestValue(t, item.High) != wantDelta || inferenceTestValue(t, item.Effect) != wantEffect || inferenceTestValue(t, item.P) != wantP || inferenceTestValue(t, item.AdjustedP) != 13*wantP || item.Verdict != "rejected" {
			t.Fatalf("joint paired known answer: %+v", item)
		}
	}
	for _, item := range model {
		inferenceTestNull(t, item)
	}
}

func TestInferenceBoundaryRowsStayOutsidePrimaryFamily(t *testing.T) {
	p := inferenceTestPlan(Mailbox)
	base := append(inferenceTestLinking(), inferenceTestMailbox()...)
	_, want, err := summarizeInferences(p, base)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, row := range p.Configurations {
		if row.Population != "boundary" {
			continue
		}
		seen++
		runs := append(append([]RunResult(nil), base...), RunResult{Configuration: row.ID, Phase: Structural})
		_, got, err := summarizeInferences(p, runs)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("structural boundary changed joint family: %v", err)
		}
		runs[len(runs)-1].Phase = Primary
		if _, _, err := summarizeInferences(p, runs); err == nil {
			t.Fatal("boundary execution entered primary inference")
		}
	}
	if seen != 7 || len(want) != 13 {
		t.Fatal("boundary or inference registry changed")
	}
}

func TestInferencePartialFamilyWithholdsHolm(t *testing.T) {
	p := inferenceTestPlan(Collude)
	_, difference, err := summarizeInferences(p, inferenceTestLinking())
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range difference {
		if item.AdjustedP.Value != nil || item.Verdict != "" || item.Planned != 30 {
			t.Fatal("partial set published a reduced Holm family")
		}
		if i < 9 && (!item.Defined || item.P.Value == nil) || i >= 9 && (item.Defined || item.Usable != 0 || item.Failures != 30) {
			t.Fatal("partial family lost its descriptive result or missing mask")
		}
	}
	runs := append(inferenceTestLinking(), inferenceTestMailbox()...)
	_, difference, err = summarizeInferences(p, runs[1:])
	if err != nil {
		t.Fatal(err)
	}
	inferenceTestNull(t, difference[0])
	if difference[0].Usable != 29 || difference[0].Failures != 1 {
		t.Fatal("shortened repeat mask became a smaller test")
	}
	for _, item := range difference {
		if item.AdjustedP.Value != nil || item.Verdict != "" {
			t.Fatal("unaccounted repeat published joint significance")
		}
	}
}

func TestInferenceInitialOutcomesAreDisjoint(t *testing.T) {
	p := inferenceTestPlan(Collude)
	for _, field := range []string{"refused", "setup-failed", "overflow"} {
		runs := append(inferenceTestLinking(), inferenceTestMailbox()...)
		switch field {
		case "refused":
			runs[0].Counts.Refused = 1
		case "setup-failed":
			runs[0].Counts.SetupFailed = 1
		case "overflow":
			runs[0].Counts.Refused = math.MaxUint64
		}
		if _, _, err := summarizeInferences(p, runs); err == nil {
			t.Fatalf("full establishment and %s accepted together", field)
		}
		if cleanInferenceRun(runs[0]) {
			t.Fatal("contradictory initial outcomes counted as clean")
		}
	}
	// five planned slots split into two established, one refused, one failed and one unstarted
	run := RunResult{Counts: Counts{Planned: 5, Attempted: 4, Established: 2, PreflightOK: 2, MessageBearing: 2, Refused: 1, SetupFailed: 1}, Flags: []Reason{ReasonSetup}}
	if !validInferenceCounts(run, 5) || cleanInferenceRun(run) {
		t.Fatal("valid failed/unstarted mask lost its outcome accounting")
	}
	run.Counts.Refused = 2
	if validInferenceCounts(run, 5) {
		t.Fatal("refused and setup-failed outcomes overlap")
	}
	runs := append(inferenceTestLinking(), inferenceTestMailbox()...)
	runs[0].Counts.Established--
	runs[0].Counts.PreflightOK--
	runs[0].Counts.MessageBearing--
	runs[0].Counts.Refused = 1
	runs[0].Flags = []Reason{ReasonRefused}
	_, difference, err := summarizeInferences(p, runs)
	if err != nil || difference[0].Usable != 29 || difference[0].Failures != 1 || difference[0].Defined || difference[0].P.Value != nil || difference[0].AdjustedP.Value != nil {
		t.Fatalf("genuine refused row produced a shortened test: %v", err)
	}
}

func TestInferenceJointUndefinedAndDegenerateConvention(t *testing.T) {
	p := inferenceTestPlan(Mailbox)
	runs := append(inferenceTestLinking(), inferenceTestMailbox()...)
	// the first comparison has no nonzero differences, hence p=1, effect=0
	// it remains visible but does not count in Holm's defined nondegenerate family
	for i := range 30 {
		runs[i].Methods[0].AUC = number(.5, ReasonNone)
	}
	// the second has 29 usable pairs and one explicit unavailable value
	// the 30th slot stays accounted, but no 29-pair test is permitted
	runs[30].Methods[0].AUC = Number{Reason: ReasonNoPositive}
	_, difference, err := summarizeInferences(p, runs)
	if err != nil {
		t.Fatal(err)
	}
	if !difference[0].Defined || difference[0].Method != "degenerate" || difference[0].Verdict != "degenerate" || inferenceTestValue(t, difference[0].P) != 1 || inferenceTestValue(t, difference[0].Effect) != 0 || inferenceTestValue(t, difference[0].MedianDelta) != 0 || difference[0].AdjustedP.Value != nil {
		t.Fatal("degenerate comparison was tested as a nondegenerate member")
	}
	inferenceTestNull(t, difference[1])
	if difference[1].Usable != 29 || difference[1].Failures != 1 {
		t.Fatal("undefined comparison lost its mask")
	}
	for _, item := range difference[2:] {
		if inferenceTestValue(t, item.AdjustedP) != 11*math.Ldexp(1, -29) {
			t.Fatal("Holm did not exclude exactly the undefined and degenerate members")
		}
	}
	// one +1/4 and one -1/4 tie at rank 3/2, so W=3/2,p=1,effect=0
	runs = append(inferenceTestLinking(), inferenceTestMailbox()...)
	for i := range 30 {
		runs[i].Methods[0].AUC = number(.5, ReasonNone)
	}
	runs[0].Methods[0].AUC, runs[1].Methods[0].AUC = number(.75, ReasonNone), number(.25, ReasonNone)
	_, difference, err = summarizeInferences(p, runs)
	if err != nil || difference[0].Method != "exact" || inferenceTestValue(t, difference[0].P) != 1 || inferenceTestValue(t, difference[0].Effect) != 0 || inferenceTestValue(t, difference[0].MedianDelta) != 0 || difference[0].Verdict != "not rejected" {
		t.Fatal("paired zeros, signs or tied ranks changed")
	}
}

func TestInferenceRejectsMalformedAggregates(t *testing.T) {
	for name, mutate := range map[string]func([]RunResult) []RunResult{
		"duplicate-repeat":   func(r []RunResult) []RunResult { return append(r, r[0]) },
		"unknown-coordinate": func(r []RunResult) []RunResult { r[0].Configuration = "other"; return r },
		"repeat-range":       func(r []RunResult) []RunResult { r[0].Repeat = 30; return r },
		"planned-count":      func(r []RunResult) []RunResult { r[0].Counts.Planned--; return r },
		"attempt-count":      func(r []RunResult) []RunResult { r[0].Counts.Attempted++; return r },
		"duplicate-method":   func(r []RunResult) []RunResult { r[0].Methods = append(r[0].Methods, r[0].Methods[0]); return r },
		"nonfinite":          func(r []RunResult) []RunResult { v := math.NaN(); r[0].Methods[0].AUC = Number{Value: &v}; return r },
		"auc-range":          func(r []RunResult) []RunResult { r[0].Methods[0].AUC = number(1.01, ReasonNone); return r },
		"auc-value-reason":   func(r []RunResult) []RunResult { r[0].Methods[0].AUC.Reason = ReasonNoView; return r },
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := summarizeInferences(inferenceTestPlan(Collude), mutate(inferenceTestLinking())); err == nil {
				t.Fatal("malformed primary aggregate accepted")
			}
		})
	}
	for name, mutate := range map[string]func([]RunResult){
		"histogram-width":    func(r []RunResult) { r[0].RouteHistogram = []uint64{32, 0, 0, 0} },
		"histogram-total":    func(r []RunResult) { r[0].RouteHistogram[0]-- },
		"histogram-overflow": func(r []RunResult) { r[0].RouteHistogram[0] = ^uint64(0) },
		"touched":            func(r []RunResult) { r[0].Touched = 33 },
		"ends":               func(r []RunResult) { r[0].Ends = 25 },
		"incomplete-marked-complete": func(r []RunResult) {
			r[0].Counts.Established = 31
			r[0].Counts.PreflightOK = 31
			r[0].Counts.MessageBearing = 31
		},
	} {
		t.Run(name, func(t *testing.T) {
			runs := inferenceTestModels()
			mutate(runs)
			if _, _, err := summarizeInferences(inferenceTestPlan(Compromise), runs); err == nil {
				t.Fatal("malformed model aggregate accepted")
			}
		})
	}
	mail := inferenceTestMailbox()
	mail[0].RequestLDA = Number{}
	if _, _, err := summarizeInferences(inferenceTestPlan(Mailbox), mail); err == nil {
		t.Fatal("missing classifier value without a reason accepted")
	}
}

func TestInferencePlanBindingAndNoGOSTInflation(t *testing.T) {
	for name, mutate := range map[string]func(*Plan){
		"registry":           func(p *Plan) { p.DifferenceFamily.IDs = p.DifferenceFamily.IDs[:12] },
		"missing-count":      func(p *Plan) { p.Powers = p.Powers[:12] },
		"duplicate-position": func(p *Plan) { p.Powers[1].ID = p.Powers[0].ID },
		"too-many-pairs":     func(p *Plan) { p.Powers[0].N = 513 },
		"mail-period-count":  func(p *Plan) { p.Powers[10].N = 31 },
	} {
		t.Run(name, func(t *testing.T) {
			p := inferenceTestPlan(Collude)
			mutate(&p)
			if _, _, err := summarizeInferences(p, nil); err == nil {
				t.Fatal("changed registered inference plan accepted")
			}
		})
	}
	p := inferenceTestPlan(Compromise)
	p.Suite = "gost"
	model, difference, err := summarizeInferences(p, inferenceTestModels())
	if err != nil || len(model) != 13 || len(difference) != 13 {
		t.Fatal("GOST changed registry size")
	}
	for _, family := range [][]Inference{model, difference} {
		for _, item := range family {
			inferenceTestNull(t, item)
			if item.Reason != ReasonUnsupported {
				t.Fatal("GOST created an inferential claim")
			}
		}
	}
	p = inferenceTestPlan(Collude)
	runs := append(inferenceTestLinking(), inferenceTestMailbox()...)
	encoded, err := json.Marshal(runs)
	if err != nil {
		t.Fatal(err)
	}
	var before []RunResult
	if err := json.Unmarshal(encoded, &before); err != nil {
		t.Fatal(err)
	}
	_, _, err = summarizeInferences(p, runs)
	if err != nil || !reflect.DeepEqual(runs, before) {
		t.Fatal("summary mutated aggregate input")
	}
}
