package nodeview

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var jointTestFixture = sync.OnceValues(func() ([2]string, error) {
	reports, err := makeJointTestReports()
	if err != nil {
		return [2]string{}, err
	}
	return serializeJointTestReports(reports)
})

func jointTestReports(t *testing.T) (Report, Report) {
	t.Helper()
	fixture, err := jointTestFixture()
	if err != nil {
		t.Fatal(err)
	}
	var reports [2]Report
	for i := range reports {
		reports[i], err = decodeJointTestReport(fixture[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	return reports[0], reports[1]
}

func decodeJointTestReport(data string) (Report, error) {
	var report Report
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func serializeJointTestReports(reports [2]Report) ([2]string, error) {
	var fixture [2]string
	for i, report := range reports {
		data, err := json.Marshal(report)
		if err != nil {
			return [2]string{}, err
		}
		cloned, err := decodeJointTestReport(string(data))
		if err != nil {
			return [2]string{}, err
		}
		roundTrip, err := json.Marshal(cloned)
		if err != nil {
			return [2]string{}, err
		}
		if string(data) != string(roundTrip) || !reflect.DeepEqual(report, cloned) {
			return [2]string{}, fmt.Errorf("joint report %d changed during cloning", i)
		}
		fixture[i] = string(data)
	}
	return fixture, nil
}

func makeJointTestReports() ([2]Report, error) {
	left, right, err := makePlanningTestPilots()
	if err != nil {
		return [2]Report{}, err
	}
	training := trainMailbox(mailboxTrainingFixture(), featureVersion, true, true)
	if !training.Releasable {
		return [2]Report{}, fmt.Errorf("test model unavailable")
	}
	var models []FrozenModel
	right.FrozenModels = nil
	for _, row := range canonicalCoordinates(Mailbox) {
		if row.Population != "classifier" {
			continue
		}
		for _, population := range []string{"request", "record"} {
			m := FrozenModel{Schema: "jimichi-nodeview-model-v1", Features: featureVersion, Population: population, Configuration: row.ID, Suite: right.Suite, TrainRevision: right.Revision, TransformDigest: right.TransformDigest, Training: training}
			b, e := json.Marshal(m)
			if e != nil {
				return [2]Report{}, e
			}
			m.Digest = publicHash(b)
			models = append(models, m)
			right.FrozenModels = append(right.FrozenModels, ModelReference{m.Configuration, m.Population, m.Digest})
		}
	}
	right, err = sealPlanningTestPlan(right)
	if err != nil {
		return [2]Report{}, err
	}
	a, b, e := CombinePilotPlans(context.Background(), left, right)
	if e != nil {
		return [2]Report{}, e
	}
	makeReport := func(p Plan, runs []RunResult) (Report, error) {
		seed := int64(11704)
		if p.Set == Mailbox {
			seed++
		}
		p, err := RegisterMainSeed(context.Background(), p, seed)
		if err != nil {
			return Report{}, err
		}
		parent := p.Digest
		p.Phase = Primary
		p.ParentDigest = parent
		p, err = sealPlanningTestPlan(p)
		if err != nil {
			return Report{}, err
		}
		peak := uint64(4096)
		return Report{Schema: reportSchema, Plan: p, Manifest: Manifest{Resources: ResourcePoint{Scope: resourceScope, MaxRSS: &peak}, BaseSeed: seed, Revision: p.Revision, Tree: p.Tree, BinarySHA256: p.BinarySHA256, Runtime: "go1.27.3", Suite: p.Suite, Protection: "all", Clock: p.Clock, ExemptionReason: p.ExemptionReason}, Runs: runs, Models: models}, nil
	}
	leftReport, err := makeReport(a, inferenceTestLinking())
	if err != nil {
		return [2]Report{}, err
	}
	rightReport, err := makeReport(b, inferenceTestMailbox())
	if err != nil {
		return [2]Report{}, err
	}
	return [2]Report{leftReport, rightReport}, nil
}

func jointTestCheckSnapshot(t *testing.T, report Report, want string) {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatal("joint report changed across clone boundaries")
	}
}

func jointTestMutateReport(report *Report) {
	plan := &report.Plan
	plan.ModelFamily.IDs[0] = "changed"
	plan.DifferenceFamily.IDs[0] = "changed"
	plan.WindowsNS[0]++
	for i := range plan.Configurations {
		row := &plan.Configurations[i]
		row.ID = "changed"
		for j := range row.Controlled {
			row.Controlled[j]++
		}
		for j := range row.ForeignPositions {
			row.ForeignPositions[j]++
		}
	}
	for i := range plan.FrozenModels {
		plan.FrozenModels[i].Digest = "changed"
	}
	for i := range plan.Samples {
		plan.Samples[i].Slots++
	}
	for i := range plan.Powers {
		plan.Powers[i].PilotX[0]++
		plan.Powers[i].PilotY[0]++
	}
	for i := range plan.PowerSearch {
		plan.PowerSearch[i].Search[0].N++
	}
	*report.Manifest.Resources.MaxRSS++
	for i := range report.Models {
		training := &report.Models[i].Training
		training.Model.Weights[0]++
		training.Model.Center[0]++
		training.Model.Normalizer++
		training.Model.Kept[0]++
		training.Model.Unused[0]++
		training.Witness.ClassSum[0][0]++
		training.Witness.Kept[0]++
		training.Witness.Unused[0]++
	}
	changeNumber := func(value *Number) {
		if value.Value != nil {
			*value.Value += .125
		}
		value.Reason = ReasonIncomplete
	}
	for i := range report.Runs {
		run := &report.Runs[i]
		run.Configuration = "changed"
		for j := range run.Flags {
			run.Flags[j] = ReasonChild
		}
		for j := range run.RouteHistogram {
			run.RouteHistogram[j]++
		}
		for j := range run.LinkingTimes {
			changeNumber(&run.LinkingTimes[j].Seconds)
		}
		for j := range run.Methods {
			method := &run.Methods[j]
			changeNumber(&method.AUC)
			changeNumber(&method.TopOne)
			changeNumber(&method.TPR)
			changeNumber(&method.BootstrapLow)
			changeNumber(&method.BootstrapHigh)
		}
		for _, value := range []*Number{&run.QueueJoined, &run.PutQ, &run.PutBaseline, &run.RequestLDA, &run.RecordLDA} {
			changeNumber(value)
		}
	}
	for i := range report.Planning {
		report.Planning[i].PilotX[0]++
		report.Planning[i].PilotY[0]++
		report.Planning[i].Power.Search[0].N++
	}
	for i := range report.Audit {
		for j := range report.Audit[i].Groups {
			for k := range report.Audit[i].Groups[j] {
				report.Audit[i].Groups[j][k].Positive++
			}
		}
		report.Audit[i].TopOne[0][0]++
	}
	for _, family := range [][]Inference{report.ModelInference, report.DifferenceInference} {
		for i := range family {
			for _, value := range []*Number{&family[i].Point, &family[i].Low, &family[i].High, &family[i].P, &family[i].AdjustedP, &family[i].Effect, &family[i].MedianDelta} {
				changeNumber(value)
			}
		}
	}
}

func TestJointTestReportsAreIndependent(t *testing.T) {
	a, b := jointTestReports(t)
	otherA, otherB := jointTestReports(t)
	fixture, err := jointTestFixture()
	if err != nil {
		t.Fatal(err)
	}
	for i, report := range []Report{a, b} {
		jointTestCheckSnapshot(t, report, fixture[i])
		if len(report.Plan.Powers) != 13 || len(report.Plan.PowerSearch) != 13 || len(report.Models) != 8 || report.Manifest.BaseSeed != int64(11704+i) || report.Plan.ParentDigest == "" || report.Plan.MainSeedCommitment == "" {
			t.Fatal("joint fixture lost its registered lineage or family")
		}
		sealed, err := sealPlanningTestPlan(report.Plan)
		if err != nil || sealed.Digest != report.Plan.Digest {
			t.Fatal("joint clone changed its plan digest")
		}
		for j, model := range report.Models {
			want := model.Digest
			model.Digest = ""
			data, err := json.Marshal(model)
			if err != nil || publicHash(data) != want || report.Plan.FrozenModels[j] != (ModelReference{model.Configuration, model.Population, want}) {
				t.Fatal("joint clone changed its frozen model binding")
			}
		}
	}
	jointTestMutateReport(&a)
	jointTestCheckSnapshot(t, b, fixture[1])
	jointTestMutateReport(&b)
	jointTestCheckSnapshot(t, otherA, fixture[0])
	jointTestCheckSnapshot(t, otherB, fixture[1])
	freshA, freshB := jointTestReports(t)
	jointTestCheckSnapshot(t, freshA, fixture[0])
	jointTestCheckSnapshot(t, freshB, fixture[1])
}

func TestJointReportClonePublicGraphKnownAnswer(t *testing.T) {
	plan := testNodeviewPlan(Collude)
	plan.Configurations[0].ForeignPositions = []int{2}
	plan.FrozenModels = []ModelReference{{"clone", "record", "digest"}}
	plan.Samples = []SampleCalculation{{ID: "clone", Slots: 32}}
	plan.Powers = []PowerCalculation{{Seed: 1<<63 - 7, PilotX: []float64{.125}, PilotY: []float64{.75}}}
	plan.PowerSearch = []PairedPowerPlan{{Seed: 1<<63 - 9, Search: []PairedPowerPoint{{N: 30, Power: .5}}}}
	peak := uint64(1<<64 - 7)
	input := Report{
		Schema: reportSchema, Plan: plan,
		Manifest: Manifest{BaseSeed: 1<<63 - 5, Resources: ResourcePoint{Scope: resourceScope, MaxRSS: &peak}},
		Models:   []FrozenModel{{Digest: "clone-digest", Training: trainMailbox(mailboxTrainingFixture(), featureVersion, true, true)}},
		Runs: []RunResult{{
			Flags: []Reason{ReasonIncomplete}, RouteHistogram: []uint64{1, 2},
			LinkingTimes: []LinkingTime{{Seconds: number(.125, ReasonNone)}, {Seconds: Number{Reason: ReasonIncomplete}, Censored: true}},
			Methods:      []MethodResult{{AUC: number(.25, ReasonNone), TopOne: number(.5, ReasonNone), TPR: number(.75, ReasonNone), BootstrapLow: number(0, ReasonNone), BootstrapHigh: number(1, ReasonNone)}},
			QueueJoined:  Number{Reason: ReasonIncomplete}, PutQ: number(math.SmallestNonzeroFloat64, ReasonNone), PutBaseline: number(math.MaxFloat64, ReasonNone), RequestLDA: number(.25, ReasonNone), RecordLDA: number(.75, ReasonNone),
		}},
		Planning:            []PlanningResult{{PilotX: []float64{.125}, PilotY: []float64{.75}, Power: plan.PowerSearch[0]}},
		Audit:               []RankAudit{{Groups: [][]RankBucket{nil, {}, {{Rank: 1, Positive: 2, Negative: 3, Category: 4}}}, TopOne: [][2]int{{1, 2}}}},
		ModelInference:      []Inference{{Point: number(.5, ReasonNone), Low: Number{Reason: ReasonIncomplete}, High: Number{}, P: number(.125, ReasonNone), AdjustedP: number(.25, ReasonNone), Effect: number(-.5, ReasonNone), MedianDelta: number(.75, ReasonNone)}},
		DifferenceInference: []Inference{},
	}
	missing := input
	missing.Manifest.Resources = ResourcePoint{Scope: resourceScope, Reason: ReasonIncomplete}
	fixture, err := serializeJointTestReports([2]Report{input, missing})
	if err != nil {
		t.Fatal(err)
	}
	a, err := decodeJointTestReport(fixture[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := decodeJointTestReport(fixture[1])
	if err != nil {
		t.Fatal(err)
	}
	jointTestMutateReport(&a)
	jointTestCheckSnapshot(t, input, fixture[0])
	jointTestCheckSnapshot(t, b, fixture[1])
	fresh, err := decodeJointTestReport(fixture[0])
	if err != nil {
		t.Fatal(err)
	}
	jointTestCheckSnapshot(t, fresh, fixture[0])
	input.Plan.PowerSearch[0].Search[0].Power = math.NaN()
	if partial, err := serializeJointTestReports([2]Report{b, input}); err == nil || partial != ([2]string{}) {
		t.Fatal("failed serialization exposed a partial fixture")
	}
	if partial, err := decodeJointTestReport(`{"schema":"partial","manifest":{"base_seed":9223372036854775808}}`); err == nil || !reflect.DeepEqual(partial, Report{}) {
		t.Fatal("typed decode overflow exposed a partial report")
	}
}

func TestJointMainInferenceFullFamilyKnownAnswer(t *testing.T) {
	a, b := jointTestReports(t)
	rows, e := JointMainInference(a, b)
	if e != nil || len(rows) != 13 {
		t.Fatalf("joint family: %v", e)
	}
	// thirty identical nonzero differences have two extreme signs out of 2^30
	// all thirteen equal p-values receive the same Holm value, 13 * 2^-29
	for _, row := range rows {
		if !row.Defined || row.Method != "exact" || row.P.Value == nil || *row.P.Value != math.Ldexp(1, -29) || row.AdjustedP.Value == nil || *row.AdjustedP.Value != 13*math.Ldexp(1, -29) || row.Verdict != "rejected" {
			t.Fatalf("joint inference %+v", row)
		}
	}
}

func TestJointMainInferenceBindingsAndMissingness(t *testing.T) {
	a, b := jointTestReports(t)
	for name, mutate := range map[string]func(*Report){"set": func(r *Report) { r.Plan.Set = Collude }, "suite": func(r *Report) { r.Manifest.Suite = "gost" }, "source": func(r *Report) { r.Manifest.Revision = strings.Repeat("f", 40) }, "tree": func(r *Report) { r.Manifest.Tree = strings.Repeat("f", 40) }, "binary": func(r *Report) { r.Manifest.BinarySHA256 = strings.Repeat("f", 64) }, "phase": func(r *Report) { r.Plan.Phase = Pilot; r.Plan = planningTestSeal(t, r.Plan) }, "digest": func(r *Report) { r.Plan.Digest = strings.Repeat("f", 64) }, "models": func(r *Report) { r.Models = r.Models[:7] }, "duplicate": func(r *Report) { r.Runs = append(append([]RunResult(nil), r.Runs...), r.Runs[0]) }} {
		t.Run(name, func(t *testing.T) {
			copyReport := b
			mutate(&copyReport)
			if _, e := JointMainInference(a, copyReport); e == nil {
				t.Fatal("unbound joint inputs accepted")
			}
		})
	}
	partial := b
	partial.Runs = append([]RunResult(nil), b.Runs[1:]...)
	rows, e := JointMainInference(a, partial)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 13 {
		t.Fatal("missing position dropped")
	}
	for _, row := range rows {
		if row.AdjustedP.Value != nil || row.Verdict == "rejected" || row.Verdict == "not rejected" {
			t.Fatal("partial matrix obtained joint correction")
		}
	}
}

func TestJointMainInferenceRecomputesPlanningAndLineage(t *testing.T) {
	for name, mutate := range map[string]func(*Plan){"empty-search": func(p *Plan) { p.PowerSearch = make([]PairedPowerPlan, 13) }, "changed-success": func(p *Plan) { p.Powers[0].Successes-- }, "missing-parent": func(p *Plan) { p.ParentDigest = "" }} {
		t.Run(name, func(t *testing.T) {
			a, b := jointTestReports(t)
			mutate(&a.Plan)
			mutate(&b.Plan)
			a.Plan = planningTestSeal(t, a.Plan)
			b.Plan = planningTestSeal(t, b.Plan)
			if _, e := JointMainInference(a, b); e == nil {
				t.Fatal("unvalidated planning or ancestry reached joint inference")
			}
		})
	}
}

func TestJointMainInferenceValidatesMailboxState(t *testing.T) {
	a, b := jointTestReports(t)
	b.Plan.ModelReady = true
	b.Plan.Samples = []SampleCalculation{{ID: "E1.R", Slots: 2048, Power: 1}}
	b.Plan = planningTestSeal(t, b.Plan)
	if _, e := JointMainInference(a, b); e == nil {
		t.Fatal("mailbox model state bypassed planning validation")
	}
}
