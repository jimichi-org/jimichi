package nodeview

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func jointTestReports(t *testing.T) (Report, Report) {
	t.Helper()
	left, right := planningTestPilots(t)
	training := trainMailbox(mailboxTrainingFixture(), featureVersion, true, true)
	if !training.Releasable {
		t.Fatal("test model unavailable")
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
				t.Fatal(e)
			}
			m.Digest = publicHash(b)
			models = append(models, m)
			right.FrozenModels = append(right.FrozenModels, ModelReference{m.Configuration, m.Population, m.Digest})
		}
	}
	right = planningTestSeal(t, right)
	a, b, e := CombinePilotPlans(context.Background(), left, right)
	if e != nil {
		t.Fatal(e)
	}
	makeReport := func(p Plan, runs []RunResult) Report {
		seed := int64(11704)
		if p.Set == Mailbox {
			seed++
		}
		p, e = RegisterMainSeed(context.Background(), p, seed)
		if e != nil {
			t.Fatal(e)
		}
		parent := p.Digest
		p.Phase = Primary
		p.ParentDigest = parent
		p = planningTestSeal(t, p)
		peak := uint64(4096)
		return Report{Schema: reportSchema, Plan: p, Manifest: Manifest{Resources: ResourcePoint{Scope: resourceScope, MaxRSS: &peak}, BaseSeed: seed, Revision: p.Revision, Tree: p.Tree, BinarySHA256: p.BinarySHA256, Runtime: "go1.27.3", Suite: p.Suite, Protection: "all", Clock: p.Clock, ExemptionReason: p.ExemptionReason}, Runs: runs, Models: models}
	}
	return makeReport(a, inferenceTestLinking()), makeReport(b, inferenceTestMailbox())
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
