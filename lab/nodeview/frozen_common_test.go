package nodeview

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

func frozenCommonJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func frozenCommonClone(t *testing.T, models []FrozenModel) []FrozenModel {
	t.Helper()
	var cloned []FrozenModel
	if err := json.Unmarshal(frozenCommonJSON(t, models), &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func frozenCommonFixture(t *testing.T) ([2]Plan, []FrozenModel) {
	t.Helper()
	plans := [2]Plan{testNodeviewPlan(Collude), testNodeviewPlan(Mailbox)}
	var models []FrozenModel
	scratch := testFitCertificate(t)
	for _, row := range canonicalCoordinates(Mailbox) {
		if row.Population != "classifier" {
			continue
		}
		for _, population := range []string{"request", "record"} {
			rows := mailboxTrainingFixture()
			training := trainMailbox(rows, featureVersion, true, true, scratch)
			clear(rows)
			if !training.Releasable || !validateMailboxTraining(training) {
				t.Fatal("independent fixed-coordinate fit did not release")
			}
			model := FrozenModel{Schema: "jimichi-nodeview-model-v1", Features: featureVersion, Population: population, Configuration: row.ID, Suite: plans[1].Suite, TrainRevision: plans[1].Revision, TransformDigest: plans[1].TransformDigest, Training: training}
			model.Digest = publicHash(frozenCommonJSON(t, model))
			for _, earlier := range models {
				if model.Training.Model == earlier.Training.Model || model.Training.Witness == earlier.Training.Witness || &model.Training.Model.Weights[0] == &earlier.Training.Model.Weights[0] || &model.Training.Witness.Kept[0] == &earlier.Training.Witness.Kept[0] {
					t.Fatal("separate fitting calls shared released backing")
				}
			}
			models = append(models, model)
		}
	}
	t.Cleanup(func() {
		for i := range models {
			wipeMailboxTraining(&models[i].Training)
		}
	})
	interval := metrics.WilsonInterval(10000, 10000, .95)
	for i := range plans {
		p := &plans[i]
		p.ParentDigest = planningTestSeal(t, *p).Digest
		p.Phase, p.TrainingReady, p.PilotReady = Pilot, true, true
		for _, model := range models {
			p.FrozenModels = append(p.FrozenModels, ModelReference{model.Configuration, model.Population, model.Digest})
		}
		for j, id := range differenceIDs() {
			seed := int64(11700 + j)
			p.Powers = append(p.Powers, PowerCalculation{ID: id, N: 30, Seed: seed, Successes: 10000, Simulations: 10000, PilotX: []float64{0, 0, 0, 0, 0}, PilotY: []float64{0, 0, 0, 0, 0}, Low: interval.Low, High: interval.High})
			// equal pilots give one positive tied rank, tail 2^-29, one memo call and no subset additions
			p.PowerSearch = append(p.PowerSearch, PairedPowerPlan{Seed: seed, SelectedN: 30, Estimate: PairedPowerEstimate(), Search: []PairedPowerPoint{{N: 30, Successes: 10000, Simulations: 10000, Power: 1, Low: interval.Low, High: interval.High}}, ExactCalls: 1})
		}
		*p = planningTestSeal(t, *p)
		if ValidatePlan(*p) != nil {
			t.Fatal("small common-family fixture is not a legal plan")
		}
	}
	return plans, models
}

func frozenCommonReport(p Plan, models []FrozenModel, seed int64) Report {
	return Report{Schema: reportSchema, Status: ReasonIncomplete, Plan: p, Models: models, Manifest: Manifest{Revision: p.Revision, Tree: p.Tree, BinarySHA256: p.BinarySHA256, Suite: p.Suite, BaseSeed: seed, Resources: ResourcePoint{Scope: resourceScope, Reason: ReasonIncomplete}}}
}

func frozenCommonFiles(t *testing.T, p Plan, models []FrozenModel) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	for name, value := range map[string]any{"plan.json": p, "frozen-models.json": models} {
		if err := os.WriteFile(filepath.Join(dir, name), frozenCommonJSON(t, value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func frozenCommonColdLoad(t *testing.T, p Plan, models []FrozenModel) {
	t.Helper()
	before := string(frozenCommonJSON(t, models))
	loaded, err := loadFrozen(frozenCommonFiles(t, p, models), p)
	if err != nil || len(loaded) != 8 || !reflect.DeepEqual(loaded, models) || string(frozenCommonJSON(t, loaded)) != before {
		t.Fatal("cold loader changed or rejected the complete frozen sidecar")
	}
	for i := range loaded {
		if loaded[i].Training.Model == models[i].Training.Model || loaded[i].Training.Witness == models[i].Training.Witness {
			t.Fatal("cold loader reused a released object")
		}
		wipeMailboxTraining(&loaded[i].Training)
	}
	if string(frozenCommonJSON(t, models)) != before {
		t.Fatal("cold loader changed its source models")
	}
}

func TestFrozenCommonModels(t *testing.T) {
	plans, models := frozenCommonFixture(t)
	t.Run("fixed-domain", func(t *testing.T) {
		want := map[string]bool{"mail-P0-C0": true, "mail-P0-C1": true, "mail-P33250000-C0": true, "mail-P33250000-C1": true}
		seen, keys := map[string]bool{}, map[string]bool{}
		for _, p := range plans {
			for _, row := range p.Configurations {
				if mailboxClassifierID(row.ID) != (p.Set == Mailbox && row.Population == "classifier") {
					t.Fatal("fixed predicate differs from the canonical traffic registries")
				}
				if row.Population == "classifier" {
					if p.Set != Mailbox || !want[row.ID] || seen[row.ID] {
						t.Fatal("unexpected or duplicate classifier coordinate")
					}
					seen[row.ID] = true
				}
			}
		}
		for _, m := range models {
			key := m.Configuration + "/" + m.Population
			if keys[key] || !want[m.Configuration] || m.Population != "request" && m.Population != "record" {
				t.Fatal("fixed model domain changed")
			}
			keys[key] = true
		}
		if !reflect.DeepEqual(seen, want) || len(keys) != 4*2 || mailboxClassifierID("") || mailboxClassifierID("mail-P0-defaults") {
			t.Fatal("four classifiers and two populations no longer give exactly eight keys")
		}
	})
	for _, original := range plans {
		t.Run(string(original.Set), func(t *testing.T) {
			p := clonePlanningPlan(original)
			beforePlan, beforeModels := string(frozenCommonJSON(t, p)), string(frozenCommonJSON(t, models))
			for i := range models {
				if validateFrozenModel(&models[i], &p) != nil {
					t.Fatal("genuine released wrapper rejected")
				}
			}
			if validateFrozenModels(models, &p) != nil || frozenCommonReport(p, models, 0).validate() != nil {
				t.Fatal("common ready bundle or incomplete report rejected")
			}
			frozenCommonColdLoad(t, p, models)
			if beforePlan != string(frozenCommonJSON(t, p)) || beforeModels != string(frozenCommonJSON(t, models)) || !reflect.DeepEqual(p.Configurations, original.Configurations) || !reflect.DeepEqual(p.FrozenModels, original.FrozenModels) {
				t.Fatal("validation changed model bits, source, references or traffic registry")
			}
		})
	}
	t.Run("partial-mailbox", func(t *testing.T) {
		p := clonePlanningPlan(plans[1])
		p.TrainingReady = false
		p.FrozenModels = p.FrozenModels[:1]
		p = planningTestSeal(t, p)
		if validateFrozenModel(&models[0], &p) != nil || validateFrozenModels(models[:1], &p) == nil {
			t.Fatal("single-wrapper and ready-bundle contracts were conflated")
		}
		p.Suite = "gost"
		m := models[0]
		m.Suite, m.Digest = p.Suite, ""
		m.Digest = publicHash(frozenCommonJSON(t, m))
		p.FrozenModels[0].Digest = m.Digest
		if validateFrozenModel(&m, &p) != nil {
			t.Fatal("separately trained GOST Mailbox leaf lost its own membership path")
		}
	})
	t.Run("allocation-free-helpers", func(t *testing.T) {
		p, m := &plans[0], &models[0]
		if !commonColludeModelConsumer(p) || !mailboxClassifierID(m.Configuration) || !frozenModelMetadataValid(m, p) || commonColludeModelConsumer(nil) || frozenModelMetadataValid(nil, p) || frozenModelMetadataValid(m, nil) {
			t.Fatal("helper known answers changed")
		}
		if got := testing.AllocsPerRun(100, func() {
			if !mailboxClassifierID(m.Configuration) || !commonColludeModelConsumer(p) || !frozenModelMetadataValid(m, p) || !frozenModelMetadataValid(m, &plans[1]) {
				panic("helper known answer changed")
			}
		}); got != 0 {
			t.Fatalf("metadata helpers allocated %g objects", got)
		}
	})
	frozenCommonEligibilityNegatives(t, plans, models)
	frozenCommonModelNegatives(t, plans, models)
	frozenCommonReportNegatives(t, plans, models)
	frozenCommonPredecessor(t, plans, models)
}

func frozenCommonEligibilityNegatives(t *testing.T, plans [2]Plan, models []FrozenModel) {
	t.Helper()
	mutations := map[string]func(*Plan){
		"before-combine": func(p *Plan) { p.TrainingReady, p.PilotReady = false, false },
		"training":       func(p *Plan) { p.TrainingReady = false },
		"pilot":          func(p *Plan) { p.PilotReady = false },
		"model":          func(p *Plan) { p.ModelReady = true },
		"samples":        func(p *Plan) { p.Samples = []SampleCalculation{{ID: "E1"}} },
		"suite":          func(p *Plan) { p.Suite = "gost" },
		"structural":     func(p *Plan) { p.Phase = Structural },
		"train":          func(p *Plan) { p.Phase = Train },
		"phase":          func(p *Plan) { p.Phase = Phase("unknown") },
		"parent":         func(p *Plan) { p.ParentDigest = "" },
		"model-m":        func(p *Plan) { p.ModelFamily.M = 12 },
		"difference-m":   func(p *Plan) { p.DifferenceFamily.M = 12 },
		"model-ids":      func(p *Plan) { p.ModelFamily.IDs = p.ModelFamily.IDs[:12] },
		"difference-ids": func(p *Plan) { p.DifferenceFamily.IDs = p.DifferenceFamily.IDs[:12] },
		"references":     func(p *Plan) { p.FrozenModels = p.FrozenModels[:7] },
		"compromise":     func(p *Plan) { p.Set = Compromise },
		"set":            func(p *Plan) { p.Set = Set("unknown") },
	}
	for _, n := range []int{9, 12, 14} {
		mutations["powers-"+strconv.Itoa(n)] = func(p *Plan) { p.Powers = append(p.Powers, p.Powers[0]); p.Powers = p.Powers[:n] }
		mutations["search-"+strconv.Itoa(n)] = func(p *Plan) {
			p.PowerSearch = append(p.PowerSearch, p.PowerSearch[0])
			p.PowerSearch = p.PowerSearch[:n]
		}
	}
	for name, mutate := range mutations {
		t.Run("eligibility/"+name, func(t *testing.T) {
			p := clonePlanningPlan(plans[0])
			mutate(&p)
			m := models[0]
			if name == "suite" {
				m.Suite = p.Suite
			}
			if commonColludeModelConsumer(&p) || frozenModelMetadataValid(&m, &p) {
				t.Fatal("ineligible common consumer accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Plan){
		"model-id":             func(p *Plan) { p.ModelFamily.IDs[0] = "unknown" },
		"model-id-duplicate":   func(p *Plan) { p.ModelFamily.IDs[1] = p.ModelFamily.IDs[0] },
		"difference-id":        func(p *Plan) { p.DifferenceFamily.IDs[0] = "unknown" },
		"difference-duplicate": func(p *Plan) { p.DifferenceFamily.IDs[1] = p.DifferenceFamily.IDs[0] },
		"alpha":                func(p *Plan) { p.ModelFamily.Alpha = .04 },
		"margin":               func(p *Plan) { p.DifferenceFamily.Delta = .04 },
		"power":                func(p *Plan) { p.DifferenceFamily.Power = .9 },
	} {
		t.Run("outer-family/"+name, func(t *testing.T) {
			p := clonePlanningPlan(plans[0])
			mutate(&p)
			p = planningTestSeal(t, p)
			if ValidatePlan(p) == nil || validateFrozenModels(models, &p) == nil || frozenCommonReport(p, models, 0).validate() == nil {
				t.Fatal("resealed counterfeit family passed an authoritative boundary")
			}
		})
	}
	for _, population := range []string{"deleted", "control"} {
		t.Run("mailbox-membership/"+population, func(t *testing.T) {
			p := clonePlanningPlan(plans[1])
			for i := range p.Configurations {
				if p.Configurations[i].ID == models[0].Configuration {
					if population == "deleted" {
						p.Configurations = append(p.Configurations[:i], p.Configurations[i+1:]...)
					} else {
						p.Configurations[i].Population = population
					}
					break
				}
			}
			if frozenModelMetadataValid(&models[0], &p) {
				t.Fatal("Mailbox lost its own classifier membership requirement")
			}
		})
	}
}

func frozenCommonModelNegatives(t *testing.T, plans [2]Plan, models []FrozenModel) {
	t.Helper()
	for name, mutate := range map[string]func(*FrozenModel){
		"schema":           func(m *FrozenModel) { m.Schema = "unknown" },
		"revision":         func(m *FrozenModel) { m.TrainRevision = strings.Repeat("d", 40) },
		"suite":            func(m *FrozenModel) { m.Suite = "gost" },
		"features":         func(m *FrozenModel) { m.Features = "unknown" },
		"transform":        func(m *FrozenModel) { m.TransformDigest = strings.Repeat("d", 64) },
		"population":       func(m *FrozenModel) { m.Population = "classifier" },
		"request":          func(m *FrozenModel) { m.Population = "record" },
		"record":           func(m *FrozenModel) { m.Population = "request" },
		"digest":           func(m *FrozenModel) { m.Digest = strings.Repeat("d", 64) },
		"preimage":         func(m *FrozenModel) { m.Training.Model.Center[0] += .125 },
		"release":          func(m *FrozenModel) { m.Training.Releasable = false },
		"ram":              func(m *FrozenModel) { m.Training.Support.RAMConformance = false },
		"stable":           func(m *FrozenModel) { m.Training.Support.Stable = false },
		"clean":            func(m *FrozenModel) { m.Training.Support.CompleteClean = false },
		"joined":           func(m *FrozenModel) { m.Training.Support.LabelsJoined = false },
		"rows":             func(m *FrozenModel) { m.Training.Support.Rows[0] = 63 },
		"conversations":    func(m *FrozenModel) { m.Training.Support.Conversations[0] = 3 },
		"dominant":         func(m *FrozenModel) { m.Training.Support.LargestConversation[0] = 33 },
		"training-version": func(m *FrozenModel) { m.Training.FeatureVersion = "unknown" },
		"model":            func(m *FrozenModel) { m.Training.Model = nil },
		"witness":          func(m *FrozenModel) { m.Training.Witness = nil },
		"witness-count":    func(m *FrozenModel) { m.Training.Witness.Count-- },
		"witness-moment":   func(m *FrozenModel) { m.Training.Witness.Sum[0]++ },
		"partition":        func(m *FrozenModel) { m.Training.Model.Kept[0] = 18 },
		"normalizer":       func(m *FrozenModel) { m.Training.Model.Normalizer = 0 },
		"finite":           func(m *FrozenModel) { m.Training.Model.Weights[0] = math.NaN() },
		"witness-finite":   func(m *FrozenModel) { m.Training.Witness.Scatter[0][0] = math.Inf(1) },
	} {
		t.Run("wrapper/"+name, func(t *testing.T) {
			changed := frozenCommonClone(t, models)
			index := 0
			if name == "record" {
				index = 1
			}
			mutate(&changed[index])
			for _, p := range plans {
				if validateFrozenModel(&changed[index], &p) == nil || validateFrozenModels(changed, &p) == nil {
					t.Fatal("mutated wrapper passed complete release validation")
				}
			}
		})
	}
	foreign := []string{"node-F5-L0", "unknown"}
	for _, row := range canonicalCoordinates(Mailbox) {
		if row.Population != "classifier" {
			foreign = append(foreign, row.ID)
		}
	}
	for _, id := range foreign {
		t.Run("coordinate/"+id, func(t *testing.T) {
			m := models[0]
			m.Configuration = id
			for _, original := range plans {
				p := clonePlanningPlan(original)
				p.FrozenModels[0].Configuration = id
				p.Configurations = append(p.Configurations, Coordinate{ID: id, Population: "classifier"})
				if frozenModelMetadataValid(&m, &p) {
					t.Fatal("forged matching reference widened the four-ID domain")
				}
			}
		})
	}
	for name, mutate := range map[string]func(*Plan, *[]FrozenModel){
		"missing-model":   func(_ *Plan, m *[]FrozenModel) { *m = (*m)[:7] },
		"duplicate-model": func(_ *Plan, m *[]FrozenModel) { (*m)[1] = (*m)[0] },
		"missing-ref":     func(p *Plan, _ *[]FrozenModel) { p.FrozenModels = p.FrozenModels[:7] },
		"duplicate-ref":   func(p *Plan, _ *[]FrozenModel) { p.FrozenModels[1] = p.FrozenModels[0] },
		"ref-population":  func(p *Plan, _ *[]FrozenModel) { p.FrozenModels[0].Population = "record" },
		"ref-coordinate":  func(p *Plan, _ *[]FrozenModel) { p.FrozenModels[0].Configuration = p.FrozenModels[2].Configuration },
		"ref-digest":      func(p *Plan, _ *[]FrozenModel) { p.FrozenModels[0].Digest = strings.Repeat("d", 64) },
	} {
		t.Run("bundle/"+name, func(t *testing.T) {
			for _, original := range plans {
				p, changed := clonePlanningPlan(original), frozenCommonClone(t, models)
				mutate(&p, &changed)
				p = planningTestSeal(t, p)
				if validateFrozenModels(changed, &p) == nil {
					t.Fatal("incomplete or mismatched bundle accepted")
				}
			}
		})
	}
	for _, original := range plans {
		for _, duplicate := range []bool{false, true} {
			p := clonePlanningPlan(original)
			if duplicate {
				p.FrozenModels[1] = p.FrozenModels[0]
			} else {
				p.FrozenModels[0].Digest = strings.Repeat("d", 64)
			}
			if frozenModelMetadataValid(&models[0], &p) {
				t.Fatal("single metadata leaf accepted an unmatched or multiply matched triple")
			}
		}
	}
}

func frozenCommonReportNegatives(t *testing.T, plans [2]Plan, models []FrozenModel) {
	t.Helper()
	for name, mutate := range map[string]func(*Report){
		"uncombined": func(r *Report) {
			r.Plan.TrainingReady, r.Plan.PilotReady = false, false
			r.Plan.Powers, r.Plan.PowerSearch, r.Plan.FrozenModels = nil, nil, nil
		},
		"wrong-phase":   func(r *Report) { r.Plan.Phase = Structural },
		"missing-model": func(r *Report) { r.Models = r.Models[:7] },
		"references":    func(r *Report) { r.Plan.FrozenModels[0].Digest = strings.Repeat("d", 64) },
		"revision":      func(r *Report) { r.Manifest.Revision = strings.Repeat("d", 40) },
		"tree":          func(r *Report) { r.Manifest.Tree = strings.Repeat("d", 40) },
		"binary":        func(r *Report) { r.Manifest.BinarySHA256 = strings.Repeat("d", 64) },
	} {
		t.Run("report/"+name, func(t *testing.T) {
			r := frozenCommonReport(clonePlanningPlan(plans[0]), models, 0)
			mutate(&r)
			r.Plan = planningTestSeal(t, r.Plan)
			if r.validate() == nil {
				t.Fatal("inconsistent common Collude report accepted")
			}
		})
	}
	t.Run("untrained-and-suppressed-reports", func(t *testing.T) {
		plain := planningTestSeal(t, testNodeviewPlan(Collude))
		if frozenCommonReport(plain, nil, 0).validate() != nil {
			t.Fatal("ordinary untrained Collude report rejected")
		}
		mail := testNodeviewPlan(Mailbox)
		mail.ParentDigest, mail.Phase = planningTestSeal(t, mail).Digest, Train
		mail = planningTestSeal(t, mail)
		failed := models[0]
		failed.Digest = ""
		failed.Training = MailboxTraining{FeatureVersion: featureVersion, Reason: "training_support"}
		if frozenCommonReport(mail, []FrozenModel{failed}, 0).validate() != nil {
			t.Fatal("suppressed Mailbox training report rejected")
		}
	})
}

func frozenCommonPredecessor(t *testing.T, plans [2]Plan, models []FrozenModel) {
	t.Helper()
	for _, original := range plans {
		t.Run("primary-predecessor/"+string(original.Set), func(t *testing.T) {
			seed := int64(117900)
			p := clonePlanningPlan(original)
			var err error
			p.MainSeedCommitment, err = mainSeedCommitment(p, seed)
			if err != nil {
				t.Fatal(err)
			}
			p = planningTestSeal(t, p)
			path := frozenCommonFiles(t, p, models)
			c := Config{Set: p.Set, Phase: Primary, Suite: jcrypto.SuiteC25519, Revision: p.Revision, Seed: seed, PlanPath: path}
			loaded, err := loadPlan(path, c, p.Tree, p.BinarySHA256)
			if err != nil || !validPhasePredecessor(c, loaded) || !reflect.DeepEqual(p, loaded) {
				t.Fatal("registered Pilot predecessor did not pass the ordinary public preparation boundary")
			}
			loaded.ParentDigest = loaded.Digest
			loaded.Digest = ""
			loaded.Phase = c.Phase
			if loaded.ParentDigest != p.Digest || loaded.Digest != "" || loaded.Phase != Primary || ValidatePlan(loaded) != nil {
				t.Fatal("Run's exact internal Primary transition is invalid")
			}
			got, err := loadFrozen(path, loaded)
			if err != nil || !reflect.DeepEqual(got, models) {
				t.Fatal("empty-Digest internal Primary could not load its eight complete models")
			}
			completed := planningTestSeal(t, loaded)
			if frozenCommonReport(completed, models, seed).validate() != nil || validPhasePredecessor(c, completed) {
				t.Fatal("completed Primary report or predecessor phase rule changed")
			}
			badReport := frozenCommonReport(completed, models, seed+1)
			if badReport.validate() == nil {
				t.Fatal("Primary report accepted a mismatched seed binding")
			}
			for name, change := range map[string]func(*Config, *string, *string){
				"revision": func(c *Config, _, _ *string) { c.Revision = strings.Repeat("d", 40) },
				"tree":     func(_ *Config, tree, _ *string) { *tree = strings.Repeat("d", 40) },
				"binary":   func(_ *Config, _, binary *string) { *binary = strings.Repeat("d", 64) },
				"seed":     func(c *Config, _, _ *string) { c.Seed++ },
				"set":      func(c *Config, _, _ *string) { c.Set = Compromise },
				"suite":    func(c *Config, _, _ *string) { c.Suite = jcrypto.SuiteGOST },
			} {
				t.Run(name, func(t *testing.T) {
					bad, tree, binary := c, p.Tree, p.BinarySHA256
					change(&bad, &tree, &binary)
					if _, err := loadPlan(path, bad, tree, binary); err == nil {
						t.Fatal("loadPlan accepted mismatched current identity or seed")
					}
				})
			}
			for name, change := range map[string]func(*Plan){
				"phase": func(p *Plan) { p.Phase = Train },
				"set":   func(p *Plan) { p.Set = Compromise },
				"suite": func(p *Plan) { p.Suite = "gost" },
			} {
				t.Run("predecessor-"+name, func(t *testing.T) {
					bad := clonePlanningPlan(p)
					change(&bad)
					if validPhasePredecessor(c, bad) {
						t.Fatal("wrong predecessor phase, set or suite accepted")
					}
				})
			}
			p.Digest = ""
			unsealed := frozenCommonFiles(t, p, models)
			if _, err := loadPlan(unsealed, c, p.Tree, p.BinarySHA256); err == nil {
				t.Fatal("unsealed external predecessor accepted")
			}
		})
	}
}

func TestFrozenCommonGenuineLineage(t *testing.T) {
	fixture, err := jointTestFixture()
	if err != nil {
		t.Fatal(err)
	}
	for i, set := range []Set{Collude, Mailbox} {
		t.Run(string(set), func(t *testing.T) {
			primary, err := decodeJointTestReport(fixture[i])
			if err != nil {
				t.Fatal(err)
			}
			combined, err := decodeJointTestReport(fixture[2+i])
			if err != nil {
				t.Fatal(err)
			}
			registered, err := decodeJointTestReport(fixture[4+i])
			if err != nil {
				t.Fatal(err)
			}
			if combined.Plan.Set != set || combined.Plan.Phase != Pilot || combined.Plan.MainSeedCommitment != "" || registered.Plan.Phase != Pilot || registered.Plan.ParentDigest != combined.Plan.Digest || primary.Plan.ParentDigest != registered.Plan.Digest || !reflect.DeepEqual(combined.Plan.Configurations, primary.Plan.Configurations) || !reflect.DeepEqual(combined.Plan.FrozenModels, primary.Plan.FrozenModels) || !reflect.DeepEqual(combined.Plan.Powers, primary.Plan.Powers) || !reflect.DeepEqual(combined.Plan.PowerSearch, primary.Plan.PowerSearch) {
				t.Fatal("shared API Arrange changed its original values or ancestry")
			}
			for _, p := range []Plan{combined.Plan, registered.Plan, primary.Plan} {
				if ValidatePlan(p) != nil || validateFrozenModels(primary.Models, &p) != nil || frozenCommonReport(p, primary.Models, primary.Manifest.BaseSeed).validate() != nil {
					t.Fatal("genuine API successor lost common frozen-model or Report compatibility")
				}
				frozenCommonColdLoad(t, p, primary.Models)
			}
			path := frozenCommonFiles(t, registered.Plan, primary.Models)
			c := Config{Set: set, Phase: Primary, Suite: jcrypto.SuiteC25519, Revision: registered.Plan.Revision, Seed: primary.Manifest.BaseSeed, PlanPath: path}
			p, err := loadPlan(path, c, registered.Plan.Tree, registered.Plan.BinarySHA256)
			if err != nil || !validPhasePredecessor(c, p) {
				t.Fatal("genuine registered Pilot failed ordinary Primary preparation")
			}
			p.ParentDigest, p.Digest, p.Phase = p.Digest, "", c.Phase
			loaded, err := loadFrozen(path, p)
			if ValidatePlan(p) != nil || err != nil || !reflect.DeepEqual(loaded, primary.Models) {
				t.Fatal("genuine internal Primary failed the real frozen loader")
			}
			if completed := planningTestSeal(t, p); !reflect.DeepEqual(completed, primary.Plan) {
				t.Fatal("ordinary Primary preparation changed the existing fixture's sealed bytes")
			}
			jointTestCheckSnapshot(t, primary, fixture[i])
			jointTestCheckSnapshot(t, combined, fixture[2+i])
			jointTestCheckSnapshot(t, registered, fixture[4+i])
		})
	}
}
