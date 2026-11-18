package nodeview

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

var seedRegistrationTestFixture = sync.OnceValues(func() ([2]string, error) {
	left, right, err := makePlanningTestPilots()
	if err != nil {
		return [2]string{}, err
	}
	inputs, err := serializeJointTestReports([2]Report{{Plan: left}, {Plan: right}})
	if err != nil {
		return [2]string{}, err
	}
	var before [2]Plan
	for i := range before {
		report, err := decodeJointTestReport(inputs[i])
		if err != nil {
			return [2]string{}, err
		}
		before[i] = report.Plan
	}
	a, b, err := CombinePilotPlans(context.Background(), left, right)
	if err != nil {
		return [2]string{}, err
	}
	if !reflect.DeepEqual(left, before[0]) || !reflect.DeepEqual(right, before[1]) {
		return [2]string{}, fmt.Errorf("plain combination changed an actual pilot input")
	}
	if len(a.Powers) == 0 || len(a.Powers[0].PilotX) == 0 || len(b.Powers) == 0 || len(b.Powers[0].PilotX) == 0 || len(a.PowerSearch) == 0 || len(a.PowerSearch[0].Search) == 0 || len(b.PowerSearch) == 0 || len(b.PowerSearch[0].Search) == 0 || len(a.FrozenModels) == 0 || len(b.FrozenModels) == 0 || len(a.Configurations) == 0 || len(a.Configurations[0].Controlled) == 0 || len(left.Configurations) == 0 || len(left.Configurations[0].Controlled) == 0 {
		return [2]string{}, fmt.Errorf("plain combination lacks its actual backing probes")
	}
	bBefore, err := json.Marshal(Report{Plan: b})
	if err != nil {
		return [2]string{}, err
	}
	pilot, search, model, controlled := a.Powers[0].PilotX[0], a.PowerSearch[0].Search[0].N, a.FrozenModels[0].Digest, a.Configurations[0].Controlled[0]
	changedModel := strings.Repeat("f", 64)
	if pilot == 1 || search == 512 || model == changedModel || controlled == 4 {
		return [2]string{}, fmt.Errorf("plain combination backing probes are ineffective")
	}
	a.Powers[0].PilotX[0] = 1
	a.PowerSearch[0].Search[0].N = 512
	a.FrozenModels[0].Digest = changedModel
	a.Configurations[0].Controlled[0] = 4
	bAfter, err := json.Marshal(Report{Plan: b})
	if err != nil {
		return [2]string{}, err
	}
	if b.Powers[0].PilotX[0] != 0 || b.PowerSearch[0].Search[0].N != 30 || reflect.DeepEqual(a.FrozenModels, b.FrozenModels) || left.Configurations[0].Controlled[0] != 0 || !bytes.Equal(bBefore, bAfter) || !reflect.DeepEqual(left, before[0]) || !reflect.DeepEqual(right, before[1]) {
		return [2]string{}, fmt.Errorf("actual plain successors or inputs share mutable backing")
	}
	a.Powers[0].PilotX[0] = pilot
	a.PowerSearch[0].Search[0].N = search
	a.FrozenModels[0].Digest = model
	a.Configurations[0].Controlled[0] = controlled
	return serializeJointTestReports([2]Report{{Plan: a}, {Plan: b}})
})

func seedRegistrationTestReadyPilots(t *testing.T) (Plan, Plan) {
	t.Helper()
	left, right, err := decodeSeedRegistrationTestReadyPilots()
	if err != nil {
		t.Fatal(err)
	}
	return left, right
}

func decodeSeedRegistrationTestReadyPilots() (Plan, Plan, error) {
	fixture, err := seedRegistrationTestFixture()
	if err != nil {
		return Plan{}, Plan{}, err
	}
	var plans [2]Plan
	for i := range plans {
		report, err := decodeJointTestReport(fixture[i])
		if err != nil {
			return Plan{}, Plan{}, err
		}
		plans[i] = report.Plan
	}
	return plans[0], plans[1], nil
}

func TestSeedRegistrationTestReadyPilotsAreIndependent(t *testing.T) {
	a, b := seedRegistrationTestReadyPilots(t)
	otherA, otherB := seedRegistrationTestReadyPilots(t)
	fixture, err := seedRegistrationTestFixture()
	if err != nil {
		t.Fatal(err)
	}
	left, right, err := makePlanningTestPilots()
	if err != nil {
		t.Fatal(err)
	}
	for i, plan := range []Plan{a, b} {
		input := []Plan{left, right}[i]
		jointTestCheckSnapshot(t, Report{Plan: plan}, fixture[i])
		if !samePlanningContract(plan, input) || !reflect.DeepEqual(plan.Configurations, input.Configurations) || plan.Set != input.Set || plan.Phase != Pilot || !plan.PilotReady || !plan.TrainingReady || plan.ModelReady || plan.MainSeedCommitment != "" || plan.ParentDigest != input.Digest || plan.Digest == input.Digest {
			t.Fatal("seed fixture changed its original plain-pilot values, readiness or ancestry")
		}
		if len(plan.Powers) != 13 || len(plan.PowerSearch) != 13 || len(plan.FrozenModels) != 8 || !reflect.DeepEqual(plan.FrozenModels, right.FrozenModels) {
			t.Fatal("seed fixture changed its original family or plain model references")
		}
		sealed, err := sealPlanningTestPlan(plan)
		if err != nil || sealed.Digest != plan.Digest {
			t.Fatal("seed fixture changed its canonical sealed digest")
		}
	}
	mutate := func(plan *Plan) {
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
			row.ForeignPositions = append(row.ForeignPositions, 4)
		}
		for i := range plan.FrozenModels {
			plan.FrozenModels[i].Digest = "changed"
		}
		plan.Samples = append(plan.Samples, SampleCalculation{ID: "changed", Slots: 1})
		for i := range plan.Powers {
			plan.Powers[i].PilotX[0]++
			plan.Powers[i].PilotY[0]++
		}
		for i := range plan.PowerSearch {
			plan.PowerSearch[i].Search[0].N++
		}
	}
	mutate(&a)
	jointTestCheckSnapshot(t, Report{Plan: b}, fixture[1])
	mutate(&b)
	jointTestCheckSnapshot(t, Report{Plan: otherA}, fixture[0])
	jointTestCheckSnapshot(t, Report{Plan: otherB}, fixture[1])
	freshA, freshB := seedRegistrationTestReadyPilots(t)
	jointTestCheckSnapshot(t, Report{Plan: freshA}, fixture[0])
	jointTestCheckSnapshot(t, Report{Plan: freshB}, fixture[1])
	type decoded struct {
		plans [2]Plan
		err   error
	}
	start := make(chan struct{})
	results := make(chan decoded, 2)
	var readers sync.WaitGroup
	readers.Add(2)
	for range 2 {
		go func() {
			defer readers.Done()
			<-start
			left, right, err := decodeSeedRegistrationTestReadyPilots()
			results <- decoded{[2]Plan{left, right}, err}
		}()
	}
	close(start)
	readers.Wait()
	close(results)
	var copies [][2]Plan
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		copies = append(copies, result.plans)
	}
	if len(copies) != 2 {
		t.Fatal("concurrent fixture readers did not both finish")
	}
	for _, pair := range copies {
		for i, plan := range pair {
			jointTestCheckSnapshot(t, Report{Plan: plan}, fixture[i])
		}
	}
	mutate(&copies[0][0])
	jointTestCheckSnapshot(t, Report{Plan: copies[0][1]}, fixture[1])
	for i, plan := range copies[1] {
		jointTestCheckSnapshot(t, Report{Plan: plan}, fixture[i])
	}
	mutate(&copies[0][1])
	for i, plan := range copies[1] {
		jointTestCheckSnapshot(t, Report{Plan: plan}, fixture[i])
	}
	mutate(&copies[1][0])
	jointTestCheckSnapshot(t, Report{Plan: copies[1][1]}, fixture[1])
	mutate(&copies[1][1])
	jointTestCheckSnapshot(t, Report{Plan: freshA}, fixture[0])
	jointTestCheckSnapshot(t, Report{Plan: freshB}, fixture[1])
	lastA, lastB := seedRegistrationTestReadyPilots(t)
	jointTestCheckSnapshot(t, Report{Plan: lastA}, fixture[0])
	jointTestCheckSnapshot(t, Report{Plan: lastB}, fixture[1])
}

func TestMainSeedCommitmentKnownInputAndHash(t *testing.T) {
	p := testNodeviewPlan(Collude)
	input, err := mainSeedInput(p, 0)
	want := append([]byte("jimichi-nodeview-main-seed-v1\x00"+strings.Repeat("a", 40)+strings.Repeat("b", 40)+strings.Repeat("c", 64)), 1, 2, 0, 22, 4, 0, 0, 0, 0, 0, 0, 0, 0)
	if err != nil || len(input) != 187 || !bytes.Equal(input[:], want) {
		t.Fatal("main seed commitment input changed")
	}
	// independently checked SHA-256 of the 187-byte input
	commitment, err := mainSeedCommitment(p, 0)
	if err != nil || commitment != "c7eacd2a9610327d89e7c487b64c2893deda8bf2a812dcc6df77011b0c5345e5" {
		t.Fatal("main seed commitment hash changed")
	}
	for _, answer := range []struct {
		seed int64
		tail string
	}{{0, "0000000000000000"}, {-1, "ffffffffffffffff"}, {math.MinInt64, "8000000000000000"}, {math.MaxInt64, "7fffffffffffffff"}} {
		input, err := mainSeedInput(p, answer.seed)
		if err != nil || hex.EncodeToString(input[179:]) != answer.tail || !bytes.Equal(input[:179], want[:179]) {
			t.Fatal("signed statistical seed encoding changed")
		}
	}
}

func TestMainSeedCommitmentBindsRegisteredTuple(t *testing.T) {
	p := testNodeviewPlan(Collude)
	base, err := mainSeedCommitment(p, 11704)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Plan){
		"revision": func(p *Plan) { p.Revision = strings.Repeat("d", 40) },
		"tree":     func(p *Plan) { p.Tree = strings.Repeat("d", 40) },
		"binary":   func(p *Plan) { p.BinarySHA256 = strings.Repeat("d", 64) },
		"suite":    func(p *Plan) { p.Suite = "gost" },
		"set":      func(p *Plan) { p.Set = Mailbox },
		"version":  func(p *Plan) { p.SeedDomainVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			copyPlan := clonePlanningPlan(p)
			mutate(&copyPlan)
			if changed, err := mainSeedCommitment(copyPlan, 11704); err == nil && changed == base {
				t.Fatal("changed registration tuple retained the seed commitment")
			}
		})
	}
	if changed, err := mainSeedCommitment(p, 11705); err != nil || changed == base {
		t.Fatal("different main base retained the seed commitment")
	}
	p.Phase = Train
	if same, err := mainSeedCommitment(p, 11704); err != nil || same != base {
		t.Fatal("commitment encoded the predecessor phase instead of primary")
	}
}

func TestRegisterMainSeedPreservesReadyPredecessorAndAncestry(t *testing.T) {
	model, err := PrepareModelPlan(context.Background(), planningTestSeal(t, testNodeviewPlan(Compromise)))
	if err != nil {
		t.Fatal(err)
	}
	left, right := seedRegistrationTestReadyPilots(t)
	inputs := []Plan{model, left, right}
	for _, set := range []Set{Compromise, Collude, Mailbox} {
		p := testNodeviewPlan(set)
		p.Suite = "gost"
		if set == Mailbox {
			p.ParentDigest = planningTestSeal(t, p).Digest
			p.Phase, p.TrainingReady = Train, true
			p.FrozenModels = append([]ModelReference(nil), right.FrozenModels...)
		}
		inputs = append(inputs, planningTestSeal(t, p))
	}
	for _, input := range inputs {
		t.Run(input.Suite+"/"+string(input.Set), func(t *testing.T) {
			before := clonePlanningPlan(input)
			registered, err := RegisterMainSeed(context.Background(), input, 11704)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(input, before) || registered.ParentDigest != input.Digest || registered.Digest == input.Digest || registered.MainSeedCommitment == "" || ValidatePlan(registered) != nil {
				t.Fatal("seed registration changed its predecessor or lost ancestry")
			}
			normalized := clonePlanningPlan(registered)
			normalized.MainSeedCommitment = input.MainSeedCommitment
			normalized.ParentDigest, normalized.Digest = input.ParentDigest, input.Digest
			if !reflect.DeepEqual(normalized, input) {
				t.Fatal("seed registration changed models, counts or planning")
			}
			for _, seed := range []int64{11704, 11705} {
				if _, err := RegisterMainSeed(context.Background(), registered, seed); err == nil {
					t.Fatal("an existing main seed registration was overwritten")
				}
			}
			registered.Configurations[0].Controlled[0] = 4
			registered.ModelFamily.IDs[0] = "changed"
			if !reflect.DeepEqual(input, before) {
				t.Fatal("seed successor retained mutable predecessor backing")
			}
		})
	}
}

func TestRegisterMainSeedRejectsPrematureAndAlteredPlanning(t *testing.T) {
	left, _ := planningTestPilots(t)
	ready, _ := seedRegistrationTestReadyPilots(t)
	for _, name := range []string{"structural", "uncombined", "unsealed", "digest", "primary", "planning", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			p := clonePlanningPlan(ready)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "structural":
				p = planningTestSeal(t, testNodeviewPlan(Collude))
			case "uncombined":
				p = left
			case "unsealed":
				p.Digest = ""
			case "digest":
				p.Digest = strings.Repeat("f", 64)
			case "primary":
				p.Phase = Primary
				p = planningTestSeal(t, p)
			case "planning":
				p.Powers[0].Successes--
				p = planningTestSeal(t, p)
			case "cancelled":
				cancel()
			}
			before := clonePlanningPlan(p)
			if output, err := RegisterMainSeed(ctx, p, 11704); err == nil || output.Digest != "" || !reflect.DeepEqual(p, before) {
				t.Fatal("incomplete or changed planning became a main seed registration")
			}
		})
	}
}

func TestMainSeedLoadingChecksBindingBeforeReturningPlan(t *testing.T) {
	p := testNodeviewPlan(Collude)
	p.Suite = "gost"
	p = planningTestSeal(t, p)
	registered, err := RegisterMainSeed(context.Background(), p, 11704)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registration.json")
	save := func(p Plan) {
		t.Helper()
		body, err := json.Marshal(p)
		if err != nil || os.WriteFile(path, body, 0600) != nil {
			t.Fatal("could not save the test registration")
		}
	}
	save(registered)
	c := Config{Set: Collude, Phase: Primary, Suite: jcrypto.SuiteGOST, Seed: 11704, Revision: p.Revision}
	loaded, err := loadPlan(path, c, p.Tree, p.BinarySHA256)
	if err != nil || !reflect.DeepEqual(loaded, registered) {
		t.Fatal("matching main seed did not load its unchanged predecessor")
	}
	for _, name := range []string{"seed", "missing", "copied-set", "malformed", "nonprimary"} {
		t.Run(name, func(t *testing.T) {
			copyPlan, config := clonePlanningPlan(registered), c
			switch name {
			case "seed":
				config.Seed++
			case "missing":
				copyPlan.MainSeedCommitment = ""
			case "copied-set":
				other := clonePlanningPlan(copyPlan)
				other.Set = Mailbox
				copyPlan.MainSeedCommitment, err = mainSeedCommitment(other, config.Seed)
				if err != nil {
					t.Fatal(err)
				}
			case "malformed":
				copyPlan.MainSeedCommitment = strings.Repeat("F", 64)
			case "nonprimary":
				config.Phase = Structural
			}
			save(planningTestSeal(t, copyPlan))
			if output, err := loadPlan(path, config, p.Tree, p.BinarySHA256); err == nil || output.Digest != "" {
				t.Fatal("unbound main configuration received a plan")
			}
		})
	}
}

func TestPrimaryReportRequiresRetainedMainSeedBinding(t *testing.T) {
	p := testNodeviewPlan(Collude)
	p.Suite = "gost"
	registered, err := RegisterMainSeed(context.Background(), planningTestSeal(t, p), 11704)
	if err != nil {
		t.Fatal(err)
	}
	registered.ParentDigest, registered.Digest, registered.Phase = registered.Digest, "", Primary
	registered = planningTestSeal(t, registered)
	r := testNodeviewReport()
	r.Plan, r.Manifest.Suite, r.Manifest.BaseSeed = registered, "gost", 11704
	if err := r.validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "seed", "parent"} {
		t.Run(name, func(t *testing.T) {
			copyReport := r
			switch name {
			case "missing":
				copyReport.Plan.MainSeedCommitment = ""
			case "seed":
				copyReport.Manifest.BaseSeed++
			case "parent":
				copyReport.Plan.ParentDigest = ""
			}
			copyReport.Plan = planningTestSeal(t, copyReport.Plan)
			if err := copyReport.validate(); err == nil {
				t.Fatal("primary report lost its registered seed or ancestry")
			}
		})
	}
}
