//go:build linux && amd64

package nodeview

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab"
)

func TestNodeViewLiveOptimized(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("optimized owned-process integration")
	}
	if e := protectProcess(controllerArenaBytes); e != nil {
		t.Fatal(e)
	}
	for _, suite := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(suite.String(), func(t *testing.T) {
			for _, name := range []string{"one-role", "two-edge", "two-adjacent-first", "two-adjacent-last", "trusted-admission", "foreign-peer", "foreign-mailbox", "mailbox-records"} {
				t.Run(name, func(t *testing.T) {
					c := Config{Set: Collude, Phase: Structural, Suite: suite, Seed: 117, Revision: strings.Repeat("1", 40)}
					row := Coordinate{ID: "node-F5-L0", Topology: "echo", Trust: "trusted", Population: "link", Controlled: []int{0, 1}, Placement: "edges", Setup: "concurrent", Mode: "immediate", N: 5, H: 3, Flows: 5, Settings: echoSettings(0)}
					task := executionTask{coordinate: row, missing: 2}
					switch name {
					case "one-role":
						task.coordinate.Controlled = []int{0}
						task.routes = [][3]uint8{{0, 2, 3}, {2, 0, 3}, {2, 3, 0}}
					case "two-edge":
						task.coordinate.Flows = 20
						task.routes = linkRoutes(task.coordinate, 117, 0)
					case "two-adjacent-first":
						task.coordinate.Placement = "adjacent-first"
						task.routes = linkRoutes(task.coordinate, 117, 0)
					case "two-adjacent-last":
						task.coordinate.Placement = "adjacent-last"
						task.routes = linkRoutes(task.coordinate, 117, 0)
					case "trusted-admission":
						c.Set = Mailbox
						task.coordinate = Coordinate{ID: "mail-P0-C0-mailbox-first", Topology: "peer", Trust: "trusted", Population: "control", Controlled: []int{0, 4}, Setup: "concurrent", N: 5, H: 3, Conversations: 16, Settings: peerSettings(false, 0)}
						task.routes = drawRoutes(c, task.coordinate, 32, 0)
						task.structural = true
					case "foreign-peer":
						c.Set = Compromise
						for _, registered := range canonicalCoordinates(Compromise) {
							if registered.ID == "trust-peer-honest-k1-m2" {
								task.coordinate = registered
							}
						}
						task.foreign = append([]int(nil), task.coordinate.ForeignPositions...)
						task.routes = exhaustiveTrustRoutes("peer", 4)
						task.structural = true
					case "foreign-mailbox":
						c.Set = Compromise
						var coordinates []Coordinate
						for _, registered := range canonicalCoordinates(Compromise) {
							if registered.ID == "trust-peer-foreign-k1-m2" {
								coordinates = append(coordinates, registered)
							}
						}
						registered := structuralTrustTasks(c, coordinates)
						if len(registered) != 1 {
							t.Fatal("foreign mailbox trust scenario is missing or ambiguous")
						}
						task = registered[0]
						task.routes = [][3]uint8{{0, 2, 4}, {2, 3, 4}}
					case "mailbox-records":
						c.Set = Mailbox
						task.coordinate = Coordinate{ID: "mail-P0-C0", Topology: "peer", Trust: "trusted", Population: "classifier", Controlled: []int{4}, Setup: "concurrent", N: 5, H: 3, Conversations: 8, Settings: peerSettings(false, 0)}
						task.routes = drawRoutes(c, task.coordinate, 16, 0)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()
					if name == "one-role" {
						exerciseActorInitializationCancellation(t, suite)
						exerciseActorEnrollmentFailures(t, suite)
						exerciseActorContactFailures(t, ctx, suite)
					}
					if name == "trusted-admission" {
						exerciseTrustedWorkloadLimit(t, ctx, c, task)
					}
					var models []FrozenModel
					if name == "mailbox-records" {
						models = liveMailboxModels(t, ctx, c, task)
						plan := defaultPlan(c, c.Revision, strings.Repeat("0", 64))
						plan.Configurations, plan.TrainingReady = []Coordinate{task.coordinate}, true
						var e error
						c, e = prepareOutputResources(c, plan, []executionTask{task})
						if e != nil {
							t.Fatalf("evaluation model admission: %v", e)
						}
					}
					result, audit, training, e := executeTask(ctx, c, task, models)
					defer func() {
						for i := range audit {
							wipeRankAudit(&audit[i])
						}
						for i := range training {
							training[i].wipe()
						}
					}()
					if e != nil {
						if name == "trusted-admission" {
							t.Fatalf("execution failed: flags=%v counts=%+v startup=%t end=%t %s", result.Flags, result.Counts, result.CostsNS[0] != 0, result.CostsNS[6] != 0, formatBoundEvidence(e))
						}
						t.Fatalf("execution: %v", e)
					}
					if len(result.Flags) > 0 || result.Counts.Attempted != uint64(len(task.routes)) {
						t.Fatalf("incomplete cohort: %+v", result.Counts)
					}
					if len(task.foreign) == 0 && result.Counts.Established != uint64(len(task.routes)) {
						t.Fatalf("established: %+v", result.Counts)
					}
					if name == "trusted-admission" && (result.Counts.PreflightOK != 32 || result.Counts.MessageBearing != 32 || result.MeasuredMessages != 32 || result.Counts.Unanswered != 0) {
						t.Fatal("trusted structural cohort did not send one measured message per admitted side")
					}
					if name == "foreign-mailbox" {
						if result.Counts.Refused != uint64(len(task.routes)) {
							t.Fatalf("foreign mailbox admitted: %+v", result.Counts)
						}
						if result.Counts.Planned != uint64(len(task.routes)) || result.Counts.Established != 0 || result.Counts.PreflightOK != 0 || result.Counts.MessageBearing != 0 || result.Counts.SetupFailed != 0 {
							t.Fatalf("foreign mailbox refusal accounting: %+v", result.Counts)
						}
						if result.NoPartner != 0 || result.Counts.Eligible != 0 || result.Counts.Unknown != 0 || result.Counts.Positive != 0 || result.Counts.Negative != 0 || result.RecordClasses != [2]uint64{} {
							t.Fatal("refused foreign mailbox manufactured an orphan or classifier population")
						}
						if result.ModelComplete || result.MeasuredMessages != 0 || result.ContentMessages != 0 || result.ContentFound != 0 || result.Touched != 0 || result.Ends != 0 {
							t.Fatal("refused foreign mailbox manufactured successful model or content evidence")
						}
						for _, count := range result.RouteHistogram {
							if count != 0 {
								t.Fatal("refused foreign mailbox contributed a measured route sample")
							}
						}
					}
					if name == "foreign-peer" && (result.Counts.Refused != 3 || result.Counts.PreflightOK != 9 || result.NoPartner != 1 || result.Counts.MessageBearing != 8) {
						t.Fatal("foreign peer population changed")
					}
					if name == "mailbox-records" {
						assertLiveMailboxPredictions(t, result, audit, len(task.routes)/2)
						if len(training) != 0 || quarantinedFixtures.Load() != 0 {
							t.Fatal("evaluation retained training rows or unjoined fixture ownership")
						}
					}
				})
			}
		})
	}
}

func exerciseTrustedWorkloadLimit(t *testing.T, ctx context.Context, c Config, task executionTask) {
	t.Helper()
	if c.Set != Mailbox || c.Phase != Structural || task.coordinate.Settings != peerSettings(false, 0) {
		t.Fatal("source-cap fixture changed its pinned phase or workload")
	}
	c.Seed = 574
	c.resources = &resourceUsage{}
	task.repeat = 0
	task.coordinate.Conversations = 1
	task.routes = drawRoutes(c, task.coordinate, 2, task.repeat)
	task.structural = false
	plan := defaultPlan(c, c.Revision, strings.Repeat("0", 64))
	plan.Configurations = []Coordinate{task.coordinate}
	var err error
	c, err = prepareOutputResources(c, plan, []executionTask{task})
	if err != nil {
		t.Fatal(reasonOf(err))
	}
	if err = c.hostCapacity.cohort(0, len(task.routes)); err != nil {
		t.Fatal(reasonOf(err))
	}
	f, err := newFixture(ctx, c.Suite, task.coordinate.Settings, 2, task.coordinate.Controlled, nil, c.binarySHA, task.missing, fixtureResources{usage: c.resources, host: c.hostCapacity})
	if err != nil {
		t.Fatal(reasonOf(err))
	}
	defer func() {
		cleanup := f.close()
		f.closeMu.Lock()
		f.mu.Lock()
		ready := f.closed && !f.quarantined && f.arena.buffer == nil
		f.mu.Unlock()
		f.closeMu.Unlock()
		if cleanup != nil || !ready || quarantinedFixtures.Load() != 0 {
			t.Fatal("source-cap fixture did not complete owned cleanup")
		}
	}()
	if err = f.budget.checkAllocation(uint64(len(task.routes)) * uint64(unsafe.Sizeof(workloadPlan{}))); err != nil {
		t.Fatal(reasonOf(err))
	}
	plans := make([]workloadPlan, len(task.routes))
	defer clear(plans)
	for i, route := range task.routes {
		plans[i] = workloadPlan{side: uint16(i), route: route, gapSeed: nodeSeed(c, uint64(task.coordinate.Settings.RelayPeriodNS), uint64(task.repeat), uint64(i), lab.StreamNodeGaps), lifetimeSeed: nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), uint64(i), lab.StreamNodeLifetime), phaseSeed: nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), uint64(i), lab.StreamNodeSetup), topology: 2, bodyArena: f.arena}
	}
	clients, err := f.addClients(plans, false)
	if err != nil {
		t.Fatal(reasonOf(err))
	}
	now := monotonicNS()
	epoch := now + 100000000
	cutoff := epoch + task.coordinate.Settings.DurationNS
	if now <= 0 || epoch <= now || cutoff <= epoch {
		t.Fatal("source-cap fixture clock is invalid")
	}
	if err = f.begin(epoch); err != nil {
		t.Fatal(reasonOf(err))
	}
	if err = waitUntil(ctx, cutoff); err != nil {
		t.Fatal(reasonOf(err))
	}
	drain := max(int64(300000000), 12*(task.coordinate.Settings.RateNS+task.coordinate.Settings.RelayPeriodNS))
	if drain > 10000000000 {
		t.Fatal("source-cap fixture exceeded its registered drain bound")
	}
	if err = waitUntil(ctx, cutoff+drain); err != nil {
		t.Fatal(reasonOf(err))
	}
	if err = f.stop(0); err != nil {
		t.Fatal(reasonOf(err))
	}
	terminalErr := f.finish()
	until, _ := f.shutdownDeadlines()
	if !f.joinReaders(until) || len(clients) != 2 || len(f.children) != 7 {
		t.Fatal("source-cap fixture did not finish its complete actor and reader exchange")
	}
	for i, child := range clients {
		want := 91
		reason := ReasonNone
		if i == 0 {
			want, reason = 128, ReasonLimit
		}
		created, sent := 0, 0
		for _, message := range child.truth.messages {
			if message.side != uint16(i) {
				t.Fatal("source-cap fixture changed message ownership")
			}
			if message.sent || !message.replied {
				created++
			}
			if message.sent {
				sent++
			}
		}
		if created != want || sent != want || child.reason != reason {
			t.Fatal("source cap did not retain its actual accepted prefix and truthful completed terminal")
		}
	}
	t.Log("source-cap prefix and End reasons verified")
	if terminalErr != nil {
		t.Fatalf("source-cap terminal exchange: %s", reasonOf(terminalErr))
	}
	if !f.captureValidated {
		t.Fatal("source-cap fixture did not validate its terminal and owned Wait exchange")
	}
	for _, child := range clients {
		if len(child.flags) != 0 || !child.reaped || child.waitErr != nil || child.usageErr != nil {
			t.Fatal("source-cap client did not complete its clean actor lifetime")
		}
	}
	for _, child := range f.relays {
		if child.reason != ReasonNone || len(child.flags) != 0 || !child.reaped || child.waitErr != nil || child.usageErr != nil {
			t.Fatal("source-cap fixture failed outside its declared workload boundary")
		}
	}
	if err = c.hostCapacity.checkObserved(f); err != nil {
		t.Fatal(reasonOf(err))
	}
}

func liveMailboxModels(t *testing.T, ctx context.Context, evaluation Config, task executionTask) []FrozenModel {
	t.Helper()
	training := evaluation
	training.Phase = Train
	training.Seed = 117001
	training.resources = &resourceUsage{}
	training.trainingBudget = &memoryBudget{limit: controllerArenaBytes}
	plan := defaultPlan(training, training.Revision, strings.Repeat("0", 64))
	plan.Configurations = []Coordinate{task.coordinate}
	var e error
	training, e = prepareOutputResources(training, plan, []executionTask{task})
	if e != nil {
		t.Fatalf("training admission: %v", e)
	}
	training.trainingBudget.beforeAllocation = training.hostCapacity.checkGrowth
	trainingTask := task
	trainingTask.routes = drawRoutes(training, task.coordinate, len(task.routes), 0)
	defer clear(trainingTask.routes)
	row, audit, rows, e := executeTask(ctx, training, trainingTask, nil)
	defer func() {
		for i := range audit {
			wipeRankAudit(&audit[i])
		}
		for i := range rows {
			rows[i].wipe()
		}
		training.trainingBudget.release(trainingBacking(rows))
	}()
	if e != nil || len(row.Flags) != 0 || !row.ModelComplete || row.Counts.Established != uint64(len(task.routes)) || row.Counts.Unknown != 0 || row.QueueJoined.Value == nil || len(rows) == 0 || row.Phase != Train || row.Seed == nodeSeed(evaluation, coordinateID(task.coordinate.ID), uint64(task.repeat), 0, lab.StreamNodeMain) {
		t.Fatalf("dedicated training capture: %v, counts %+v", e, row.Counts)
	}
	if row.Counts.Positive == 0 || row.Counts.Negative == 0 || row.RecordClasses[0] == 0 || row.RecordClasses[1] == 0 || uint64(len(rows)) != row.Counts.Eligible || quarantinedFixtures.Load() != 0 {
		t.Fatal("training classes, labels or cleanup incomplete")
	}
	poolBytes := trainingBacking(rows)
	if training.trainingBudget.used != poolBytes || training.trainingBudget.beforeAllocation == nil {
		t.Fatal("dedicated rows lost their single shared raw charge or fresh host hook")
	}
	hostGrowth := training.trainingBudget.beforeAllocation
	var fitAllocations atomic.Uint32
	training.trainingBudget.beforeAllocation = func(n uint64) error {
		if n >= 8<<20 {
			fitAllocations.Add(1)
		}
		return hostGrowth(n)
	}
	fitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	f := &fixture{ctx: fitCtx, cancel: cancel, suite: training.Suite, binaryDigest: training.binarySHA, resources: training.resources, budget: training.trainingBudget}
	// this arena lease conservatively overlaps the per-role 8MiB fixed allowance
	f.arena, e = newBudgetedArena(4096, 4096, f.budget)
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	defer func() {
		if e := f.close(); e != nil {
			t.Errorf("training cleanup: %v", e)
		}
	}()
	assertLiveFitLedger(t, f, poolBytes)
	var models []FrozenModel
	pool := rows
	for _, population := range []string{"request", "record"} {
		if population == "record" {
			kept := pool[:0]
			for _, row := range pool {
				if row.Values[0] == 1 && row.Values[1] == 3 {
					kept = append(kept, row)
				}
			}
			clear(pool[len(kept):])
			pool = kept
		}
		if e := training.hostCapacity.checkGrowth(uint64(len(pool))*512 + 8<<20); e != nil {
			t.Fatal(e)
		}
		beforeHigh := f.budget.high
		beforeAllocations := fitAllocations.Load()
		reservation := uint64(len(pool))*512 + 8<<20
		trained, e := f.train(pool, len(row.Flags) == 0 && quarantinedFixtures.Load() == 0, row.QueueJoined.Value != nil)
		if e != nil || !validateMailboxTraining(trained) || !trained.Releasable || trained.Model == nil || !trained.Support.RAMConformance || !trained.Support.Stable {
			t.Fatalf("guarded %s fitting: %v, release reason %q", population, e, trained.Reason)
		}
		classes := [2]int{int(row.Counts.Negative), int(row.Counts.Positive)}
		if population == "record" {
			classes = [2]int{int(row.RecordClasses[0]), int(row.RecordClasses[1])}
		}
		if trained.Support.Rows != classes || trained.Witness.ClassCount != classes {
			t.Fatalf("%s fitted population does not match dedicated observations", population)
		}
		assertLiveFitLedger(t, f, poolBytes)
		if f.budget.high < max(beforeHigh, poolBytes+4096+reservation) || fitAllocations.Load()-beforeAllocations != 2 {
			t.Fatal("fitting did not admit its per-role raw envelope")
		}
		if e := training.hostCapacity.checkObserved(f); e != nil {
			t.Fatal(e)
		}
		released := FrozenModel{Schema: "jimichi-nodeview-model-v1", Features: featureVersion, Population: population, Configuration: task.coordinate.ID, Suite: training.Suite.String(), TrainRevision: training.Revision, TransformDigest: plan.TransformDigest, Training: trained}
		encoded, e := json.Marshal(released)
		if e != nil {
			t.Fatal(e)
		}
		released.Digest = publicHash(encoded)
		clear(encoded)
		models = append(models, released)
	}
	if len(f.children) != 4 {
		t.Fatal("both populations did not run trainer and fit-auditor")
	}
	for i, child := range f.children {
		if child.role != []byte{roleTrainer, roleFitAuditor, roleTrainer, roleFitAuditor}[i] || !child.reaped || child.waitErr != nil || child.usageErr != nil || child.reason != ReasonNone || child.resource == nil || child.resource.usage != training.resources || i%2 == 1 && !child.fitOK {
			t.Fatal("training participant did not complete guarded fit and owned Wait")
		}
	}
	if e := f.close(); e != nil || f.arena.buffer != nil || quarantinedFixtures.Load() != 0 {
		t.Fatal("training ownership survived final cleanup")
	}
	if f.budget.used != poolBytes || f.scorerReservation != 0 {
		t.Fatal("fitting cleanup released input ownership or retained its arena/role loans")
	}
	if point := training.resources.snapshot(0, nil); point.MaxRSS == nil || point.Reason != ReasonNone {
		t.Fatal("fitting resource tickets were not finalized by definitive Wait")
	}
	return models
}

func assertLiveFitLedger(t *testing.T, f *fixture, poolBytes uint64) {
	t.Helper()
	if f.budget == nil || f.budget.beforeAllocation == nil || f.arena.allocated != 4096 || f.arena.budget != f.budget || f.scorerReservation != 0 {
		t.Fatal("fitting fixture bypassed shared raw admission or retained a completed role lease")
	}
	want := poolBytes + 4096
	for _, child := range f.children {
		want += child.statusCharge
	}
	if f.budget.used != want {
		t.Fatal("fitting ledger does not equal input rows, owned arena and live status loans")
	}
}

func TestNodeViewFitterRejectsOneByteRawDeficitBeforeStart(t *testing.T) {
	rows := make([]encodedTrainingRow, 7)
	defer clear(rows)
	input := trainingBacking(rows)
	reservation := uint64(len(rows))*512 + 8<<20
	host := &hostCapacity{}
	budget := &memoryBudget{limit: input + reservation - 1, used: input, high: input, beforeAllocation: host.checkGrowth}
	if input != 294 || reservation != 8392192 || budget.limit != 8392485 {
		t.Fatal("seven 42-byte rows plus 7*512+8MiB no longer leave an exact one-byte deficit")
	}
	usage := &resourceUsage{}
	f := &fixture{ctx: context.Background(), budget: budget, resources: usage}
	model, e := f.train(rows, true, true)
	if reasonOf(e) != ReasonLimit || model.Releasable || len(f.children) != 0 || f.scorerReservation != 0 || budget.used != input || budget.high != input || usage.pending != 0 || usage.peak != 0 {
		t.Fatal("one-byte raw deficit started a fitter or changed existing input ownership")
	}
	budget.release(input)
}

func assertLiveMailboxPredictions(t *testing.T, row RunResult, audit []RankAudit, conversations int) {
	t.Helper()
	if row.Counts.Positive == 0 || row.Counts.Negative == 0 || row.RecordClasses[0] == 0 || row.RecordClasses[1] == 0 || row.Counts.Unknown != 0 || row.Counts.Eligible != row.Counts.Positive+row.Counts.Negative || row.QueueJoined.Value == nil || row.RequestLDA.Value == nil || row.RecordLDA.Value == nil || !row.ModelComplete {
		t.Fatalf("evaluation classes, labels or model-backed scores incomplete: %+v", row.Counts)
	}
	for _, population := range []string{"request", "record"} {
		wantPositive, wantNegative := int(row.Counts.Positive), int(row.Counts.Negative)
		if population == "record" {
			wantPositive, wantNegative = int(row.RecordClasses[1]), int(row.RecordClasses[0])
		}
		methods, witnesses := 0, 0
		for _, method := range row.Methods {
			if method.Method != population {
				continue
			}
			methods++
			if method.WindowNS != peerSettings(false, 0).DurationNS || method.Candidates != wantPositive+wantNegative || method.AUC.Value == nil || method.Undefined != 0 || method.Impossible != 0 {
				t.Fatalf("%s prediction tuples missing or duplicated", population)
			}
		}
		for _, witness := range audit {
			if witness.Method != population {
				continue
			}
			witnesses++
			positive, negative := 0, 0
			if witness.Configuration != row.Configuration || witness.Repeat != row.Repeat || witness.WindowNS != peerSettings(false, 0).DurationNS || len(witness.Groups) != conversations {
				t.Fatalf("%s evaluation witness scope changed", population)
			}
			for _, group := range witness.Groups {
				for _, bucket := range group {
					positive += bucket.Positive
					negative += bucket.Negative
				}
			}
			if positive != wantPositive || negative != wantNegative {
				t.Fatalf("%s predictions do not cover actual evaluation classes", population)
			}
		}
		if methods != 1 || witnesses != 1 {
			t.Fatalf("%s frozen direction absent or duplicated", population)
		}
	}
}
