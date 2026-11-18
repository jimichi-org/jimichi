//go:build linux && amd64

package nodeview

import (
	"context"
	"crypto/rand"
	"encoding/json"
	mathrand "math/rand"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/lab"
)

func run(ctx context.Context, c Config) (Report, error) {
	if c.resources == nil {
		c.resources = &resourceUsage{}
	}
	if c.Set == Compromise && c.Phase == Pilot && c.Suite.String() == "gost" {
		return Report{}, ErrUnsupported
	}
	tree, binary, e := sourceIdentity(c)
	if e != nil {
		return Report{}, e
	}
	c.binarySHA = binary
	p := defaultPlan(c, tree, binary)
	modelPlanning := c.Set == Compromise && c.Phase == Pilot && c.Suite.String() == "c25519"
	if c.PlanPath != "" {
		p, e = loadPlan(c.PlanPath, c, tree, binary)
		if e != nil {
			return Report{}, e
		}
		if !validPhasePredecessor(c, p) {
			return Report{}, ErrInvalid
		}
		if modelPlanning {
			p, e = PrepareModelPlan(ctx, p)
			if e != nil {
				return Report{}, e
			}
		} else {
			p.ParentDigest = p.Digest
			p.Digest = ""
			p.Phase = c.Phase
		}
	}
	if e = validatePlanning(ctx, p); e != nil {
		return Report{}, e
	}
	if e = preflightTaskDescriptors(c, p); e != nil {
		return Report{}, e
	}
	var tasks []executionTask
	if !modelPlanning {
		if c.Phase == Train {
			tasks = pairedMailboxTasks(c, p)
		} else {
			tasks = registeredTasks(c, p)
		}
	}
	defer func() {
		for i := range tasks {
			clear(tasks[i].routes)
		}
		clear(tasks)
	}()
	c, e = prepareOutputResources(c, p, tasks)
	if e != nil {
		return Report{}, e
	}
	var replayOwned bool
	c, replayOwned, e = acquireSourceReplay(c)
	if e != nil {
		return Report{}, e
	}
	if replayOwned {
		defer c.sourceReplay.close()
	}
	if e = preflightTaskSources(c, tasks); e != nil {
		return Report{}, e
	}
	if e = protectProcess(controllerArenaBytes); e != nil {
		return Report{}, ErrUnsupported
	}
	if runtime.Version() != "go1.27.4" {
		return Report{}, ErrUnsupported
	}
	report := Report{Schema: reportSchema, Plan: p, Manifest: Manifest{BaseSeed: c.Seed, Revision: c.Revision, Tree: tree, BinarySHA256: binary, Runtime: runtime.Version(), Kernel: kernelRelease(), Suite: c.Suite.String(), Protection: "all", Clock: "CLOCK_MONOTONIC-same-kernel", LoadBefore: safeLoad(), LoopbackExemptions: [4]int{-1, -1, -1, -1}, ExemptionReason: p.ExemptionReason}}
	inferenceReason := ReasonIncomplete
	if c.Suite.String() == "gost" {
		inferenceReason = ReasonUnsupported
	}
	for _, id := range modelIDs() {
		report.ModelInference = append(report.ModelInference, Inference{ID: id, Reason: inferenceReason})
	}
	for _, id := range differenceIDs() {
		report.DifferenceInference = append(report.DifferenceInference, Inference{ID: id, Reason: inferenceReason})
	}
	var models []FrozenModel
	if c.Phase == Pilot || c.Phase == Primary {
		if p.TrainingReady {
			models, e = loadFrozen(c.PlanPath, p)
			if e != nil {
				return Report{}, e
			}
			report.Models = models
		}
	}
	if modelPlanning {
		if !p.ModelReady {
			return Report{}, ErrInvalid
		}
	} else if c.Phase == Train {
		e = runTraining(ctx, c, &report)
	} else {
		for index, task := range tasks {
			if quarantinedFixtures.Load() != 0 {
				report.Status = preferReason(report.Status, ReasonChild)
				if e = appendUnstartedTasks(&report, c, tasks[index:], ReasonChild); e != nil {
					report.Status = preferReason(report.Status, reasonOf(e))
				}
				break
			}
			if ctx.Err() != nil {
				report.Status = preferReason(report.Status, ReasonCancelled)
				if e = appendUnstartedTasks(&report, c, tasks[index:], ReasonCancelled); e != nil {
					report.Status = preferReason(report.Status, reasonOf(e))
				}
				break
			}
			row, audit, discarded, err := executeTask(ctx, c, task, models)
			for i := range discarded {
				discarded[i].wipe()
			}
			if row.Configuration == "" {
				report.Status = preferReason(report.Status, preferReason(reasonOf(err), ReasonIncomplete))
				break
			}
			if e = appendTaskOutput(&report, c.outputBudget, row, audit); e != nil {
				report.Status = preferReason(report.Status, reasonOf(e))
				_ = appendUnstartedTasks(&report, c, tasks[index+1:], reasonOf(e))
				break
			}
			if err != nil {
				report.Status = preferReason(report.Status, reasonOf(err))
			}
		}
		if c.Phase == Pilot && c.Suite.String() == "c25519" && report.Status == ReasonNone {
			e = registerPilot(ctx, c, &report)
		}
		if c.Phase == Primary {
			model, difference, err := summarizeInferences(report.Plan, report.Runs)
			if err != nil {
				report.Status = preferReason(report.Status, reasonOf(err))
			} else {
				report.ModelInference, report.DifferenceInference = model, difference
			}
		}
	}
	if e != nil {
		report.Status = preferReason(report.Status, reasonOf(e))
	}
	report.Manifest.LoadAfter = safeLoad()
	report.Plan.Digest = ""
	b, err := json.Marshal(report.Plan)
	if err != nil {
		return Report{}, ErrInvalid
	}
	report.Plan.Digest = publicHash(b)
	peak, usageErr := selfRSS()
	report.Manifest.Resources = c.resources.snapshot(peak, usageErr)
	if report.Status == ReasonNone && report.Manifest.Resources.MaxRSS == nil {
		report.Status = report.Manifest.Resources.Reason
	}
	if report.Status != ReasonNone {
		return report, fail(report.Status)
	}
	return report, nil
}

func kernelRelease() string {
	b, e := os.ReadFile("/proc/sys/kernel/osrelease")
	if e != nil {
		return "unavailable"
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 128 {
		return "unavailable"
	}
	return strings.Clone(s)
}
func preferReason(a, b Reason) Reason {
	return preferredRuntimeReason(a, b)
}

func registeredTasks(c Config, p Plan) []executionTask {
	var tasks []executionTask
	gostDescription := c.Set == Collude && c.Suite.String() == "gost" && c.Phase == Primary
	if c.Set == Compromise && (c.Phase == Structural || c.Suite.String() == "gost" && c.Phase == Primary) {
		structuralConfig := c
		structuralConfig.Phase = Structural
		for _, row := range p.Configurations {
			if row.Population == "trust" || row.Population == "membership" || c.Peer && row.Topology != "peer" {
				continue
			}
			routes := allRoutes(row.Topology == "peer", row.Mailbox)
			for at := 0; at < len(routes); at += min(32, len(routes)-at) {
				n := min(32, len(routes)-at)
				tasks = append(tasks, executionTask{coordinate: row, repeat: at / 32, routes: routes[at : at+n], missing: row.Missing, structural: true})
			}
		}
		return append(tasks, structuralTrustTasks(structuralConfig, p.Configurations)...)
	}
	if c.Set == Mailbox && (c.Phase == Pilot || c.Phase == Primary) {
		return pairedMailboxTasks(c, p)
	}
	for _, row := range p.Configurations {
		if row.Settings.ControlProfile != 0 {
			if c.Set == Mailbox && c.Phase == Structural {
				profile, ok := boundaryProfileFor(row.Settings.ControlProfile)
				if ok {
					tasks = append(tasks, executionTask{coordinate: row, routes: append([][3]uint8(nil), profile.routes[:]...), missing: row.Missing, structural: true})
				}
			}
			continue
		}
		if row.Population == "trust" || row.Population == "membership" {
			continue
		}
		if c.Set == Compromise && c.Phase == Primary {
			for at := 0; at < row.Slots; at += 32 {
				tasks = append(tasks, executionTask{coordinate: row, repeat: at / 32, plannedSides: 32, missing: row.Missing, structural: true})
			}
			continue
		}
		repeats := 1
		if c.Phase == Pilot {
			repeats = 5
		} else if c.Phase == Primary {
			repeats = row.Main
		}
		if row.Population == "control" || row.Population == "incomplete" || row.Population == "defaults-control" {
			if c.Phase != Structural && !gostDescription {
				continue
			}
			if c.Set == Collude && c.Suite.String() == "c25519" {
				repeats = 5
			}
		}
		if gostDescription {
			repeats = 1
		}
		for repeat := range repeats {
			task := executionTask{coordinate: row, repeat: repeat, missing: row.Missing}
			if c.Set == Collude {
				task.plannedSides = row.Flows
			} else {
				task.plannedSides = row.Conversations * 2
			}
			tasks = append(tasks, task)
		}
	}
	return tasks
}

func pairedMailboxTasks(c Config, p Plan) []executionTask {
	var tasks []executionTask
	for _, period := range []int64{0, 33250000} {
		var pair [2]Coordinate
		for _, row := range p.Configurations {
			if row.Population == "classifier" && row.Settings.RelayPeriodNS == period {
				pair[boolInt(row.Settings.CoverPuts)] = row
			}
		}
		repeats := 5
		if c.Phase == Primary && c.Suite.String() == "c25519" {
			repeats = pair[0].Main
		}
		for repeat := range repeats {
			first := mathrand.New(mathrand.NewSource(nodeSeed(c, uint64(period), uint64(repeat), 0, lab.StreamNodePairOrder))).Intn(2)
			for _, index := range []int{first, first ^ 1} {
				row := pair[index]
				tasks = append(tasks, executionTask{coordinate: row, repeat: repeat, plannedSides: row.Conversations * 2, missing: row.Missing})
			}
		}
	}
	return tasks
}

func controlledFor(id string) []int {
	switch id {
	case "E2", "H2":
		return []int{0, 1}
	case "M1":
		return []int{4}
	case "M2":
		return []int{0, 4}
	default:
		return []int{0}
	}
}
func allRoutes(peer bool, exit uint8) [][3]uint8 {
	var out [][3]uint8
	for a := uint8(0); a < 5; a++ {
		for b := uint8(0); b < 5; b++ {
			if a == b {
				continue
			}
			if peer {
				if a != exit && b != exit {
					out = append(out, [3]uint8{a, b, exit})
				}
				continue
			}
			for c := uint8(0); c < 5; c++ {
				if c != a && c != b {
					out = append(out, [3]uint8{a, b, c})
				}
			}
		}
	}
	return out
}
func drawRoutes(c Config, row Coordinate, count, repeat int) [][3]uint8 {
	if row.Topology == "peer" && (row.Placement == "mailbox-first" || row.Placement == "mailbox-middle") {
		routes, e := conditionedPeerRoutes(nodeSeed(c, coordinateID(row.ID), uint64(repeat), 0, lab.StreamNodeSetup), row.Placement, count)
		if e != nil {
			return nil
		}
		return routes
	}
	var out [][3]uint8
	r := mathrand.New(mathrand.NewSource(nodeSeed(c, coordinateID(row.ID), uint64(repeat), 0, lab.StreamNodeSetup)))
	for range count {
		var path []int
		if row.Topology == "peer" {
			entry, e := client.ChooseEntryExcept(5, 4, r)
			if e != nil {
				break
			}
			path, _ = client.ChooseRestTo(entry, 4, 5, 3, r)
		} else {
			path, _ = client.Choose(5, 3, r)
		}
		if len(path) != 3 {
			break
		}
		out = append(out, [3]uint8{uint8(path[0]), uint8(path[1]), uint8(path[2])})
	}
	return out
}
func linkRoutes(row Coordinate, seed int64, repeat int) [][3]uint8 {
	var out [][3]uint8
	r := mathrand.New(mathrand.NewSource(lab.Derive(seed, lab.StreamNodeSetup, coordinateID(row.ID), uint64(repeat), 0)))
	for i := range row.Flows {
		path := [3]uint8{0, uint8(2 + r.Intn(3)), 1}
		if row.Placement == "adjacent-first" {
			path = [3]uint8{0, 1, uint8(2 + r.Intn(3))}
		} else if row.Placement == "adjacent-last" {
			path = [3]uint8{uint8(2 + r.Intn(3)), 0, 1}
		}
		if row.Population == "incomplete" {
			if i >= 8 && i < 10 {
				path = [3]uint8{0, 2, 3}
			} else if i >= 10 {
				path = [3]uint8{2, 3, 1}
			}
		}
		out = append(out, path)
	}
	return out
}

func describeWorkloads(c Config, task executionTask, plans []workloadPlan) error {
	n := max(len(task.routes), task.plannedSides)
	if n > maxClients || n < 0 || len(plans) != n {
		return fail(ReasonContract)
	}
	ceiling, e := sourceAttemptCeiling()
	if e != nil {
		return e
	}
	topology := uint8(1)
	if task.coordinate.Topology == "peer" {
		topology = 2
	}
	for i := range plans {
		path := [3]uint8{}
		if len(task.routes) != 0 {
			path = task.routes[i]
		}
		pairID := coordinateID(task.coordinate.ID)
		if topology == 2 {
			pairID = uint64(task.coordinate.Settings.RelayPeriodNS)
		}
		plans[i] = workloadPlan{side: uint16(i), route: path, gapSeed: nodeSeed(c, pairID, uint64(task.repeat), uint64(i), lab.StreamNodeGaps), lifetimeSeed: nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), uint64(i), lab.StreamNodeLifetime), phaseSeed: nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), uint64(i), lab.StreamNodeSetup), topology: topology, structural: task.structural, defaultsControl: task.coordinate.Population == "defaults-control"}
		if topology == 2 {
			plans[i].sourceLimit = ceiling
		}
	}
	return nil
}

func preflightTaskSources(c Config, tasks []executionTask) error {
	var backing [maxClients]workloadPlan
	defer clear(backing[:])
	for _, task := range tasks {
		if task.membership {
			continue
		}
		n := max(len(task.routes), task.plannedSides)
		if n < 0 || n > len(backing) {
			return fail(ReasonContract)
		}
		plans := backing[:n]
		if e := describeWorkloads(c, task, plans); e != nil {
			return e
		}
		if e := admitPeerSources(plans, task.coordinate.Settings, c.sourceReplay); e != nil {
			return e
		}
		clear(plans)
	}
	return nil
}

func executeTask(ctx context.Context, c Config, task executionTask, models []FrozenModel) (RunResult, []RankAudit, []encodedTrainingRow, error) {
	if c.resources == nil {
		c.resources = &resourceUsage{}
	}
	if quarantinedFixtures.Load() != 0 {
		return RunResult{Configuration: task.coordinate.ID, Repeat: task.repeat, Phase: c.Phase, Flags: []Reason{ReasonChild}}, nil, nil, fail(ReasonChild)
	}
	if c.outputBudget == nil {
		p := defaultPlan(c, c.Revision, strings.Repeat("0", 64))
		p.Configurations = []Coordinate{task.coordinate}
		var e error
		c, e = prepareOutputResources(c, p, []executionTask{task})
		if e != nil {
			return RunResult{Configuration: task.coordinate.ID, Repeat: task.repeat, Phase: c.Phase, Flags: []Reason{reasonOf(e)}}, nil, nil, e
		}
	}
	if e := c.hostCapacity.cohort(c.retainedRawBytes, max(len(task.routes), task.plannedSides)); e != nil {
		return unavailableTask(c, task, reasonOf(e)), nil, nil, e
	}
	var replayOwned bool
	var replayErr error
	c, replayOwned, replayErr = acquireSourceReplay(c)
	if replayErr != nil {
		return unavailableTask(c, task, reasonOf(replayErr)), nil, nil, replayErr
	}
	if replayOwned {
		defer c.sourceReplay.close()
	}
	charge := &resultCharge{}
	c.resultCharge = charge
	row, audit, training, e := executeTaskSource(ctx, c, task, models)
	if e != nil {
		reason := reasonOf(e)
		present := false
		for _, flag := range row.Flags {
			present = present || flag == reason
		}
		if !present {
			row.Flags = append(row.Flags, reason)
		}
	}
	var admissionErr error
	row, audit, admissionErr = finalizeTaskOutput(c, task, row, audit, charge)
	if admissionErr != nil {
		e = mergeRuntimeFailure(e, admissionErr)
	}
	reason := ReasonNone
	for _, flag := range row.Flags {
		reason = preferReason(reason, flag)
	}
	if reason != ReasonNone {
		e = carryBoundReason(e, reason)
	}
	return row, audit, training, e
}

func executeTaskSource(ctx context.Context, c Config, task executionTask, models []FrozenModel) (result RunResult, resultAudit []RankAudit, resultTraining []encodedTrainingRow, resultErr error) {
	var replayOwned bool
	var replayErr error
	c, replayOwned, replayErr = acquireSourceReplay(c)
	if replayErr != nil {
		return unavailableTask(c, task, reasonOf(replayErr)), nil, nil, replayErr
	}
	if replayOwned {
		defer c.sourceReplay.close()
	}

	if task.plannedSides > 0 {
		if len(task.routes) != 0 || task.plannedSides > maxClients {
			return RunResult{Configuration: task.coordinate.ID, Repeat: task.repeat, Phase: c.Phase}, nil, nil, ErrInvalid
		}
		if c.Set == Collude {
			phaseSeed := lab.Derive(c.Seed, phaseDomain(c.Phase), coordinateID(task.coordinate.ID), uint64(task.repeat), 0)
			task.routes = linkRoutes(task.coordinate, phaseSeed, task.repeat)
		} else {
			task.routes = drawRoutes(c, task.coordinate, task.plannedSides, task.repeat)
		}
		defer clear(task.routes)
		if len(task.routes) != task.plannedSides {
			return RunResult{Configuration: task.coordinate.ID, Repeat: task.repeat, Phase: c.Phase}, nil, nil, fail(ReasonContract)
		}
	}
	if task.membership {
		row, audit, training, e := membershipProbe(ctx, c, task)
		row.Seed = nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), 0, lab.StreamNodeMain)
		if e != nil {
			row.Flags = append(row.Flags, reasonOf(e))
		}
		return row, audit, training, e
	}
	row := RunResult{Configuration: task.coordinate.ID, Repeat: task.repeat, Phase: c.Phase, Seed: nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), 0, lab.StreamNodeMain), Counts: Counts{Planned: uint64(len(task.routes))}, QueueJoined: Number{Reason: ReasonNoView}, PutQ: Number{Reason: ReasonNoView}, PutBaseline: Number{Reason: ReasonNoView}, RequestLDA: Number{Reason: ReasonTraining}, RecordLDA: Number{Reason: ReasonTraining}}
	start := monotonicNS()
	if start <= 0 {
		return row, nil, nil, fail(ReasonClock)
	}
	topology := byte(1)
	if task.coordinate.Topology == "peer" {
		topology = 2
	}
	var planBacking [maxClients]workloadPlan
	if len(task.routes) > len(planBacking) {
		return row, nil, nil, fail(ReasonLimit)
	}
	plans := planBacking[:len(task.routes)]
	defer func() {
		for i := range plans {
			clear(plans[i].bodies[:cap(plans[i].bodies)])
		}
		clear(planBacking[:])
	}()
	if e := describeWorkloads(c, task, plans); e != nil {
		return row, nil, nil, e
	}
	if e := admitPeerSources(plans, task.coordinate.Settings, c.sourceReplay); e != nil {
		return row, nil, nil, e
	}
	host := c.hostCapacity
	if host == nil {
		host = &hostCapacity{}
	}
	if e := host.cohort(c.retainedRawBytes, len(plans)); e != nil {
		return row, nil, nil, e
	}
	f, e := newFixture(ctx, c.Suite, task.coordinate.Settings, topology, task.coordinate.Controlled, task.foreign, c.binarySHA, task.missing, fixtureResources{retained: c.retainedRawBytes, usage: c.resources, host: c.hostCapacity})
	if e != nil {
		row.Flags = []Reason{reasonOf(e)}
		return row, nil, nil, e
	}
	defer closeTaskFixture(f, &result, &resultErr)
	f.resultCharge = c.resultCharge
	if c.resultCharge != nil {
		c.resultCharge.budget = f.budget
	}
	f.missing = task.missing
	f.allowOrphan = registeredOrphan(c, task.coordinate)
	count := 0
	if task.structural {
		count = 1
	}
	if task.coordinate.Population == "defaults-control" {
		count = 100
	}
	if profile, ok := boundaryProfileFor(task.coordinate.Settings.ControlProfile); ok {
		count = profile.sourceCount
	}
	if count < 0 || count > 0 && len(task.routes) > maxMessages/count {
		return row, nil, nil, fail(ReasonLimit)
	}
	if e := f.budget.checkAllocation(uint64(len(task.routes)*count)*2*uint64(unsafe.Sizeof(arenaRef{})) + uint64(len(task.routes))*uint64(unsafe.Sizeof(workloadPlan{}))); e != nil {
		return row, nil, nil, e
	}
	declared := make([]arenaRef, 0, len(task.routes)*count)
	defer func() { clear(declared[:cap(declared)]) }()
	for i := range plans {
		plans[i].bodyArena = f.arena
		plans[i].bodies = make([]arenaRef, 0, count)
		for range count {
			if len(declared) >= maxMessages {
				return row, nil, nil, fail(ReasonLimit)
			}
			var body [128]byte
			ref, bodyErr := declareSourceBody(f.arena, declared, rand.Read, &body)
			if bodyErr != nil {
				return row, nil, nil, bodyErr
			}
			declared = append(declared, ref)
			plans[i].bodies = append(plans[i].bodies, ref)
		}
	}
	clients, e := f.addClients(plans, task.coordinate.Setup == "serial")
	if e != nil {
		row.Flags = []Reason{reasonOf(e)}
		return row, nil, nil, e
	}
	row.CostsNS[0] = monotonicNS() - start
	lead := int64(100000000)
	if task.coordinate.Settings.ControlProfile != 0 {
		lead = 200000000
	}
	now := monotonicNS()
	if now <= 0 {
		return row, nil, nil, fail(ReasonClock)
	}
	epoch := now + lead
	cutoff := epoch + task.coordinate.Settings.DurationNS
	if epoch <= now || cutoff <= epoch {
		return row, nil, nil, fail(ReasonClock)
	}
	if e = f.begin(epoch); e != nil {
		row.Flags = []Reason{reasonOf(e)}
		return row, nil, nil, e
	}
	if e = waitUntil(ctx, cutoff); e != nil {
		row.Flags = []Reason{reasonOf(e)}
		return row, nil, nil, e
	}
	drain := max(int64(300000000), 12*(task.coordinate.Settings.RateNS+task.coordinate.Settings.RelayPeriodNS))
	if drain > 10000000000 {
		row.Flags = []Reason{ReasonLimit}
		return row, nil, nil, fail(ReasonLimit)
	}
	if e = waitUntil(ctx, cutoff+drain); e != nil {
		row.Flags = []Reason{reasonOf(e)}
		return row, nil, nil, e
	}
	if e = f.stop(0); e == nil {
		e = f.finish()
	}
	if e != nil {
		row.Flags = []Reason{reasonOf(e)}
		return row, nil, nil, e
	}
	views := viewSet{}
	truth := privateTruth{arena: f.arena, budget: f.budget}
	defer truth.wipeMetadata()
	portToRoster := map[uint16]int{}
	defer clear(portToRoster)
	established := make(map[uint16]bool, maxClients)
	defer clear(established)
	var processSummaries summaryAccumulator
	for i, ch := range f.relays {
		if !ch.hasSummary {
			return row, nil, nil, fail(ReasonIncomplete)
		}
		if e = processSummaries.add(ch.processSummary); e != nil {
			return row, nil, nil, e
		}
		row.MaxRSS = max(row.MaxRSS, ch.maxRSS)
		portToRoster[ch.port] = i
		if ch.selected {
			ch.view.position = uint8(i)
			views.nodes = append(views.nodes, ch.view)
		}
		if e = mergeTruth(&truth, ch.truth); e != nil {
			return row, nil, nil, e
		}
		if ch.reason != ReasonNone {
			row.Flags = append(row.Flags, ch.reason)
		}
		for _, reason := range ch.flags {
			row.Flags = appendRuntimeReason(row.Flags, reason)
		}
	}
	for i, ch := range clients {
		established[uint16(i)] = ch.counts.PreflightOK == 1
		row.MaxRSS = max(row.MaxRSS, ch.maxRSS)
		if ch.orphan {
			row.NoPartner++
			row.Counts.Missing++
		}
		mergeCounts(&row.Counts, ch.counts)
		if e = mergeTruth(&truth, ch.truth); e != nil {
			return row, nil, nil, e
		}
		if ch.reason != ReasonNone {
			row.Flags = append(row.Flags, ch.reason)
		}
		for _, reason := range ch.flags {
			row.Flags = appendRuntimeReason(row.Flags, reason)
		}
	}
	processSummary, _, summaryErr := processSummaries.result()
	if summaryErr != nil {
		return row, nil, nil, summaryErr
	}
	row.Capture = processSummary
	if len(task.foreign) > 0 {
		filtered := row.Flags[:0]
		for _, r := range row.Flags {
			if r != ReasonRefused {
				filtered = append(filtered, r)
			}
		}
		row.Flags = filtered
	}
	row.Counts.Unanswered = truth.resolveMessageReceipts()
	for ni := range views.nodes {
		shuffle := mathrand.New(mathrand.NewSource(nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), uint64(ni), lab.StreamNodeAnonymous)))
		shuffle.Shuffle(len(views.nodes[ni].setups), func(i, j int) {
			views.nodes[ni].setups[i], views.nodes[ni].setups[j] = views.nodes[ni].setups[j], views.nodes[ni].setups[i]
		})
	}
	public := publicConfig{suite: uint8(c.Suite), n: 5, h: 3, controlled: task.coordinate.Controlled, settings: task.coordinate.Settings, binNS: 100000000, windowsNS: []int64{1000000000, 2000000000, 5000000000, 10000000000, 20000000000}, population: task.coordinate.Topology, epochNS: epoch, cutoffNS: cutoff}
	defer func() { public = publicConfig{} }()
	for i, node := range f.roster {
		public.roster[i] = node.port
	}
	frozen := frozenTraining{}
	for _, m := range models {
		if m.Configuration == task.coordinate.ID {
			if m.Population == "request" {
				frozen.request = m.Training.Model
			} else if m.Population == "record" {
				frozen.record = m.Training.Model
			}
		}
	}
	captureFailure := ReasonNone
	for _, flag := range row.Flags {
		switch flag {
		case ReasonContract, ReasonIPC, ReasonLabel, ReasonClock, ReasonLimit:
			captureFailure = preferReason(captureFailure, flag)
		}
	}
	if captureFailure != ReasonNone {
		row.RequestLDA, row.RecordLDA = Number{Reason: captureFailure}, Number{Reason: captureFailure}
		return row, nil, nil, fail(captureFailure)
	}
	pred, e := f.score(views, public, frozen)
	if e != nil {
		row.Flags = append(row.Flags, reasonOf(e))
		return row, nil, nil, e
	}
	defer pred.wipe()
	truth.ownership, e = parseSetupOwnership(truth.setups, f.budget)
	if e != nil {
		return row, nil, nil, e
	}
	nkEndpoints := make(map[uint32]int, 2*maxConnections)
	defer clear(nkEndpoints)
	for _, s := range truth.setups {
		owner, ok := ownerOf(truth, s.circuit, s.roster)
		if !ok || owner.group != 1 {
			continue
		}
		if int(s.side) >= len(plans) {
			return row, nil, nil, fail(ReasonLabel)
		}
		plans[s.side].route[s.hop] = s.roster
	}
	for _, node := range views.nodes {
		for _, s := range node.setups {
			owner, ok := ownerOf(truth, s.circuit, node.position)
			if !ok || owner.group != 1 || s.index != 0 {
				continue
			}
			incoming, present := connection(node, s.connection)
			if !present || !incoming.authenticated || incoming.initiator || incoming.peer != 255 || incoming.selectorPort != 0 || incoming.localPort == 0 || incoming.remotePort == 0 {
				continue
			}
			key := uint32(incoming.localPort)<<16 | uint32(incoming.remotePort)
			token := 5 + int(owner.side)
			if old, present := nkEndpoints[key]; present && old != token {
				return row, nil, nil, fail(ReasonContract)
			}
			nkEndpoints[key] = token
		}
	}
	var sources [5]fragmentSourceGroup
	if len(f.relays) > len(sources) {
		return row, nil, nil, fail(ReasonContract)
	}
	for i, ch := range f.relays {
		sources[i] = fragmentSourceGroup{uint8(i), ch.truth.fragments}
	}
	fragmentSources, releaseSources, e := buildFragmentSourceIndex(sources[:], f.budget)
	clear(sources[:])
	if e != nil {
		return row, nil, nil, e
	}
	defer releaseSources()
	in := evaluationInput{queueFalsePairs: &row.QueueFalsePairs, resultCharge: c.resultCharge, budget: f.budget, views: views, truth: truth, plans: plans, public: public, portToRoster: portToRoster, fragmentSource: fragmentSources, established: established, nkEndpoints: nkEndpoints}
	if e = checkBoundaryEvaluation(task.coordinate.Settings.ControlProfile, in); e != nil {
		row.Flags = append(row.Flags, reasonOf(e))
	}
	evaluated, e := firstChainOutcomes(pred, in, row.Counts, len(row.Flags) == 0)
	fragmentSources = nil
	in.fragmentSource = nil
	releaseSources()
	if e != nil {
		return row, nil, nil, e
	}
	row.SetupOverlap, e = observedSetupOverlap(in)
	if e != nil {
		return row, nil, nil, e
	}
	if task.coordinate.Setup == "serial" && row.SetupOverlap > 0 {
		evaluated.ModelComplete = false
	}
	row.RouteHistogram, row.ContentFound, row.ContentMessages, row.MeasuredMessages = evaluated.RouteHistogram, evaluated.ContentFound, evaluated.ContentMessages, evaluated.MeasuredMessages
	row.Touched, row.Ends, row.ModelComplete = evaluated.Touched, evaluated.Ends, evaluated.ModelComplete
	if task.coordinate.Settings.ControlProfile == 0 && task.coordinate.Population != "trust" && !row.ModelComplete {
		row.Flags = append(row.Flags, ReasonIncomplete)
	}
	selected, selectedErr := selectedCaptureSummary(views, epoch, cutoff)
	if selectedErr != nil {
		return row, nil, nil, selectedErr
	}
	row.Capture.Counters, row.Capture.Stages, row.Capture.Roles, row.Capture.Lifecycle, row.Capture.OperationLengths = selected.Counters, selected.Stages, evaluated.Capture.Roles, selected.Lifecycle, selected.OperationLengths
	row.Capture.NeighbourConfirmed, row.Capture.NeighbourUnknown, row.Capture.NeighbourConflicting = selected.NeighbourConfirmed, selected.NeighbourUnknown, selected.NeighbourConflicting
	var audit []RankAudit
	acquisition := captureLinkingAcquisition(in, f.captureValidated && pred.layout != nil && pred.received == pred.layout.total)
	clear(portToRoster)
	clear(nkEndpoints)
	clear(established)
	in.portToRoster, in.nkEndpoints, in.established = nil, nil, nil
	for index, m := range pred.methods {
		var result MethodResult
		var witness RankAudit
		available, cause := acquiredMethod(acquisition, m)
		var err error
		if available {
			result, witness, err = summarizeMethod(m, in, row.Configuration, row.Repeat, nodeSeed(c, coordinateID(row.Configuration), uint64(task.repeat), uint64(index), lab.StreamNodeBootstrap))
		} else {
			err = fail(cause)
		}
		if err != nil {
			failMethodAcquisition(&acquisition, m, reasonOf(err))
			row.Flags = append(row.Flags, reasonOf(err))
			missing := Number{Reason: reasonOf(err)}
			result = MethodResult{Method: m.method, WindowNS: m.windowNS, AUC: missing, TopOne: missing, TPR: missing, BootstrapLow: missing, BootstrapHigh: missing}
			row.Methods = append(row.Methods, result)
			if m.method == "request" {
				row.RequestLDA = missing
			} else if m.method == "record" {
				row.RecordLDA = missing
			}
			continue
		}
		row.Methods = append(row.Methods, result)
		audit = append(audit, witness)
		if m.method == "request" {
			row.RequestLDA = result.AUC
		} else if m.method == "record" {
			row.RecordLDA = result.AUC
		}
	}
	var training []encodedTrainingRow
	row.LinkingTimes, e = linkingTimes(row.Methods, acquisition)
	if e != nil {
		row.Flags = append(row.Flags, ReasonContract)
		return row, audit, nil, fail(ReasonContract)
	}
	for _, ch := range f.relays {
		for _, v := range ch.view.cells {
			if v.hop == 0 {
				continue
			}
			if v.stages&stageLocal != 0 {
				row.Counts.LocalProcessed++
			}
			if v.stages&stageWritten != 0 {
				row.Counts.WriteComplete++
			}
		}
	}
	if e := f.releaseEvaluatedInput(&views, &pred); e != nil {
		return row, audit, nil, e
	}
	if topology == 2 {
		population, excluded, recordClasses, err := mailboxPopulation(in)
		row.Counts.Eligible, row.Counts.Positive, row.Counts.Negative, row.Counts.Unknown = population.Eligible, population.Positive, population.Negative, population.Unknown
		row.RequestExclusions = excluded
		row.RecordClasses = recordClasses
		if err != nil {
			row.Flags = append(row.Flags, reasonOf(err))
		}
		q, auc, joined, requests, records, err := mailboxEvaluation(in)
		row.PutQ, row.PutBaseline, row.QueueJoined = q, auc, joined
		if err != nil {
			row.Flags = append(row.Flags, reasonOf(err))
		}
		training = requests
		if task.coordinate.Settings.ControlProfile != 0 {
			for i := range training {
				training[i].wipe()
			}
			training = nil
			row.RequestLDA = Number{Reason: ReasonTraining}
			row.RecordLDA = Number{Reason: ReasonTraining}
		}
		for i := range records {
			records[i].wipe()
		}
		if e := c.resultCharge.releasePart(trainingBacking(records)); e != nil {
			return row, audit, nil, e
		}
		if c.Phase != Train {
			for i := range training {
				training[i].wipe()
			}
			if e := c.resultCharge.releasePart(trainingBacking(training)); e != nil {
				return row, audit, nil, e
			}
			training = nil
		}
		if c.Phase == Train {
			n := trainingBacking(training)
			if c.trainingBudget == nil {
				for i := range training {
					training[i].wipe()
				}
				_ = c.resultCharge.releasePart(n)
				return row, audit, nil, fail(ReasonContract)
			}
			if e := c.trainingBudget.reserve(n); e != nil {
				for i := range training {
					training[i].wipe()
				}
				_ = c.resultCharge.releasePart(n)
				return row, audit, nil, e
			}
			if e := c.resultCharge.releasePart(n); e != nil {
				c.trainingBudget.release(n)
				for i := range training {
					training[i].wipe()
				}
				return row, audit, nil, e
			}
		}
	}
	row.ClockResolutionNS, e = clockResolution()
	if e != nil {
		row.Flags = append(row.Flags, reasonOf(e))
	}
	row.CostsNS[6] = monotonicNS() - start
	if e := c.hostCapacity.checkObserved(f); e != nil {
		row.Flags = append(row.Flags, reasonOf(e))
	}
	for _, child := range f.children {
		row.MaxRSS = max(row.MaxRSS, child.maxRSS)
	}
	if peak, e := selfRSS(); e == nil {
		row.MaxRSS = max(row.MaxRSS, peak)
	} else {
		row.Flags = append(row.Flags, reasonOf(e))
	}
	if len(row.Flags) > 0 {
		return row, audit, training, fail(row.Flags[0])
	}
	return row, audit, training, nil
}

func mergeCounts(dst *Counts, src Counts) {
	dst.Attempted += src.Attempted
	dst.Refused += src.Refused
	dst.SetupFailed += src.SetupFailed
	dst.Established += src.Established
	dst.PreflightOK += src.PreflightOK
	dst.MessageBearing += src.MessageBearing
	dst.Eligible += src.Eligible
	dst.Unanswered += src.Unanswered
	dst.Rebuilt += src.Rebuilt
	dst.Missing += src.Missing
	dst.Positive += src.Positive
	dst.Negative += src.Negative
	dst.Unknown += src.Unknown
}

func closeTrainingRole(f *fixture, operationErr, resourceErr error) error {
	result := mergeRuntimeFailure(operationErr, resourceErr)
	return mergeRuntimeFailure(result, f.close())
}

func runTraining(ctx context.Context, c Config, r *Report) (resultErr error) {
	var replayOwned bool
	var replayErr error
	c, replayOwned, replayErr = acquireSourceReplay(c)
	if replayErr != nil {
		return replayErr
	}
	if replayOwned {
		defer c.sourceReplay.close()
	}
	tasks := pairedMailboxTasks(c, r.Plan)
	defer clear(tasks)
	if e := preflightTaskSources(c, tasks); e != nil {
		return e
	}
	accountingFailed := false
	defer func() {
		if resultErr != nil && !accountingFailed {
			resultErr = mergeRuntimeFailure(resultErr, appendMissingTrainingTasks(r, c, tasks, reasonOf(resultErr)))
		}
	}()
	for _, period := range []int64{0, 33250000} {
		var pools [2][]encodedTrainingRow
		clean, joined := [2]bool{true, true}, [2]bool{true, true}
		poolBudget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: c.hostCapacity.checkGrowth}
		c.trainingBudget = poolBudget
		wipePools := func() {
			for i := range pools {
				for j := range pools[i] {
					pools[i][j].wipe()
				}
				releaseCapacity(pools[i], poolBudget)
				pools[i] = nil
			}
		}
		for _, task := range tasks {
			if quarantinedFixtures.Load() != 0 {
				wipePools()
				return fail(ReasonChild)
			}
			if ctx.Err() != nil {
				wipePools()
				return fail(ReasonCancelled)
			}
			if task.coordinate.Settings.RelayPeriodNS != period {
				continue
			}
			index := boolInt(task.coordinate.Settings.CoverPuts)
			c.retainedRawBytes = poolBudget.used
			row, audit, rows, e := executeTask(ctx, c, task, nil)
			returnedBytes := trainingBacking(rows)
			if row.Configuration == "" {
				accountingFailed = true
				for i := range rows {
					rows[i].wipe()
				}
				poolBudget.release(returnedBytes)
				wipePools()
				return mergeRuntimeFailure(e, fail(ReasonIncomplete))
			}
			if e := appendTaskOutput(r, c.outputBudget, row, audit); e != nil {
				accountingFailed = true
				for i := range rows {
					rows[i].wipe()
				}
				poolBudget.release(returnedBytes)
				wipePools()
				return e
			}
			if e != nil {
				clean[index] = false
				r.Status = preferReason(r.Status, reasonOf(e))
			}
			if len(pools[index])+len(rows) > maxTrainingRows {
				for i := range rows {
					rows[i].wipe()
				}
				poolBudget.release(returnedBytes)
				wipePools()
				return fail(ReasonLimit)
			}
			for i := range rows {
				rows[i].Conversation += uint16(task.repeat * task.coordinate.Conversations)
			}
			pools[index], e = appendCapacity(pools[index], len(rows), poolBudget)
			if e != nil {
				for i := range rows {
					rows[i].wipe()
				}
				poolBudget.release(returnedBytes)
				wipePools()
				return e
			}
			pools[index] = append(pools[index], rows...)
			for i := range rows {
				rows[i].wipe()
			}
			poolBudget.release(returnedBytes)
			if row.QueueJoined.Value == nil {
				joined[index] = false
			}
		}
		for index := range 2 {
			coordinate := Coordinate{}
			for _, candidate := range r.Plan.Configurations {
				if candidate.Population == "classifier" && candidate.Settings.RelayPeriodNS == period && boolInt(candidate.Settings.CoverPuts) == index {
					coordinate = candidate
				}
			}
			pool := pools[index]
			// the two populations reuse one bounded encoded matrix rather than duplicate it
			for _, population := range []string{"request", "record"} {
				if population == "record" {
					kept := pool[:0]
					for _, row := range pool {
						if row.Values[0] == 1 && row.Values[1] == 3 {
							kept = append(kept, row)
						}
					}
					for i := len(kept); i < len(pool); i++ {
						pool[i].wipe()
					}
					pool = kept
				}
				if poolBudget.used+uint64(len(pool))*512+8<<20 > controllerArenaBytes {
					wipePools()
					return fail(ReasonLimit)
				}
				if e := c.hostCapacity.checkGrowth(uint64(len(pool))*512 + (8 << 20)); e != nil {
					wipePools()
					return e
				}
				f := &fixture{ctx: ctx, suite: c.Suite, binaryDigest: c.binarySHA, resources: c.resources, budget: poolBudget}
				f.ctx, f.cancel = context.WithTimeout(ctx, time.Minute)
				f.arena, _ = newArena(4096)
				if f.arena == nil {
					wipePools()
					return fail(ReasonUnsupported)
				}
				model, e := f.train(pool, clean[index], joined[index])
				e = closeTrainingRole(f, e, c.hostCapacity.checkObserved(f))
				if e != nil {
					wipePools()
					return e
				}
				released := FrozenModel{Schema: "jimichi-nodeview-model-v1", Features: featureVersion, Population: population, Configuration: coordinate.ID, Suite: c.Suite.String(), TrainRevision: c.Revision, TransformDigest: r.Plan.TransformDigest, Training: model}
				if model.Releasable {
					b, e := json.Marshal(released)
					if e != nil {
						wipePools()
						return fail(ReasonConformance)
					}
					released.Digest = publicHash(b)
					r.Plan.FrozenModels = append(r.Plan.FrozenModels, ModelReference{coordinate.ID, population, released.Digest})
				} else {
					r.Status = preferReason(r.Status, Reason(model.Reason))
				}
				r.Models = append(r.Models, released)
			}
			for i := range pool {
				pool[i].wipe()
			}
		}
		wipePools()
	}
	r.Plan.TrainingReady = len(r.Plan.FrozenModels) == 8 && r.Status == ReasonNone
	if !r.Plan.TrainingReady {
		return fail(ReasonSupport)
	}
	return nil
}

func registerPilot(ctx context.Context, c Config, r *Report) error {
	ids := differenceIDs()
	if c.Set == Collude {
		ids = ids[:9]
	} else if c.Set == Mailbox {
		ids = ids[9:]
	} else {
		return ErrInvalid
	}
	for _, id := range ids {
		var x, y []float64
		if strings.HasPrefix(id, "node-") {
			for _, row := range r.Runs {
				if row.Configuration != id || len(row.Flags) > 0 {
					continue
				}
				var a, b *float64
				for _, m := range row.Methods {
					if m.WindowNS != 20000000000 {
						continue
					}
					if m.Method == "cells" {
						a = m.AUC.Value
					} else if m.Method == "frames" {
						b = m.AUC.Value
					}
				}
				if a != nil && b != nil {
					x = append(x, *a)
					y = append(y, *b)
				}
			}
		} else {
			period := "mail-P0"
			if strings.Contains(id, "33250000") {
				period = "mail-P33250000"
			}
			record := strings.HasSuffix(id, "record")
			for repeat := range 5 {
				var off, on *float64
				for _, row := range r.Runs {
					if row.Repeat != repeat || len(row.Flags) > 0 {
						continue
					}
					value := row.RequestLDA.Value
					if record {
						value = row.RecordLDA.Value
					}
					if row.Configuration == period+"-C0" {
						off = value
					} else if row.Configuration == period+"-C1" {
						on = value
					}
				}
				if on != nil && off != nil {
					x = append(x, *on)
					y = append(y, *off)
				}
			}
		}
		if len(x) != 5 || len(y) != 5 {
			return fail(ReasonPilot)
		}
		power, e := PlanPairedPower(ctx, x, y, nodeSeed(c, coordinateID(id), 0, 0, lab.StreamNodePower))
		r.Planning = append(r.Planning, PlanningResult{ID: id, PilotX: append([]float64(nil), x...), PilotY: append([]float64(nil), y...), Power: power})
		if e != nil {
			return e
		}
		point, e := PairedPowerAtN(ctx, x, y, power.Seed, power.SelectedN)
		if e != nil {
			return e
		}
		r.Plan.Powers = append(r.Plan.Powers, PowerCalculation{ID: id, N: power.SelectedN, Seed: power.Seed, Successes: point.Successes, Simulations: 10000, PilotX: x, PilotY: y, Low: point.Low, High: point.High})
	}
	r.Plan.PilotReady = false
	return nil
}
