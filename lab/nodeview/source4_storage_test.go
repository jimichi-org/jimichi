package nodeview

import (
	"math"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func TestSource4OwnedTimesAndBinsEndAtTheirConsumers(t *testing.T) {
	times := make([]time.Duration, 2, 5)
	times[0] = 10 * time.Millisecond
	times[1] = 110 * time.Millisecond
	times[:cap(times)][4] = 999 * time.Second
	allTimes := times[:cap(times)]
	bins := binOwnedTimes(times, 300*time.Millisecond, 100*time.Millisecond)
	if !slices.Equal(bins, []float64{1, 1, 0}) || !slices.Equal(allTimes, make([]time.Duration, len(allTimes))) {
		t.Fatal("Bin changed values or retained owned timestamps")
	}
	left := [][]float64{{1, 0, 1}}
	right := [][]float64{{1, 0, 1}, {0, 1, 0}}
	l, r0, r1 := left[0], right[0], right[1]
	out := predictions{methods: make([]predictedMethod, 0, 1)}
	appendOwnedBins(&out, "frames", 1_000_000_000, left, right)
	defer out.wipe()
	if !slices.Equal(l, []float64{0, 0, 0}) || !slices.Equal(r0, []float64{0, 0, 0}) || !slices.Equal(r1, []float64{0, 0, 0}) || left[0] != nil || right[0] != nil || right[1] != nil {
		t.Fatal("ScorePairs inputs outlived their real consumer")
	}
	if len(out.methods) != 1 || !reflect.DeepEqual(out.methods[0].values, []pairValue{{0, 0, 1}, {0, 1, -1}}) || !reflect.DeepEqual(out.methods[0].matches, []metrics.ViewEdge{{First: 0, Second: 0}}) {
		t.Fatal("owned-bin cleanup erased returned predictions or changed numerical order")
	}
}

func TestSource4OwnershipFullDomainAndFailureWipe(t *testing.T) {
	setups := make([]actualSetup, maxContexts)
	for i := range setups {
		circuit := uint64(math.MaxUint64) - uint64(i)
		if i == 0 {
			circuit = 0
		}
		setups[i] = setupRecord(uint16((i/3)%maxClients), uint8(2-i%3), circuit)
	}
	owners, e := parseSetupOwnership(setups)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(owners)
	first, ok := owners.lookup(setupIdentity{0, 2})
	if !ok || !first.complete || first.group != 1 || first.side != 0 {
		t.Fatal("zero/full-width identity or original construction order changed")
	}
	last, ok := owners.lookup(setupIdentity{setups[len(setups)-1].circuit, 1})
	if !ok || last.complete {
		t.Fatal("partial final construction became complete")
	}
	saved := append(setupOwnershipIndex(nil), owners...)
	if _, ok := ownerOf(privateTruth{ownership: owners}, 0, 2); !ok || !reflect.DeepEqual(owners, saved) {
		t.Fatal("borrowed ownership storage was changed")
	}
	invalid := append([]actualSetup(nil), setups...)
	invalid[len(invalid)-1].circuit = 0
	failed := make(setupOwnershipIndex, len(invalid))
	if reasonOf(parseSetupOwnershipInto(invalid, failed)) != ReasonLabel || !reflect.DeepEqual(failed, make(setupOwnershipIndex, len(failed))) {
		t.Fatal("failed full-domain parse retained a partial owner index")
	}
	budget := &memoryBudget{used: 17, limit: controllerArenaBytes, beforeAllocation: func(uint64) error { return fail(ReasonClock) }}
	if result, e := parseSetupOwnership(setups, budget); result != nil || reasonOf(e) != ReasonClock || budget.used != 17 {
		t.Fatal("ownership allocation changed an earlier charge or flattened its cause")
	}
}

func TestSource4CounterWideKeysFirstSeenAndExactLease(t *testing.T) {
	if unsafe.Sizeof(counterPrevious{}) != 32 {
		t.Fatal("counter state layout changed")
	}
	const full = uint32(math.MaxUint32)
	const half = uint32(0x7fffffff)
	cells := []cellView{
		{hop: full, kind: 1, dir: 0, counter: 10, localTime: 50, stages: stageInput},
		{hop: full, kind: 1, dir: 0, counter: 11, outputCounter: 12, localTime: 110, sealTime: 111, stages: stageInput | stageLocal | stageSealed},
		{hop: half, kind: 1, dir: 0, counter: 20, outputCounter: 21, localTime: 110, sealTime: 111, stages: stageInput | stageLocal | stageSealed},
		{hop: full, kind: 1, dir: 1, counter: 5, outputCounter: 6, localTime: 120, stages: stageInput | stageLocal},
		{hop: half, kind: 1, dir: 1, counter: 8, outputCounter: 9, localTime: 120, stages: stageInput | stageLocal},
		{hop: full, kind: 1, dir: 0, counter: 12, outputCounter: 13, localTime: 130, sealTime: 131, stages: stageInput | stageLocal | stageSealed},
	}
	budget := &memoryBudget{used: 17, limit: 1000}
	c := collector{view: nodeView{budget: budget, cells: cells, setups: []setupView{{hop: full, first: 10}, {hop: half, first: 20}}}, start: 100, cutoff: 200}
	if e := c.checkCounters(); e != nil {
		t.Fatal(e)
	}
	x := c.summary.Counters
	// two unaliased forward first checks, five measured records and two input/output advances
	if x.FirstChecked != 2 || x.FirstOK != 2 || x.FirstFailed != 0 || x.Samples != 5 || x.Matched != 3 || x.Missing != 2 || x.Transitions != 2 || x.Advanced != 2 || x.ShiftChecks != 1 || x.ShiftOK != 1 {
		t.Fatalf("wide-key/window counter answer changed: %+v", x)
	}
	if budget.used != 17 || budget.high != 17+6*8+4*32 {
		t.Fatal("counter leases were doubled or not returned")
	}
	scratch, release, e := makeCounterScratch(cells, budget)
	if e != nil {
		t.Fatal(e)
	}
	keys, states := scratch.keys[:cap(scratch.keys)], scratch.states
	states[0].input = 99
	release()
	release()
	if !slices.Equal(keys, make([]uint64, len(keys))) || !reflect.DeepEqual(states, make([]counterPrevious, len(states))) || scratch.keys != nil || scratch.states != nil || budget.used != 17 {
		t.Fatal("counter last-consumer release retained owned backing")
	}
	for _, cause := range []Reason{ReasonLimit, ReasonClock} {
		calls := 0
		b := &memoryBudget{used: 17, limit: 1000, beforeAllocation: func(uint64) error {
			calls++
			if calls == 2 {
				return fail(cause)
			}
			return nil
		}}
		before := append([]cellView(nil), cells...)
		if s, done, e := makeCounterScratch(cells, b); s != nil || done != nil || reasonOf(e) != cause || b.used != 17 || !reflect.DeepEqual(cells, before) {
			t.Fatal("second counter admission changed input or an existing charge")
		}
	}
}

func TestSource4ValidatorHandles8192PartialSetups(t *testing.T) {
	budget := &memoryBudget{used: 17, limit: controllerArenaBytes}
	node := nodeView{budget: budget, setups: make([]setupView, maxContexts)}
	for i := range node.setups {
		node.setups[i] = setupView{generation: uint32(i + 1), hop: uint32(0x80000000 + i), index: 2}
	}
	before := append([]setupView(nil), node.setups...)
	if e := validateViewBindings(node, nil); e != nil || budget.used != 17 || budget.high != 17+16*maxContexts || !reflect.DeepEqual(node.setups, before) {
		t.Fatal("pre-linking validator imposed a new128 bound or changed borrowed partial setups")
	}
	node.setups[len(node.setups)-1].hop = node.setups[0].hop
	if reasonOf(validateViewBindings(node, nil)) != ReasonContract || budget.used != 17 {
		t.Fatal("full-domain duplicate was not rejected transactionally")
	}
}

func TestSource4TrainingFullUint16DomainAndPrefixFailure(t *testing.T) {
	rows := make([]encodedTrainingRow, 0, maxTrainingRows)
	for id := 0; id < 1<<16; id++ {
		rows = append(rows, encodedTrainingRow{Conversation: uint16(id)}, encodedTrainingRow{Conversation: uint16(id), Positive: true})
	}
	result := trainMailbox(rows, featureVersion, false, true)
	if result.Releasable || result.Support.Rows != [2]int{65536, 65536} || result.Support.Conversations != [2]int{65536, 65536} || result.Support.LargestConversation != [2]int{1, 1} {
		t.Fatal("full uint16 conversation IDs were restricted or counted differently")
	}
	prefix := []encodedTrainingRow{{Conversation: math.MaxUint16, OriginalSeal: true}, {Conversation: 17, Positive: true, OriginalSeal: true}, {Positive: true}}
	prefix[2].Values[17] = -1
	failed := trainMailbox(prefix, featureVersion, true, true)
	if failed.Reason != string(ReasonContract) || failed.Support.Rows != [2]int{1, 1} || failed.Support.OriginalSeals != [2]int{1, 1} || failed.Support.Conversations != [2]int{} || failed.Support.LargestConversation != [2]int{} {
		t.Fatal("invalid suffix changed prefix error support")
	}
}

func TestSource4PredictKeepsEmptyAndBothMailboxMethods(t *testing.T) {
	model := &metrics.Discriminant{Weights: make([]float64, 18), Center: make([]float64, 18), Normalizer: 1, Kept: []int{0}}
	model.Weights[0] = 1
	for i := 1; i < 18; i++ {
		model.Unused = append(model.Unused, i)
	}
	public := publicConfig{n: 5, h: 3, binNS: 100_000_000, epochNS: 100, cutoffNS: 200, windowsNS: linkingGrid[:], settings: Settings{RateNS: 35_000_000}}
	views := viewSet{nodes: []nodeView{{position: 4, mailbox: []mailboxObservation{{Circuit: 1, Order: 1, CallNS: 10, ReturnNS: 10, Complete: true}}}, {position: 4, mailbox: []mailboxObservation{{Circuit: 2, Order: 1, CallNS: 10, ReturnNS: 10, Complete: true}}}}}
	out, e := predict(views, public, frozenTraining{request: model, record: model})
	if e != nil {
		t.Fatal(e)
	}
	defer out.wipe()
	if len(out.methods) != 18 {
		t.Fatal("empty per-node model metadata was dropped or truncated at16")
	}
	for i, m := range out.methods {
		if len(m.values) != 0 {
			t.Fatal("out-of-window rows manufactured predictions")
		}
		if i >= 14 && m.method != []string{"request", "record", "request", "record"}[i-14] {
			t.Fatal("per-node population order changed")
		}
	}
	views.nodes[0].mailbox[0].CallNS = 110
	views.nodes[0].mailbox[0].ReturnNS = 110
	invalid := *model
	invalid.Normalizer = 0
	failed, e := predict(views, public, frozenTraining{request: &invalid})
	if reasonOf(e) != ReasonTraining || failed.methods != nil || model.Normalizer != 1 {
		t.Fatal("failed model scoring retained partial owned output or changed a borrowed model")
	}
}

func TestSource4OriginalSealUsesOnlyEligibleOriginalOrder(t *testing.T) {
	a := outcomeTestArena(t)
	makeRecord := func(number byte) arenaRef {
		body := make([]byte, 392)
		body[0] = 3
		body[4] = number
		return outcomeTestCopy(t, a, body)
	}
	first, second := makeRecord(1), makeRecord(2)
	in := evaluationInput{truth: privateTruth{arena: a, setups: outcomeTestGroup(0, [3]uint8{0, 1, 4}, 100), seals: []actualSeal{{record: first, real: true}, {record: second, real: false}}}, plans: []workloadPlan{{side: 0}, {side: 1}}, public: publicConfig{epochNS: 100, cutoffNS: 1000, settings: Settings{RateNS: 35_000_000}}, views: viewSet{nodes: []nodeView{{position: 4, arena: a, setups: []setupView{{hop: 10, circuit: 102}}}}}}
	for i, entry := range []struct {
		alias       uint32
		record      arenaRef
		eligibility uint8
	}{{math.MaxUint32, first, 1}, {0, arenaRef{}, 2}, {math.MaxUint32, first, 2}, {math.MaxUint32, first, 2}, {1, second, 2}, {0, arenaRef{}, 2}} {
		o := mailboxObservation{Circuit: 10, Order: uint32(i + 1), Tag: uint16(i + 1), CallNS: int64(100 + i*10), ReturnNS: int64(101 + i*10), Complete: true, FetchQueue: 9, RecordAlias: entry.alias, record: entry.record}
		if entry.alias != 0 {
			o.HasPut = true
			o.PutQueue = 7
			o.RecordKind = 3
			o.RecordNumber = uint32(a.bytes(entry.record)[4])
		}
		in.views.nodes[0].mailbox = append(in.views.nodes[0].mailbox, o)
		in.truth.requests = append(in.truth.requests, actualRequest{side: 0, generation: 1, tag: o.Tag, record: entry.record, eligibility: entry.eligibility, success: true})
	}
	_, _, _, requests, records, e := mailboxEvaluation(in)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for i := range requests {
			requests[i].wipe()
		}
		for i := range records {
			records[i].wipe()
		}
	}()
	var flags []bool
	for _, row := range requests {
		flags = append(flags, row.OriginalSeal)
	}
	if !slices.Equal(flags, []bool{false, true, false, true, false}) || len(records) != 3 || !records[0].OriginalSeal || records[1].OriginalSeal || !records[2].OriginalSeal {
		t.Fatal("future, excluded, zero or sparse alias changed OriginalSeal in original order")
	}
}

func TestSource4RankRevalidationChecksPhysicalGrowthOnly(t *testing.T) {
	m := MethodResult{Method: "setup", Candidates: 2, Partners: 1, Made: 1, AUC: number(1, ReasonNone), TPR: number(1, ReasonNone), TopOne: number(1, ReasonNone)}
	a := RankAudit{Method: "setup", Groups: [][]RankBucket{{{Rank: 1, Negative: 1}, {Rank: 2, Positive: 1, Category: 1}}}, TopOne: [][2]int{{1, 1}}, Made: 1}
	calls := 0
	b := &memoryBudget{used: 17, limit: 1000, beforeAllocation: func(n uint64) error {
		calls++
		if n != 96 {
			t.Fatal("rank capacity is not actual sizeof")
		}
		return fail(ReasonClock)
	}}
	if reasonOf(validateRankRelease(m, a, b)) != ReasonClock || calls != 1 || b.used != 17 || a.Groups[0][1].Positive != 1 || *m.AUC.Value != 1 {
		t.Fatal("late rank validation flattened growth cause, double charged or changed borrowed input")
	}
}
