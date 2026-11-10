package nodeview

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func TestOutputMemoryKnownAnswer(t *testing.T) {
	a := &outputArithmetic{}
	if a.add(11, 13, 17) != 41 || a.mul(13, 17) != 221 || a.err != nil {
		t.Fatal("checked arithmetic changed")
	}
	bucket := plannedOutputType(reflect.TypeFor[RankBucket](), outputShape{buckets: 32768}, a)
	// ASCII keys/braces/separators cost 46; rank and two counts need five digits, category needs two
	if bucket.backing != uint64(unsafe.Sizeof(RankBucket{})) || bucket.json != 63 {
		t.Fatalf("bucket layout/JSON bound: %+v", bucket)
	}
	groups := plannedOutputGroups(outputShape{groups: 2, buckets: 3}, a)
	// N=3 needs one-digit ranks/counts, hence 51-byte buckets: 2+2*5+3*52 = 168
	want := uint64(unsafe.Sizeof([][]RankBucket{})) + 8*2*uint64(unsafe.Sizeof([]RankBucket{})) + 8*3*uint64(unsafe.Sizeof(RankBucket{}))
	if groups.backing != want || groups.json != 168 || a.err != nil {
		t.Fatalf("nested group bound: %+v, want backing %d", groups, want)
	}
}

func TestOutputMemoryHostBoundary(t *testing.T) {
	p := outputMemoryPlan{RetainedBytes: 10, EmitterBytes: 20, TotalBytes: 30}
	// 10 retained + 20 emitter + 17 explicitly overlapping bytes = 47
	if err := checkOutputHost(p, 47, 17); err != nil {
		t.Fatal(err)
	}
	if reasonOf(checkOutputHost(p, 46, 17)) != ReasonLimit {
		t.Fatal("one-byte host shortfall admitted")
	}
	p.TotalBytes++
	if !errors.Is(checkOutputHost(p, 100, 0), ErrInvalid) {
		t.Fatal("inconsistent total admitted")
	}
	if err := checkOutputHost(outputMemoryPlan{}, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestOutputMemoryOverflow(t *testing.T) {
	for _, operation := range []func(*outputArithmetic){
		func(a *outputArithmetic) { a.add(math.MaxUint64, 1) },
		func(a *outputArithmetic) { a.mul(math.MaxUint64, 2) },
		func(a *outputArithmetic) { outputSliceBacking(math.MaxUint64, reflect.TypeFor[RankBucket](), a) },
		func(a *outputArithmetic) { outputMapBytes(math.MaxUint64, 24, 24, a) },
	} {
		a := &outputArithmetic{}
		operation(a)
		if reasonOf(a.err) != ReasonLimit {
			t.Fatal("overflow admitted")
		}
	}
	if reasonOf(checkOutputHost(outputMemoryPlan{RetainedBytes: math.MaxUint64, TotalBytes: math.MaxUint64}, math.MaxUint64, 1)) != ReasonLimit {
		t.Fatal("overlapping host bytes overflowed")
	}
	a := &outputArithmetic{}
	if _, err := finishOutputMemory(outputSize{backing: 1, json: math.MaxUint64}, 1, 1, 1, outputShape{}, outputEmitterParts{}, a); reasonOf(err) != ReasonLimit {
		t.Fatal("emitter arithmetic overflowed")
	}
}

func TestOutputMemoryCountsAndZero(t *testing.T) {
	for _, bound := range []outputTaskBound{
		{First: -1}, {First: 129}, {Second: -1}, {Second: 129},
		{MailboxRows: -1}, {MailboxRows: maxTruthRecords + 1, MailboxGroups: 1},
		{MailboxGroups: -1}, {MailboxGroups: maxClients/2 + 1}, {MailboxRows: 1},
	} {
		if _, err := plannedOutputMemory(Plan{}, []outputTaskBound{bound}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid output count admitted: %+v", bound)
		}
	}
	for _, bounds := range [][]outputTaskBound{nil, {{}}, {{MailboxGroups: 1}}, {{First: 0, Second: 128}}} {
		p, err := plannedOutputMemory(Plan{}, bounds)
		if err != nil || p.RetainedBytes == 0 || p.EmitterBytes == 0 || p.TotalBytes != p.RetainedBytes+p.EmitterBytes {
			t.Fatalf("zero/empty output not bounded: %+v %v", p, err)
		}
	}
	if _, err := actualOutputMemory(Report{}); err != nil {
		t.Fatal(err)
	}
}

func TestOutputMemoryCountsHiddenCapacity(t *testing.T) {
	groups := make([][]RankBucket, 1, 3)
	groups[0] = make([]RankBucket, 1, 5)
	groups[:cap(groups)][2] = make([]RankBucket, 0, 7)
	audits := make([]RankAudit, 1, 2)
	audits[0].Groups = groups
	audits[:cap(audits)][1].TopOne = make([][2]int, 0, 4)
	a := &outputArithmetic{}
	with := actualOutputValue(reflect.ValueOf(Report{Audit: audits}), a)
	base := actualOutputValue(reflect.ValueOf(Report{}), a)
	// full audit capacity, all group headers, both bucket capacities and a hidden audit's top1 capacity
	want := 2*2*uint64(unsafe.Sizeof(RankAudit{})) + 2*3*uint64(unsafe.Sizeof([]RankBucket{})) + 2*(5+7)*uint64(unsafe.Sizeof(RankBucket{})) + 2*4*uint64(unsafe.Sizeof([2]int{}))
	if a.err != nil || with.backing-base.backing != want {
		t.Fatalf("hidden nested capacity omitted: got %d, want %d, err %v", with.backing-base.backing, want, a.err)
	}
}

func TestOutputMemoryDoesNotMutateReleasedBacking(t *testing.T) {
	v := .75
	r := Report{
		Plan:  Plan{Powers: []PowerCalculation{{PilotX: []float64{1, 2}, PilotY: []float64{3, 4}}}},
		Runs:  []RunResult{{Methods: []MethodResult{{Method: "cells", AUC: Number{Value: &v}}}}},
		Audit: []RankAudit{{Groups: [][]RankBucket{{{Rank: 1, Positive: 1}}}, TopOne: [][2]int{{1, 1}}}},
	}
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	first, err := actualOutputMemory(r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := actualOutputMemory(r)
	after, marshalErr := json.Marshal(r)
	if err != nil || marshalErr != nil || first != second || string(before) != string(after) || v != .75 || cap(r.Audit[0].Groups[0]) != 1 {
		t.Fatal("output measurement mutated released backing")
	}
}

func TestOutputMemoryPlannedCoversReleasedFixture(t *testing.T) {
	r := testNodeviewReport()
	r.Plan.Phase = Train
	r.Plan.FrozenModels = make([]ModelReference, 8)
	r.Plan.Powers = make([]PowerCalculation, 13)
	r.Plan.PowerSearch = make([]PairedPowerPlan, 13)
	for i := range r.Plan.Powers {
		r.Plan.Powers[i].PilotX, r.Plan.Powers[i].PilotY = make([]float64, 5), make([]float64, 5)
		r.Plan.PowerSearch[i].Search = make([]PairedPowerPoint, 483)
	}
	r.Models = make([]FrozenModel, 8)
	for i := range r.Models {
		r.Models[i].Training.Model = &metrics.Discriminant{Weights: make([]float64, 18), Center: make([]float64, 18), Kept: make([]int, 18)}
		r.Models[i].Training.Witness = &MailboxFitWitness{Kept: make([]int, 18), Unused: make([]int, 18)}
	}
	bound := outputTaskBound{First: 2, Second: 3, MailboxRows: 5, MailboxGroups: 2}
	for repeat := range 3 {
		run := RunResult{Configuration: r.Plan.Configurations[0].ID, Flags: []Reason{ReasonIncomplete}, RouteHistogram: make([]uint64, 5)}
		for method := range 16 {
			run.Methods = append(run.Methods, MethodResult{Method: "cells", WindowNS: int64(method)})
			groups, buckets := bound.First, bound.First*bound.Second
			if method >= 14 {
				groups, buckets = bound.MailboxGroups, bound.MailboxRows
			}
			audit := RankAudit{Groups: make([][]RankBucket, groups)}
			for bucket := range buckets {
				group := bucket % groups
				audit.Groups[group] = append(audit.Groups[group], RankBucket{Rank: bucket + 1, Negative: 1})
			}
			if method < 14 {
				for range groups {
					audit.TopOne = append(audit.TopOne, [2]int{1, 1})
				}
			}
			r.Audit = append(r.Audit, audit)
		}
		run.Repeat = repeat
		r.Runs = append(r.Runs, run)
	}
	planned, err := plannedOutputMemory(r.Plan, []outputTaskBound{bound, bound, bound})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := actualOutputMemory(r)
	if err != nil || actual.RetainedBytes > planned.RetainedBytes || actual.EmitterBytes > planned.EmitterBytes {
		t.Fatalf("released fixture exceeds planned reservation: actual %+v, planned %+v, err %v", actual, planned, err)
	}
}

func TestOutputMemoryEmitterWorstStringsAndNumbers(t *testing.T) {
	r := testNodeviewReport()
	r.Manifest.Kernel = strings.Repeat("\x00<>&\"\\\xff", 64)
	r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Methods: []MethodResult{{Method: "cells", AUC: number(-math.MaxFloat64, ReasonNone)}}}}
	r.Audit = []RankAudit{{Groups: [][]RankBucket{{{Rank: math.MinInt, Positive: math.MaxInt, Negative: math.MaxInt}}}}}
	a := &outputArithmetic{}
	size := actualOutputValue(reflect.ValueOf(r), a)
	encoded, err := json.Marshal(r)
	if err != nil || a.err != nil || uint64(len(encoded)) > size.json {
		t.Fatalf("escaped string/integer/float JSON exceeds bound: encoded %d, bound %d, err %v/%v", len(encoded), size.json, err, a.err)
	}
	p, err := actualOutputMemory(r)
	if err != nil || p.EmitterBytes < 3*outputMarshalAllocation(size, uint64(unsafe.Sizeof(Report{})), a) {
		t.Fatal("whole-report marshal growth/copies omitted")
	}
	bad := math.Inf(1)
	r.Runs[0].Methods[0].AUC.Value = &bad
	if _, err := actualOutputMemory(r); !errors.Is(err, ErrInvalid) {
		t.Fatal("nonfinite output admitted")
	}
}

func TestOutputMemoryMarshalAllocationKnownAnswer(t *testing.T) {
	a := &outputArithmetic{}
	// J=100: six 208-byte capacities, copy112, two values16, Encoder320 and options224
	if got := outputMarshalAllocation(outputSize{json: 100}, 16, a); got != 1936 {
		t.Fatalf("marshal allocation %d, want 1936", got)
	}
	// JSONL grows by at least 5/4: all capacities<=5*round(2*100)=1040
	if got := outputBodyAllocation(100, a); got != 1040 {
		t.Fatalf("JSONL cumulative backing %d, want 1040", got)
	}
	if got := outputNewlineAllocation(100, a); got != 208 || a.err != nil {
		t.Fatalf("newline old/new backing %d, want 208, %v", got, a.err)
	}
	for _, test := range []struct{ input, want uint64 }{{0, 0}, {1, 8}, {33, 48}, {53, 64}, {1025, 1152}, {32769, 40960}} {
		if got := outputRoundBytes(test.input, a); got != test.want {
			t.Fatalf("round(%d)=%d, want %d", test.input, got, test.want)
		}
	}
	if got := outputRoundObject(1024, a); got != 1152 {
		t.Fatalf("pointer object header rounding %d, want 1152", got)
	}
	for n := uint64(1); n <= 32768; n++ {
		if outputRoundBytes(n, a) > (5*n)/4+16 {
			t.Fatalf("size-class rounding proof fails at %d", n)
		}
	}
}

func TestOutputMemorySummaryAndCLIPlanningRecord(t *testing.T) {
	r := testNodeviewReport()
	r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Methods: []MethodResult{{Method: "cells", WindowNS: 1, AUC: number(.5, ReasonNone)}}}}
	a := &outputArithmetic{}
	parts := outputEmitterParts{
		modelFamily: actualOutputValue(reflect.ValueOf(r.ModelInference), a), differenceFamily: actualOutputValue(reflect.ValueOf(r.DifferenceInference), a),
		planning: actualOutputValue(reflect.ValueOf(r.Planning), a),
	}
	parts.descriptions, parts.keys = outputDescriptiveCounts(r, a)
	if parts.descriptions != 16 || parts.keys != 14 {
		t.Fatal("missing method values changed the requested summary inventory")
	}
	summary, _ := outputSummarySize(parts, outputShape{strings: 128}, a)
	encoded, err := json.Marshal(struct {
		Schema      string               `json:"schema"`
		Status      Reason               `json:"status"`
		Models      []Inference          `json:"model_family"`
		Differences []Inference          `json:"difference_family"`
		Planning    PowerEstimate        `json:"planning_estimate"`
		Search      []PlanningResult     `json:"power_search"`
		Descriptive []DescriptiveSummary `json:"descriptive"`
	}{r.Schema, r.Status, r.ModelInference, r.DifferenceInference, PairedPowerEstimate(), r.Planning, descriptiveSummaries(r)})
	if err != nil || a.err != nil || summary.json < uint64(len(encoded)) || summary.custom == 0 {
		t.Fatalf("summary or nested custom marshal omitted: %d/%d, %v/%v", summary.json, len(encoded), err, a.err)
	}
	estimate := outputPlanningEstimateLayout{"jimichi-nodeview-planning-estimate-v1", Collude, Primary, PairedPowerEstimate()}
	encoded, err = json.Marshal(estimate)
	bound := plannedOutputType(reflect.TypeFor[outputPlanningEstimateLayout](), outputShape{strings: 128}, a)
	if err != nil || bound.json < uint64(len(encoded)) {
		t.Fatal("prior CLI planning estimate JSON omitted")
	}
}

func TestOutputMemoryJSONStringBounds(t *testing.T) {
	a := &outputArithmetic{}
	for _, value := range []string{"rank", "\x00<>&\"\\\xff", "\n\t\b\f\r", "日本語", "\u2028\u2029", "\ufffd"} {
		encoded, err := json.Marshal(value)
		if got := outputJSONString(value, a); err != nil || got < uint64(len(encoded)) || utf8.ValidString(value) && got != uint64(len(encoded)) {
			t.Fatalf("JSON string length differs for %q: got %d, encoded %q (%d), %v", value, got, encoded, len(encoded), err)
		}
	}
	for _, value := range []float64{-1.0000000000000002e-6, math.MaxFloat64, math.SmallestNonzeroFloat64, -1.2345678901234567e20, math.Copysign(0, -1)} {
		encoded, err := json.Marshal(value)
		bound := plannedOutputType(reflect.TypeFor[float64](), outputShape{}, a)
		if err != nil || uint64(len(encoded)) > bound.json {
			t.Fatalf("float JSON bound failed for %g", value)
		}
	}
}

func TestOutputMemoryPhaseMetadataAndMainSeed(t *testing.T) {
	p := testNodeviewPlan(Collude)
	p.Phase, p.Suite = Structural, "c25519"
	empty, err := plannedOutputMemory(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Phase = Pilot
	pilot, err := plannedOutputMemory(p, nil)
	if err != nil || pilot.RetainedBytes <= empty.RetainedBytes || pilot.EmitterBytes <= empty.EmitterBytes {
		t.Fatal("prospective pilot power search omitted")
	}
	a := &outputArithmetic{}
	before := actualOutputValue(reflect.ValueOf(p), a)
	p.MainSeedCommitment = strings.Repeat("a", 64)
	after := actualOutputValue(reflect.ValueOf(p), a)
	if after.backing-before.backing != 64 || after.json-before.json != 64 {
		t.Fatal("64-byte main seed commitment omitted")
	}
	for _, set := range []Set{Compromise, Collude, Mailbox} {
		if len(canonicalCoordinates(set)) > 27 {
			t.Fatal("validation catalog bound requires revision")
		}
	}
}

func TestOutputMemoryDescriptiveKeyCounts(t *testing.T) {
	r := Report{Plan: Plan{Configurations: []Coordinate{{ID: "a", Controlled: []int{0, 4}}}}}
	for range 20 {
		r.Runs = append(r.Runs, RunResult{Configuration: "a", Methods: []MethodResult{{Method: "cells", WindowNS: 1}, {Method: "frames", WindowNS: 1}}, LinkingTimes: []LinkingTime{{Method: "cells"}, {Method: "frames"}}})
	}
	a := &outputArithmetic{}
	descriptions, keys := outputDescriptiveCounts(r, a)
	if descriptions != 16 || keys != 14 || a.err != nil {
		t.Fatalf("repeats multiplied descriptive keys: %d/%d %v", descriptions, keys, a.err)
	}
}

func TestOutputMemoryNestedGrowthMonotonic(t *testing.T) {
	previous := outputMemoryPlan{}
	for _, bound := range []outputTaskBound{{}, {First: 1, Second: 1}, {First: 2, Second: 3}, {First: 128, Second: 128, MailboxRows: maxTruthRecords, MailboxGroups: 16}} {
		current, err := plannedOutputMemory(Plan{}, []outputTaskBound{bound})
		if err != nil || current.RetainedBytes <= previous.RetainedBytes || current.EmitterBytes <= previous.EmitterBytes {
			t.Fatalf("nested witness growth omitted: previous %+v, current %+v, err %v", previous, current, err)
		}
		previous = current
	}
}
