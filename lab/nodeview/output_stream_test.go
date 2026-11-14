//go:build linux && amd64 && goexperiment.jsonv2

package nodeview

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func outputLegacyBytes(value any, jsonl bool) ([]byte, error) {
	var result []byte
	appendValue := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		result = append(result, b...)
		result = append(result, '\n')
		return nil
	}
	if !jsonl {
		if err := appendValue(value); err != nil {
			return nil, err
		}
		return result, nil
	}
	switch rows := value.(type) {
	case []RunResult:
		for i := range rows {
			if err := appendValue(rows[i]); err != nil {
				return nil, err
			}
		}
	case []RankAudit:
		for i := range rows {
			if err := appendValue(rows[i]); err != nil {
				return nil, err
			}
		}
	default:
		return nil, ErrInvalid
	}
	return result, nil
}

func outputCheckStreamBytes(t *testing.T, value any, jsonl bool) {
	t.Helper()
	expected, err := outputLegacyBytes(value, jsonl)
	if err != nil {
		t.Fatal(err)
	}
	var actual bytes.Buffer
	if err := outputStream(&actual, value, jsonl); err != nil || !bytes.Equal(expected, actual.Bytes()) {
		t.Fatalf("stream bytes differ for %T: %v", value, err)
	}
	var segmented segmentedPublicWriter
	if err := outputStream(&segmented, value, jsonl); err != nil || !bytes.Equal(expected, segmented.Bytes()) {
		t.Fatalf("segmented stream differs for %T: %v", value, err)
	}
}

func outputStreamEquivalenceCases(t *testing.T) {
	t.Helper()
	r := testNodeviewReport()
	r.Manifest.Kernel = "\x00<>&\"\\\xff日本語\u2028\u2029"
	r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Phase: Structural, Methods: []MethodResult{{Method: "cells", AUC: number(-math.MaxFloat64, ReasonNone), TopOne: number(math.Copysign(0, -1), ReasonNone)}}}}
	r.Audit = []RankAudit{{Configuration: r.Plan.Configurations[0].ID, Method: "cells", Groups: [][]RankBucket{nil, {}, {{Rank: 1, Positive: 2, Negative: 3, Category: 4}}}, TopOne: [][2]int{{1, 2}}}}
	summary := outputPublicSummary{r.Schema, r.Status, r.ModelInference, r.DifferenceInference, PairedPowerEstimate(), r.Planning, descriptiveSummaries(r)}
	for _, value := range []any{&r, &r.Plan, &r.Manifest, &r.Models, &summary, ReasonNone, ReasonIncomplete} {
		outputCheckStreamBytes(t, value, false)
	}
	outputCheckStreamBytes(t, r.Runs, true)
	outputCheckStreamBytes(t, r.Audit, true)
	for _, value := range []any{[]RunResult(nil), []RunResult{}, []RankAudit(nil), []RankAudit{}} {
		outputCheckStreamBytes(t, value, true)
	}
	for _, value := range []float64{math.SmallestNonzeroFloat64, -1.0000000000000002e-6, math.MaxFloat64, math.Copysign(0, -1)} {
		outputCheckStreamBytes(t, &value, false)
	}
}

func TestOutputStreamLegacyEquivalence(t *testing.T) {
	outputStreamEquivalenceCases(t)
	plans, models := frozenCommonFixture(t)
	r := frozenCommonReport(plans[0], models, 0)
	outputCheckStreamBytes(t, &r, false)
	outputCheckStreamBytes(t, &models, false)
	large := testNodeviewReport()
	row := RankAudit{Configuration: large.Plan.Configurations[0].ID, Method: "cells", Groups: make([][]RankBucket, 5), TopOne: [][2]int{{1, 1}}}
	for i := range row.Groups {
		row.Groups[i] = make([]RankBucket, 32768)
		for j := range row.Groups[i] {
			row.Groups[i][j] = RankBucket{Rank: j + 1, Positive: 1, Negative: 1}
		}
	}
	large.Audit = []RankAudit{row}
	body, err := json.Marshal(&large)
	if err != nil || len(body) <= 8<<20 {
		t.Fatal("complete nested schema fixture did not exceed the small ceiling")
	}
	outputCheckStreamBytes(t, &large, false)
	outputCheckStreamBytes(t, large.Audit, true)
}

func TestOutputStreamHistoryKnownAnswers(t *testing.T) {
	a := &outputArithmetic{}
	if outputEncoderMetadata(0, a) != 544 || outputEncoderMetadata(4, a) != 656 || outputEncoderMetadata(5, a) != 784 || outputMarshalAllocation(outputSize{json: 100}, 16, a) != 1936 {
		t.Fatal("independent encoder known answer changed")
	}
	// 8192 + 4*(31664+24472) + 640 = 233376; six rounded double capacities pay 2801664
	burst := a.add(8192, a.mul(4, 31664+24472), 640)
	if burst != 233376 || a.mul(6, outputRoundBytes(a.mul(2, burst), a)) != 2801664 || a.err != nil {
		t.Fatal("stream burst history changed")
	}
	// the historical A burst65640 paid835584 per episode; final minus A is1966080
	if 2801664-a.mul(6, outputRoundBytes(2*65640, a)) != 1966080 || 15*(2801664-2752512) != 737280 {
		t.Fatal("independent added buffer history changed")
	}
	for _, op := range []func(*outputArithmetic){func(a *outputArithmetic) {
		outputStreamAllocation(outputSize{longest: math.MaxUint64}, outputMethodCounts{}, a)
	}, func(a *outputArithmetic) { outputPools(math.MaxUint64, 64, a) }, func(a *outputArithmetic) { outputTrie(math.MaxUint64, a) }} {
		a := &outputArithmetic{}
		op(a)
		if reasonOf(a.err) != ReasonLimit {
			t.Fatal("stream arithmetic overflow accepted")
		}
	}
}

type outputCountWriter struct{ mode int }

func (w outputCountWriter) Write(p []byte) (int, error) {
	switch w.mode {
	case -1:
		return -1, nil
	case 0:
		return 0, nil
	case 1:
		return len(p) + 1, nil
	default:
		return 0, errors.New("private-writer-sentinel")
	}
}

type outputMutatingWriter struct {
	bytes.Buffer
	report  *Report
	changed bool
}

func (w *outputMutatingWriter) Write(p []byte) (int, error) {
	if !w.changed {
		w.report.Runs[0].Configuration = "mutated-after-serialization"
		w.changed = true
	}
	return w.Buffer.Write(p)
}

type outputPointerOnly struct {
	Value int `json:"value"`
}

func (*outputPointerOnly) MarshalJSON() ([]byte, error) { return []byte("0"), nil }

func outputStreamFailureCases(t *testing.T) {
	t.Helper()
	r := testNodeviewReport()
	for _, mode := range []int{-1, 0, 1, 2} {
		err := outputStream(outputCountWriter{mode}, &r, false)
		if reasonOf(err) != ReasonIncomplete || strings.Contains(err.Error(), "private-writer-sentinel") {
			t.Fatal("stream exposed a writer failure or accepted an invalid count")
		}
	}
	if outputMethodSet(reflect.TypeFor[outputPointerOnly](), 0) == nil {
		t.Fatal("pointer-only method drift accepted")
	}
	if outputMethodSet(reflect.TypeFor[Report](), 0) != nil || outputMethodSet(reflect.TypeFor[MailboxTraining](), 0) != nil {
		t.Fatal("current value method set refused")
	}
	r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Phase: Structural}}
	want, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	mutating := outputMutatingWriter{report: &r}
	if err := WriteReport(&mutating, r); err != nil || !bytes.Equal(want, mutating.Bytes()) || !mutating.changed {
		t.Fatal("generic writer lost serialize-before-callback behavior")
	}
	var nilFile *os.File
	if reasonOf(WriteReport(nilFile, testNodeviewReport())) != ReasonIncomplete {
		t.Fatal("nil file did not retain buffered incomplete behavior")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".summary.json.nonce"), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	bad := outputPublicSummary{Schema: reportSchema, Status: ReasonIncomplete, Descriptive: []DescriptiveSummary{{Median: Number{Reason: "private-summary-sentinel"}}}}
	if err := writeReportFile(dir, "nonce", "summary.json", &bad, false); !errors.Is(err, ErrInvalid) {
		t.Fatal("temp-open failure preempted complete derived-summary serialization")
	}
	bad.Descriptive = nil
	if reasonOf(writeReportFile(dir, "nonce", "summary.json", &bad, false)) != ReasonIncomplete {
		t.Fatal("exclusive temp-open refusal changed")
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.json")); !os.IsNotExist(err) {
		t.Fatal("failed serialization/open published a file")
	}
}

func TestOutputStreamAdmissionAndFailure(t *testing.T) {
	outputStreamFailureCases(t)
	r := testNodeviewReport()
	sizing := 0
	if _, err := prepareReportEmissionCore(nil, false, false, func(uint64) error { return fail(ReasonLimit) }, func() { sizing++ }); reasonOf(err) != ReasonLimit || sizing != 0 {
		t.Fatal("entry control refusal occurred after count or sizing")
	}
	var calls []uint64
	if _, err := prepareReportEmissionCore(&r, false, true, func(n uint64) error { calls = append(calls, n); return nil }, nil); err != nil || len(calls) < 3 {
		t.Fatal("selected preparation fixture failed")
	}
	for _, at := range []int{1, len(calls) - 1} {
		sizing = 0
		limit := calls[at] - 1
		_, err := prepareReportEmissionCore(&r, false, true, func(n uint64) error {
			if n > limit {
				return fail(ReasonLimit)
			}
			return nil
		}, func() { sizing++ })
		if reasonOf(err) != ReasonLimit || at == 1 && sizing != 0 || at > 1 && sizing != 1 {
			t.Fatal("public owner refusal crossed its covered consumer")
		}
	}
}

func TestOutputStreamPublicEnvelope(t *testing.T) {
	outputSourceCertificateCases(t)
	outputValidationTupleCases(t)
	a := &outputArithmetic{}
	if outputDefaultConstruction(27, a) != 415628 || outputPlanNoncodec(27, a) != 3137748 || a.err != nil {
		t.Fatal("complete default/validator noncodec source owner changed")
	}
	if outputSourceGraph(reflect.TypeFor[DescriptiveSummary](), 27, a) != 240 || outputSourceGraph(reflect.TypeFor[string](), 27, a) != 128 {
		t.Fatal("descriptive Method source bound changed another string family")
	}
	r := testNodeviewReport()
	r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Phase: Structural}}
	actual, err := actualOutputMemory(r)
	if err != nil || actual.ReportLimitBytes == 0 || actual.LegacyTotalBytes != actual.RetainedBytes+actual.ReportLimitBytes || actual.TotalBytes != actual.RetainedBytes+actual.EmitterBytes {
		t.Fatal("selected and literal old record identities changed")
	}
	plain := actual
	for i := 0; i < 64; i++ {
		r.Runs[0].Methods = append(r.Runs[0].Methods, MethodResult{Method: "cells", WindowNS: int64(i)})
	}
	long, err := actualOutputMemory(r)
	if err != nil || long.EmitterBytes <= plain.EmitterBytes || long.ReportLimitBytes <= plain.ReportLimitBytes {
		t.Fatal("same-schema overlength methods were clipped by a producer method cap")
	}
	if err := checkOutputHost(actual, actual.TotalBytes, 0); err != nil || reasonOf(checkOutputHost(actual, actual.TotalBytes-1, 0)) != ReasonLimit {
		t.Fatal("selected exact/one-byte admission changed")
	}
}

func outputValidationTupleCases(t *testing.T) {
	t.Helper()
	r := testNodeviewReport()
	for repeat := 0; repeat < 5; repeat++ {
		row := RunResult{Configuration: r.Plan.Configurations[0].ID, Phase: Structural, Repeat: repeat, Methods: []MethodResult{{Method: "setup"}, {Method: "close"}, {Method: "shared"}, {Method: "mixed"}}}
		for _, window := range []int64{1000000000, 2000000000, 5000000000, 10000000000, 20000000000} {
			row.Methods = append(row.Methods, MethodResult{Method: "cells", WindowNS: window}, MethodResult{Method: "frames", WindowNS: window})
		}
		r.Runs = append(r.Runs, row)
	}
	price, rows, err := outputValidationAllocationWithSummary(&r)
	actual, actualErr := outputValidationAllocation(&r)
	// five runs give V=5*(14+2)=80; one requested pair has K=14 and D=16
	want := outputValidationSummary{keys: 14, descriptions: 16, maps: 1057536, values: 10560, keyHistory: 8520, copies: 2944, descriptionHistory: 30560, backing: 23144}
	if len(r.Plan.Configurations) != 27 || reflect.TypeFor[DescriptiveSummary]().Size() != 152 || err != nil || actualErr != nil || actual != price || rows != want {
		t.Fatalf("validation summary allocation uses wrong K/D multiplicities: %+v, %v/%v", rows, err, actualErr)
	}
	if rows.maps+rows.values+rows.keyHistory+rows.copies+rows.descriptionHistory+rows.backing != 1133264 {
		t.Fatal("independent validation summary family changed")
	}
}

func outputSourceCertificateCases(t *testing.T) {
	t.Helper()
	vectors := []struct {
		tasks, configs, mail uint64
		links                []outputSourceLink
	}{
		{284, 27, 0, []outputSourceLink{{104, 5}, {90, 10}, {90, 20}}},
		{120, 21, 120, nil},
		{321, 25, 0, []outputSourceLink{{64, 32}, {128, 128}}},
		{27, 27, 0, []outputSourceLink{{3, 5}, {3, 10}, {3, 20}, {18, 12}}},
		{20, 21, 20, nil},
		{33, 25, 0, []outputSourceLink{{33, 128}}},
	}
	retained := [6]uint64{214321260, 2031353036, 7865720564, 26267396, 345057836, 1967020532}
	emitter := [6]uint64{1049828943, 989745491, 1133009843, 974255815, 964762689, 993085619}
	oldLimit := [6]uint64{4042230230, 33049042282, 126168293594, 758726190, 5862146472, 31738514394}
	earlier := [6]uint64{242545851, 240124711, 241684291, 242545851, 240124711, 241684291}
	preflight := [6]uint64{1969380214, 3723907398, 9703098858, 1705753222, 2012629396, 3664474602}
	var result [6]outputSourceEnvelope
	wantInputs := [3][10]uint64{
		{1573392, 167560088, 4053656, 352784, 11191615, 207800, 51201796, 6275496, 22712, 106512},
		{1532432, 166587636, 4053656, 352784, 11191615, 207800, 50038532, 6033192, 20552, 106512},
		{1557008, 167222384, 4053656, 352784, 11191615, 207800, 50775812, 6194728, 21992, 106512},
	}
	for i, v := range vectors {
		x, err := outputDefaultSourceEnvelope(v.tasks, v.configs, v.mail, v.links)
		if err != nil {
			t.Fatal(err)
		}
		result[i] = x
		if x.inputs != wantInputs[i%3] {
			t.Fatalf("source route%d earlier input rows differ: %v", i, x.inputs)
		}
		if x.RetainedBytes != retained[i] || x.EmitterBytes != emitter[i] || x.earlier != earlier[i] || x.preflight != preflight[i] {
			t.Fatalf("source route%d differs: retained%d/%d emitter%d/%d earlier%d/%d preflight%d/%d", i, x.RetainedBytes, retained[i], x.EmitterBytes, emitter[i], x.earlier, earlier[i], x.preflight, preflight[i])
		}
		if x.ReportLimitBytes > oldLimit[i] || x.LegacyTotalBytes != x.RetainedBytes+x.ReportLimitBytes {
			t.Fatal("literal old bound escaped its complete conservative source envelope")
		}
	}
	for i := 0; i < 3; i++ {
		for k := range result[i].owners {
			if result[i+3].owners[k] > result[i].owners[k] {
				t.Fatal("GOST selected owner is not termwise dominated")
			}
		}
		for k := range result[i].inputs {
			if result[i+3].inputs[k] > result[i].inputs[k] {
				t.Fatal("GOST earlier input owner is not termwise dominated")
			}
		}
	}
	if _, err := outputDefaultSourceEnvelope(math.MaxUint64, 27, 0, nil); reasonOf(err) != ReasonLimit {
		t.Fatal("source count overflow accepted")
	}
}
