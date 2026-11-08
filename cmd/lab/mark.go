package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

const markSchema = "mark-v1"

var markExecute = lab.Execute
var markLoadavg = loadavg
var markPeriods = []time.Duration{0, 25 * time.Millisecond, 47500 * time.Microsecond, 50 * time.Millisecond, 52500 * time.Microsecond, 75 * time.Millisecond}

type markFlags struct {
	flows, hops, repeats         int
	duration, send               time.Duration
	seed                         int64
	suite, revision, out, replay string
	explicit                     map[string]bool
}
type markCondition struct {
	ClientMode  string        `json:"client_mode"`
	RelayPeriod time.Duration `json:"relay_period"`
	Active      bool          `json:"active"`
}
type markSeeds struct {
	Workload    int64 `json:"workload_seed"`
	Code        int64 `json:"code_seed"`
	Target      int64 `json:"target_seed"`
	Permutation int64 `json:"permutation_seed"`
	Order       int64 `json:"order_seed"`
}
type markSlot struct {
	ID        int           `json:"id"`
	Repeat    int           `json:"repeat"`
	Order     int           `json:"execution_order"`
	Condition markCondition `json:"condition"`
	Seeds     markSeeds     `json:"seeds"`
	State     string        `json:"state"`
}
type markManifest struct {
	Schema      string         `json:"schema"`
	Version     int            `json:"experiment_version"`
	Revision    string         `json:"revision"`
	Suite       string         `json:"suite"`
	Environment map[string]any `json:"environment"`
	BaseSeed    int64          `json:"base_seed"`
	Repeats     int            `json:"repeats"`
	Purpose     string         `json:"purpose"`
	Complete    bool           `json:"complete"`
	ErrorClass  string         `json:"normalized_error_class"`
	Slots       []markSlot     `json:"requested_matrix"`
}
type markObservationRecord struct {
	Schema        string                   `json:"schema"`
	ID            int                      `json:"id"`
	CaptureStatus string                   `json:"capture_status"`
	Epoch         time.Duration            `json:"epoch"`
	Detector      metrics.MarkDetector     `json:"detector"`
	Observation   *metrics.MarkObservation `json:"observation"`
}
type markEvaluation struct {
	Schema              string                 `json:"schema"`
	ID                  int                    `json:"id"`
	Condition           markCondition          `json:"condition"`
	Repeat              int                    `json:"repeat"`
	Target              int                    `json:"target_truth"`
	Permutation         []int                  `json:"candidate_permutation"`
	ClientPeriod        *time.Duration         `json:"client_period"`
	CoverPeriod         time.Duration          `json:"cover_period"`
	ReferencePeriod     time.Duration          `json:"reference_period"`
	RelayReferenceRatio *float64               `json:"relay_reference_ratio"`
	Flows               int                    `json:"flows"`
	Hops                int                    `json:"hops"`
	Payload             int                    `json:"payload_bytes"`
	MeanGap             time.Duration          `json:"send_mean_gap"`
	Run                 *lab.MarkResult        `json:"run"`
	ErrorClass          string                 `json:"normalized_error_class"`
	Detection           *metrics.MarkDetection `json:"detection"`
	Correct             *bool                  `json:"correctness"`
	AUC                 *float64               `json:"auc"`
	FrameCounts         [4]*int                `json:"observed_link_frame_counts_entry_forward_entry_back_last_forward_last_back"`
	FrameStatus         [4]string              `json:"frame_count_status"`
	ObservedTraces      [4]int                 `json:"observed_traces_per_link_direction"`
	Multipliers         [4]*float64            `json:"multipliers_per_successful_send_return_before_cutoff"`
	MultiplierStatus    [4]string              `json:"multiplier_status"`
	SuccessfulReturns   *int                   `json:"successful_send_returns_before_cutoff"`
	LatencyCount        *int                   `json:"latency_sample_count"`
	Unanswered          *int                   `json:"unanswered_calls"`
	DeliveryStatus      string                 `json:"delivery_status"`
	ObservedFlows       int                    `json:"observed_delivery_flows"`
	LatencyStatus       string                 `json:"latency_percentile_status"`
	LatencyP50          *time.Duration         `json:"latency_p50"`
	LatencyP95          *time.Duration         `json:"latency_p95"`
	LatencyP99          *time.Duration         `json:"latency_p99"`
	Diagnostics         map[string]uint64      `json:"diagnostic_counters"`
	LoadBefore          markLoad               `json:"loadavg_before"`
	LoadAfter           markLoad               `json:"loadavg_after"`
}

type markLoad struct {
	Value  *string `json:"value"`
	Status string  `json:"status"`
}

func sampleMarkLoad() markLoad {
	value := markLoadavg()
	if value == "" {
		return markLoad{Status: "unavailable"}
	}
	return markLoad{Value: &value, Status: "available"}
}

type markLedger struct {
	Schema     string `json:"schema"`
	ID         int    `json:"id"`
	State      string `json:"state"`
	ErrorClass string `json:"normalized_error_class"`
}

func markMatrix(base int64, repeats int) []markSlot {
	var slots []markSlot
	for r := 0; r < repeats; r++ {
		seeds := markSeeds{lab.Derive(base, lab.StreamMarkWorkload, uint64(r)), lab.Derive(base, lab.StreamMarkCode, uint64(r)), lab.Derive(base, lab.StreamMarkTarget, uint64(r)), lab.Derive(base, lab.StreamMarkPermutation, uint64(r)), lab.Derive(base, lab.StreamMarkOrder, uint64(r))}
		var conditions []markCondition
		for _, mode := range []string{"immediate", "constant-rate"} {
			for _, period := range markPeriods {
				for _, active := range []bool{true, false} {
					conditions = append(conditions, markCondition{mode, period, active})
				}
			}
		}
		rand.New(rand.NewSource(seeds.Order)).Shuffle(len(conditions), func(i, j int) { conditions[i], conditions[j] = conditions[j], conditions[i] })
		for i, c := range conditions {
			slots = append(slots, markSlot{ID: len(slots), Repeat: r, Order: i, Condition: c, Seeds: seeds, State: "unexecuted"})
		}
	}
	return slots
}

func markBlock(s markSeeds) ([]int8, int, []int) {
	code := make([]int8, 12)
	for i := range code {
		code[i] = -1
	}
	p := rand.New(rand.NewSource(s.Code)).Perm(12)
	for _, i := range p[:6] {
		code[i] = 1
	}
	target := rand.New(rand.NewSource(s.Target)).Intn(6)
	return code, target, rand.New(rand.NewSource(s.Permutation)).Perm(6)
}
func markDetector(code []int8) metrics.MarkDetector {
	lags := make([]time.Duration, 25)
	for i := range lags {
		lags[i] = time.Duration(i) * 25 * time.Millisecond
	}
	return metrics.MarkDetector{Code: code, Slot: 200 * time.Millisecond, Lags: lags, Alpha: 0.05}
}

func markCommand(f markFlags, stdout, stderr io.Writer) int {
	for name := range f.explicit {
		switch name {
		case "set", "suite", "seed", "repeats", "rev", "out", "mark-replay":
		case "flows":
			if f.flows != 6 {
				return markUsage(stderr, "mark requires -flows 6")
			}
		case "hops":
			if f.hops != 3 {
				return markUsage(stderr, "mark requires -hops 3")
			}
		case "duration":
			if f.duration != 16*time.Second {
				return markUsage(stderr, "mark requires -duration 16s")
			}
		case "send":
			if f.send != 200*time.Millisecond {
				return markUsage(stderr, "mark requires -send 200ms")
			}
		default:
			return markUsage(stderr, "explicit flag does not apply to mark: -"+name)
		}
	}
	if f.replay != "" {
		if err := replayMark(f.replay, stdout); err != nil {
			fmt.Fprintln(stderr, "mark replay: validation or input failure")
			return 1
		}
		return 0
	}
	if !f.explicit["repeats"] {
		f.repeats = 40
	}
	if f.repeats <= 0 || f.repeats > 10000 {
		return markUsage(stderr, "mark repeats must be in 1..10000")
	}
	chosen, err := suite.Parse(f.suite)
	if err != nil {
		return markUsage(stderr, "unsupported suite")
	}
	if f.revision == "unknown" {
		fmt.Fprintln(stderr, "warning: no -rev given, rows cannot be traced to a revision")
	}
	dir, err := os.MkdirTemp(f.out, "mark-v1-")
	if os.IsNotExist(err) {
		if e := os.MkdirAll(f.out, 0755); e == nil {
			dir, err = os.MkdirTemp(f.out, "mark-v1-")
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "mark: output failure")
		return 1
	}
	manifest := markManifest{Schema: markSchema, Version: 1, Revision: f.revision, Suite: f.suite, Environment: map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go_version": runtime.Version(), "num_cpu": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0)}, BaseSeed: f.seed, Repeats: f.repeats, Purpose: "recorded-preset", Slots: markMatrix(f.seed, f.repeats)}
	if f.repeats != 40 {
		manifest.Purpose = "smoke-descriptive"
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err = markJSON(manifestPath, manifest); err != nil {
		fmt.Fprintln(stderr, "mark: output failure")
		return 1
	}
	files := make([]*os.File, 3)
	for i, name := range []string{"ledger.jsonl", "observations.jsonl", "evaluation.jsonl"} {
		files[i], err = os.Create(filepath.Join(dir, name))
		if err != nil {
			for _, p := range files {
				if p != nil {
					_ = p.Close()
				}
			}
			manifest.ErrorClass = "output"
			_ = markJSON(manifestPath, manifest)
			fmt.Fprintln(stderr, "mark: output failure")
			return 1
		}
	}
	defer func() {
		for _, p := range files {
			_ = p.Close()
		}
	}()
	appendRecord := func(i int, v any) error {
		if e := json.NewEncoder(files[i]).Encode(v); e != nil {
			return e
		}
		return files[i].Sync()
	}
	var evaluations []markEvaluation
	failedOutput := func() int {
		manifest.Complete = false
		manifest.ErrorClass = "output"
		_ = markJSON(manifestPath, manifest)
		fmt.Fprintln(stderr, "mark: output failure; incomplete manifest retained")
		return 1
	}
	for i := range manifest.Slots {
		s := &manifest.Slots[i]
		s.State = "unknown"
		if appendRecord(0, markLedger{markSchema, s.ID, "started", ""}) != nil || markJSON(manifestPath, manifest) != nil {
			return failedOutput()
		}
		code, target, permutation := markBlock(s.Seeds)
		cfg := lab.Config{Hops: 3, Flows: 6, Duration: 16 * time.Second, SendEvery: 200 * time.Millisecond, Payload: 128, Seed: s.Seeds.Workload, Suite: chosen, RelayPeriod: s.Condition.RelayPeriod, Mark: &lab.MarkConfig{Enabled: s.Condition.Active, Flow: target, Code: code, Slot: 200 * time.Millisecond, Offset: 2 * time.Second}}
		if s.Condition.ClientMode == "constant-rate" {
			cfg.Mode = client.ConstantRate
			cfg.Rate = 50 * time.Millisecond
		} else {
			cfg.CoverEvery = 66666667 * time.Nanosecond
		}
		before := sampleMarkLoad()
		run, runErr := markExecute(cfg)
		after := sampleMarkLoad()
		observation, evaluation := markAnalyse(*s, cfg, run, runErr, permutation)
		evaluation.LoadBefore = before
		evaluation.LoadAfter = after
		if appendRecord(1, observation) != nil || appendRecord(2, evaluation) != nil {
			return failedOutput()
		}
		s.State = "executed"
		evaluations = append(evaluations, evaluation)
		if appendRecord(0, markLedger{markSchema, s.ID, "finished", evaluation.ErrorClass}) != nil || markJSON(manifestPath, manifest) != nil {
			return failedOutput()
		}
		fmt.Fprintf(stdout, "mark %d/%d repeat=%d mode=%s relay=%s active=%t status=%s\n", i+1, len(manifest.Slots), s.Repeat, s.Condition.ClientMode, s.Condition.RelayPeriod, s.Condition.Active, evaluation.ErrorClass)
		if evaluation.ErrorClass == "environment" || evaluation.ErrorClass == "cleanup" || evaluation.ErrorClass == "output" {
			manifest.ErrorClass = evaluation.ErrorClass
			_ = markJSON(manifestPath, manifest)
			_ = markJSON(filepath.Join(dir, "summary.json"), summariseMark(manifest, evaluations))
			fmt.Fprintln(stderr, "mark: fatal failure; incomplete manifest retained")
			return 1
		}
	}
	manifest.Complete = true
	if markJSON(filepath.Join(dir, "summary.json"), summariseMark(manifest, evaluations)) != nil || markJSON(manifestPath, manifest) != nil {
		return failedOutput()
	}
	fmt.Fprintf(stdout, "mark-v1 artifacts: %s (%s)\n", dir, manifest.Purpose)
	return 0
}
func markUsage(w io.Writer, s string) int { fmt.Fprintln(w, s); return 2 }
func markJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, append(b, '\n'), 0644); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}

func markAnalyse(slot markSlot, cfg lab.Config, run *lab.Run, runErr error, permutation []int) (markObservationRecord, markEvaluation) {
	o := markObservationRecord{Schema: markSchema, ID: slot.ID, CaptureStatus: "not_started", Detector: markDetector(cfg.Mark.Code)}
	e := markEvaluation{Schema: markSchema, ID: slot.ID, Condition: slot.Condition, Repeat: slot.Repeat, Target: cfg.Mark.Flow, Permutation: permutation, CoverPeriod: cfg.CoverEvery, ReferencePeriod: 50 * time.Millisecond, Flows: 6, Hops: 3, Payload: 128, MeanGap: 200 * time.Millisecond, ErrorClass: lab.MarkErrorClass(runErr), DeliveryStatus: "unavailable", LatencyStatus: "unavailable", LoadBefore: markLoad{Status: "unavailable"}, LoadAfter: markLoad{Status: "unavailable"}}
	for i := range e.FrameStatus {
		e.FrameStatus[i] = "unavailable"
		e.MultiplierStatus[i] = "unavailable"
	}
	if cfg.Rate > 0 {
		d := cfg.Rate
		e.ClientPeriod = &d
	}
	if cfg.RelayPeriod > 0 {
		e.RelayReferenceRatio = opt(float64(cfg.RelayPeriod) / float64(e.ReferencePeriod))
	}
	if run == nil || run.Mark == nil {
		if e.ErrorClass == "" {
			e.ErrorClass = "capture"
		}
		return o, e
	}
	e.Run = run.Mark
	if run.Mark.ErrorClass != "" && e.ErrorClass != "environment" {
		e.ErrorClass = run.Mark.ErrorClass
	}
	o.CaptureStatus = run.Mark.CaptureStatus
	o.Epoch = run.Origin + cfg.Mark.Offset
	if run.Mark.CounterAt > 0 {
		e.Diagnostics = map[string]uint64{"relay_dropped": run.RelayDropped, "relay_padding": run.RelayPadding, "relay_broken": run.RelayBroken, "relay_timed_out": run.RelayTimedOut, "relay_expired": run.RelayExpired, "relay_refused": run.RelayRefused, "client_dropped": run.Dropped, "client_broken_flows": uint64(run.BrokenFlows)}
	}
	markMeasurements(&e, cfg, run)
	if run.Mark.SetupStatus != "established" || run.Mark.CaptureStatus != "complete" || run.Mark.CaptureStart == nil || run.Mark.CaptureEnd == nil || len(run.Exit) != 6 {
		return o, e
	}
	for _, trace := range run.Exit {
		if trace == nil {
			e.ErrorClass = "capture"
			return o, e
		}
	}
	candidates := make([][]time.Duration, 6)
	for i, j := range permutation {
		candidates[i] = run.Exit[j].Events()
	}
	o.Observation = &metrics.MarkObservation{Candidates: candidates, CaptureStart: *run.Mark.CaptureStart, CaptureEnd: *run.Mark.CaptureEnd}
	detection, err := metrics.DetectMark(*o.Observation, o.Epoch, o.Detector)
	if err != nil {
		e.ErrorClass = "capture"
		return o, e
	}
	e.Detection = &detection
	correct := detection.SelectedCandidate != nil && permutation[*detection.SelectedCandidate] == cfg.Mark.Flow
	if cfg.Mark.Enabled {
		e.Correct = &correct
		scores := make([]metrics.Score, 6)
		for i, score := range detection.CandidateScores {
			scores[i] = metrics.Score{Value: score, True: permutation[i] == cfg.Mark.Flow}
		}
		e.AUC = opt(metrics.AUC(scores))
	}
	return o, e
}

func markMeasurements(e *markEvaluation, cfg lab.Config, run *lab.Run) {
	m := run.Mark
	if m.SetupStatus != "established" || m.CaptureStart == nil || m.CaptureEnd == nil || *m.CaptureEnd < *m.CaptureStart {
		return
	}
	windowStatus := "partial"
	if m.CaptureStatus == "complete" && *m.CaptureEnd-*m.CaptureStart == cfg.Duration {
		windowStatus = "complete"
	}
	if len(m.Flows) > 0 {
		e.DeliveryStatus = windowStatus
		if len(m.Flows) != cfg.Flows {
			e.DeliveryStatus = "partial"
		}
		e.ObservedFlows = len(m.Flows)
		returns, unanswered := 0, 0
		var samples []time.Duration
		for _, flow := range m.Flows {
			returns += flow.NilReturns
			unanswered += flow.CallsStarted - flow.Echoes
			samples = append(samples, flow.Latency...)
		}
		e.SuccessfulReturns = &returns
		e.Unanswered = &unanswered
		n := len(samples)
		e.LatencyCount = &n
		e.LatencyStatus = "no_echoes"
		if n > 0 {
			e.LatencyStatus = e.DeliveryStatus
		}
		for i, q := range []float64{.5, .95, .99} {
			if p, ok := metrics.Percentile(samples, q); ok {
				switch i {
				case 0:
					e.LatencyP50 = &p
				case 1:
					e.LatencyP95 = &p
				case 2:
					e.LatencyP99 = &p
				}
			}
		}
	}
	for i, group := range [][]*lab.Trace{run.Entry, run.EntryBack, run.Exit, run.ExitBack} {
		count := 0
		for _, trace := range group {
			if trace == nil {
				continue
			}
			e.ObservedTraces[i]++
			for _, at := range trace.Events() {
				if at >= *m.CaptureStart && at < *m.CaptureEnd {
					count++
				}
			}
		}
		if e.ObservedTraces[i] == 0 {
			continue
		}
		e.FrameCounts[i] = &count
		e.FrameStatus[i] = windowStatus
		if e.ObservedTraces[i] != cfg.Flows {
			e.FrameStatus[i] = "partial"
		}
		if e.SuccessfulReturns == nil {
			continue
		}
		e.Multipliers[i] = opt(metrics.Multiplier(count, *e.SuccessfulReturns))
		if e.Multipliers[i] == nil {
			e.MultiplierStatus[i] = "zero_denominator"
		} else if e.FrameStatus[i] == "complete" && e.DeliveryStatus == "complete" {
			e.MultiplierStatus[i] = "complete"
		} else {
			e.MultiplierStatus[i] = "partial"
		}
	}
}

func replayMark(path string, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 64<<20)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		var o markObservationRecord
		if err = json.Unmarshal(scanner.Bytes(), &o); err != nil {
			return err
		}
		if o.Schema != markSchema {
			return errors.New("schema")
		}
		if o.Observation == nil {
			continue
		}
		d, err := metrics.DetectMark(*o.Observation, o.Epoch, o.Detector)
		if err != nil {
			return err
		}
		if err = enc.Encode(struct {
			ID        int                   `json:"id"`
			Detection metrics.MarkDetection `json:"detection"`
		}{o.ID, d}); err != nil {
			return err
		}
	}
	return scanner.Err()
}

type markEndpoint struct {
	Numerator    int      `json:"numerator"`
	Denominator  int      `json:"denominator"`
	Unknown      int      `json:"unknown"`
	Estimate     *float64 `json:"estimate"`
	Low          *float64 `json:"wilson_low"`
	High         *float64 `json:"wilson_high"`
	Coverage     *float64 `json:"coverage"`
	OverallLower *float64 `json:"overall_lower_bound"`
	OverallUpper *float64 `json:"overall_upper_bound"`
}

func markFraction(n, d, u int) markEndpoint {
	e := markEndpoint{Numerator: n, Denominator: d, Unknown: u}
	if d > 0 {
		e.Estimate = opt(float64(n) / float64(d))
		ci := metrics.WilsonInterval(n, d, .95)
		e.Low = opt(ci.Low)
		e.High = opt(ci.High)
	}
	if d+u > 0 {
		e.Coverage = opt(float64(d) / float64(d+u))
		e.OverallLower = opt(float64(n) / float64(d+u))
		e.OverallUpper = opt(float64(n+u) / float64(d+u))
	}
	return e
}

type markGroup struct {
	Condition                markCondition             `json:"condition"`
	Executed                 int                       `json:"executed"`
	SetupFailures            int                       `json:"setup_failures"`
	Unscorable               int                       `json:"unscorable"`
	CorrectPerAttempt        markEndpoint              `json:"correct_per_planned_executed_attempt"`
	CorrectScorable          markEndpoint              `json:"correct_among_established_scorable"`
	Wrong                    int                       `json:"wrong_declarations"`
	Ambiguous                int                       `json:"ambiguous_abstentions"`
	None                     int                       `json:"no_declarations"`
	ShamDeclarations         markEndpoint              `json:"sham_any_declaration_per_scorable"`
	Open                     markEndpoint              `json:"target_open_survival"`
	Responsive               markEndpoint              `json:"target_responsive_survival"`
	CorrectOpen              markEndpoint              `json:"correct_with_open_survival"`
	CorrectResponsive        markEndpoint              `json:"correct_with_responsive_survival_per_planned_executed_attempt"`
	AllCircuitFractions      []float64                 `json:"all_circuit_open_fraction_per_execution"`
	AUC                      []float64                 `json:"run_level_auc"`
	AUCUnscorable            int                       `json:"auc_unscorable"`
	Realization              map[string]int            `json:"realization"`
	Errors                   map[string]int            `json:"failures"`
	DeliveryAvailability     markAvailabilityCounts    `json:"delivery_availability"`
	FrameAvailability        [4]markAvailabilityCounts `json:"frame_count_availability"`
	LatencyPercentileDefined int                       `json:"latency_percentiles_defined"`
	LoadBeforeAvailable      int                       `json:"loadavg_before_available"`
	LoadAfterAvailable       int                       `json:"loadavg_after_available"`
}

type markAvailabilityCounts struct {
	Complete    int `json:"complete"`
	Partial     int `json:"partial"`
	Unavailable int `json:"unavailable"`
}

func (a *markAvailabilityCounts) add(status string) {
	switch status {
	case "complete":
		a.Complete++
	case "partial":
		a.Partial++
	default:
		a.Unavailable++
	}
}

type markComparison struct {
	Mode      string        `json:"client_mode"`
	Period    time.Duration `json:"relay_period"`
	Pairs     int           `json:"matched_repeat_coverage"`
	Expected  int           `json:"expected_repeats"`
	P         *float64      `json:"p"`
	Adjusted  *float64      `json:"holm_p"`
	Method    string        `json:"method"`
	Statistic *float64      `json:"statistic"`
	Effect    *float64      `json:"effect"`
}
type markLatencyPair struct {
	Mode        string          `json:"client_mode"`
	Period      time.Duration   `json:"relay_period"`
	Pairs       int             `json:"defined_pair_count"`
	Expected    int             `json:"expected_repeats"`
	Differences []time.Duration `json:"active_minus_sham_p50"`
}
type markSummary struct {
	Schema       string            `json:"schema"`
	Purpose      string            `json:"purpose"`
	Complete     bool              `json:"complete"`
	Executed     int               `json:"executed"`
	Unexecuted   int               `json:"unexecuted"`
	Unknown      int               `json:"unknown"`
	Groups       []markGroup       `json:"groups"`
	Comparisons  []markComparison  `json:"fixed_ten_comparisons"`
	LatencyPairs []markLatencyPair `json:"descriptive_paired_latency"`
}

func summariseMark(manifest markManifest, rows []markEvaluation) markSummary {
	s := markSummary{Schema: markSchema, Purpose: manifest.Purpose, Complete: manifest.Complete}
	for _, slot := range manifest.Slots {
		switch slot.State {
		case "executed":
			s.Executed++
		case "unknown":
			s.Unknown++
		default:
			s.Unexecuted++
		}
	}
	groups := make(map[markCondition][]markEvaluation)
	for _, r := range rows {
		groups[r.Condition] = append(groups[r.Condition], r)
	}
	for _, mode := range []string{"immediate", "constant-rate"} {
		for _, period := range markPeriods {
			for _, active := range []bool{true, false} {
				key := markCondition{mode, period, active}
				g := markGroup{Condition: key, Realization: map[string]int{}, Errors: map[string]int{}}
				established, scorable, correct, openN, openD, respN, respD, jointOpen, jointResp, shamN := 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
				for _, r := range groups[key] {
					g.Executed++
					g.DeliveryAvailability.add(r.DeliveryStatus)
					for i, status := range r.FrameStatus {
						g.FrameAvailability[i].add(status)
					}
					if r.LatencyP50 != nil {
						g.LatencyPercentileDefined++
					}
					if r.LoadBefore.Status == "available" {
						g.LoadBeforeAvailable++
					}
					if r.LoadAfter.Status == "available" {
						g.LoadAfterAvailable++
					}
					if r.ErrorClass != "" {
						g.Errors[r.ErrorClass]++
					}
					if r.Run == nil || r.Run.SetupStatus != "established" {
						g.SetupFailures++
						g.Unscorable++
						g.AUCUnscorable++
						continue
					}
					established++
					g.Realization[r.Run.Counters.Realization]++
					if r.Detection == nil {
						g.Unscorable++
					} else {
						scorable++
						switch r.Detection.Decision {
						case "declared":
							if active && r.Correct != nil && *r.Correct {
								correct++
							} else if active {
								g.Wrong++
							}
							if !active {
								shamN++
							}
						case "ambiguous":
							g.Ambiguous++
						default:
							g.None++
						}
					}
					if r.AUC != nil {
						g.AUC = append(g.AUC, *r.AUC)
					} else if active {
						g.AUCUnscorable++
					}
					if r.Target >= 0 && r.Target < len(r.Run.Flows) {
						f := r.Run.Flows[r.Target]
						if f.Open != nil {
							openD++
							if *f.Open {
								openN++
								if r.Correct != nil && *r.Correct {
									jointOpen++
								}
							}
						}
						if f.Responsive != nil {
							respD++
							if *f.Responsive {
								respN++
								if r.Correct != nil && *r.Correct {
									jointResp++
								}
							}
						}
					}
					known, n := 0, 0
					for _, f := range r.Run.Flows {
						if f.Open != nil {
							known++
							if *f.Open {
								n++
							}
						}
					}
					if known == len(r.Run.Flows) && known > 0 {
						g.AllCircuitFractions = append(g.AllCircuitFractions, float64(n)/float64(known))
					}
				}
				g.CorrectPerAttempt = markFraction(correct, g.Executed, 0)
				g.CorrectScorable = markFraction(correct, scorable, 0)
				g.ShamDeclarations = markFraction(shamN, scorable, 0)
				g.Open = markFraction(openN, openD, established-openD)
				g.Responsive = markFraction(respN, respD, established-respD)
				g.CorrectOpen = markFraction(jointOpen, g.Executed, 0)
				g.CorrectResponsive = markFraction(jointResp, g.Executed, 0)
				sort.Float64s(g.AUC)
				s.Groups = append(s.Groups, g)
			}
		}
	}
	endpoint := func(r markEvaluation) float64 {
		if r.Correct != nil && *r.Correct && r.Run != nil && r.Target < len(r.Run.Flows) && r.Run.Flows[r.Target].Responsive != nil && *r.Run.Flows[r.Target].Responsive {
			return 1
		}
		return 0
	}
	lookup := make(map[markCondition]map[int]markEvaluation)
	for _, r := range rows {
		if lookup[r.Condition] == nil {
			lookup[r.Condition] = make(map[int]markEvaluation)
		}
		lookup[r.Condition][r.Repeat] = r
	}
	ps := make([]float64, 10)
	for i := range ps {
		ps[i] = 1
	}
	for _, mode := range []string{"immediate", "constant-rate"} {
		for _, period := range markPeriods[1:] {
			c := markComparison{Mode: mode, Period: period, Expected: manifest.Repeats}
			var a, b []float64
			for repeat := 0; repeat < manifest.Repeats; repeat++ {
				x, xok := lookup[markCondition{mode, period, true}][repeat]
				y, yok := lookup[markCondition{mode, 0, true}][repeat]
				if xok && yok {
					a = append(a, endpoint(x))
					b = append(b, endpoint(y))
				}
			}
			c.Pairs = len(a)
			if manifest.Complete && manifest.Purpose == "recorded-preset" && len(a) == manifest.Repeats {
				test := metrics.Wilcoxon(a, b)
				c.P = opt(test.P)
				c.Method = test.Method
				c.Statistic = opt(test.Statistic)
				c.Effect = opt(test.Effect)
				if c.P != nil {
					ps[len(s.Comparisons)] = *c.P
				}
			} else {
				c.Method = "unavailable"
			}
			s.Comparisons = append(s.Comparisons, c)
		}
	}
	adjusted := metrics.Holm(ps)
	for i := range s.Comparisons {
		if s.Comparisons[i].P != nil {
			s.Comparisons[i].Adjusted = opt(adjusted[i])
		}
	}
	for _, mode := range []string{"immediate", "constant-rate"} {
		for _, period := range markPeriods {
			p := markLatencyPair{Mode: mode, Period: period, Expected: manifest.Repeats}
			for repeat := 0; repeat < manifest.Repeats; repeat++ {
				a, aok := lookup[markCondition{mode, period, true}][repeat]
				b, bok := lookup[markCondition{mode, period, false}][repeat]
				if aok && bok && a.LatencyP50 != nil && b.LatencyP50 != nil {
					p.Pairs++
					p.Differences = append(p.Differences, *a.LatencyP50-*b.LatencyP50)
				}
			}
			s.LatencyPairs = append(s.LatencyPairs, p)
		}
	}
	return s
}
