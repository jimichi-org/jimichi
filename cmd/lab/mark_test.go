package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

func markFixture(cfg lab.Config) *lab.Run {
	origin := time.Second
	end := origin + cfg.Duration
	mark := &lab.MarkResult{SetupStatus: "established", CaptureStatus: "complete", CaptureStart: &origin, CaptureEnd: &end, Cutoff: &end, Counters: lab.MarkCounters{Realization: "none", RealizedFrames: make([]int, 12)}, Flows: make([]lab.MarkFlow, 6)}
	r := &lab.Run{Config: cfg, Origin: origin, Mark: mark}
	for i := 0; i < 6; i++ {
		trace := lab.NewTrace(time.Unix(0, 0))
		for k, c := range cfg.Mark.Code {
			base := origin + cfg.Mark.Offset + time.Duration(4*k)*cfg.Mark.Slot
			if i == cfg.Mark.Flow {
				if c > 0 {
					base += 2 * cfg.Mark.Slot
				}
				trace.Mark(time.Unix(0, int64(base+time.Millisecond)))
				trace.Mark(time.Unix(0, int64(base+2*time.Millisecond)))
			} else {
				trace.Mark(time.Unix(0, int64(base+time.Millisecond)))
				trace.Mark(time.Unix(0, int64(base+2*cfg.Mark.Slot+time.Millisecond)))
			}
		}
		r.Exit = append(r.Exit, trace)
		r.Entry = append(r.Entry, trace)
		r.EntryBack = append(r.EntryBack, lab.NewTrace(time.Unix(0, 0)))
		r.ExitBack = append(r.ExitBack, lab.NewTrace(time.Unix(0, 0)))
		open, responsive := true, true
		mark.Flows[i] = lab.MarkFlow{Open: &open, Responsive: &responsive, CallsStarted: 1, NilReturns: 1, Echoes: 1, Latency: []time.Duration{time.Millisecond}}
	}
	return r
}

func TestMarkMatrixSeeds(t *testing.T) {
	slots := markMatrix(7, 40)
	if len(slots) != 960 {
		t.Fatal(len(slots))
	}
	for repeat := 0; repeat < 40; repeat++ {
		seen := map[markCondition]bool{}
		seeds := slots[repeat*24].Seeds
		values := []int64{seeds.Workload, seeds.Code, seeds.Target, seeds.Permutation, seeds.Order}
		for i, v := range values {
			for _, w := range values[:i] {
				if v == w {
					t.Fatal("shared stream")
				}
			}
		}
		for _, slot := range slots[repeat*24 : (repeat+1)*24] {
			seen[slot.Condition] = true
			if slot.Seeds != seeds || slot.Repeat != repeat {
				t.Fatal(slot)
			}
		}
		if len(seen) != 24 {
			t.Fatal(seen)
		}
	}
	if reflect.DeepEqual(markMatrix(7, 1), markMatrix(8, 1)) {
		t.Fatal("seed ignored")
	}
	for _, slot := range slots[:24] {
		code, target, p := markBlock(slot.Seeds)
		sum := 0
		for _, v := range code {
			sum += int(v)
		}
		if sum != 0 || target < 0 || target >= 6 || len(p) != 6 {
			t.Fatal(code, target, p)
		}
	}
}

func TestMarkCommandRetainsFailures(t *testing.T) {
	previous := markExecute
	defer func() { markExecute = previous }()
	calls := 0
	markExecute = func(cfg lab.Config) (*lab.Run, error) {
		calls++
		if cfg.Flows != 6 || cfg.Hops != 3 || cfg.Duration != 16*time.Second || cfg.Payload != 128 || cfg.SendEvery != 200*time.Millisecond {
			t.Fatal(cfg)
		}
		return nil, errors.New("private address 127.0.0.1:54321 secret")
	}
	dir := t.TempDir()
	var out, errout bytes.Buffer
	if status := command([]string{"-set", "mark", "-repeats", "1", "-out", dir, "-rev", "fixture"}, &out, &errout); status != 0 {
		t.Fatal(status, errout.String())
	}
	if calls != 24 {
		t.Fatal(calls)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal(entries, e)
	}
	path := filepath.Join(dir, entries[0].Name())
	var manifest markManifest
	b, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if e = json.Unmarshal(b, &manifest); e != nil || !manifest.Complete || manifest.Purpose != "smoke-descriptive" {
		t.Fatal(e, manifest)
	}
	for _, name := range []string{"ledger.jsonl", "evaluation.jsonl", "observations.jsonl", "summary.json"} {
		b, e := os.ReadFile(filepath.Join(path, name))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(b, []byte("127.0.0.1")) || bytes.Contains(b, []byte("secret")) {
			t.Fatal("raw error leaked")
		}
		if name == "evaluation.jsonl" && bytes.Count(b, []byte("\n")) != 24 {
			t.Fatal("missing failed attempts")
		}
	}
}

func TestMarkCommandDefaultPlans960AndFatal(t *testing.T) {
	previous := markExecute
	defer func() { markExecute = previous }()
	calls := 0
	markExecute = func(lab.Config) (*lab.Run, error) {
		calls++
		return &lab.Run{Mark: &lab.MarkResult{SetupStatus: "failed", CaptureStatus: "not_started", ErrorClass: "environment"}}, errors.New("private environment detail")
	}
	dir := t.TempDir()
	var out, errout bytes.Buffer
	if code := command([]string{"-set", "mark", "-out", dir}, &out, &errout); code != 1 || calls != 1 {
		t.Fatal(code, calls)
	}
	entries, _ := os.ReadDir(dir)
	var manifest markManifest
	b, e := os.ReadFile(filepath.Join(dir, entries[0].Name(), "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &manifest); e != nil {
		t.Fatal(e)
	}
	if len(manifest.Slots) != 960 || manifest.Complete || manifest.Repeats != 40 || manifest.Purpose != "recorded-preset" || manifest.Slots[0].State != "executed" || manifest.Slots[1].State != "unexecuted" || manifest.ErrorClass != "environment" {
		t.Fatal(manifest)
	}
}
func TestMarkCommandArtifactsReplay(t *testing.T) {
	previous := markExecute
	defer func() { markExecute = previous }()
	markExecute = func(cfg lab.Config) (*lab.Run, error) { return markFixture(cfg), nil }
	dir := t.TempDir()
	var out, errout bytes.Buffer
	if status := command([]string{"-set", "mark", "-repeats", "1", "-out", dir, "-flows", "6", "-hops", "3", "-duration", "16s", "-send", "200ms", "-suite", "gost"}, &out, &errout); status != 0 {
		t.Fatal(status, errout.String())
	}
	entries, _ := os.ReadDir(dir)
	path := filepath.Join(dir, entries[0].Name())
	b, _ := os.ReadFile(filepath.Join(path, "observations.jsonl"))
	if strings.Contains(string(b), "target_truth") || strings.Contains(string(b), "candidate_permutation") || strings.Contains(string(b), "realization") {
		t.Fatal("truth in observation")
	}
	var replay bytes.Buffer
	if err := replayMark(filepath.Join(path, "observations.jsonl"), &replay); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(replay.Bytes()), []byte("\n"))
	if len(lines) != 24 {
		t.Fatal(len(lines))
	}
	var sum markSummary
	b, _ = os.ReadFile(filepath.Join(path, "summary.json"))
	if err := json.Unmarshal(b, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Purpose != "smoke-descriptive" || len(sum.Comparisons) != 10 || len(sum.Groups) != 24 {
		t.Fatal(sum)
	}
	for _, c := range sum.Comparisons {
		if c.P != nil || c.Adjusted != nil {
			t.Fatal("smoke inference", c)
		}
	}
}
func TestMarkExplicitFlags(t *testing.T) {
	for _, args := range [][]string{{"-duration", "20s"}, {"-flows", "5"}, {"-hops", "2"}, {"-send", "100ms"}, {"-bins", "100ms"}, {"-base", "0.001"}, {"-train", "5"}} {
		var out, errout bytes.Buffer
		all := append([]string{"-set", "mark"}, args...)
		if status := command(all, &out, &errout); status != 2 {
			t.Fatal(args, status)
		}
	}
}
func TestMarkSummaryUnknownAndNull(t *testing.T) {
	key := markCondition{"immediate", 0, true}
	yes := true
	rows := []markEvaluation{{Condition: key, Run: &lab.MarkResult{SetupStatus: "established", Counters: lab.MarkCounters{Realization: "none"}, Flows: []lab.MarkFlow{{Open: &yes, Responsive: &yes}}}, Target: 0, Correct: &yes, Detection: &metrics.MarkDetection{Decision: "declared"}}, {Condition: key, Run: &lab.MarkResult{SetupStatus: "established", Flows: []lab.MarkFlow{{}}}, Target: 0}}
	manifest := markManifest{Repeats: 40, Purpose: "recorded-preset", Slots: []markSlot{{State: "executed"}, {State: "unknown"}, {State: "unexecuted"}}}
	s := summariseMark(manifest, rows)
	g := s.Groups[0]
	if g.CorrectPerAttempt.Numerator != 1 || g.CorrectPerAttempt.Denominator != 2 || g.Open.Denominator != 1 || g.Open.Unknown != 1 || *g.Open.OverallLower != .5 || *g.Open.OverallUpper != 1 {
		t.Fatal(g)
	}
	if s.Unknown != 1 || s.Unexecuted != 1 || s.Executed != 1 {
		t.Fatal(s)
	}
	if s.Groups[1].Open.Estimate != nil {
		t.Fatal("zero denominator not null")
	}
	if len(s.Comparisons) != 10 {
		t.Fatal(s.Comparisons)
	}
}
func TestMarkSummaryFixedHolmFamily(t *testing.T) {
	m := markManifest{Complete: true, Purpose: "recorded-preset", Repeats: 40}
	var rows []markEvaluation
	for r := 0; r < 40; r++ {
		for _, period := range []time.Duration{0, 25 * time.Millisecond} {
			rows = append(rows, markEvaluation{Repeat: r, Condition: markCondition{"immediate", period, true}})
		}
	}
	s := summariseMark(m, rows)
	if len(s.Comparisons) != 10 || s.Comparisons[0].P == nil || *s.Comparisons[0].P != 1 || *s.Comparisons[0].Adjusted != 1 || s.Comparisons[0].Method != "degenerate" {
		t.Fatal(s.Comparisons)
	}
	for _, c := range s.Comparisons[1:] {
		if c.P != nil || c.Adjusted != nil {
			t.Fatal(c)
		}
	}
}

func TestMarkMeasurementsIndependentOfDetector(t *testing.T) {
	cfg := lab.Config{Flows: 6, Hops: 3, Duration: 16 * time.Second, Mark: &lab.MarkConfig{Enabled: true, Flow: 0, Code: []int8{1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1}, Slot: 200 * time.Millisecond, Offset: 2 * time.Second}}
	permutation := []int{0, 1, 2, 3, 4, 5}
	for _, kind := range []string{"incomplete", "detector_rejected", "missing_exit"} {
		t.Run(kind, func(t *testing.T) {
			run := markFixture(cfg)
			switch kind {
			case "incomplete":
				run.Mark.CaptureStatus = "incomplete"
				end := *run.Mark.CaptureStart + 8*time.Second
				run.Mark.CaptureEnd = &end
			case "detector_rejected":
				end := *run.Mark.CaptureStart + time.Second
				run.Mark.CaptureEnd = &end
			case "missing_exit":
				run.Exit = nil
			}
			_, e := markAnalyse(markSlot{}, cfg, run, nil, permutation)
			if e.Detection != nil || e.SuccessfulReturns == nil || *e.SuccessfulReturns != 6 || e.LatencyCount == nil || *e.LatencyCount != 6 || e.LatencyP50 == nil || *e.LatencyP50 != time.Millisecond || e.Unanswered == nil || *e.Unanswered != 0 {
				t.Fatal(e)
			}
			if kind == "missing_exit" {
				if e.FrameCounts[2] != nil || e.FrameStatus[2] != "unavailable" || e.FrameCounts[0] == nil || *e.FrameCounts[0] == 0 || e.FrameStatus[0] != "complete" {
					t.Fatal(e)
				}
			} else {
				if e.DeliveryStatus != "partial" || e.FrameStatus[0] != "partial" {
					t.Fatal(e)
				}
			}
			b, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			var restored markEvaluation
			if err = json.Unmarshal(b, &restored); err != nil {
				t.Fatal(err)
			}
			if restored.SuccessfulReturns == nil || *restored.SuccessfulReturns != 6 || restored.LatencyP50 == nil {
				t.Fatal(string(b))
			}
		})
	}
}

func TestMarkMissingMeasurementsVersusObservedZero(t *testing.T) {
	cfg := lab.Config{Flows: 6, Hops: 3, Duration: 16 * time.Second, Mark: &lab.MarkConfig{Code: []int8{1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1}, Slot: 200 * time.Millisecond, Offset: 2 * time.Second}}
	for _, run := range []*lab.Run{nil, {Mark: &lab.MarkResult{SetupStatus: "failed", CaptureStatus: "not_started"}}} {
		_, e := markAnalyse(markSlot{}, cfg, run, errors.New("setup"), []int{0, 1, 2, 3, 4, 5})
		if e.SuccessfulReturns != nil || e.LatencyCount != nil || e.Unanswered != nil || e.DeliveryStatus != "unavailable" || e.FrameCounts[0] != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(e)
		if !bytes.Contains(b, []byte(`"successful_send_returns_before_cutoff":null`)) || !bytes.Contains(b, []byte(`"latency_sample_count":null`)) {
			t.Fatal(string(b))
		}
	}
	run := markFixture(cfg)
	for i := range run.Mark.Flows {
		run.Mark.Flows[i] = lab.MarkFlow{}
	}
	for _, group := range [][]*lab.Trace{run.Entry, run.EntryBack, run.Exit, run.ExitBack} {
		for i := range group {
			group[i] = lab.NewTrace(time.Unix(0, 0))
		}
	}
	_, e := markAnalyse(markSlot{}, cfg, run, nil, []int{0, 1, 2, 3, 4, 5})
	if e.SuccessfulReturns == nil || *e.SuccessfulReturns != 0 || e.LatencyCount == nil || *e.LatencyCount != 0 || e.FrameCounts[0] == nil || *e.FrameCounts[0] != 0 || e.DeliveryStatus != "complete" || e.MultiplierStatus[0] != "zero_denominator" || e.LatencyStatus != "no_echoes" {
		t.Fatal(e)
	}
}

func TestMarkMeasurementSummaryCoverage(t *testing.T) {
	key := markCondition{"immediate", 0, true}
	rows := []markEvaluation{{Condition: key, DeliveryStatus: "complete", FrameStatus: [4]string{"complete", "complete", "partial", "unavailable"}, LoadBefore: markLoad{Status: "available"}}, {Condition: key, DeliveryStatus: "partial", FrameStatus: [4]string{"partial", "unavailable", "unavailable", "unavailable"}}, {Condition: key, DeliveryStatus: "unavailable", FrameStatus: [4]string{"unavailable", "unavailable", "unavailable", "unavailable"}}}
	g := summariseMark(markManifest{}, rows).Groups[0]
	if g.DeliveryAvailability != (markAvailabilityCounts{Complete: 1, Partial: 1, Unavailable: 1}) || g.FrameAvailability[0] != g.DeliveryAvailability || g.FrameAvailability[2].Partial != 1 || g.FrameAvailability[2].Unavailable != 2 || g.LoadBeforeAvailable != 1 || g.LoadAfterAvailable != 0 {
		t.Fatal(g)
	}
}

func TestMarkFailedAttemptsRecordLoadAvailability(t *testing.T) {
	oldExecute, oldLoad := markExecute, markLoadavg
	defer func() { markExecute = oldExecute; markLoadavg = oldLoad }()
	loads := 0
	markLoadavg = func() string {
		loads++
		if loads%2 == 1 {
			return "1.00 2.00 3.00"
		}
		return ""
	}
	markExecute = func(lab.Config) (*lab.Run, error) { return nil, errors.New("setup failed") }
	dir := t.TempDir()
	var out, errout bytes.Buffer
	if code := command([]string{"-set", "mark", "-repeats", "1", "-out", dir}, &out, &errout); code != 0 {
		t.Fatal(code, errout.String())
	}
	if loads != 48 {
		t.Fatal(loads)
	}
	entries, _ := os.ReadDir(dir)
	b, err := os.ReadFile(filepath.Join(dir, entries[0].Name(), "evaluation.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e markEvaluation
		if err = json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.LoadBefore.Status != "available" || e.LoadBefore.Value == nil || *e.LoadBefore.Value != "1.00 2.00 3.00" || e.LoadAfter.Status != "unavailable" || e.LoadAfter.Value != nil || e.SuccessfulReturns != nil {
			t.Fatal(e)
		}
	}
}

func TestMarkLockingFailureStopsAfterOnePersistedAttempt(t *testing.T) {
	old := markExecute
	defer func() { markExecute = old }()
	calls := 0
	markExecute = func(lab.Config) (*lab.Run, error) { calls++; return nil, secmem.ErrNotLocked }
	dir := t.TempDir()
	var out, errout bytes.Buffer
	if code := command([]string{"-set", "mark", "-repeats", "1", "-out", dir}, &out, &errout); code != 1 || calls != 1 {
		t.Fatal(code, calls, errout.String())
	}
	entries, _ := os.ReadDir(dir)
	path := filepath.Join(dir, entries[0].Name())
	var m markManifest
	b, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Complete || m.ErrorClass != "environment" || m.Slots[0].State != "executed" || m.Slots[1].State != "unexecuted" {
		t.Fatal(m)
	}
	b, _ = os.ReadFile(filepath.Join(path, "evaluation.jsonl"))
	if bytes.Count(b, []byte("\n")) != 1 || !bytes.Contains(b, []byte(`"normalized_error_class":"environment"`)) {
		t.Fatal(string(b))
	}
}
