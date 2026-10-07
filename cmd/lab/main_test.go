package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab"
)

// two flows with a few frames each, enough for analyse to score them
func syntheticRun(broken uint64, brokenFlows int, closures ...lab.Closure) *lab.Run {
	start := time.Now()
	trace := func(offsets ...time.Duration) *lab.Trace {
		t := lab.NewTrace(start)
		for _, o := range offsets {
			t.Mark(start.Add(o))
		}
		return t
	}
	ms := time.Millisecond
	return &lab.Run{
		Config:       lab.Config{Hops: 3, Flows: 2, Duration: time.Second, Suite: jcrypto.SuiteC25519, Payload: 128},
		Entry:        []*lab.Trace{trace(10*ms, 300*ms, 310*ms), trace(500*ms, 900*ms)},
		Exit:         []*lab.Trace{trace(20*ms, 320*ms, 330*ms), trace(520*ms, 910*ms)},
		EntryBack:    []*lab.Trace{trace(30 * ms), trace(530 * ms)},
		ExitBack:     []*lab.Trace{trace(25 * ms), trace(525 * ms)},
		Sent:         5,
		RelayBroken:  broken,
		BrokenFlows:  brokenFlows,
		RelayDropped: 4,
		Origin:       100 * ms,
		Closures:     closures,
	}
}

// a run without protection as the harness hands it over: the setup of each
// flow before the origin, two messages and their echoes inside the window,
// one of them on the origin itself, and a frame exactly where the window
// closes. The window is [100 ms, 1100 ms), so each direction of each link
// counts 2 frames per flow, 4 for the 4 messages sent: x1 on every link
func TestCostWithoutProtectionIsExactlyOneOnEveryLinkAndDirection(t *testing.T) {
	start := time.Now()
	ms := time.Millisecond
	traces := func(offsets ...time.Duration) []*lab.Trace {
		out := make([]*lab.Trace, 2)
		for i := range out {
			out[i] = lab.NewTrace(start)
			for _, o := range offsets {
				out[i].Mark(start.Add(o))
			}
		}
		return out
	}
	run := &lab.Run{
		Config:    lab.Config{Hops: 3, Flows: 2, Duration: time.Second, Suite: jcrypto.SuiteC25519, Payload: 128},
		Entry:     traces(40*ms, 100*ms, 600*ms, 1100*ms),
		Exit:      traces(60*ms, 100*ms, 601*ms, 1100*ms),
		EntryBack: traces(102*ms, 603*ms, 1100*ms),
		ExitBack:  traces(101*ms, 602*ms, 1100*ms),
		Sent:      4,
		Origin:    100 * ms,
	}
	res, _ := analyse(run, "none", 100*ms)
	for _, c := range []struct {
		name string
		got  float64
	}{
		{"entry", res.Multiplier},
		{"entry back", res.EntryBackMultiplier},
		{"relay link", res.RelayMultiplier},
		{"relay link back", res.RelayBackMultiplier},
	} {
		if c.got != 1 {
			t.Errorf("%s: x%v, want exactly 1", c.name, c.got)
		}
	}
	if res.Cells != 4 || res.Messages != 4 {
		t.Errorf("%d cells for %d messages at the entry, want 4 and 4", res.Cells, res.Messages)
	}
}

// flow 0 closed 350 ms on the trace clock, 250 ms after the flows started at
// 100 ms; flow 1 stayed open
func TestFlowClosuresReachTheReport(t *testing.T) {
	ms := time.Millisecond
	res, _ := analyse(syntheticRun(0, 0, lab.Closure{Closed: true, At: 350 * ms}, lab.Closure{}), "x", 100*ms)
	if len(res.FlowClosed) != 2 || !res.FlowClosed[0] || res.FlowClosed[1] ||
		res.FlowClosedAfter[0] != "250ms" || res.FlowClosedAfter[1] != "" {
		t.Fatalf("flow_closed %v, flow_closed_after %q; want [true false] and [250ms \"\"]", res.FlowClosed, res.FlowClosedAfter)
	}
	// no relay or client counted it, the flow alone makes the run broken
	sum := summarise([]result{res})
	if sum[0].BrokenRuns != 1 || sum[0].AUC != nil {
		t.Fatalf("a run with a closed flow was summarised as clean: %s", encode(t, sum[0]))
	}
}

func TestBreakCountsReachTheReport(t *testing.T) {
	res, _ := analyse(syntheticRun(2, 1), "x", 100*time.Millisecond)
	if res.RelayBrokenCircuits != 2 || res.BrokenFlows != 1 || res.RelayDroppedCells != 4 {
		t.Fatalf("row carries %d closed circuits, %d broken flows, %d dropped cells; want 2, 1 and 4",
			res.RelayBrokenCircuits, res.BrokenFlows, res.RelayDroppedCells)
	}
}

// three runs of one configuration, the third with a closed circuit. Worked by
// hand from the two clean runs only:
//
//	auc 0.6 and 0.8: median (0.6 + 0.8) / 2 = 0.7, min 0.6, max 0.8
//	top1 0.5 and 1.0: median 0.75
//	multiplier 2 and 4: median 3; relay multiplier 1 and 3: median 2
//	p50 10ms and 30ms: median 20 ms
//	deg: the one degenerate run is the broken one, so 0
//
// with the broken run counted the auc median would be 0.6 and the range [0.1, 0.8]
func TestBrokenRunsStayOutOfTheMedians(t *testing.T) {
	rows := []result{
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.6, TopOne: 0.5, Multiplier: 2, RelayMultiplier: 1, P50: "10ms"},
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.8, TopOne: 1.0, Multiplier: 4, RelayMultiplier: 3, P50: "30ms"},
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.1, TopOne: 0, Multiplier: 9, RelayMultiplier: 9, P50: "900ms",
			CIDegenerate: true, RelayBrokenCircuits: 1},
	}
	sum := summarise(rows)
	if len(sum) != 1 {
		t.Fatalf("%d summary lines, want 1", len(sum))
	}
	s := sum[0]
	if s.Runs != 3 || s.BrokenRuns != 1 {
		t.Fatalf("runs %d, broken %d; want 3 and 1", s.Runs, s.BrokenRuns)
	}
	near := func(a *float64, b float64) bool { return a != nil && *a-b < 1e-9 && b-*a < 1e-9 }
	if !near(s.AUC, 0.7) || !near(s.AUCMin, 0.6) || !near(s.AUCMax, 0.8) || !near(s.TopOne, 0.75) ||
		!near(s.Multiplier, 3) || !near(s.RelayMult, 2) || !near(s.LatencyP50Ms, 20) ||
		s.DegenerateRuns == nil || *s.DegenerateRuns != 0 {
		t.Fatalf("summary does not match the two clean runs: %s", encode(t, s))
	}
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("summary does not encode: %v", err)
	}
	return string(b)
}

var medianFields = []string{
	"auc_median", "auc_min", "auc_max", "top1_median", "bandwidth_multiplier_median",
	"relay_link_multiplier_median", "ci_degenerate_runs", "latency_p50_ms_median",
}

func fields(t *testing.T, s summary) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(encode(t, s)), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// a configuration whose every run closed a circuit keeps its line, and every
// field that would hold a result is null rather than a zero that reads as one
func TestEveryRunBrokenLeavesNothingToSummarise(t *testing.T) {
	rows := []result{
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.9, P50: "10ms", BrokenFlows: 1},
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.4, P50: "20ms", RelayBrokenCircuits: 3},
	}
	sum := summarise(rows)
	if len(sum) != 1 || sum[0].Runs != 2 || sum[0].BrokenRuns != 2 {
		t.Fatalf("summary %s, want two runs, both broken", encode(t, sum))
	}
	m := fields(t, sum[0])
	for _, f := range medianFields {
		v, present := m[f]
		if !present || v != nil {
			t.Fatalf("%s is %v, want null: %s", f, v, encode(t, sum[0]))
		}
	}
}

// clean runs without a single latency sample leave the latency median null:
// Median of nothing is NaN, which JSON cannot hold
func TestNoLatencySampleLeavesTheLatencyMedianNull(t *testing.T) {
	sum := summarise([]result{{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.6}})
	m := fields(t, sum[0])
	if v, present := m["latency_p50_ms_median"]; !present || v != nil {
		t.Fatalf("latency median %v, want null", v)
	}
	if m["auc_median"] != 0.6 || m["ci_degenerate_runs"] != 0.0 {
		t.Fatalf("clean fields lost: %s", encode(t, sum[0]))
	}
}

// the report holds a latency to the microsecond: 155 us is 0.155 ms, which two
// decimals would print as 0.15 or 0.16, and 1.555 ms as 1.55 or 1.56. The
// median of 155 and 156 us is 155.5 us, 0.1555 ms, and of 82.59 and 82.6 ms
// it is 82.595 ms
func TestSummaryPrintsLatencyAsTheReportHoldsIt(t *testing.T) {
	sum := summarise([]result{
		{Suite: "c25519", Traffic: "fast", Bin: "100ms", AUC: 1, P50: "155µs"},
		{Suite: "c25519", Traffic: "edge", Bin: "100ms", AUC: 1, P50: "999µs"},
		{Suite: "c25519", Traffic: "one", Bin: "100ms", AUC: 1, P50: "1ms"},
		{Suite: "c25519", Traffic: "mid", Bin: "100ms", AUC: 1, P50: "1.555ms"},
		{Suite: "c25519", Traffic: "five", Bin: "100ms", AUC: 1, P50: "5ms"},
		{Suite: "c25519", Traffic: "slow", Bin: "100ms", AUC: 1, P50: "48.5ms"},
		{Suite: "c25519", Traffic: "half", Bin: "100ms", AUC: 1, P50: "155µs"},
		{Suite: "c25519", Traffic: "half", Bin: "100ms", AUC: 1, P50: "156µs"},
		{Suite: "c25519", Traffic: "paced", Bin: "100ms", AUC: 1, P50: "82.59ms"},
		{Suite: "c25519", Traffic: "paced", Bin: "100ms", AUC: 1, P50: "82.6ms"},
	})
	var out bytes.Buffer
	printSummary(&out, sum)
	lines := map[string][]string{}
	for _, l := range strings.Split(out.String(), "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines[f[0]] = f
		}
	}
	// traffic, bin, runs, brk, lim, clean, auc and its two bounds, top1, mult and
	// relay-x come before p50
	for traffic, want := range map[string]string{
		"fast": "0.155", "edge": "0.999", "one": "1.000", "mid": "1.555", "five": "5.000", "slow": "48.500",
		"half": "0.1555", "paced": "82.595",
	} {
		f := lines[traffic]
		if len(f) < 13 || f[12] != want {
			t.Errorf("%s: p50 printed in %q, want %s", traffic, strings.Join(f, " "), want)
		}
	}
}

// one clean run gives values, not a median, and the printed line says so; a
// line with no clean run prints no numbers at all
func TestSummaryMarksLinesWithOneOrNoCleanRun(t *testing.T) {
	sum := summarise([]result{
		{Suite: "c25519", Traffic: "one", Bin: "100ms", AUC: 0.6, P50: "10ms"},
		{Suite: "c25519", Traffic: "one", Bin: "100ms", AUC: 0.9, RelayBrokenCircuits: 1},
		{Suite: "c25519", Traffic: "none", Bin: "100ms", AUC: 0.9, BrokenFlows: 2},
		{Suite: "c25519", Traffic: "two", Bin: "100ms", AUC: 0.6},
		{Suite: "c25519", Traffic: "two", Bin: "100ms", AUC: 0.8},
	})
	var out bytes.Buffer
	printSummary(&out, sum)
	lines := map[string]string{}
	for _, l := range strings.Split(out.String(), "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines[f[0]] = l
		}
	}
	if !strings.Contains(lines["one"], "one clean run") {
		t.Fatalf("a single clean run is printed as a median: %q", lines["one"])
	}
	if !strings.Contains(lines["none"], "nothing to summarise") || strings.Contains(lines["none"], "0.900") {
		t.Fatalf("a line without clean runs prints numbers: %q", lines["none"])
	}
	if strings.Contains(lines["two"], "one clean run") || !strings.Contains(lines["two"], "0.700") {
		t.Fatalf("a line of two clean runs lost its median: %q", lines["two"])
	}
}
