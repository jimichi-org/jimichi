package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

func nearly(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func is(p *float64, v float64) bool { return p != nil && nearly(*p, v) }

func ms(v ...int) *lab.Trace {
	start := time.Now()
	t := lab.NewTrace(start)
	for _, x := range v {
		t.Mark(start.Add(time.Duration(x) * time.Millisecond))
	}
	return t
}

// the traces and labels of TestCellFeaturesKnownAnswer: the window [15 ms,
// 60 ms) is the origin plus the duration, and without relay clocks r_idx is
// a column. Six forward frames lie in the window, three of each flow: four
// cells with every feature, flow 0's at 20, 35 and 40 and flow 1's at 30, and
// two without, flow 1's at 16 (no g_prev) and 50 (no back[2]). Its payload
// labels are those of flow 0, 2, and of flow 1, 2
func labelledRunOfSection4() *lab.Run {
	return &lab.Run{
		Config:    lab.Config{Hops: 3, Flows: 2, Duration: 45 * time.Millisecond, Suite: jcrypto.SuiteC25519, Payload: 128},
		Origin:    15 * time.Millisecond,
		Entry:     []*lab.Trace{ms(0, 10, 20, 35, 40, 60), ms(5, 16, 30, 50, 70)},
		EntryBack: []*lab.Trace{ms(11, 22, 41, 43, 61), ms(17, 55)},
		Labels:    []*lab.Labels{lab.NewLabels(false, true, false, true, false), lab.NewLabels(false, false, true, true)},
		Sent:      4,
	}
}

func TestLabelledCellsOfARun(t *testing.T) {
	run := labelledRunOfSection4()
	cells, payload, ok := labelledCells(run)
	if !ok || payload != 4 {
		t.Fatalf("ok %v with %d payload labels, want true and 4", ok, payload)
	}
	want := [][]float64{
		{0.010, 0.015, 0, 0.002, 0.002},
		{0.015, 0.005, 0.005, 0.006, 0.006},
		{0.005, 0.020, 0.005, 0.001, 0.003},
		{0.014, 0.020, 0.003, 0.025, 0.025},
	}
	if len(cells.Rows) != len(want) || !slices.Equal(cells.Truth, []bool{true, false, true, false}) ||
		!slices.Equal(cells.Flow, []int{0, 0, 0, 1}) || cells.Undefined != 2 {
		t.Fatalf("cells %+v", cells)
	}
	for i, r := range want {
		for j, v := range r {
			if !nearly(cells.Rows[i][j], v) {
				t.Errorf("row %d: %v, want %v", i, cells.Rows[i], r)
				break
			}
		}
	}
	p := countTrue(cells.Truth)
	if base := coverBase(run, "x"); p != 2 || len(cells.Truth)-p != 2 || base.Cells != p+(len(cells.Truth)-p)+cells.Undefined {
		t.Errorf("%d payload, %d cover and %d undefined cells against %d in the window, want 2, 2, 2 and 6",
			p, len(cells.Truth)-p, cells.Undefined, base.Cells)
	}

	dropped := labelledRunOfSection4()
	dropped.Sent, dropped.Dropped = 5, 1
	if _, _, ok := labelledCells(dropped); !ok {
		t.Error("a message the schedule dropped was counted against the labels")
	}
	for _, c := range []struct {
		name   string
		change func(*lab.Run)
	}{
		{"one message more", func(r *lab.Run) { r.Sent = 5 }},
		{"one message fewer", func(r *lab.Run) { r.Sent = 3 }},
		{"labels of flow 0 one short", func(r *lab.Run) { r.Labels[0] = lab.NewLabels(false, true, false, true) }},
		{"no labels for one flow", func(r *lab.Run) { r.Labels[1] = nil }},
		{"a run without LabelCells", func(r *lab.Run) { r.Labels = nil }},
	} {
		run := labelledRunOfSection4()
		c.change(run)
		if _, _, ok := labelledCells(run); ok {
			t.Errorf("%s: the labels were taken as consistent", c.name)
		}
	}
}

func cellsOf(flow []int, truth []bool, rows ...[]float64) metrics.Cells {
	return metrics.Cells{Rows: rows, Truth: truth, Flow: flow}
}

// the training rows differ only in r_next, so the discriminant is r_next
// alone: payload mean (0.003 + 0.005)/2 = 0.004, cover (0.001 + 0.002)/2 =
// 0.0015, m = 0.00275, d = 0.0025, score (x - 0.00275)/0.0025. The claim
// rows vary in the unused columns on purpose
func scoreRunCase() (direction, metrics.Cells) {
	run1 := cellsOf([]int{0, 0}, []bool{true, false}, []float64{0.1, 0.1, 0, 0.003, 0.001}, []float64{0.1, 0.1, 0, 0.001, 0.001})
	run2 := cellsOf([]int{0, 1}, []bool{true, false}, []float64{0.1, 0.1, 0, 0.005, 0.001}, []float64{0.1, 0.1, 0, 0.002, 0.001})
	claim := cellsOf([]int{0, 0, 0, 1, 1}, []bool{true, false, true, false, true},
		[]float64{0.05, 0.2, 0.01, 0.004, 0.009},
		[]float64{0.05, 0.3, 0.02, 0.001, 0.008},
		[]float64{0.02, 0.4, 0.03, 0.002, 0.007},
		[]float64{0.08, 0.5, 0.04, 0.003, 0.006},
		[]float64{0.07, 0.6, 0.05, 0.005, 0.005},
	)
	return trainDirection([]metrics.Cells{run1, run2}), claim
}

// scores 1/2, -7/10, -3/10, 1/10, 9/10: payload 1/2, -3/10, 9/10 against cover
// -7/10, 1/10 order 5 of 6 pairs. D and TV are on g_prev, payload {0.05, 0.02,
// 0.07} against cover {0.05, 0.08}, the 0.05 tie one group: D = 3/6 after
// 0.07; TV over N = 5 bins with groups at ranks 0, 1, 3, 4 is (|2 - 0| +
// |2 - 3| + |2 - 0| + |0 - 3|)/12 = 2/3. The shift by one in each flow gives
// payload {0.05, 0.02, 0.08} against {0.05, 0.07}: D 1/3, TV 2/3; the
// permutation [F, F, T, T, T] gives {0.02, 0.08, 0.07} against {0.05, 0.05}:
// D 2/3, TV 1. On the scores D would be 2/3 and TV 1, so the column is the
// one checked. Pooled alone: the ROC rises to (0, 1/3) and (0, 2/3) before
// the first cover cell, TPR at FPR 0.01 is 2/3, the share of payload 3/5,
// precision (2/5)/(2/5 + 0.01 * 2/5) = 100/101
func TestScoreRunKnownAnswer(t *testing.T) {
	d, claim := scoreRunCase()
	if d.reason != "" || d.runs != 2 || !slices.Equal(d.unused, []int{0, 1, 2, 4}) {
		t.Fatalf("direction %q from %d runs leaving out %v, want \"\", 2, [0 1 2 4]", d.reason, d.runs, d.unused)
	}
	shifted, permuted := []bool{false, true, true, true, false}, []bool{false, false, true, true, true}
	if got := metrics.CircularShift(claim.Truth, claim.Flow, []int{1, 1}); !slices.Equal(got, shifted) {
		t.Fatalf("shift by one: %v", got)
	}
	s := scoreRun(d, claim, 2, shifted, permuted)
	want := []float64{0.5, -0.7, -0.3, 0.1, 0.9}
	if len(s.scores) != len(want) {
		t.Fatalf("scores %+v", s.scores)
	}
	for i, sc := range s.scores {
		if !nearly(sc.Value, want[i]) || sc.True != claim.Truth[i] || sc.Entry != claim.Flow[i] {
			t.Errorf("score %d: %+v, want %v", i, sc, want[i])
		}
	}
	if !nearly(s.auc, 5.0/6) || s.method != "bca-10000" || s.degenerate != "" {
		t.Errorf("lda auc %v by %q, degenerate %q; want 5/6 by bca-10000", s.auc, s.method, s.degenerate)
	}
	for j, v := range s.features {
		if j == metrics.RNext && !nearly(v, 5.0/6) || j != metrics.RNext && !math.IsNaN(v) {
			t.Errorf("feature %s: AUC %v", metrics.FeatureNames[j], v)
		}
	}
	for _, c := range []struct {
		name      string
		got, want float64
	}{
		{"ks", s.ks, 0.5}, {"tv", s.tv, 2.0 / 3}, {"ks null", s.ksNull, 1.0 / 3}, {"tv null", s.tvNull, 2.0 / 3},
		{"ks permuted", s.ksPermuted, 2.0 / 3}, {"tv permuted", s.tvPermuted, 1},
	} {
		if !nearly(c.got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, c.got, c.want)
		}
	}

	auc := s.auc
	row := coverRow{Role: "claim", Traffic: "fixed-2x", Mode: "constant-rate", AUC: &auc, scores: s.scores}
	l := summariseCover([]coverRow{row}, 0.2, 1).Levels[0]
	if !is(l.CellTPR, 2.0/3) || !is(l.CellBaseRate, 0.6) || !is(l.CellPrecision, 100.0/101) ||
		l.CellNegatives == nil || *l.CellNegatives != 2 {
		t.Errorf("pooled precision: %s", encode(t, l))
	}
}

func TestTrainingDirectionReasons(t *testing.T) {
	same := []float64{0.1, 0.1, 0, 0.002, 0.001}
	for _, c := range []struct {
		name string
		runs []metrics.Cells
		want string
	}{
		{"payload only", []metrics.Cells{cellsOf([]int{0, 1}, []bool{true, true}, []float64{0.1, 0.1, 0, 0.001, 0.001}, same)}, "missing_class"},
		{"no rows", nil, "missing_class"},
		{"four identical rows", []metrics.Cells{cellsOf([]int{0, 0, 1, 1}, []bool{true, false, true, false}, same, same, same, same)}, "no_feature"},
		// r_next payload {0.001, 0.003} against cover {0.002, 0.002}: the means
		// are both 0.002
		{"equal means", []metrics.Cells{cellsOf([]int{0, 0, 1, 1}, []bool{true, false, true, false},
			[]float64{0.1, 0.1, 0, 0.001, 0.001}, []float64{0.1, 0.1, 0, 0.002, 0.001},
			[]float64{0.1, 0.1, 0, 0.003, 0.001}, []float64{0.1, 0.1, 0, 0.002, 0.001})}, "equal_means"},
	} {
		if got := trainDirection(c.runs).reason; got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if d, _ := scoreRunCase(); d.reason != "" {
		t.Errorf("the training set of the known answer: %q", d.reason)
	}
}

// A left out: B and C give the class means 0.0035 and 0.003, rising, and A's
// payload 0.003 is above its cover 0.001; B left out: A and C give 0.0025 and
// 0.0025, equal in float too; C left out: A and B give 0.004 and 0.0015, and
// C's payload 0.002 is below its cover 0.004, AUC 0 and not folded
func TestTrainingRowsLeaveOneRunOut(t *testing.T) {
	run := func(seed int64, payload, cover float64) labelledRun {
		return labelledRun{
			row:    coverRow{Role: "training", Flows: 2, Seed: seed},
			cells:  cellsOf([]int{0, 1}, []bool{true, false}, []float64{0.1, 0.1, 0, payload, 0.001}, []float64{0.1, 0.1, 0, cover, 0.001}),
			usable: true,
		}
	}
	rows := leaveOneOut([]labelledRun{run(1, 0.003, 0.001), run(2, 0.005, 0.002), run(3, 0.002, 0.004), {row: coverRow{Role: "training", Flows: 2}}})
	if !is(rows[0].AUC, 1) || rows[0].Degenerate != "" {
		t.Errorf("A: AUC %s, degenerate %q; want 1", dash(rows[0].AUC), rows[0].Degenerate)
	}
	if rows[1].AUC != nil || rows[1].Degenerate != "training_equal_means" {
		t.Errorf("B: AUC %s, degenerate %q; want null and training_equal_means", dash(rows[1].AUC), rows[1].Degenerate)
	}
	if !is(rows[2].AUC, 0) || rows[2].Degenerate != "" {
		t.Errorf("C: AUC %s, degenerate %q; want 0", dash(rows[2].AUC), rows[2].Degenerate)
	}
	if rows[3].AUC != nil || rows[3].KS != nil || rows[3].Unused != nil {
		t.Errorf("a training run that is not usable was scored: %s", encode(t, rows[3]))
	}
	if !slices.Equal(rows[0].Unused, []string{"g_prev", "g_next", "dev", "r_idx"}) {
		t.Errorf("unused %v", rows[0].Unused)
	}
}

func TestShiftOffsets(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 10}
	for seed := int64(0); seed < 1000; seed++ {
		got := shiftOffsets(seed, sizes)
		if got[0] != 0 || got[1] != 0 || got[2] != 1 || got[3] < 1 || got[3] > 2 || got[4] < 1 || got[4] > 9 {
			t.Fatalf("seed %d: offsets %v", seed, got)
		}
		if again := shiftOffsets(seed, sizes); !slices.Equal(got, again) {
			t.Fatalf("seed %d: %v, then %v", seed, got, again)
		}
	}
	c := cellsOf([]int{0, 0, 0, 1, 1, 1, 1}, []bool{true, false, false, true, true, false, false},
		nil, nil, nil, nil, nil, nil, nil)
	for seed := int64(0); seed < 100; seed++ {
		shifted, permuted := nullLabels(c, seed)
		if countTrue(permuted) != 3 {
			t.Fatalf("seed %d: the permutation holds %d true labels", seed, countTrue(permuted))
		}
		for f, want := range []int{1, 2} {
			n := 0
			for i, fl := range c.Flow {
				if fl == f && shifted[i] {
					n++
				}
			}
			if n != want {
				t.Fatalf("seed %d flow %d: %d true labels after the shift, want %d", seed, f, n, want)
			}
		}
	}
}

var seventeen = []float64{0.46, 0.47, 0.48, 0.49, 0.50, 0.51, 0.52, 0.53, 0.54, 0.50, 0.49, 0.51, 0.48, 0.52, 0.47, 0.53, 0.50}

// at s 0.2 and m 1 the bounds are x_(1) and x_(17): P(K = 0) = 0.8^17 =
// 0.0225 <= 0.025. Of 16 runs 0.8^16 = 0.0281 leaves no bound, and at m 2
// 0.0225 is above 0.0125
func TestCorridor(t *testing.T) {
	low, high, verdict := corridor(seventeen, 0.2, 1)
	if low != 0.46 || high != 0.54 || verdict != "equivalent" {
		t.Errorf("17 runs: [%v, %v] %q", low, high, verdict)
	}
	wide := slices.Clone(seventeen)
	wide[16] = 0.56
	if low, high, verdict := corridor(wide, 0.2, 1); low != 0.46 || high != 0.56 || verdict != "not shown" {
		t.Errorf("one run at 0.56: [%v, %v] %q", low, high, verdict)
	}
	for _, c := range []struct {
		name   string
		auc    []float64
		claims int
	}{{"16 runs", seventeen[:16], 1}, {"17 runs at m 2", seventeen, 2}} {
		low, high, verdict := corridor(c.auc, 0.2, c.claims)
		if !math.IsNaN(low) || !math.IsNaN(high) || verdict != "" {
			t.Errorf("%s: [%v, %v] %q, want no bound", c.name, low, high, verdict)
		}
	}
}

func claimRow(traffic, mode string, repeat int, lda, ks, ks0, tv, tv0 *float64) coverRow {
	return coverRow{Role: "claim", Traffic: traffic, Mode: mode, Repeat: repeat, AUC: lda, KS: ks, KSNull: ks0, TV: tv, TVNull: tv0}
}

func f(v float64) *float64 { return &v }

func TestCorridorOnlyForTheClaimLevel(t *testing.T) {
	var rows []coverRow
	for _, l := range []struct{ traffic, mode string }{{"add-1x", "immediate"}, {"fixed-2x", "constant-rate"}} {
		for r, v := range seventeen {
			rows = append(rows, claimRow(l.traffic, l.mode, r, f(v), nil, nil, nil, nil))
		}
	}
	sum := summariseCover(rows, 0.2, 1)
	add, fixed := sum.Levels[0], sum.Levels[1]
	if !fixed.EquivalenceClaim || !is(fixed.CorridorLow, 0.46) || !is(fixed.CorridorHigh, 0.54) ||
		fixed.Corridor == nil || *fixed.Corridor != "equivalent" {
		t.Errorf("fixed-2x at m 1: %s", encode(t, fixed))
	}
	if add.EquivalenceClaim || add.CorridorLow != nil || add.CorridorHigh != nil || add.Corridor != nil {
		t.Errorf("add-1x at m 1: %s", encode(t, add))
	}
	for _, l := range summariseCover(rows, 0.2, 2).Levels {
		if l.CorridorLow != nil || l.CorridorHigh != nil || l.Corridor != nil {
			t.Errorf("%s at m 2: %s", l.Traffic, encode(t, l))
		}
	}
}

// readings 0, 0, 0, 5, 5, 7, 7, 7, 12, 20 ns: steps 5, 2 and 5 at n 3 with
// nine readings used
func TestClockStepKnownAnswer(t *testing.T) {
	readings := []time.Duration{0, 0, 0, 5, 5, 7, 7, 7, 12, 20}
	used := 0
	clock := func() time.Duration {
		used++
		return readings[used-1]
	}
	if got := clockStep(clock, 3); got != 2 || used != 9 {
		t.Errorf("step %v after %d readings, want 2ns after 9", got, used)
	}
	if got := clockStep(coarseClock(), 20); got != 500*time.Microsecond {
		t.Errorf("step %v, want 500µs", got)
	}
}

// moves by 500 µs at every third reading
func coarseClock() func() time.Duration {
	n := 0
	return func() time.Duration {
		n++
		return time.Duration(n/3) * 500 * time.Microsecond
	}
}

func empty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%s holds %d files", dir, len(entries))
	}
}

func TestCoverRefusesFlagsAndACoarseClock(t *testing.T) {
	for _, c := range []struct {
		flag string
		args []string
	}{
		{"-train", []string{"-set", "cover", "-train", "0"}},
		{"-corridor", []string{"-set", "cover", "-corridor", "0"}},
		{"-corridor", []string{"-set", "cover", "-corridor", "0.5"}},
		{"-claims", []string{"-set", "cover", "-claims", "0"}},
		{"-base", []string{"-set", "main", "-base", "0"}},
		{"-base", []string{"-set", "main", "-base", "1"}},
		{"-base", []string{"-set", "main", "-base", "1.5"}},
	} {
		dir := t.TempDir()
		var out, errOut bytes.Buffer
		status := command(append(c.args, "-rev", "abc", "-out", dir), &out, &errOut)
		if status != 2 || !strings.Contains(errOut.String(), c.flag) {
			t.Errorf("%v: status %d, stderr %q; want 2 naming %s", c.args, status, errOut.String(), c.flag)
		}
		empty(t, dir)
	}
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	status := cover(coverFlags{
		flows: 3, hops: 3, duration: time.Second, send: 200 * time.Millisecond, train: 1, repeats: 1,
		corridor: 0.2, claims: 1, seed: 1, suite: jcrypto.SuiteC25519, rev: "abc", out: dir, now: coarseClock(),
	}, &out, &errOut)
	if status != 2 || !strings.Contains(errOut.String(), "500µs") {
		t.Errorf("a coarse clock: status %d, stderr %q", status, errOut.String())
	}
	empty(t, dir)
}

func TestCoverSummaryKnownAnswer(t *testing.T) {
	var rows []coverRow
	for r, v := range [][5]float64{
		{0.62, 0.30, 0.10, 0.50, 0.20}, {0.70, 0.25, 0.12, 0.45, 0.22}, {0.66, 0.40, 0.09, 0.60, 0.18},
		{0.58, 0.35, 0.11, 0.55, 0.25}, {0.74, 0.28, 0.13, 0.40, 0.21}, {0.64, 0.33, 0.08, 0.52, 0.19},
		{0.99, 0.90, 0.10, 0.90, 0.10},
	} {
		row := claimRow("add-1x", "immediate", r, f(v[0]), f(v[1]), f(v[2]), f(v[3]), f(v[4]))
		if r == 6 {
			row.RelayBrokenCircuits = 1
		}
		rows = append(rows, row)
	}
	mismatch := claimRow("add-1x", "immediate", 7, nil, nil, nil, nil, nil)
	mismatch.LabelMismatch = true
	missing := claimRow("add-1x", "immediate", 8, nil, nil, nil, nil, nil)
	missing.Degenerate = "missing_class"
	rows = append(rows, mismatch, missing)
	for r, v := range [][5]float64{
		{0.50, 0.12, 0.11, 0.21, 0.20}, {0.52, 0.11, 0.12, 0.20, 0.22}, {0.48, 0.10, 0.10, 0.19, 0.18},
		{0.51, 0.13, 0.10, 0.27, 0.25}, {0.49, 0.09, 0.10, 0.20, 0.21}, {0.47, 0.12, 0.11, 0.18, 0.19},
		{0.53, 0.11, 0.10, 0.22, 0.20}, {0.46, 0.10, 0.12, 0.17, 0.19}, {0.50, 0.12, 0.10, 0.21, 0.20},
	} {
		rows = append(rows, claimRow("fixed-2x", "constant-rate", r, f(v[0]), f(v[1]), f(v[2]), f(v[3]), f(v[4])))
	}
	sum := summariseCover(rows, 0.2, 1)
	if len(sum.Levels) != 2 || len(sum.Tests) != 7 {
		t.Fatalf("%d levels and %d tests: %s", len(sum.Levels), len(sum.Tests), encode(t, sum))
	}
	iv := func(name string, got interval, median, low, high float64) {
		t.Helper()
		if !is(got.Median, median) || !is(got.Low, low) || !is(got.High, high) {
			t.Errorf("%s: %s, want %v [%v, %v]", name, encode(t, got), median, low, high)
		}
	}
	// add-1x: six clean runs with every value (n = 6: x_(1) and x_(6),
	// P(K = 0) = 1/64), the missing class clean but undefined
	add := sum.Levels[0]
	if add.Runs != 9 || add.BrokenRuns != 1 || add.LabelMismatchRuns != 1 || add.CleanRuns != 7 || add.DegenerateRuns != 1 ||
		add.AUCRuns != 6 || add.KSRuns != 6 ||
		add.EquivalenceClaim || add.CorridorLow != nil || add.CorridorHigh != nil || add.Corridor != nil ||
		!is(add.AUCMin, 0.58) || !is(add.AUCMax, 0.74) {
		t.Errorf("add-1x counts: %s", encode(t, add))
	}
	iv("add-1x lda_auc", add.AUC, 0.65, 0.58, 0.74)
	iv("add-1x ks", add.KS, 0.315, 0.25, 0.40)
	iv("add-1x ks_null", add.KSNull, 0.105, 0.08, 0.13)
	iv("add-1x tv", add.TV, 0.51, 0.40, 0.60)
	iv("add-1x tv_null", add.TVNull, 0.205, 0.18, 0.25)
	// fixed-2x: nine clean runs, x_(2) and x_(8); 0.8^9 is above 0.025, so
	// no corridor bound
	fixed := sum.Levels[1]
	if fixed.Runs != 9 || fixed.CleanRuns != 9 || fixed.DegenerateRuns != 0 || !fixed.EquivalenceClaim ||
		fixed.AUCRuns != 9 || fixed.KSRuns != 9 ||
		fixed.CorridorLow != nil || fixed.CorridorHigh != nil || fixed.Corridor != nil ||
		!is(fixed.AUCMin, 0.46) || !is(fixed.AUCMax, 0.53) {
		t.Errorf("fixed-2x counts: %s", encode(t, fixed))
	}
	iv("fixed-2x lda_auc", fixed.AUC, 0.50, 0.47, 0.52)
	iv("fixed-2x ks", fixed.KS, 0.11, 0.10, 0.12)
	iv("fixed-2x ks_null", fixed.KSNull, 0.10, 0.10, 0.12)
	iv("fixed-2x tv", fixed.TV, 0.20, 0.18, 0.22)
	iv("fixed-2x tv_null", fixed.TVNull, 0.20, 0.19, 0.22)
	for _, l := range sum.Levels {
		if l.CellTPR != nil || l.CellNegatives != nil || l.CellBaseRate != nil || l.CellPrecision != nil {
			t.Errorf("%s: cell precision without scores: %s", l.Traffic, encode(t, l))
		}
	}

	// add-1x: six differences, all positive, W 21 of 21, p 2/64; fixed-2x ks:
	// the zero difference of r2 is dropped, n' 8, W 23.5; tv n' 9, W 24.
	// Holm of 1/32, 1/32, 0.5390625, 0.984375 gives 0.125, 0.125, 1, 1; the
	// modes pair r0..r5 (r6 broken, r7 mismatched, r8 undefined at add-1x),
	// add-1x above in all six, Holm of three times 1/32
	for i, c := range []struct {
		family, name       string
		pairs, dropped     int
		w, p, effect, holm float64
	}{
		{"null", "add-1x ks_distance against ks_null", 6, 1, 21, 0.03125, 1, 0.125},
		{"null", "add-1x tv against tv_null", 6, 1, 21, 0.03125, 1, 0.125},
		{"null", "fixed-2x ks_distance against ks_null", 9, 0, 23.5, 0.5390625, 0.3055556, 1},
		{"null", "fixed-2x tv against tv_null", 9, 0, 24, 0.984375, 0.0666667, 1},
		{"modes", "lda_auc", 6, 3, 21, 0.03125, 1, 0.09375},
		{"modes", "ks_excess", 6, 3, 21, 0.03125, 1, 0.09375},
		{"modes", "tv_excess", 6, 3, 21, 0.03125, 1, 0.09375},
	} {
		got := sum.Tests[i]
		if got.Family != c.family || got.Name != c.name || got.Pairs != c.pairs || got.DroppedPairs != c.dropped ||
			!is(got.Statistic, c.w) || !is(got.P, c.p) || got.Effect == nil || math.Abs(*got.Effect-c.effect) > 5e-8 ||
			!is(got.Holm, c.holm) || got.Method != "exact" {
			t.Errorf("test %d: %s, want %+v", i, encode(t, got), c)
		}
	}
}

// level a: two clean runs, one without a class, so every median rests on one
// run; b: a degenerate run keeps D and TV, so only lda_auc rests on one; c:
// two runs behind every median
func TestCoverSummaryMarksMediansOfOneRun(t *testing.T) {
	missing := claimRow("a", "immediate", 1, nil, nil, nil, nil, nil)
	missing.Degenerate = "missing_class"
	equal := claimRow("b", "immediate", 1, nil, f(0.2), f(0.1), f(0.3), f(0.2))
	equal.Degenerate = "training_equal_means"
	sum := summariseCover([]coverRow{
		claimRow("a", "immediate", 0, f(0.6), f(0.3), f(0.1), f(0.5), f(0.2)), missing,
		claimRow("b", "immediate", 0, f(0.6), f(0.3), f(0.1), f(0.5), f(0.2)), equal,
		claimRow("c", "immediate", 0, f(0.6), f(0.3), f(0.1), f(0.5), f(0.2)),
		claimRow("c", "immediate", 1, f(0.7), f(0.2), f(0.1), f(0.3), f(0.2)),
	}, 0.2, 1)
	for i, want := range [][2]int{{1, 1}, {1, 2}, {2, 2}} {
		if l := sum.Levels[i]; l.CleanRuns != 2 || l.AUCRuns != want[0] || l.KSRuns != want[1] {
			t.Errorf("%s: clean %d, lda_auc_runs %d, ks_runs %d; want 2, %d, %d", l.Traffic, l.CleanRuns, l.AUCRuns, l.KSRuns, want[0], want[1])
		}
	}
	var out bytes.Buffer
	printCoverSummary(&out, sum)
	lines := map[string]string{}
	for _, l := range strings.Split(out.String(), "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[0] == "level" {
			lines[f[1]] = l
		}
	}
	for traffic, want := range map[string][2]bool{"a": {true, true}, "b": {true, false}, "c": {false, false}} {
		l := lines[traffic]
		if strings.Contains(l, "lda auc of one run") != want[0] || strings.Contains(l, "ks and tv of one run") != want[1] {
			t.Errorf("level %s printed %q, want the lda mark %v and the ks mark %v", traffic, l, want[0], want[1])
		}
	}
}

func TestOptKeepsNaNOutOfTheReport(t *testing.T) {
	if opt(math.NaN()) != nil || opt(math.Inf(1)) != nil || opt(math.Inf(-1)) != nil || *opt(0.5) != 0.5 || *opt(0) != 0 {
		t.Fatal("opt")
	}
	// a clean claim row of each level without a single defined value
	sum := summariseCover([]coverRow{
		{Role: "claim", Traffic: "add-1x", Mode: "immediate"},
		{Role: "claim", Traffic: "fixed-2x", Mode: "constant-rate"},
	}, 0.2, 1)
	raw, err := json.Marshal(sum)
	if err != nil {
		t.Fatalf("the summary does not encode: %v", err)
	}
	var back struct {
		Levels []map[string]any `json:"levels"`
		Tests  []map[string]any `json:"tests"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	for _, l := range back.Levels {
		for _, k := range []string{"lda_auc_min", "lda_auc_max", "auc_corridor_low", "auc_corridor_high", "auc_corridor",
			"cell_tpr_at_fpr_0.01", "cell_negatives", "cell_base_rate", "cell_precision", "bandwidth_multiplier_median"} {
			if v, present := l[k]; !present || v != nil {
				t.Errorf("%s: %s is %v, want null", l["traffic"], k, v)
			}
		}
		for _, k := range []string{"lda_auc", "ks_distance", "ks_null", "tv", "tv_null", "feature_auc_median"} {
			for name, v := range l[k].(map[string]any) {
				if v != nil {
					t.Errorf("%s: %s.%s is %v, want null", l["traffic"], k, name, v)
				}
			}
		}
	}
	for _, c := range back.Tests {
		for _, k := range []string{"statistic", "p", "effect", "holm_p"} {
			if v, present := c[k]; !present || v != nil {
				t.Errorf("%s: %s is %v, want null", c["name"], k, v)
			}
		}
	}
	if len(back.Tests) != 7 {
		t.Errorf("%d tests, want 7", len(back.Tests))
	}
	if _, err := json.Marshal(coverRow{}); err != nil {
		t.Fatalf("a row without values does not encode: %v", err)
	}
}

// the keys of feature_auc are the feature names in their order
func TestFeatureAUCFollowsTheFeatureNames(t *testing.T) {
	var a featureAUC
	for j, p := range a.fields() {
		*p = f(float64(j))
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for j, name := range metrics.FeatureNames {
		want = append(want, fmt.Sprintf("%q:%d", name, j))
	}
	if got := string(raw); got != "{"+strings.Join(want, ",")+"}" {
		t.Errorf("feature_auc %s, want the order of %v", got, metrics.FeatureNames)
	}
}
