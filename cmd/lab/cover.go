package main

import (
	"fmt"
	"io"
	"math"
	"math/rand"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

// a reply on loopback comes some tens of µs after its cell, and a coarser
// clock marks it at the reading of the cell
const coverClockLimit = 10 * time.Microsecond

type coverFlags struct {
	flows, hops    int
	duration, send time.Duration
	train, repeats int
	corridor       float64
	claims         int
	seed           int64
	suite          jcrypto.Suite
	rev, out       string
	// the clock the step check reads; nil is the time since cover started
	now func() time.Duration
}

// at a mean gap of 200 ms both send about ten cells a second per flow, half
// of them payload: one bandwidth price and close group sizes
func coverVariants() []variant {
	return []variant{
		{"add-1x", lab.Config{CoverEvery: 200 * time.Millisecond, LabelCells: true}},
		{"fixed-2x", lab.Config{Mode: client.ConstantRate, Rate: 100 * time.Millisecond, LabelCells: true}},
	}
}

func clockStep(now func() time.Duration, n int) time.Duration {
	step := time.Duration(math.MaxInt64)
	last := now()
	for range n {
		next := now()
		for next == last {
			next = now()
		}
		step = min(step, next-last)
		last = next
	}
	return step
}

type featureAUC struct {
	GPrev *float64 `json:"g_prev"`
	GNext *float64 `json:"g_next"`
	Dev   *float64 `json:"dev"`
	RNext *float64 `json:"r_next"`
	RIdx  *float64 `json:"r_idx"`
}

// in metrics.FeatureNames order
func (f *featureAUC) fields() []**float64 {
	return []**float64{&f.GPrev, &f.GNext, &f.Dev, &f.RNext, &f.RIdx}
}

type coverRow struct {
	Role        string `json:"role"`
	Traffic     string `json:"traffic"`
	Repeat      int    `json:"repeat"`
	BaseSeed    int64  `json:"base_seed"`
	Seed        int64  `json:"seed"`
	Suite       string `json:"suite"`
	Mode        string `json:"mode"`
	Rate        string `json:"rate"`
	CoverEvery  string `json:"cover_every"`
	RelayPeriod string `json:"relay_period"`
	Jitter      string `json:"jitter"`
	Send        string `json:"send_mean_gap"`
	Payload     int    `json:"payload_bytes"`
	Duration    string `json:"duration"`
	Flows       int    `json:"flows"`
	Hops        int    `json:"hops"`
	Rev         string `json:"rev"`
	GOOS        string `json:"goos"`
	NumCPU      int    `json:"num_cpu"`
	GOMAXPROCS  int    `json:"gomaxprocs"`
	LoadBefore  string `json:"loadavg_before,omitempty"`
	LoadAfter   string `json:"loadavg_after,omitempty"`
	ClockStep   string `json:"clock_step"`

	Messages      int      `json:"messages"`
	Dropped       uint64   `json:"dropped"`
	Cells         int      `json:"cells"`
	Multiplier    *float64 `json:"bandwidth_multiplier"`
	PayloadLabels int      `json:"payload_labels"`
	LabelMismatch bool     `json:"label_mismatch"`

	PayloadCells   *int `json:"payload_cells"`
	CoverCells     *int `json:"cover_cells"`
	UndefinedCells *int `json:"undefined_cells"`

	AUC        *float64   `json:"lda_auc"`
	AUCLow     *float64   `json:"lda_auc_ci_low"`
	AUCHigh    *float64   `json:"lda_auc_ci_high"`
	CIMethod   string     `json:"lda_auc_ci_method"`
	FeatureAUC featureAUC `json:"feature_auc"`
	Unused     []string   `json:"unused_features"`
	Degenerate string     `json:"degenerate"`

	KS         *float64 `json:"ks_distance"`
	KSNull     *float64 `json:"ks_null"`
	KSPermuted *float64 `json:"ks_permuted"`
	TV         *float64 `json:"tv"`
	TVNull     *float64 `json:"tv_null"`
	TVPermuted *float64 `json:"tv_permuted"`

	RelayDroppedCells   uint64   `json:"relay_dropped_cells"`
	RelayBrokenCircuits uint64   `json:"relay_broken_circuits"`
	BrokenFlows         int      `json:"broken_flows"`
	FlowClosed          []bool   `json:"flow_closed"`
	FlowClosedAfter     []string `json:"flow_closed_after"`
	RelayTimedOut       uint64   `json:"relay_timed_out"`
	RelayExpired        uint64   `json:"relay_expired"`
	RelayRefused        uint64   `json:"relay_refused"`

	scores []metrics.Score
	// of the direction trained on every usable training run of the level
	noDirection string
	levelUnused []string
}

func (r coverRow) broken() bool {
	return r.RelayBrokenCircuits > 0 || r.BrokenFlows > 0 || slices.Contains(r.FlowClosed, true)
}

func (r coverRow) limited() bool {
	return r.RelayTimedOut > 0 || r.RelayExpired > 0 || r.RelayRefused > 0
}

func (r coverRow) clean() bool { return !r.broken() && !r.limited() && !r.LabelMismatch }

func cover(cfg coverFlags, stdout, stderr io.Writer) int {
	switch {
	case cfg.train < 1:
		fmt.Fprintf(stderr, "-train %d: the cover set needs at least 1 training run per level\n", cfg.train)
		return 2
	case !(cfg.corridor > 0 && cfg.corridor < 0.5):
		fmt.Fprintf(stderr, "-corridor %v must lie in (0, 0.5)\n", cfg.corridor)
		return 2
	case cfg.claims < 1:
		fmt.Fprintf(stderr, "-claims %d: at least 1 equivalence claim\n", cfg.claims)
		return 2
	}
	now := cfg.now
	if now == nil {
		start := time.Now()
		now = func() time.Duration { return time.Since(start) }
	}
	step := clockStep(now, 20)
	if step > coverClockLimit {
		fmt.Fprintf(stderr, "cover: the monotonic clock moves in steps of %v, above %v: a reply would carry the reading of its cell\n", step, coverClockLimit)
		return 2
	}
	fmt.Fprintf(stdout, "clock step %v\n", step)

	stamp := time.Now().UTC().Format("20060102-150405")
	fmt.Fprintf(stdout, "%-8s %-9s %3s %5s %5s %5s %26s %6s %6s %6s %6s\n",
		"role", "traffic", "rep", "pay", "cov", "und", "lda auc [95% ci]", "ks", "ks0", "tv", "tv0")
	var rows []coverRow
	for _, v := range coverVariants() {
		level, status := coverLevelRows(cfg, v, step, stdout, stderr)
		if status != 0 {
			return status
		}
		rows = append(rows, level...)
	}

	if err := write(stdout, cfg.out, "cells-cover-"+stamp, rows); err != nil {
		fmt.Fprintf(stderr, "report: %v\n", err)
		return 1
	}
	sum := summariseCover(rows, cfg.corridor, cfg.claims)
	printCoverSummary(stdout, sum)
	if err := write(stdout, cfg.out, "summary-cover-"+stamp, sum); err != nil {
		fmt.Fprintf(stderr, "summary: %v\n", err)
		return 1
	}
	return 0
}

type labelledRun struct {
	row    coverRow
	cells  metrics.Cells
	usable bool
}

func coverLevelRows(cfg coverFlags, v variant, step time.Duration, stdout, stderr io.Writer) ([]coverRow, int) {
	var training []labelledRun
	for t := 0; t < cfg.train; t++ {
		r, status := coverRun(cfg, v, "training", t, lab.Derive(cfg.seed, lab.StreamTraining, uint64(t)), step, stderr)
		if status != 0 {
			return nil, status
		}
		training = append(training, r)
	}
	var usable []metrics.Cells
	for _, r := range training {
		if r.usable {
			usable = append(usable, r.cells)
		}
	}
	claim := trainDirection(usable)

	var rows []coverRow
	for _, r := range leaveOneOut(training) {
		rows = append(rows, r)
		printCoverRow(stdout, r)
	}
	for rep := 0; rep < cfg.repeats; rep++ {
		r, status := coverRun(cfg, v, "claim", rep, lab.Derive(cfg.seed, uint64(rep)), step, stderr)
		if status != 0 {
			return nil, status
		}
		if !r.row.LabelMismatch {
			score(&r.row, claim, r.cells)
		}
		rows = append(rows, r.row)
		printCoverRow(stdout, r.row)
	}
	for i := range rows {
		rows[i].noDirection, rows[i].levelUnused = claim.reason, featureNames(claim.unused)
	}
	return rows, 0
}

// the AUC the pilot sizes the series by: each usable training run scored with
// a direction from the other usable ones
func leaveOneOut(training []labelledRun) []coverRow {
	rows := make([]coverRow, len(training))
	for i, r := range training {
		rows[i] = r.row
		if !r.usable {
			continue
		}
		var others []metrics.Cells
		for j, o := range training {
			if j != i && o.usable {
				others = append(others, o.cells)
			}
		}
		score(&rows[i], trainDirection(others), r.cells)
	}
	return rows
}

func coverRun(cfg coverFlags, v variant, role string, repeat int, seed int64, step time.Duration, stderr io.Writer) (labelledRun, int) {
	c := v.cfg
	c.Hops, c.Flows, c.Duration, c.SendEvery, c.Suite, c.Seed = cfg.hops, cfg.flows, cfg.duration, cfg.send, cfg.suite, seed
	before := loadavg()
	run, err := lab.Execute(c)
	if err != nil {
		fmt.Fprintf(stderr, "run failed: %v\n", err)
		return labelledRun{}, 1
	}
	if run.Sent == 0 {
		fmt.Fprintf(stderr, "%s: no message was sent, nothing to score\n", v.label)
		return labelledRun{}, 1
	}
	row := coverBase(run, v.label)
	row.Role, row.Repeat, row.BaseSeed, row.Rev, row.ClockStep = role, repeat, cfg.seed, cfg.rev, step.String()
	row.GOOS, row.NumCPU, row.GOMAXPROCS = runtime.GOOS, runtime.NumCPU(), runtime.GOMAXPROCS(0)
	row.LoadBefore, row.LoadAfter = before, loadavg()
	if row.broken() {
		closed := 0
		for _, f := range row.FlowClosed {
			if f {
				closed++
			}
		}
		fmt.Fprintf(stderr, "%s: relays closed %d circuits, clients %d, and %d flows saw their circuit close during the run\n",
			v.label, run.RelayBroken, run.BrokenFlows, closed)
	}
	cells, payload, ok := labelledCells(run)
	row.PayloadLabels, row.LabelMismatch = payload, !ok
	if !ok {
		fmt.Fprintf(stderr, "%s %s %d: the labels disagree with the frames or with messages less dropped, the run is left out\n", v.label, role, repeat)
		return labelledRun{row: row}, 0
	}
	p := countTrue(cells.Truth)
	cv, und := len(cells.Truth)-p, cells.Undefined
	row.PayloadCells, row.CoverCells, row.UndefinedCells = &p, &cv, &und
	return labelledRun{row: row, cells: cells, usable: !row.broken() && !row.limited()}, 0
}

func coverBase(run *lab.Run, traffic string) coverRow {
	cfg := run.Config
	cells := metrics.CellsWithin(sinceOrigin(run.Entry, run.Origin), cfg.Duration)
	row := coverRow{
		Traffic:     traffic,
		Seed:        cfg.Seed,
		Suite:       cfg.Suite.String(),
		Mode:        modeName(cfg.Mode),
		Rate:        cfg.Rate.String(),
		CoverEvery:  cfg.CoverEvery.String(),
		RelayPeriod: cfg.RelayPeriod.String(),
		Jitter:      cfg.Jitter.String(),
		Send:        cfg.SendEvery.String(),
		Payload:     cfg.Payload,
		Duration:    cfg.Duration.String(),
		Flows:       cfg.Flows,
		Hops:        cfg.Hops,

		Messages:   run.Sent,
		Dropped:    run.Dropped,
		Cells:      cells,
		Multiplier: opt(metrics.Multiplier(cells, run.Sent)),

		RelayDroppedCells:   run.RelayDropped,
		RelayBrokenCircuits: run.RelayBroken,
		BrokenFlows:         run.BrokenFlows,
		FlowClosed:          make([]bool, len(run.Closures)),
		FlowClosedAfter:     make([]string, len(run.Closures)),
		RelayTimedOut:       run.RelayTimedOut,
		RelayExpired:        run.RelayExpired,
		RelayRefused:        run.RelayRefused,
	}
	for i, c := range run.Closures {
		if c.Closed {
			row.FlowClosed[i] = true
			row.FlowClosedAfter[i] = max(c.At-run.Origin, 0).Round(time.Millisecond).String()
		}
	}
	return row
}

// the cells of a run with their labels, the payload labels over the full
// lists, and whether the labels agree with the frames of every flow and with
// the messages handed over less those the schedule dropped
func labelledCells(run *lab.Run) (metrics.Cells, int, bool) {
	ok := len(run.Labels) == len(run.Entry)
	labels := make([][]bool, len(run.Labels))
	payload := 0
	for f, l := range run.Labels {
		if l == nil {
			ok = false
			continue
		}
		cells, consistent := l.Cells()
		ok = ok && consistent
		labels[f] = cells
		payload += countTrue(cells)
	}
	if !ok {
		return metrics.Cells{}, payload, false
	}
	cells, aligned := metrics.CellFeatures(events(run.Entry), events(run.EntryBack), labels,
		run.Origin, run.Origin+run.Config.Duration, run.Config.RelayPeriod == 0)
	if !aligned || payload != run.Sent-int(run.Dropped) {
		return metrics.Cells{}, payload, false
	}
	return cells, payload, true
}

func events(traces []*lab.Trace) [][]time.Duration {
	out := make([][]time.Duration, len(traces))
	for i, t := range traces {
		out[i] = t.Events()
	}
	return out
}

func countTrue(v []bool) int {
	n := 0
	for _, b := range v {
		if b {
			n++
		}
	}
	return n
}

type direction struct {
	rows   [][]float64
	truth  []bool
	runs   int
	unused []int
	reason string
}

func trainDirection(runs []metrics.Cells) direction {
	d := direction{runs: len(runs)}
	for _, c := range runs {
		d.rows = append(d.rows, c.Rows...)
		d.truth = append(d.truth, c.Truth...)
	}
	d.unused = metrics.UnusedColumns(d.rows)
	switch payload := countTrue(d.truth); {
	case payload == 0 || payload == len(d.truth):
		d.reason = "missing_class"
	case d.unused == nil || len(d.unused) == len(d.rows[0]):
		d.reason = "no_feature"
	case metrics.DiscriminantScores(d.rows, d.truth, d.rows[:1]) == nil:
		d.reason = "equal_means"
	}
	return d
}

type cellScores struct {
	auc, low, high float64
	method         string
	// in metrics.FeatureNames order, NaN where undefined
	features               []float64
	degenerate             string
	ks, ksNull, ksPermuted float64
	tv, tvNull, tvPermuted float64
	scores                 []metrics.Score
}

// D and TV are taken on g_prev, which needs no direction, so a level without
// one still has them
func scoreRun(d direction, test metrics.Cells, flows int, shifted, permuted []bool) cellScores {
	nan := math.NaN()
	out := cellScores{auc: nan, low: nan, high: nan}
	out.ks, out.tv = gapDistance(test, test.Truth)
	out.ksNull, out.tvNull = gapDistance(test, shifted)
	out.ksPermuted, out.tvPermuted = gapDistance(test, permuted)
	out.features = make([]float64, len(metrics.FeatureNames))
	for j := range out.features {
		out.features[j] = nan
		if len(test.Rows) == 0 || len(d.rows) == 0 || j >= len(test.Rows[0]) || j >= len(d.rows[0]) {
			continue
		}
		if v := metrics.DiscriminantScores(column(d.rows, j), d.truth, column(test.Rows, j)); v != nil {
			out.features[j] = metrics.AUC(metrics.RequestScores(test.Flow, flows, v, test.Truth))
		}
	}
	switch payload := countTrue(test.Truth); {
	case d.reason != "":
		out.degenerate = "training_" + d.reason
		return out
	case payload == 0 || payload == len(test.Truth):
		out.degenerate = "missing_class"
		return out
	}
	v := metrics.DiscriminantScores(d.rows, d.truth, test.Rows)
	if v == nil {
		out.degenerate = "training_equal_means"
		return out
	}
	s := metrics.RequestScores(test.Flow, flows, v, test.Truth)
	ci := metrics.BootstrapAUC(s, flows, 10000, 7)
	out.auc, out.low, out.high, out.method = ci.Point, ci.Low, ci.High, ci.Method+"-10000"
	out.scores = s
	return out
}

func column(rows [][]float64, j int) [][]float64 {
	out := make([][]float64, len(rows))
	for i, r := range rows {
		out[i] = []float64{r[j]}
	}
	return out
}

func gapDistance(c metrics.Cells, truth []bool) (ks, tv float64) {
	if len(truth) != len(c.Rows) {
		return math.NaN(), math.NaN()
	}
	var a, b []float64
	for i, r := range c.Rows {
		if truth[i] {
			a = append(a, r[metrics.GPrev])
		} else {
			b = append(b, r[metrics.GPrev])
		}
	}
	return metrics.KSDistance(a, b), metrics.TotalVariation(a, b, 16)
}

func score(row *coverRow, d direction, c metrics.Cells) {
	shifted, permuted := nullLabels(c, row.Seed)
	s := scoreRun(d, c, row.Flows, shifted, permuted)
	row.AUC, row.AUCLow, row.AUCHigh, row.CIMethod = opt(s.auc), opt(s.low), opt(s.high), s.method
	for j, f := range row.FeatureAUC.fields() {
		*f = opt(s.features[j])
	}
	row.Unused, row.Degenerate = featureNames(d.unused), s.degenerate
	row.KS, row.KSNull, row.KSPermuted = opt(s.ks), opt(s.ksNull), opt(s.ksPermuted)
	row.TV, row.TVNull, row.TVPermuted = opt(s.tv), opt(s.tvNull), opt(s.tvPermuted)
	row.scores = s.scores
}

func featureNames(columns []int) []string {
	if columns == nil {
		return nil
	}
	out := []string{}
	for _, j := range columns {
		out = append(out, metrics.FeatureNames[j])
	}
	return out
}

// one draw per run: the shift of every flow and a permutation of all cells,
// each from a stream of the run's seed
func nullLabels(c metrics.Cells, seed int64) (shifted, permuted []bool) {
	var sizes []int
	for _, f := range c.Flow {
		for len(sizes) <= f {
			sizes = append(sizes, 0)
		}
		sizes[f]++
	}
	shifted = metrics.CircularShift(c.Truth, c.Flow, shiftOffsets(seed, sizes))
	permuted = slices.Clone(c.Truth)
	rng := rand.New(rand.NewSource(lab.Derive(seed, lab.StreamPermute)))
	rng.Shuffle(len(permuted), func(i, j int) { permuted[i], permuted[j] = permuted[j], permuted[i] })
	return shifted, permuted
}

// a stream per flow, so an offset does not depend on the sizes of the flows
// before it; uniform on 1..n-1, and a flow of fewer than two cells stays
func shiftOffsets(seed int64, sizes []int) []int {
	out := make([]int, len(sizes))
	for f, n := range sizes {
		if n < 2 {
			continue
		}
		out[f] = 1 + rand.New(rand.NewSource(lab.Derive(seed, lab.StreamShift, uint64(f)))).Intn(n-1)
	}
	return out
}

type interval struct {
	Median *float64 `json:"median"`
	Low    *float64 `json:"low"`
	High   *float64 `json:"high"`
}

func optInterval(iv metrics.Interval) interval {
	return interval{Median: opt(iv.Point), Low: opt(iv.Low), High: opt(iv.High)}
}

type coverTest struct {
	Family       string   `json:"family"`
	Name         string   `json:"name"`
	Pairs        int      `json:"pairs"`
	DroppedPairs int      `json:"dropped_pairs"`
	Statistic    *float64 `json:"statistic"`
	P            *float64 `json:"p"`
	Effect       *float64 `json:"effect"`
	Magnitude    string   `json:"magnitude"`
	Method       string   `json:"method"`
	Holm         *float64 `json:"holm_p"`
}

func optTest(t metrics.Test, holm float64) coverTest {
	return coverTest{
		Statistic: opt(t.Statistic), P: opt(t.P), Effect: opt(t.Effect),
		Magnitude: metrics.EffectMagnitude(t.Effect), Method: t.Method, Holm: opt(holm),
	}
}

// over the claim runs of the level unless the name says otherwise; a run that
// is broken, limited or whose labels disagree is counted and left out of every
// value
type coverLevel struct {
	Traffic          string   `json:"traffic"`
	Mode             string   `json:"mode"`
	Rate             string   `json:"rate"`
	CoverEvery       string   `json:"cover_every"`
	EquivalenceClaim bool     `json:"equivalence_claim"`
	TrainingRuns     int      `json:"training_runs"`
	TrainingRunsUsed int      `json:"training_runs_used"`
	NoDirection      string   `json:"no_direction"`
	Unused           []string `json:"unused_features"`

	Runs              int `json:"runs"`
	BrokenRuns        int `json:"broken_runs"`
	LimitedRuns       int `json:"limited_runs"`
	LabelMismatchRuns int `json:"label_mismatch_runs"`
	CleanRuns         int `json:"clean_runs"`
	DegenerateRuns    int `json:"degenerate_runs"`

	// the clean runs each median rests on: a degenerate run has no AUC, and a
	// run without one class has no D or TV
	AUCRuns      int        `json:"lda_auc_runs"`
	KSRuns       int        `json:"ks_runs"`
	AUC          interval   `json:"lda_auc"`
	AUCMin       *float64   `json:"lda_auc_min"`
	AUCMax       *float64   `json:"lda_auc_max"`
	CorridorLow  *float64   `json:"auc_corridor_low"`
	CorridorHigh *float64   `json:"auc_corridor_high"`
	Corridor     *string    `json:"auc_corridor"`
	FeatureAUC   featureAUC `json:"feature_auc_median"`
	KS           interval   `json:"ks_distance"`
	KSNull       interval   `json:"ks_null"`
	TV           interval   `json:"tv"`
	TVNull       interval   `json:"tv_null"`
	PayloadCells int        `json:"payload_cells"`
	CoverCells   int        `json:"cover_cells"`

	CellTPR       *float64 `json:"cell_tpr_at_fpr_0.01"`
	CellNegatives *int     `json:"cell_negatives"`
	CellBaseRate  *float64 `json:"cell_base_rate"`
	CellPrecision *float64 `json:"cell_precision"`
	Multiplier    *float64 `json:"bandwidth_multiplier_median"`
}

type coverSummary struct {
	Set       string       `json:"set"`
	Suite     string       `json:"suite"`
	Hops      int          `json:"hops"`
	Flows     int          `json:"flows"`
	ClockStep string       `json:"clock_step"`
	CorridorS float64      `json:"corridor_s"`
	Claims    int          `json:"claims"`
	Levels    []coverLevel `json:"levels"`
	Tests     []coverTest  `json:"tests"`
}

// the bounds of the s- and (1 - s)-quantiles of the per-run AUC at the level
// of one claim among m, and whether both lie in the corridor
func corridor(auc []float64, s float64, claims int) (low, high float64, verdict string) {
	level := 1 - 0.05/float64(claims)
	low = metrics.QuantileInterval(auc, s, level).Low
	high = metrics.QuantileInterval(auc, 1-s, level).High
	return low, high, metrics.Equivalence(metrics.Interval{Low: low, High: high}, 0.5, 0.05)
}

func defined(p *float64) bool { return p != nil }

// only the constant-rate level claims equivalence: the block asks whether a
// constant rate hides the moment of sending, so an invocation makes one claim
func summariseCover(rows []coverRow, s float64, claims int) coverSummary {
	sum := coverSummary{Set: "cover", CorridorS: s, Claims: claims, Levels: []coverLevel{}, Tests: []coverTest{}}
	if len(rows) > 0 {
		sum.Suite, sum.Hops, sum.Flows, sum.ClockStep = rows[0].Suite, rows[0].Hops, rows[0].Flows, rows[0].ClockStep
	}
	var order []string
	groups := map[string][]coverRow{}
	for _, r := range rows {
		if _, seen := groups[r.Traffic]; !seen {
			order = append(order, r.Traffic)
		}
		groups[r.Traffic] = append(groups[r.Traffic], r)
	}
	claimRows := make([][]coverRow, len(order))
	var nullFamily []coverTest
	var nullTests []metrics.Test
	for i, traffic := range order {
		g := groups[traffic]
		l := coverLevel{
			Traffic: traffic, Mode: g[0].Mode, Rate: g[0].Rate, CoverEvery: g[0].CoverEvery,
			EquivalenceClaim: g[0].Mode == modeName(client.ConstantRate),
			NoDirection:      g[0].noDirection, Unused: g[0].levelUnused,
		}
		var auc, ks, ksNull, tv, tvNull, mult []float64
		features := make([][]float64, len(metrics.FeatureNames))
		var pooled []metrics.Score
		var ksPairs, tvPairs [2][]float64
		for _, r := range g {
			if r.Role == "training" {
				l.TrainingRuns++
				if r.clean() {
					l.TrainingRunsUsed++
				}
				continue
			}
			claimRows[i] = append(claimRows[i], r)
			l.Runs++
			if r.broken() {
				l.BrokenRuns++
			}
			if r.limited() {
				l.LimitedRuns++
			}
			if r.LabelMismatch {
				l.LabelMismatchRuns++
			}
			if !r.clean() {
				continue
			}
			l.CleanRuns++
			if r.Degenerate != "" {
				l.DegenerateRuns++
			}
			for _, v := range []struct {
				p   *float64
				out *[]float64
			}{{r.AUC, &auc}, {r.KS, &ks}, {r.KSNull, &ksNull}, {r.TV, &tv}, {r.TVNull, &tvNull}, {r.Multiplier, &mult}} {
				if defined(v.p) {
					*v.out = append(*v.out, *v.p)
				}
			}
			for j, f := range r.FeatureAUC.fields() {
				if defined(*f) {
					features[j] = append(features[j], **f)
				}
			}
			if defined(r.KS) && defined(r.KSNull) {
				ksPairs[0], ksPairs[1] = append(ksPairs[0], *r.KS), append(ksPairs[1], *r.KSNull)
			}
			if defined(r.TV) && defined(r.TVNull) {
				tvPairs[0], tvPairs[1] = append(tvPairs[0], *r.TV), append(tvPairs[1], *r.TVNull)
			}
			if r.PayloadCells != nil {
				l.PayloadCells += *r.PayloadCells
			}
			if r.CoverCells != nil {
				l.CoverCells += *r.CoverCells
			}
			if defined(r.AUC) {
				pooled = append(pooled, r.scores...)
			}
		}
		l.AUCRuns, l.KSRuns = len(auc), len(ks)
		l.AUC = optInterval(metrics.QuantileInterval(auc, 0.5, 0.95))
		if len(auc) > 0 {
			l.AUCMin, l.AUCMax = opt(slices.Min(auc)), opt(slices.Max(auc))
		}
		if l.EquivalenceClaim {
			low, high, verdict := corridor(auc, s, claims)
			l.CorridorLow, l.CorridorHigh = opt(low), opt(high)
			if verdict != "" {
				l.Corridor = &verdict
			}
		}
		for j, f := range l.FeatureAUC.fields() {
			*f = opt(metrics.Median(features[j]))
		}
		l.KS = optInterval(metrics.QuantileInterval(ks, 0.5, 0.95))
		l.KSNull = optInterval(metrics.QuantileInterval(ksNull, 0.5, 0.95))
		l.TV = optInterval(metrics.QuantileInterval(tv, 0.5, 0.95))
		l.TVNull = optInterval(metrics.QuantileInterval(tvNull, 0.5, 0.95))
		l.Multiplier = opt(metrics.Median(mult))
		if len(pooled) > 0 {
			tpr := metrics.TPRAtFPR(pooled, 0.01)
			trues := 0
			for _, sc := range pooled {
				if sc.True {
					trues++
				}
			}
			negatives := len(pooled) - trues
			base := float64(trues) / float64(len(pooled))
			l.CellTPR, l.CellNegatives, l.CellBaseRate = opt(tpr), &negatives, opt(base)
			l.CellPrecision = opt(metrics.PrecisionAtBaseRate(tpr, 0.01, base))
		}
		sum.Levels = append(sum.Levels, l)

		for _, c := range []struct {
			name  string
			pairs [2][]float64
		}{{traffic + " ks_distance against ks_null", ksPairs}, {traffic + " tv against tv_null", tvPairs}} {
			test := metrics.Wilcoxon(c.pairs[0], c.pairs[1])
			nullTests = append(nullTests, test)
			nullFamily = append(nullFamily, coverTest{Family: "null", Name: c.name, Pairs: len(c.pairs[0]), DroppedPairs: l.CleanRuns - len(c.pairs[0])})
		}
	}
	sum.Tests = append(sum.Tests, family(nullFamily, nullTests)...)
	if len(order) == 2 {
		sum.Tests = append(sum.Tests, modes(claimRows[0], claimRows[1])...)
	}
	return sum
}

func family(names []coverTest, tests []metrics.Test) []coverTest {
	holm := metrics.HolmTests(tests)
	out := make([]coverTest, len(tests))
	for i, t := range tests {
		out[i] = optTest(t, holm[i])
		out[i].Family, out[i].Name, out[i].Pairs, out[i].DroppedPairs = names[i].Family, names[i].Name, names[i].Pairs, names[i].DroppedPairs
	}
	return out
}

// the two levels pair by repeat: claim run r of both shares its seed
func modes(a, b []coverRow) []coverTest {
	byRepeat := func(rows []coverRow) map[int]coverRow {
		m := map[int]coverRow{}
		for _, r := range rows {
			m[r.Repeat] = r
		}
		return m
	}
	ra, rb := byRepeat(a), byRepeat(b)
	repeats := map[int]bool{}
	for r := range ra {
		repeats[r] = true
	}
	for r := range rb {
		repeats[r] = true
	}
	var order []int
	for r := range repeats {
		order = append(order, r)
	}
	slices.Sort(order)
	excess := func(v, null *float64) *float64 {
		if !defined(v) || !defined(null) {
			return nil
		}
		return opt(*v - *null)
	}
	values := []struct {
		name string
		of   func(coverRow) *float64
	}{
		{"lda_auc", func(r coverRow) *float64 { return r.AUC }},
		{"ks_excess", func(r coverRow) *float64 { return excess(r.KS, r.KSNull) }},
		{"tv_excess", func(r coverRow) *float64 { return excess(r.TV, r.TVNull) }},
	}
	var names []coverTest
	var tests []metrics.Test
	for _, v := range values {
		var x, y []float64
		for _, r := range order {
			p, okA := ra[r]
			q, okB := rb[r]
			if !okA || !okB || !p.clean() || !q.clean() {
				continue
			}
			if vp, vq := v.of(p), v.of(q); defined(vp) && defined(vq) {
				x, y = append(x, *vp), append(y, *vq)
			}
		}
		tests = append(tests, metrics.Wilcoxon(x, y))
		names = append(names, coverTest{Family: "modes", Name: v.name, Pairs: len(x), DroppedPairs: len(order) - len(x)})
	}
	return family(names, tests)
}

func dash(p *float64) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf("%.3f", *p)
}

func dashInt(p *int) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprint(*p)
}

func printCoverRow(w io.Writer, r coverRow) {
	note := r.Degenerate
	if r.LabelMismatch {
		note = "labels disagree"
	}
	fmt.Fprintf(w, "%-8s %-9s %3d %5s %5s %5s %8s [%6s, %6s] %6s %6s %6s %6s %s\n",
		r.Role, r.Traffic, r.Repeat, dashInt(r.PayloadCells), dashInt(r.CoverCells), dashInt(r.UndefinedCells),
		dash(r.AUC), dash(r.AUCLow), dash(r.AUCHigh), dash(r.KS), dash(r.KSNull), dash(r.TV), dash(r.TVNull), note)
}

func printCoverSummary(w io.Writer, sum coverSummary) {
	fmt.Fprintf(w, "\nsuite %s, clock step %s, corridor s %v, claims %d\n", sum.Suite, sum.ClockStep, sum.CorridorS, sum.Claims)
	fmt.Fprintf(w, "%-5s %-9s %4s %5s %4s %4s %26s %26s %6s %6s %6s %6s %s\n",
		"", "traffic", "runs", "clean", "lab", "deg", "lda auc median [95% ci]", "corridor", "ks", "ks0", "tv", "tv0", "unused")
	for _, l := range sum.Levels {
		verdict := "-"
		if l.Corridor != nil {
			verdict = *l.Corridor
		}
		unused := "-"
		if len(l.Unused) > 0 {
			unused = strings.Join(l.Unused, ",")
		}
		note := ""
		if l.NoDirection != "" {
			note = " no direction: " + l.NoDirection
		}
		if l.AUCRuns == 1 {
			note += "  lda auc of one run: its value, not a median"
		}
		if l.KSRuns == 1 {
			note += "  ks and tv of one run: its values, not medians"
		}
		fmt.Fprintf(w, "level %-9s %4d %5d %4d %4d %8s [%6s, %6s] [%6s, %6s] %s %6s %6s %6s %6s %s%s\n",
			l.Traffic, l.Runs, l.CleanRuns, l.LabelMismatchRuns, l.DegenerateRuns,
			dash(l.AUC.Median), dash(l.AUC.Low), dash(l.AUC.High), dash(l.CorridorLow), dash(l.CorridorHigh), verdict,
			dash(l.KS.Median), dash(l.KSNull.Median), dash(l.TV.Median), dash(l.TVNull.Median), unused, note)
	}
	for _, t := range sum.Tests {
		fmt.Fprintf(w, "test %-5s %-40s pairs %3d dropped %3d W %8s p %8s effect %6s holm %8s\n",
			t.Family, t.Name, t.Pairs, t.DroppedPairs, dash(t.Statistic), dash(t.P), dash(t.Effect), dash(t.Holm))
	}
	fmt.Fprintln(w, "lab: runs whose labels disagree with the frames or the messages; they, broken and limited runs stay out of every value")
}
