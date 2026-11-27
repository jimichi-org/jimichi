package main

import (
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"

	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

// medians and intervals rest on clean runs only; the order interval of the
// median at 0.95 needs 6 values (0.5^6 = 0.0156 <= 0.025 < 0.5^5)
const perfLevel = 0.95

type perfCI struct {
	Median *float64 `json:"median"`
	Low    *float64 `json:"low"`
	High   *float64 `json:"high"`
}

func ciOf(v []float64, level float64) perfCI {
	if len(v) == 0 {
		return perfCI{}
	}
	iv := metrics.QuantileInterval(v, 0.5, level)
	return perfCI{Median: opt(iv.Point), Low: opt(iv.Low), High: opt(iv.High)}
}

type perfSummary struct {
	Environment perfEnv          `json:"environment"`
	Plan        perfPlanOut      `json:"plan"`
	Complete    bool             `json:"complete"`
	Lines       []perfLine       `json:"lines"`
	Saturation  []perfSaturation `json:"saturation"`
	Suites      []perfSuiteCmp   `json:"suites"`
	Cost        []perfCost       `json:"cost"`
	Increments  []perfIncrement  `json:"increments"`
	Scaling     []perfScaling    `json:"scaling"`
	KeyMem      []perfKeyMem     `json:"keymem"`
}

type perfPlanOut struct {
	Flags          map[string]string `json:"flags"`
	OrderStream    uint64            `json:"order_stream"`
	ClaimsM        int               `json:"claims_m"`
	Margin         float64           `json:"margin"`
	PlateauTol     float64           `json:"plateau_tol"`
	BoundThreshold float64           `json:"bound_threshold"`
	MaxForeign     float64           `json:"max_foreign"`
}

type perfLine struct {
	Part         string            `json:"part"`
	Suite        string            `json:"suite"`
	KeyMem       string            `json:"keymem"`
	Hops         *int              `json:"hops,omitempty"`
	Cores        *int              `json:"cores,omitempty"`
	Flows        *int              `json:"flows,omitempty"`
	PerCore      *int              `json:"circuits_per_core,omitempty"`
	Runs         int               `json:"runs"`
	BrokenRuns   int               `json:"broken_runs"`
	LimitedRuns  int               `json:"limited_runs"`
	NoisyRuns    int               `json:"noisy_runs"`
	UnpinnedRuns int               `json:"unpinned_runs"`
	WarmupRuns   int               `json:"warmup_runs"`
	CleanRuns    int               `json:"clean_runs"`
	Metrics      map[string]perfCI `json:"metrics"`
}

type perfVotes struct {
	NodeCPU   int `json:"node_cpu"`
	Generator int `json:"generator"`
	Other     int `json:"other"`
}

type perfSaturation struct {
	Part          string     `json:"part"`
	Suite         string     `json:"suite"`
	KeyMem        string     `json:"keymem"`
	Hops          *int       `json:"hops,omitempty"`
	Cores         *int       `json:"cores,omitempty"`
	LadderMedians []*float64 `json:"ladder_medians"`
	Plateau       bool       `json:"plateau"`
	PlateauReason string     `json:"plateau_reason"`
	Sat           *float64   `json:"sat"`
	SatGoodput    *float64   `json:"sat_goodput_mean"`
	Votes         *perfVotes `json:"bound_votes,omitempty"`
	Reason        string     `json:"reason"`
	ForeignTrend  *float64   `json:"foreign_trend"`
}

type perfSuiteCmp struct {
	Part         string `json:"part"`
	Metric       string `json:"metric"`
	Level        string `json:"level"`
	KeyMem       string `json:"keymem"`
	Pairs        int    `json:"pairs"`
	DroppedPairs int    `json:"dropped_pairs"`
	Ratio        perfCI `json:"ratio_gost_over_c25519"`
	Reason       string `json:"reason"`
}

type perfCost struct {
	Suite  string `json:"suite"`
	KeyMem string `json:"keymem"`
	Cores  int    `json:"cores"`
	Runs   int    `json:"runs"`
	Cost   perfCI `json:"core_ns_per_cell"`
}

type perfIncrement struct {
	Suite        string `json:"suite"`
	KeyMem       string `json:"keymem"`
	FromHops     int    `json:"from_hops"`
	ToHops       int    `json:"to_hops"`
	Quantile     string `json:"quantile"`
	Pairs        int    `json:"pairs"`
	DroppedPairs int    `json:"dropped_pairs"`
	Delta        perfCI `json:"delta_us"`
}

type perfScaling struct {
	Suite      string `json:"suite"`
	KeyMem     string `json:"keymem"`
	Cores      int    `json:"cores"`
	Pairs      int    `json:"pairs"`
	Efficiency perfCI `json:"efficiency"`
	Reason     string `json:"reason"`
}

type perfKeyMem struct {
	Part            string  `json:"part"`
	Metric          string  `json:"metric"`
	Level           string  `json:"level"`
	Suite           string  `json:"suite"`
	Pairs           int     `json:"pairs"`
	DroppedPairs    int     `json:"dropped_pairs"`
	Ratio           perfCI  `json:"ratio_all_over_nolock"`
	CILevel         float64 `json:"ci_level"`
	Margin          float64 `json:"margin"`
	Verdict         string  `json:"verdict"`
	Reason          string  `json:"reason"`
	RepeatsForPower *int    `json:"repeats_for_power"`
}

func val(p *float64) float64 {
	if p == nil {
		return math.NaN()
	}
	return *p
}

// the value of a named metric in a row; NaN where the row has none
func perfMetric(r perfRow, name string) float64 {
	switch name {
	case "foreign_cores":
		return val(r.ForeignCores)
	}
	if l := r.perfLatency; l != nil {
		switch name {
		case "latency_p50_us":
			return val(l.P50)
		case "latency_p95_us":
			return val(l.P95)
		case "latency_p99_us":
			return val(l.P99)
		}
	}
	if c := r.perfChain; c != nil {
		switch name {
		case "throughput_msgs_per_s":
			return val(c.Throughput)
		case "process_utilisation":
			return val(c.ProcessUtil)
		}
	}
	if n := r.perfNode; n != nil {
		switch name {
		case "node_cells_per_s":
			return val(n.NodeRate)
		case "node_core_ns_per_cell":
			return val(n.CorePerCell)
		case "node_busy_utilisation":
			return val(n.NodeBusyUtil)
		case "node_utilisation":
			return val(n.NodeUtil)
		case "parent_utilisation":
			return val(n.ParentUtil)
		}
	}
	if g := r.perfGoodput; g != nil {
		switch name {
		case "goodput_mean_bps":
			return val(g.Mean)
		case "goodput_min_bps":
			return val(g.Min)
		}
	}
	return math.NaN()
}

var perfLineMetrics = map[string][]string{
	"latency": {"latency_p50_us", "latency_p95_us", "latency_p99_us"},
	"chain":   {"throughput_msgs_per_s", "goodput_mean_bps", "goodput_min_bps", "process_utilisation"},
	"node":    {"node_cells_per_s", "node_core_ns_per_cell", "node_busy_utilisation", "node_utilisation", "parent_utilisation", "goodput_mean_bps", "goodput_min_bps"},
}

func (c perfCell) holds(r perfRow) bool {
	if r.Part != c.part || r.Suite != c.suite.String() || r.KeyMemLevel != c.keymem {
		return false
	}
	switch c.part {
	case "latency":
		return r.Hops != nil && *r.Hops == c.hops
	case "chain":
		return r.Flows != nil && *r.Flows == c.flows
	case "node":
		return r.perfNode != nil && r.Cores == c.cores && r.PerCore == c.circuits
	}
	return false
}

func (c perfCell) rows(all []perfRow) []perfRow {
	var out []perfRow
	for _, r := range all {
		if c.holds(r) {
			out = append(out, r)
		}
	}
	return out
}

// the clean runs of a cell by repeat
func (c perfCell) clean(all []perfRow) map[int]perfRow {
	out := map[int]perfRow{}
	for _, r := range c.rows(all) {
		if _, seen := out[r.Repeat]; r.clean() && !seen {
			out[r.Repeat] = r
		}
	}
	return out
}

func cleanValues(rows []perfRow, metric string) []float64 {
	var v []float64
	for _, r := range rows {
		if r.clean() {
			if x := perfMetric(r, metric); !math.IsNaN(x) {
				v = append(v, x)
			}
		}
	}
	return v
}

// the pairs of two cells by repeat, where both runs are clean and keep pairs
// them; a repeat with one side missing is a dropped pair
func pairUp(a, b map[int]perfRow, metric string, keep func(x, y perfRow) bool) (x, y []float64, missing int) {
	repeats := map[int]bool{}
	for r := range a {
		repeats[r] = true
	}
	for r := range b {
		repeats[r] = true
	}
	order := make([]int, 0, len(repeats))
	for r := range repeats {
		order = append(order, r)
	}
	slices.Sort(order)
	for _, r := range order {
		ra, okA := a[r]
		rb, okB := b[r]
		if !okA || !okB || keep != nil && !keep(ra, rb) {
			missing++
			continue
		}
		x = append(x, perfMetric(ra, metric))
		y = append(y, perfMetric(rb, metric))
	}
	return x, y, missing
}

func nodeCPUBound(x, y perfRow) bool {
	return x.perfNode != nil && y.perfNode != nil && x.Bound == "node_cpu" && y.Bound == "node_cpu"
}

func median(v []float64) float64 { return metrics.Median(v) }

func optMedian(v []float64) *float64 {
	if len(v) == 0 {
		return nil
	}
	return opt(median(v))
}

func summarisePerf(rows []perfRow, p perfPlan) perfSummary {
	s := perfSummary{
		Plan: perfPlanOut{Flags: p.flags, OrderStream: lab.StreamPerfOrder, ClaimsM: p.claims, Margin: p.margin,
			PlateauTol: p.plateau, BoundThreshold: perfBoundThreshold, MaxForeign: p.foreign},
		Lines: []perfLine{}, Saturation: []perfSaturation{}, Suites: []perfSuiteCmp{}, Cost: []perfCost{},
		Increments: []perfIncrement{}, Scaling: []perfScaling{}, KeyMem: []perfKeyMem{},
	}
	cells := p.cells()
	for _, c := range cells {
		line := perfLine{Part: c.part, Suite: c.suite.String(), KeyMem: c.keymem, Metrics: map[string]perfCI{}}
		switch c.part {
		case "latency":
			line.Hops = intp(c.hops)
		case "chain":
			line.Hops, line.Flows = intp(c.hops), intp(c.flows)
		case "node":
			line.Cores, line.PerCore = intp(c.cores), intp(c.circuits)
		}
		rs := c.rows(rows)
		for _, r := range rs {
			if r.Warmup {
				line.WarmupRuns++
				continue
			}
			line.Runs++
			if r.broken() {
				line.BrokenRuns++
			}
			if r.limited() {
				line.LimitedRuns++
			}
			if r.Noisy {
				line.NoisyRuns++
			}
			if r.unpinned() {
				line.UnpinnedRuns++
			}
			if r.clean() {
				line.CleanRuns++
			}
		}
		for _, m := range perfLineMetrics[c.part] {
			line.Metrics[m] = ciOf(cleanValues(rs, m), perfLevel)
		}
		s.Lines = append(s.Lines, line)
	}

	type satKey struct {
		suite, keymem string
		cores         int
	}
	chainSat := map[satKey]bool{}
	nodeSat := map[satKey]bool{}
	ladderOf := func(part string, k satKey) []perfCell {
		var out []perfCell
		for _, c := range cells {
			if c.part == part && c.suite.String() == k.suite && c.keymem == k.keymem && (part != "node" || c.cores == k.cores) {
				out = append(out, c)
			}
		}
		return out
	}
	trend := func(ladder []perfCell) *float64 {
		pick := func(c perfCell) []float64 {
			var v []float64
			for _, r := range c.rows(rows) {
				if !r.Warmup && !r.broken() && !r.limited() && !r.unpinned() {
					if x := val(r.ForeignCores); !math.IsNaN(x) {
						v = append(v, x)
					}
				}
			}
			return v
		}
		first, last := pick(ladder[0]), pick(ladder[len(ladder)-1])
		if len(first) == 0 || len(last) == 0 {
			return nil
		}
		return opt(median(last) - median(first))
	}
	for _, part := range p.parts {
		if part == "latency" {
			continue
		}
		for _, su := range perfSuites {
			for _, level := range p.levels {
				ns := []int{0}
				if part == "node" {
					ns = p.cores
				}
				for _, n := range ns {
					k := satKey{su.String(), level, n}
					ladder := ladderOf(part, k)
					metric := "throughput_msgs_per_s"
					if part == "node" {
						metric = "node_cells_per_s"
					}
					medians := make([]float64, len(ladder))
					out := perfSaturation{Part: part, Suite: k.suite, KeyMem: level, LadderMedians: make([]*float64, len(ladder))}
					for i, c := range ladder {
						medians[i] = median(cleanValues(c.rows(rows), metric))
						out.LadderMedians[i] = opt(medians[i])
					}
					out.Plateau, out.PlateauReason = metrics.Plateau(medians, p.plateau)
					last := ladder[len(ladder)-1]
					satGoodput := optMedian(cleanValues(last.rows(rows), "goodput_mean_bps"))
					out.ForeignTrend = trend(ladder)
					if part == "chain" {
						out.Hops = intp(3)
						if out.Plateau {
							out.Sat, out.SatGoodput = opt(medians[len(medians)-1]), satGoodput
							chainSat[k] = true
						} else {
							out.Reason = out.PlateauReason
						}
					} else {
						out.Cores = intp(n)
						votes := perfVotes{}
						clean := 0
						for _, r := range last.clean(rows) {
							clean++
							switch r.Bound {
							case "node_cpu":
								votes.NodeCPU++
							case "generator":
								votes.Generator++
							default:
								votes.Other++
							}
						}
						out.Votes = &votes
						switch {
						case clean == 0:
							out.Reason = out.PlateauReason
						case 2*votes.NodeCPU > clean:
							if out.Plateau {
								out.Sat, out.SatGoodput = opt(medians[len(medians)-1]), satGoodput
								nodeSat[k] = true
							} else {
								out.Reason = out.PlateauReason
							}
						case 2*votes.Generator > clean:
							out.Reason = "generator"
						default:
							out.Reason = "unattributed"
						}
					}
					s.Saturation = append(s.Saturation, out)
				}
			}
		}
	}

	lastStep := func(part, suite, keymem string, n int) perfCell {
		l := ladderOf(part, satKey{suite, keymem, n})
		return l[len(l)-1]
	}
	latencyCell := func(suite, keymem string, h int) perfCell {
		for _, c := range cells {
			if c.part == "latency" && c.suite.String() == suite && c.keymem == keymem && c.hops == h {
				return c
			}
		}
		return perfCell{}
	}
	ratio := func(a, b map[int]perfRow, metric string, keep func(x, y perfRow) bool) (perfCI, int, int) {
		x, y, missing := pairUp(a, b, metric, keep)
		r, dropped := metrics.Ratios(x, y)
		return ciOf(r, perfLevel), len(r), missing + dropped
	}
	c25519, gost := perfSuites[0].String(), perfSuites[1].String()
	for _, part := range p.parts {
		for _, level := range p.levels {
			switch part {
			case "latency":
				for h := 1; h <= 3; h++ {
					ci, pairs, dropped := ratio(latencyCell(gost, level, h).clean(rows), latencyCell(c25519, level, h).clean(rows), "latency_p50_us", nil)
					s.Suites = append(s.Suites, perfSuiteCmp{Part: part, Metric: "latency_p50_us", Level: "hops=" + strconv.Itoa(h), KeyMem: level, Pairs: pairs, DroppedPairs: dropped, Ratio: ci})
				}
			case "chain":
				g, c := lastStep(part, gost, level, 0), lastStep(part, c25519, level, 0)
				ci, pairs, dropped := ratio(g.clean(rows), c.clean(rows), "throughput_msgs_per_s", nil)
				e := perfSuiteCmp{Part: part, Metric: "throughput_msgs_per_s", Level: "flows=" + strconv.Itoa(g.flows), KeyMem: level, Pairs: pairs, DroppedPairs: dropped, Ratio: ci}
				if !chainSat[satKey{gost, level, 0}] || !chainSat[satKey{c25519, level, 0}] {
					e.Ratio, e.Reason = perfCI{}, "unsaturated"
				}
				s.Suites = append(s.Suites, e)
			case "node":
				for _, n := range p.cores {
					g, c := lastStep(part, gost, level, n), lastStep(part, c25519, level, n)
					ci, pairs, dropped := ratio(g.clean(rows), c.clean(rows), "node_cells_per_s", nil)
					e := perfSuiteCmp{Part: part, Metric: "node_cells_per_s", Level: "cores=" + strconv.Itoa(n), KeyMem: level, Pairs: pairs, DroppedPairs: dropped, Ratio: ci}
					if !nodeSat[satKey{gost, level, n}] || !nodeSat[satKey{c25519, level, n}] {
						e.Ratio, e.Reason = perfCI{}, "unsaturated"
					}
					s.Suites = append(s.Suites, e)
					ci, pairs, dropped = ratio(g.clean(rows), c.clean(rows), "node_core_ns_per_cell", nodeCPUBound)
					s.Suites = append(s.Suites, perfSuiteCmp{Part: part, Metric: "node_core_ns_per_cell", Level: "cores=" + strconv.Itoa(n), KeyMem: level, Pairs: pairs, DroppedPairs: dropped, Ratio: ci})
				}
			}
		}
	}

	for _, su := range perfSuites {
		for _, level := range p.levels {
			if slices.Contains(p.parts, "node") {
				for _, n := range p.cores {
					var v []float64
					for _, r := range lastStep("node", su.String(), level, n).clean(rows) {
						if r.Bound == "node_cpu" {
							if x := val(r.CorePerCell); !math.IsNaN(x) {
								v = append(v, x)
							}
						}
					}
					s.Cost = append(s.Cost, perfCost{Suite: su.String(), KeyMem: level, Cores: n, Runs: len(v), Cost: ciOf(v, perfLevel)})
				}
				if slices.Contains(p.cores, 1) {
					one := lastStep("node", su.String(), level, 1)
					for _, n := range p.cores {
						if n == 1 {
							continue
						}
						x, y, _ := pairUp(lastStep("node", su.String(), level, n).clean(rows), one.clean(rows), "node_cells_per_s", nodeCPUBound)
						var e []float64
						for i := range x {
							if v := metrics.Scaling(y[i], x[i], n); !math.IsNaN(v) {
								e = append(e, v)
							}
						}
						out := perfScaling{Suite: su.String(), KeyMem: level, Cores: n, Pairs: len(e), Efficiency: ciOf(e, perfLevel)}
						if !nodeSat[satKey{su.String(), level, n}] || !nodeSat[satKey{su.String(), level, 1}] {
							out.Efficiency, out.Reason = perfCI{}, "unsaturated"
						}
						s.Scaling = append(s.Scaling, out)
					}
				}
			}
			if slices.Contains(p.parts, "latency") {
				for h := 2; h <= 3; h++ {
					for _, q := range []string{"p50", "p95", "p99"} {
						metric := "latency_" + q + "_us"
						x, y, missing := pairUp(latencyCell(su.String(), level, h).clean(rows), latencyCell(su.String(), level, h-1).clean(rows), metric, nil)
						d, dropped := metrics.Differences(x, y)
						s.Increments = append(s.Increments, perfIncrement{Suite: su.String(), KeyMem: level, FromHops: h - 1, ToHops: h, Quantile: q,
							Pairs: len(d), DroppedPairs: missing + dropped, Delta: ciOf(d, perfLevel)})
					}
				}
			}
		}
	}

	if slices.Contains(p.levels, "all") && slices.Contains(p.levels, "nolock") {
		level := 1 - 0.05/float64(p.claims)
		claim := func(part, metric, lvl, suite string, all, nolock perfCell, saturated bool) {
			x, y, missing := pairUp(all.clean(rows), nolock.clean(rows), metric, nil)
			lambda, dropped := metrics.Ratios(x, y)
			out := perfKeyMem{Part: part, Metric: metric, Level: lvl, Suite: suite, Pairs: len(lambda), DroppedPairs: missing + dropped,
				Ratio: ciOf(lambda, level), CILevel: level, Margin: p.margin}
			switch {
			case !saturated:
				out.Reason = "unsaturated"
			default:
				iv := metrics.QuantileInterval(lambda, 0.5, level)
				out.Verdict = metrics.Equivalence(iv, 1, p.margin)
				if out.Verdict == "" {
					out.Reason = "undefined_interval"
				}
			}
			if len(lambda) >= 5 {
				seed := uint64(lab.Derive(p.seed, lab.StreamPerfPower, uint64(len(s.KeyMem))))
				if n, ok := metrics.RepeatsForPower(lambda, level, p.margin, 0.8, 10000, 1000, seed); ok {
					out.RepeatsForPower = intp(max(30, n))
				}
			}
			s.KeyMem = append(s.KeyMem, out)
		}
		for _, part := range p.parts {
			for _, su := range perfSuites {
				name := su.String()
				switch part {
				case "latency":
					claim(part, "latency_p50_us", "hops=3", name, latencyCell(name, "all", 3), latencyCell(name, "nolock", 3), true)
				case "chain":
					a, b := lastStep(part, name, "all", 0), lastStep(part, name, "nolock", 0)
					claim(part, "throughput_msgs_per_s", "flows="+strconv.Itoa(a.flows), name, a, b,
						chainSat[satKey{name, "all", 0}] && chainSat[satKey{name, "nolock", 0}])
				case "node":
					for _, n := range p.cores {
						a, b := lastStep(part, name, "all", n), lastStep(part, name, "nolock", n)
						claim(part, "node_cells_per_s", "cores="+strconv.Itoa(n), name, a, b,
							nodeSat[satKey{name, "all", n}] && nodeSat[satKey{name, "nolock", n}])
					}
				}
			}
		}
	}
	return s
}

func show(p *float64, format string) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf(format, *p)
}

func printPerf(w io.Writer, s perfSummary) {
	fmt.Fprintf(w, "\nperf: %s on %s, %d logical cpus, complete %v\n", s.Environment.GOOS, s.Environment.CPUModel, s.Environment.NumCPU, s.Complete)
	fmt.Fprintf(w, "%-8s %-7s %-7s %-12s %4s %5s  %s\n", "part", "suite", "keymem", "step", "runs", "clean", "median of the first metric [0.95]")
	for _, l := range s.Lines {
		step := ""
		switch {
		case l.Part == "latency":
			step = fmt.Sprintf("hops=%d", *l.Hops)
		case l.Part == "chain":
			step = fmt.Sprintf("flows=%d", *l.Flows)
		default:
			step = fmt.Sprintf("n=%d k=%d", *l.Cores, *l.PerCore)
		}
		m := perfLineMetrics[l.Part][0]
		ci := l.Metrics[m]
		fmt.Fprintf(w, "%-8s %-7s %-7s %-12s %4d %5d  %s %s [%s, %s]\n", l.Part, l.Suite, l.KeyMem, step, l.Runs, l.CleanRuns, m,
			show(ci.Median, "%.1f"), show(ci.Low, "%.1f"), show(ci.High, "%.1f"))
	}
	for _, sat := range s.Saturation {
		fmt.Fprintf(w, "saturation %s %s %s: plateau %v %s, sat %s, reason %q\n", sat.Part, sat.Suite, sat.KeyMem, sat.Plateau, sat.PlateauReason, show(sat.Sat, "%.1f"), sat.Reason)
	}
	for _, k := range s.KeyMem {
		fmt.Fprintf(w, "keymem %s %s %s: %d pairs, verdict %q %s\n", k.Part, k.Suite, k.Level, k.Pairs, k.Verdict, k.Reason)
	}
}
