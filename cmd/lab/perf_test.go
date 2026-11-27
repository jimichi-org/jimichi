package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab/perf"
)

// the node part starts the test binary as its child
func TestMain(m *testing.M) {
	if handled, code := perf.MaybeRunChild(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

var testRev = strings.Repeat("0123456789", 4)

func TestPerfRefusals(t *testing.T) {
	perfArgs := func(extra ...string) []string {
		return append([]string{"-set", "perf", "-rev", testRev, "-perf-parts", "latency,chain"}, extra...)
	}
	type perfCase struct {
		name string
		args []string
		want string
	}
	cases := []perfCase{
		{"perf flag without the set", []string{"-perf-cores", "1"}, "requires -set perf"},
		{"bench flag without the set", []string{"-bench-in", "x"}, "requires -set bench"},
		{"suite", perfArgs("-suite", "gost"), "-suite does not apply"},
		{"hops", perfArgs("-hops", "2"), "-hops does not apply"},
		{"positional", perfArgs("extra"), "positional"},
		{"inflight 0", perfArgs("-perf-inflight", "0"), "-perf-inflight"},
		{"inflight 65", perfArgs("-perf-inflight", "65"), "-perf-inflight"},
		{"flows down", perfArgs("-perf-flows", "8,4"), "-perf-flows"},
		{"flows one step", perfArgs("-perf-flows", "8"), "-perf-flows"},
		{"circuits over 64", perfArgs("-perf-cores", "1,2", "-perf-circuits", "1,40"), "exceed 64"},
		{"circuits one step", perfArgs("-perf-circuits", "4"), "-perf-circuits"},
		{"cores down", perfArgs("-perf-cores", "2,1"), "-perf-cores"},
		{"rev", []string{"-set", "perf", "-rev", "abc", "-perf-parts", "latency"}, "-rev"},
		{"claims below m", perfArgs("-claims", "3"), "-claims 3 below the 4"},
		{"warmup half", perfArgs("-duration", "2s", "-perf-warmup", "1s"), "-perf-warmup"},
		{"plateau", perfArgs("-perf-plateau", "0"), "-perf-plateau"},
		{"margin", perfArgs("-perf-margin", "1"), "-perf-margin"},
		{"foreign", perfArgs("-perf-max-foreign", "-1"), "-perf-max-foreign"},
		{"repeats", perfArgs("-repeats", "0"), "-repeats"},
		{"repeats over", perfArgs("-repeats", "1001"), "-repeats"},
		{"flows", perfArgs("-flows", "65"), "-flows"},
		{"duration", perfArgs("-duration", "500ms"), "-duration"},
		{"parts twice", perfArgs("-perf-parts", "latency,latency"), "-perf-parts"},
		{"parts unknown", perfArgs("-perf-parts", "middle"), "-perf-parts"},
		{"bench with a run flag", []string{"-set", "bench", "-bench-in", ".", "-rev", testRev, "-duration", "1s"}, "-duration does not apply"},
		{"bench without input", []string{"-set", "bench", "-rev", testRev}, "-bench-in"},
		{"bench with perf flag", []string{"-set", "bench", "-perf-cores", "1"}, "requires -set perf"},
	}
	if runtime.GOOS != "linux" {
		cases = append(cases,
			perfCase{"node off linux", perfArgs("-perf-parts", "node"), "node part needs linux"},
			perfCase{"keymem off linux", perfArgs("-perf-keymem", "all"), "-perf-keymem needs linux"},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := command(c.args, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), c.want) {
				t.Fatalf("exit %d, stderr %q; want 2 and %q", code, errOut.String(), c.want)
			}
		})
	}
	t.Run("bench input files", func(t *testing.T) {
		for _, name := range []string{"notes.txt", "call-01.txt", "call-0.txt"} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte(realCPU1), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			if code := command([]string{"-set", "bench", "-bench-in", dir, "-rev", testRev}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "not a call-<k>.txt") {
				t.Fatalf("%s: exit %d, stderr %q", name, code, errOut.String())
			}
		}
	})
}

func TestPerfOrderIsSeeded(t *testing.T) {
	a, b, c := perfOrder(5, 0, 68), perfOrder(5, 0, 68), perfOrder(5, 1, 68)
	if !slices.Equal(a, b) {
		t.Fatal("one seed and repeat gave two orders")
	}
	if slices.Equal(a, c) {
		t.Fatal("two repeats gave one order")
	}
	sorted := slices.Clone(a)
	slices.Sort(sorted)
	for i, v := range sorted {
		if v != i {
			t.Fatalf("order %v is not a permutation", a)
		}
	}
}

func TestSeriesEligibleOnlyOnLinux(t *testing.T) {
	if seriesEligible("windows") || !seriesEligible("linux") {
		t.Fatal("only linux rows go into a series")
	}
}

// synthetic rows of the summary, each built clean unless told otherwise
type rowSpec struct {
	part, suite, keymem string
	repeat, a, b        int // latency: hops; chain: flows; node: cores and circuits per core
	value               float64
	bound               string
	foreign             *float64
	noisy, warmup       bool
}

func synthRow(s rowSpec) perfRow {
	r := perfRow{Part: s.part, Suite: s.suite, KeyMemLevel: s.keymem, Repeat: s.repeat, ForeignCores: s.foreign, Noisy: s.noisy, Warmup: s.warmup}
	v := opt(s.value)
	switch s.part {
	case "latency":
		r.Hops = intp(s.a)
		r.perfLatency = &perfLatency{P50: v}
	case "chain":
		r.Hops, r.Flows = intp(3), intp(s.a)
		r.perfChain = &perfChain{Throughput: v}
		r.perfGoodput = &perfGoodput{Mean: v}
	case "node":
		r.perfNode = &perfNode{Cores: s.a, PerCore: s.b, NodeRate: v, CorePerCell: v, Bound: s.bound, AffinityOK: true}
	}
	return r
}

func testPlan(parts []string, levels []string, ladder, cores, circuits []int, claims int) perfPlan {
	return perfPlan{parts: parts, levels: levels, ladder: ladder, cores: cores, circuits: circuits, claims: claims,
		margin: 0.05, plateau: 0.05, foreign: 0.25, seed: 1}
}

func fp(v float64) *float64 { return &v }

func TestPerfSummaryKnownAnswer(t *testing.T) {
	c := jcrypto.SuiteC25519.String()
	g := jcrypto.SuiteGOST.String()

	t.Run("increment per hop", func(t *testing.T) {
		// h1 {100, 110, 120}, h2 {150, 170, 160}: differences {50, 60, 40},
		// median 50, no interval at 3 pairs
		var rows []perfRow
		for r, v := range []float64{100, 110, 120} {
			rows = append(rows, synthRow(rowSpec{part: "latency", suite: c, keymem: "heap", repeat: r, a: 1, value: v}))
		}
		for r, v := range []float64{150, 170, 160} {
			rows = append(rows, synthRow(rowSpec{part: "latency", suite: c, keymem: "heap", repeat: r, a: 2, value: v}))
		}
		s := summarisePerf(rows, testPlan([]string{"latency"}, []string{"heap"}, nil, nil, nil, 2))
		for _, in := range s.Increments {
			if in.Suite == c && in.FromHops == 1 && in.Quantile == "p50" {
				if in.Pairs != 3 || *in.Delta.Median != 50 || in.Delta.Low != nil {
					t.Fatalf("increment %+v, want 3 pairs, median 50, no interval", in)
				}
				return
			}
		}
		t.Fatal("no increment 1 -> 2")
	})

	chainRows := func(lambda []float64, nolockFirst float64) []perfRow {
		var rows []perfRow
		for r, l := range lambda {
			rows = append(rows,
				synthRow(rowSpec{part: "chain", suite: c, keymem: "nolock", repeat: r, a: 1, value: nolockFirst}),
				synthRow(rowSpec{part: "chain", suite: c, keymem: "nolock", repeat: r, a: 2, value: 1000}),
				synthRow(rowSpec{part: "chain", suite: c, keymem: "all", repeat: r, a: 1, value: 1000}),
				synthRow(rowSpec{part: "chain", suite: c, keymem: "all", repeat: r, a: 2, value: 1000 * l}))
		}
		return rows
	}
	keymemClaim := func(s perfSummary) perfKeyMem {
		for _, k := range s.KeyMem {
			if k.Part == "chain" && k.Suite == c {
				return k
			}
		}
		t.Fatal("no chain claim on c25519")
		return perfKeyMem{}
	}
	lambda := []float64{0.99, 1.01, 1, 1.005, 0.995, 1.002, 0.998, 1.008, 0.992, 1}
	plan := testPlan([]string{"chain"}, []string{"all", "nolock"}, []int{1, 2}, nil, nil, 10)

	t.Run("mlock equivalent", func(t *testing.T) {
		// m 10: alpha/2 = 0.0025; P(K <= 0) = 1/1024 <= 0.0025 < P(K <= 1) =
		// 11/1024, so the interval of 10 values is [x(1), x(10)] = [0.99, 1.01],
		// inside [0.95, 1.05]
		k := keymemClaim(summarisePerf(chainRows(lambda, 1000), plan))
		if k.Verdict != "equivalent" || k.Pairs != 10 || !near(*k.Ratio.Low, 0.99) || !near(*k.Ratio.High, 1.01) || !near(k.CILevel, 0.995) {
			t.Fatalf("claim %+v", k)
		}
		// every value inside the corridor: power 1 from n 9, the series takes 30
		if k.RepeatsForPower == nil || *k.RepeatsForPower != 30 {
			t.Fatalf("repeats_for_power %v, want 30", k.RepeatsForPower)
		}
	})
	t.Run("mlock not shown", func(t *testing.T) {
		wide := slices.Clone(lambda)
		wide[3] = 1.06
		if k := keymemClaim(summarisePerf(chainRows(wide, 1000), plan)); k.Verdict != "not shown" {
			t.Fatalf("claim %+v, want not shown", k)
		}
	})
	t.Run("mlock unsaturated", func(t *testing.T) {
		// the nolock line rises from 500 to 1000: no plateau, no claim
		k := keymemClaim(summarisePerf(chainRows(lambda, 500), plan))
		if k.Verdict != "" || k.Reason != "unsaturated" {
			t.Fatalf("claim %+v, want no verdict, reason unsaturated", k)
		}
	})

	satOf := func(s perfSummary, part, suite string) perfSaturation {
		for _, x := range s.Saturation {
			if x.Part == part && x.Suite == suite && (x.KeyMem == "heap") {
				return x
			}
		}
		t.Fatalf("no saturation of %s %s", part, suite)
		return perfSaturation{}
	}
	t.Run("plateau at the last step", func(t *testing.T) {
		// {1000, 1900, 1850}: |1850-1900| = 50 <= 95, sat 1850 and not 1900;
		// {1000, 1900, 1200}: declined, no sat
		ladder := []int{1, 2, 3}
		var rows []perfRow
		for i, v := range []float64{1000, 1900, 1850} {
			rows = append(rows, synthRow(rowSpec{part: "chain", suite: c, keymem: "heap", a: ladder[i], value: v}))
		}
		for i, v := range []float64{1000, 1900, 1200} {
			rows = append(rows, synthRow(rowSpec{part: "chain", suite: g, keymem: "heap", a: ladder[i], value: v}))
		}
		s := summarisePerf(rows, testPlan([]string{"chain"}, []string{"heap"}, ladder, nil, nil, 2))
		if x := satOf(s, "chain", c); !x.Plateau || *x.Sat != 1850 {
			t.Fatalf("c25519 %+v, want a plateau at 1850", x)
		}
		if x := satOf(s, "chain", g); x.Plateau || x.PlateauReason != "declined" || x.Sat != nil {
			t.Fatalf("gost %+v, want declined and no sat", x)
		}
		// c25519 saturated and gost not: no suite ratio
		for _, e := range s.Suites {
			if e.Part == "chain" && (e.Ratio.Median != nil || e.Reason != "unsaturated") {
				t.Fatalf("suite ratio %+v, want null, reason unsaturated", e)
			}
		}
	})

	t.Run("node classes", func(t *testing.T) {
		for _, tc := range []struct {
			bounds []string
			sat    bool
			reason string
		}{
			{[]string{"node_cpu", "generator", "generator"}, false, "generator"},
			{[]string{"node_cpu", "other", "other"}, false, "unattributed"},
			{[]string{"node_cpu", "node_cpu", "other"}, true, ""},
		} {
			var rows []perfRow
			for r, b := range tc.bounds {
				rows = append(rows,
					synthRow(rowSpec{part: "node", suite: c, keymem: "heap", repeat: r, a: 1, b: 1, value: 100, bound: b}),
					synthRow(rowSpec{part: "node", suite: c, keymem: "heap", repeat: r, a: 1, b: 2, value: 100, bound: b}))
			}
			s := summarisePerf(rows, testPlan([]string{"node"}, []string{"heap"}, nil, []int{1}, []int{1, 2}, 2))
			x := satOf(s, "node", c)
			if (x.Sat != nil) != tc.sat || x.Reason != tc.reason {
				t.Fatalf("classes %v: %+v, want sat %v and reason %q", tc.bounds, x, tc.sat, tc.reason)
			}
		}
	})

	t.Run("scaling", func(t *testing.T) {
		// T(1) {10000, 11000}, T(4) {36000, 33000}: E = 36000/40000 = 0.9 and
		// 33000/44000 = 0.75, median 0.825, no interval at 2 pairs
		var rows []perfRow
		for r, v := range []float64{10000, 11000} {
			for _, k := range []int{1, 2} {
				rows = append(rows, synthRow(rowSpec{part: "node", suite: c, keymem: "heap", repeat: r, a: 1, b: k, value: v, bound: "node_cpu"}))
			}
		}
		for r, v := range []float64{36000, 33000} {
			for _, k := range []int{1, 2} {
				rows = append(rows, synthRow(rowSpec{part: "node", suite: c, keymem: "heap", repeat: r, a: 4, b: k, value: v, bound: "node_cpu"}))
			}
		}
		s := summarisePerf(rows, testPlan([]string{"node"}, []string{"heap"}, nil, []int{1, 4}, []int{1, 2}, 4))
		for _, e := range s.Scaling {
			if e.Suite == c && e.Cores == 4 {
				if e.Pairs != 2 || !near(*e.Efficiency.Median, 0.825) || e.Efficiency.Low != nil || e.Reason != "" {
					t.Fatalf("scaling %+v, want 2 pairs, median 0.825", e)
				}
				return
			}
		}
		t.Fatal("no scaling at 4 cores")
	})

	t.Run("foreign trend and noise", func(t *testing.T) {
		// step 1 {0.05, 0.07, 0.06}, step K {0.30, 0.10, 0.12}: 0.12 - 0.06 =
		// 0.06, the noisy 0.30 included; it stays out of the medians
		var rows []perfRow
		for r, fc := range []float64{0.05, 0.07, 0.06} {
			rows = append(rows, synthRow(rowSpec{part: "chain", suite: c, keymem: "heap", repeat: r, a: 1, value: 1000, foreign: fp(fc)}))
		}
		for r, fc := range []float64{0.30, 0.10, 0.12} {
			rows = append(rows, synthRow(rowSpec{part: "chain", suite: c, keymem: "heap", repeat: r, a: 2, value: 1000 + 1000*fc, foreign: fp(fc), noisy: fc > 0.25}))
		}
		rows = append(rows, synthRow(rowSpec{part: "chain", suite: c, keymem: "heap", a: 2, value: 1e9, warmup: true}))
		s := summarisePerf(rows, testPlan([]string{"chain"}, []string{"heap"}, []int{1, 2}, nil, nil, 2))
		x := satOf(s, "chain", c)
		if x.ForeignTrend == nil || !near(*x.ForeignTrend, 0.06) {
			t.Fatalf("foreign trend %v, want 0.06", x.ForeignTrend)
		}
		for _, l := range s.Lines {
			if l.Part == "chain" && l.Suite == c && *l.Flows == 2 {
				// clean values 1100 and 1120: median 1110
				if l.NoisyRuns != 1 || l.Runs != 3 || l.WarmupRuns != 1 || l.CleanRuns != 2 || !near(*l.Metrics["throughput_msgs_per_s"].Median, 1110) {
					t.Fatalf("line %+v", l)
				}
				return
			}
		}
		t.Fatal("no line at flows 2")
	})
}

// a smoke of the set through the command line: every latency and chain cell
// on both suites, reports under one stamp
func TestPerfLatencyFromTheCommandLine(t *testing.T) {
	if testing.Short() {
		t.Skip("runs live chains for seconds")
	}
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	args := []string{"-set", "perf", "-perf-parts", "latency,chain", "-perf-flows", "1,2", "-perf-inflight", "2", "-flows", "2",
		"-duration", "1s", "-perf-warmup", "100ms", "-send", "20ms", "-repeats", "1", "-rev", testRev, "-out", dir}
	if runtime.GOOS == "linux" {
		args = append(args, "-perf-keymem", "nolock")
	}
	if code := command(args, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	stamps := map[string]bool{}
	named := regexp.MustCompile(`^(perf|summary-perf)-(\d{8}-\d{6})\.json$`)
	var rowsFile string
	for _, p := range files {
		m := named.FindStringSubmatch(filepath.Base(p))
		if m == nil {
			t.Fatalf("unexpected report %s", p)
		}
		stamps[m[2]] = true
		if m[1] == "perf" {
			rowsFile = p
		}
	}
	if len(files) != 2 || len(stamps) != 1 {
		t.Fatalf("reports %v, want two under one stamp", files)
	}
	b, err := os.ReadFile(rowsFile)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if r["warmup"] == true {
			continue
		}
		if r["messages"].(float64) <= 0 {
			t.Fatalf("row without messages: %v", r)
		}
		key := r["part"].(string) + "/" + r["suite"].(string)
		switch r["part"] {
		case "latency":
			key += "/h" + jsonNumber(r["hops"])
		case "chain":
			key += "/f" + jsonNumber(r["flows"])
			if r["payload_bytes"].(float64) != 444 {
				t.Fatalf("chain payload %v, want 444", r["payload_bytes"])
			}
		}
		seen[key] = true
	}
	for _, s := range []string{"c25519", "gost"} {
		for _, k := range []string{"latency/" + s + "/h1", "latency/" + s + "/h2", "latency/" + s + "/h3", "chain/" + s + "/f1", "chain/" + s + "/f2"} {
			if !seen[k] {
				t.Fatalf("no row %s in %v", k, seen)
			}
		}
	}
}

func jsonNumber(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
