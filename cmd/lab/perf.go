package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/perf"
)

// the class threshold of block 6: a side whose CPUs are busy at least this
// share of the window is the one that ran out
const perfBoundThreshold = 0.9

var perfSuites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

type perfFlags struct {
	explicit   map[string]bool
	positional int

	parts, keymem, cores, circuits, ladder string
	inflight                               int
	warmup, duration, send                 time.Duration
	flows                                  int
	plateau, margin, maxForeign            float64
	claims, repeats                        int
	seed                                   int64
	rev, out                               string
}

type perfPlan struct {
	parts    []string
	levels   []string
	cores    []int
	circuits []int
	ladder   []int
	inflight int
	warmup   time.Duration
	duration time.Duration
	send     time.Duration
	flows    int
	plateau  float64
	margin   float64
	foreign  float64
	m        int
	claims   int
	repeats  int
	seed     int64
	rev, out string
	topo     perf.Topo
	allowed  []int
	flags    map[string]string
}

// one configuration of the set; step is its place on the ladder of its part
type perfCell struct {
	part     string
	suite    jcrypto.Suite
	keymem   string
	hops     int
	flows    int
	cores    int
	circuits int
	step     int
}

var perfRefused = []string{"suite", "hops", "bins", "base", "train", "corridor", "mark-replay", "nodes", "rogue",
	"samples", "missing", "leftout", "withhold", "containers", "resamples", "bench-in", "bench-grace", "bench-rotate"}

func intList(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func increasing(v []int, low, high int) bool {
	for i, x := range v {
		if x < low || x > high || i > 0 && x <= v[i-1] {
			return false
		}
	}
	return len(v) > 0
}

// the m of 1 - 0.05/m: one mlock claim per part and per core count of the
// node part, on each suite
func perfClaims(parts []string, cores []int) int {
	m := 0
	for _, p := range parts {
		switch p {
		case "latency", "chain":
			m++
		case "node":
			m += len(cores)
		}
	}
	return 2 * m
}

var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)

// every check of the flags and the platform runs before the first run; code 2
// is a refusal, 1 a probe that failed for another reason
func planPerf(f perfFlags, stderr io.Writer) (perfPlan, int) {
	fail := func(format string, a ...any) (perfPlan, int) {
		fmt.Fprintf(stderr, "perf: "+format+"\n", a...)
		return perfPlan{}, 2
	}
	for _, name := range perfRefused {
		if f.explicit[name] {
			return fail("perf runs both suites at hops 1, 2, 3; -%s does not apply", name)
		}
	}
	if f.positional != 0 {
		return fail("perf runs both suites at hops 1, 2, 3; positional arguments do not apply")
	}
	linux := runtime.GOOS == "linux"
	p := perfPlan{inflight: f.inflight, warmup: f.warmup, plateau: f.plateau, margin: f.margin, foreign: f.maxForeign,
		repeats: f.repeats, seed: f.seed, rev: f.rev, out: f.out, flags: map[string]string{}}

	parts := "latency,chain,node"
	if !linux {
		parts = "latency,chain"
	}
	if f.explicit["perf-parts"] {
		parts = f.parts
	} else if !linux {
		fmt.Fprintln(stderr, "perf: the node part needs linux (core affinity), running latency and chain")
	}
	for _, part := range strings.Split(parts, ",") {
		part = strings.TrimSpace(part)
		if !slices.Contains([]string{"latency", "chain", "node"}, part) || slices.Contains(p.parts, part) {
			return fail("-perf-parts %q: latency, chain and node, each at most once", parts)
		}
		if part == "node" && !linux {
			return fail("node part needs linux (core affinity)")
		}
		p.parts = append(p.parts, part)
	}

	switch {
	case !linux && f.explicit["perf-keymem"]:
		return fail("-perf-keymem needs linux, where the levels differ")
	case !linux:
		p.levels = []string{"heap"}
	case f.explicit["perf-keymem"]:
		for _, l := range strings.Split(f.keymem, ",") {
			l = strings.TrimSpace(l)
			if (l != "all" && l != "nolock") || slices.Contains(p.levels, l) {
				return fail("-perf-keymem %q: a subset of all and nolock", f.keymem)
			}
			p.levels = append(p.levels, l)
		}
	default:
		p.levels = []string{"all", "nolock"}
	}

	var err error
	if p.cores, err = intList(f.cores); err != nil || !increasing(p.cores, 1, 1<<10) {
		return fail("-perf-cores %q: increasing, at least 1", f.cores)
	}
	if p.circuits, err = intList(f.circuits); err != nil || !increasing(p.circuits, 1, 64) || len(p.circuits) < 2 {
		return fail("-perf-circuits %q: increasing, at least 1, at least two steps", f.circuits)
	}
	if p.circuits[len(p.circuits)-1]*p.cores[len(p.cores)-1] > maxWindowFlows {
		return fail("-perf-circuits %q: %d circuits on %d cores exceed %d", f.circuits, p.circuits[len(p.circuits)-1], p.cores[len(p.cores)-1], maxWindowFlows)
	}
	if p.ladder, err = intList(f.ladder); err != nil || !increasing(p.ladder, 1, 64) || len(p.ladder) < 2 {
		return fail("-perf-flows %q: increasing, 1..64, at least two steps", f.ladder)
	}
	switch {
	case f.inflight < 1 || f.inflight > 64:
		return fail("-perf-inflight %d outside 1..64", f.inflight)
	case f.duration < time.Second:
		return fail("-duration %v below 1s", f.duration)
	case f.warmup < 0 || f.warmup >= f.duration/2:
		return fail("-perf-warmup %v: at least 0 and below half of -duration", f.warmup)
	case !(f.plateau > 0 && f.plateau < 1):
		return fail("-perf-plateau %v outside (0, 1)", f.plateau)
	case !(f.margin > 0 && f.margin < 1):
		return fail("-perf-margin %v outside (0, 1)", f.margin)
	case !(f.maxForeign >= 0):
		return fail("-perf-max-foreign %v below 0", f.maxForeign)
	case f.flows < 1 || f.flows > 64:
		return fail("-flows %d outside 1..64", f.flows)
	case f.send <= 0:
		return fail("-send %v must be positive", f.send)
	case f.repeats < 1 || f.repeats > 1000:
		return fail("-repeats %d outside 1..1000", f.repeats)
	case !revision.MatchString(f.rev):
		return fail("-rev %q: the 40 hex digits of the revision", f.rev)
	}
	p.duration, p.send, p.flows = f.duration, f.send, f.flows
	p.m = perfClaims(p.parts, p.cores)
	p.claims = p.m
	if f.explicit["claims"] {
		if f.claims < p.m {
			return fail("-claims %d below the %d claims of this invocation", f.claims, p.m)
		}
		p.claims = f.claims
	}

	if slices.Contains(p.levels, "all") {
		if code := probeLocking(stderr); code != 0 {
			return perfPlan{}, code
		}
	}
	if slices.Contains(p.parts, "node") {
		topo, err := perf.Topology(p.cores[len(p.cores)-1])
		if errors.Is(err, perf.ErrCoresUnavailable) {
			return fail("cores_unavailable: %d node CPUs, one per core of one L3 group, and as many for the load", p.cores[len(p.cores)-1])
		}
		if err != nil {
			fmt.Fprintf(stderr, "perf: topology: %v\n", err)
			return perfPlan{}, 1
		}
		p.topo, p.allowed = topo, perf.Allowed()
	}
	p.flags = map[string]string{
		"parts": strings.Join(p.parts, ","), "keymem": strings.Join(p.levels, ","), "cores": f.cores, "circuits": f.circuits,
		"flows_ladder": f.ladder, "inflight": strconv.Itoa(f.inflight), "warmup": f.warmup.String(), "duration": f.duration.String(),
		"flows": strconv.Itoa(f.flows), "send": f.send.String(), "repeats": strconv.Itoa(f.repeats), "seed": strconv.FormatInt(f.seed, 10),
		"claims": strconv.Itoa(p.claims),
	}
	return p, 0
}

const maxWindowFlows = 64

// a level that locks either locks every key or fails the run, so the check is
// made once before the first run
func probeLocking(stderr io.Writer) int {
	prev := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		fmt.Fprintf(stderr, "perf: probe: %v\n", err)
		return 1
	}
	defer func() { _ = secmem.SetPolicy(prev) }()
	buf, err := secmem.New(32)
	switch {
	case errors.Is(err, secmem.ErrNotLocked):
		fmt.Fprintln(stderr, "perf: keymem all needs mlock: RLIMIT_MEMLOCK")
		return 2
	case err != nil:
		fmt.Fprintf(stderr, "perf: probe: %v\n", err)
		return 1
	}
	locked := buf.Locked()
	buf.Release()
	budget, err := secmem.MemlockBudget()
	if !locked || err == nil && budget != ^uint64(0) && budget < 1<<20 {
		fmt.Fprintln(stderr, "perf: keymem all needs mlock: RLIMIT_MEMLOCK")
		return 2
	}
	return 0
}

// the cells of one repeat in the order of the plan
func (p perfPlan) cells() []perfCell {
	var out []perfCell
	for _, part := range p.parts {
		for _, s := range perfSuites {
			for _, level := range p.levels {
				switch part {
				case "latency":
					for h := 1; h <= 3; h++ {
						out = append(out, perfCell{part: part, suite: s, keymem: level, hops: h, step: h - 1})
					}
				case "chain":
					for i, f := range p.ladder {
						out = append(out, perfCell{part: part, suite: s, keymem: level, hops: 3, flows: f, step: i})
					}
				case "node":
					for _, n := range p.cores {
						for i, k := range p.circuits {
							out = append(out, perfCell{part: part, suite: s, keymem: level, hops: 1, cores: n, circuits: k, step: i})
						}
					}
				}
			}
		}
	}
	return out
}

// a permutation of the cells of repeat r: drift of the host falls on every
// level alike on average
func perfOrder(seed int64, r, cells int) []int {
	order := make([]int, cells)
	for i := range order {
		order[i] = i
	}
	rng := rand.New(rand.NewSource(lab.Derive(seed, lab.StreamPerfOrder, uint64(r))))
	for i := cells - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		order[i], order[j] = order[j], order[i]
	}
	return order
}

func perfCommand(f perfFlags, stdout, stderr io.Writer) int {
	plan, code := planPerf(f, stderr)
	if code != 0 {
		return code
	}
	cells := plan.cells()
	runs := len(cells)*plan.repeats + 1
	estimate := time.Duration(runs) * (time.Second + plan.duration + time.Second)
	fmt.Fprintf(stdout, "perf: parts %s, keymem %s, %d cells x %d repeats + 1 warmup = %d runs, m %d, about %v\n",
		strings.Join(plan.parts, ","), strings.Join(plan.levels, ","), len(cells), plan.repeats, runs, plan.claims, estimate.Round(time.Minute))

	stamp := time.Now().UTC().Format("20060102-150405")
	env := perfEnvironment(plan)
	var rows []perfRow
	finish := func(complete bool) int {
		if err := write(stdout, plan.out, "perf-"+stamp, rows); err != nil {
			fmt.Fprintf(stderr, "report: %v\n", err)
			return 1
		}
		sum := summarisePerf(rows, plan)
		sum.Environment, sum.Complete = env, complete
		printPerf(stdout, sum)
		if err := write(stdout, plan.out, "summary-perf-"+stamp, sum); err != nil {
			fmt.Fprintf(stderr, "summary: %v\n", err)
			return 1
		}
		if !complete {
			return 1
		}
		return 0
	}
	runOne := func(c perfCell, r, index int, warmup bool) bool {
		row, err := runPerfCell(plan, env, c, r)
		if err != nil {
			fmt.Fprintf(stderr, "perf: %s %s %s: %v\n", c.part, c.suite, c.keymem, err)
			return false
		}
		row.Warmup, row.OrderIndex = warmup, index
		rows = append(rows, row)
		return true
	}
	if !runOne(cells[0], 0, -1, true) {
		return finish(false)
	}
	for r := 0; r < plan.repeats; r++ {
		for i, ci := range perfOrder(plan.seed, r, len(cells)) {
			if !runOne(cells[ci], r, i, false) {
				return finish(false)
			}
		}
	}
	return finish(true)
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func governors() []string {
	out := []string{}
	paths, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			if g := strings.TrimSpace(string(b)); !slices.Contains(out, g) {
				out = append(out, g)
			}
		}
	}
	return out
}
