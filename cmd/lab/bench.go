package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/lab/perf"
)

// the packages whose benchmarks block 6 reads; a call is complete only with
// an ok line for each
var benchPackages = []string{"github.com/jimichi-org/jimichi/relay", "github.com/jimichi-org/jimichi/wire"}

type benchLine struct {
	pkg     string
	name    string
	procs   int
	n       int64
	metrics map[string]float64
}

// what one go test invocation printed
type benchCall struct {
	goos, goarch, cpu string
	ok                map[string]bool
	failed            bool
	skipped           []string
	lines             []benchLine
}

var procsSuffix = regexp.MustCompile(`-(\d+)$`)

// the -<procs> suffix is optional, go test leaves it out when GOMAXPROCS is 1;
// no sub-benchmark of block 6 ends in -<digits>, so a trailing one is the
// suffix
func splitProcs(name string) (string, int) {
	if m := procsSuffix.FindStringSubmatchIndex(name); m != nil {
		p, err := strconv.Atoi(name[m[2]:m[3]])
		if err == nil {
			return name[:m[0]], p
		}
	}
	return name, 1
}

func parseBench(r io.Reader) (benchCall, error) {
	call := benchCall{ok: map[string]bool{}}
	pkg := ""
	lines := bufio.NewScanner(r)
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for lines.Scan() {
		text := lines.Text()
		trimmed := strings.TrimSpace(text)
		switch {
		case strings.HasPrefix(text, "goos: "):
			call.goos = strings.TrimSpace(strings.TrimPrefix(text, "goos: "))
		case strings.HasPrefix(text, "goarch: "):
			call.goarch = strings.TrimSpace(strings.TrimPrefix(text, "goarch: "))
		case strings.HasPrefix(text, "pkg: "):
			pkg = strings.TrimSpace(strings.TrimPrefix(text, "pkg: "))
		case strings.HasPrefix(text, "cpu: "):
			call.cpu = strings.TrimSpace(strings.TrimPrefix(text, "cpu: "))
		case strings.HasPrefix(text, "ok "):
			if f := strings.Fields(text); len(f) >= 2 {
				call.ok[f[1]] = true
			}
		case strings.HasPrefix(text, "FAIL") || strings.HasPrefix(trimmed, "--- FAIL"):
			call.failed = true
		case strings.HasPrefix(trimmed, "--- SKIP: "):
			call.skipped = append(call.skipped, strings.Fields(strings.TrimPrefix(trimmed, "--- SKIP: "))[0])
		case strings.HasPrefix(text, "Benchmark"):
			f := strings.Fields(text)
			if len(f) < 4 || len(f)%2 != 0 {
				continue
			}
			n, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				continue
			}
			name, procs := splitProcs(f[0])
			line := benchLine{pkg: pkg, name: name, procs: procs, n: n, metrics: map[string]float64{}}
			for i := 2; i+1 < len(f); i += 2 {
				v, err := strconv.ParseFloat(f[i], 64)
				if err != nil {
					return call, fmt.Errorf("bench: %q: %v", text, err)
				}
				line.metrics[f[i+1]] = v
			}
			call.lines = append(call.lines, line)
		}
	}
	return call, lines.Err()
}

func (c benchCall) leaves() map[string]benchLine {
	out := map[string]benchLine{}
	for _, l := range c.lines {
		out[l.pkg+" "+l.name] = l
	}
	return out
}

type benchFlags struct {
	explicit      map[string]bool
	positional    int
	in            string
	grace, rotate time.Duration
	rev, out      string
}

type benchRow struct {
	Package       string             `json:"package"`
	Name          string             `json:"name"`
	Suite         string             `json:"suite"`
	Params        string             `json:"params"`
	Procs         int                `json:"procs"`
	SamplesNs     []float64          `json:"samples_ns"`
	MedianNs      *float64           `json:"median_ns"`
	MinNs         *float64           `json:"min_ns"`
	MaxNs         *float64           `json:"max_ns"`
	BytesPerOp    *float64           `json:"bytes_per_op_median"`
	AllocsPerOp   *float64           `json:"allocs_per_op_median"`
	OtherMedians  map[string]float64 `json:"other_medians"`
	samplesByCall map[int]float64
}

type benchRatio struct {
	Kind   string `json:"kind"`
	Num    string `json:"numerator"`
	Den    string `json:"denominator"`
	Pairs  int    `json:"pairs"`
	Ratio  perfCI `json:"ratio"`
	values []float64
}

type benchExpected struct {
	Suite        string   `json:"suite"`
	KeyMem       string   `json:"keymem"`
	ExpectedNs   *float64 `json:"expected_setup_ns"`
	Duty         *float64 `json:"duty_cycle"`
	ModelUniform bool     `json:"model_uniform_arrivals"`
}

type benchReport struct {
	Rev          string          `json:"rev"`
	GOOS         string          `json:"goos"`
	GOARCH       string          `json:"goarch"`
	CPU          string          `json:"cpu"`
	Virtualized  *bool           `json:"virtualized"`
	Calls        int             `json:"calls"`
	DroppedCalls int             `json:"dropped_calls"`
	Grace        string          `json:"grace"`
	Rotate       string          `json:"rotate"`
	Rows         []benchRow      `json:"rows"`
	SuiteRatio   []benchRatio    `json:"suite_ratio"`
	KeysRatio    []benchRatio    `json:"keys_ratio"`
	MlockRatio   []benchRatio    `json:"mlock_ratio"`
	Expected     []benchExpected `json:"expected_setup"`
}

var callFile = regexp.MustCompile(`^call-([1-9][0-9]*)\.txt$`)

type benchError struct {
	code int
	msg  string
}

func (e benchError) Error() string { return e.msg }

// reads one file per go test call, keeps the complete calls and pairs their
// leaves by call number
func benchFromDir(dir string, grace, rotate time.Duration) (benchReport, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return benchReport{}, benchError{2, fmt.Sprintf("bench: -bench-in: %v", err)}
	}
	calls := map[int]benchCall{}
	for _, e := range entries {
		m := callFile.FindStringSubmatch(e.Name())
		if m == nil || e.IsDir() {
			return benchReport{}, benchError{2, fmt.Sprintf("bench: %s is not a call-<k>.txt file", e.Name())}
		}
		k, _ := strconv.Atoi(m[1])
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			return benchReport{}, benchError{1, fmt.Sprintf("bench: %v", err)}
		}
		call, err := parseBench(f)
		f.Close()
		if err != nil {
			return benchReport{}, benchError{1, err.Error()}
		}
		if len(call.lines) == 0 {
			return benchReport{}, benchError{1, fmt.Sprintf("bench: %s holds no benchmark line", e.Name())}
		}
		calls[k] = call
	}
	if len(calls) == 0 {
		return benchReport{}, benchError{2, "bench: no call-<k>.txt file in -bench-in"}
	}
	return summariseBench(calls, grace, rotate)
}

func summariseBench(calls map[int]benchCall, grace, rotate time.Duration) (benchReport, error) {
	rep := benchReport{Grace: grace.String(), Rotate: rotate.String(), Rows: []benchRow{},
		SuiteRatio: []benchRatio{}, KeysRatio: []benchRatio{}, MlockRatio: []benchRatio{}, Expected: []benchExpected{}}
	ks := make([]int, 0, len(calls))
	for k := range calls {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	union := map[string]benchLine{}
	for _, k := range ks {
		for key, l := range calls[k].leaves() {
			if _, seen := union[key]; !seen {
				union[key] = l
			}
		}
	}
	var complete []int
	for _, k := range ks {
		c := calls[k]
		ok := !c.failed
		for _, p := range benchPackages {
			ok = ok && c.ok[p]
		}
		leaves := c.leaves()
		for key := range union {
			if _, has := leaves[key]; !has {
				ok = false
			}
		}
		if ok {
			complete = append(complete, k)
		} else {
			rep.DroppedCalls++
		}
		if rep.GOOS == "" {
			rep.GOOS, rep.GOARCH, rep.CPU = c.goos, c.goarch, c.cpu
		}
	}
	rep.Calls = len(complete)
	if len(complete) == 0 {
		return rep, benchError{1, "bench: no complete call"}
	}
	keys := make([]string, 0, len(union))
	for key := range union {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	byName := map[string]*benchRow{}
	for _, key := range keys {
		l := union[key]
		parts := strings.SplitN(l.name, "/", 3)
		row := benchRow{Package: l.pkg, Name: l.name, Procs: l.procs, OtherMedians: map[string]float64{}, samplesByCall: map[int]float64{}}
		if len(parts) > 1 {
			row.Suite = parts[1]
		}
		if len(parts) > 2 {
			row.Params = parts[2]
		}
		other := map[string][]float64{}
		var bytes, allocs []float64
		for _, k := range complete {
			cl := calls[k].leaves()[key]
			ns := cl.metrics["ns/op"]
			row.SamplesNs = append(row.SamplesNs, ns)
			row.samplesByCall[k] = ns
			for unit, v := range cl.metrics {
				switch unit {
				case "ns/op":
				case "B/op":
					bytes = append(bytes, v)
				case "allocs/op":
					allocs = append(allocs, v)
				default:
					other[unit] = append(other[unit], v)
				}
			}
		}
		row.MedianNs, row.MinNs, row.MaxNs = opt(metrics.Median(row.SamplesNs)), opt(slices.Min(row.SamplesNs)), opt(slices.Max(row.SamplesNs))
		row.BytesPerOp, row.AllocsPerOp = optMedian(bytes), optMedian(allocs)
		for unit, v := range other {
			row.OtherMedians[unit] = metrics.Median(v)
		}
		rep.Rows = append(rep.Rows, row)

	}
	for i := range rep.Rows {
		byName[rep.Rows[i].Package+" "+rep.Rows[i].Name] = &rep.Rows[i]
	}

	pair := func(kind string, num, den *benchRow) benchRatio {
		var x, y []float64
		for _, k := range complete {
			x, y = append(x, num.samplesByCall[k]), append(y, den.samplesByCall[k])
		}
		r, _ := metrics.Ratios(x, y)
		return benchRatio{Kind: kind, Num: num.Name, Den: den.Name, Pairs: len(r), Ratio: ciOf(r, perfLevel), values: r}
	}
	find := func(pkg, name string) *benchRow { return byName[pkg+" "+name] }
	replace := func(name, old, repl string) string {
		parts := strings.Split(name, "/")
		for i, p := range parts {
			if p == old {
				parts[i] = repl
				return strings.Join(parts, "/")
			}
		}
		return ""
	}
	for i := range rep.Rows {
		row := &rep.Rows[i]
		if row.Suite == "gost" {
			if den := find(row.Package, replace(row.Name, "gost", "c25519")); den != nil {
				rep.SuiteRatio = append(rep.SuiteRatio, pair("suite", row, den))
			}
		}
		if strings.Contains(row.Name, "/keys=2/") {
			base := strings.Replace(row.Name, "/keys=2/layer=current/", "/keys=1/", 1)
			base = strings.Replace(base, "/keys=2/layer=previous/", "/keys=1/", 1)
			if den := find(row.Package, base); den != nil {
				rep.KeysRatio = append(rep.KeysRatio, pair("keys", row, den))
			}
		}
		if strings.HasSuffix(row.Name, "/keymem=all") {
			if den := find(row.Package, strings.TrimSuffix(row.Name, "all")+"nolock"); den != nil {
				rep.MlockRatio = append(rep.MlockRatio, pair("mlock", row, den))
			}
		}
		if strings.HasSuffix(row.Name, "/keymem=nolock") && rep.GOOS == "linux" {
			if find(row.Package, strings.TrimSuffix(row.Name, "nolock")+"all") == nil {
				return rep, benchError{1, "bench: keymem=all skipped, memory locking unavailable"}
			}
		}
	}
	duty := metrics.DutyCycle(grace, rotate)
	for i := range rep.Rows {
		one := &rep.Rows[i]
		if !strings.HasPrefix(one.Name, "BenchmarkSetupAtNode/") || !strings.Contains(one.Name, "/keys=1/") {
			continue
		}
		cur := find(one.Package, strings.Replace(one.Name, "/keys=1/", "/keys=2/layer=current/", 1))
		prev := find(one.Package, strings.Replace(one.Name, "/keys=1/", "/keys=2/layer=previous/", 1))
		if cur == nil || prev == nil {
			continue
		}
		two := (val(cur.MedianNs) + val(prev.MedianNs)) / 2
		level := one.Name[strings.LastIndex(one.Name, "keymem=")+len("keymem="):]
		rep.Expected = append(rep.Expected, benchExpected{Suite: one.Suite, KeyMem: level,
			ExpectedNs: opt(metrics.ExpectedSetup(val(one.MedianNs), two, duty)), Duty: opt(duty), ModelUniform: true})
	}
	return rep, nil
}

func benchCommand(f benchFlags, stdout, stderr io.Writer) int {
	allowed := map[string]bool{"set": true, "bench-in": true, "bench-grace": true, "bench-rotate": true, "rev": true, "out": true}
	for name := range f.explicit {
		if !allowed[name] {
			fmt.Fprintf(stderr, "bench: -%s does not apply to the set\n", name)
			return 2
		}
	}
	switch {
	case f.positional != 0:
		fmt.Fprintln(stderr, "bench: no positional arguments")
		return 2
	case f.in == "":
		fmt.Fprintln(stderr, "bench: -bench-in names the directory of call-<k>.txt files")
		return 2
	case !(f.grace > 0 && f.grace <= f.rotate):
		fmt.Fprintln(stderr, "bench: need 0 < -bench-grace <= -bench-rotate")
		return 2
	case !revision.MatchString(f.rev):
		fmt.Fprintf(stderr, "bench: -rev %q: the 40 hex digits of the revision\n", f.rev)
		return 2
	}
	if st, err := os.Stat(f.in); err != nil || !st.IsDir() {
		fmt.Fprintln(stderr, "bench: -bench-in is not a directory")
		return 2
	}
	rep, err := benchFromDir(f.in, f.grace, f.rotate)
	if err != nil {
		code := 1
		if be, ok := err.(benchError); ok {
			code = be.code
		}
		fmt.Fprintln(stderr, err)
		return code
	}
	rep.Rev = f.rev
	if rep.GOOS == runtime.GOOS {
		if v, ok := perf.Virtualized(); ok {
			rep.Virtualized = &v
		}
	}
	fmt.Fprintf(stdout, "bench: %d complete calls, %d dropped, %d leaves\n", rep.Calls, rep.DroppedCalls, len(rep.Rows))
	for _, r := range rep.SuiteRatio {
		fmt.Fprintf(stdout, "%-60s gost/c25519 %s\n", r.Num, show(r.Ratio.Median, "%.2f"))
	}
	if err := write(stdout, f.out, "bench-"+time.Now().UTC().Format("20060102-150405"), rep); err != nil {
		fmt.Fprintf(stderr, "report: %v\n", err)
		return 1
	}
	return 0
}
