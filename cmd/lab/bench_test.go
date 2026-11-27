package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// real output of go test -run '^$' -bench ... -benchmem -benchtime 1x -cpu 1
// on linux: with GOMAXPROCS 1 the names carry no -<procs> suffix
const realCPU1 = `goos: linux
goarch: amd64
pkg: github.com/jimichi-org/jimichi/relay
cpu: AMD Ryzen 9 9950X3D 16-Core Processor
BenchmarkSetupAtNode/c25519/keys=1/keymem=all         	       1	     86065 ns/op	    6968 B/op	      99 allocs/op
BenchmarkSetupAtNode/c25519/keys=1/keymem=nolock      	       1	     91384 ns/op	    6968 B/op	      99 allocs/op
PASS
ok  	github.com/jimichi-org/jimichi/relay	0.100s
goos: linux
goarch: amd64
pkg: github.com/jimichi-org/jimichi/wire
cpu: AMD Ryzen 9 9950X3D 16-Core Processor
BenchmarkSeal/c25519/hops=1  	       1	      4300 ns/op	 119.07 MB/s	    1544 B/op	       5 allocs/op
BenchmarkWrap/c25519/pos=entry         	       1	       920.0 ns/op	 556.52 MB/s	    1064 B/op	       4 allocs/op
PASS
ok  	github.com/jimichi-org/jimichi/wire	0.317s
`

// and with -cpu 8, where the suffix is there
const realCPU8 = `BenchmarkSetupAtNode/c25519/keys=1/keymem=all-8         	       1	    102355 ns/op	    6968 B/op	      99 allocs/op
`

func TestParseBenchReadsRealOutput(t *testing.T) {
	call, err := parseBench(strings.NewReader(realCPU1))
	if err != nil {
		t.Fatal(err)
	}
	if call.goos != "linux" || call.goarch != "amd64" || !strings.HasPrefix(call.cpu, "AMD Ryzen") || call.failed {
		t.Fatalf("headers %q %q %q, failed %v", call.goos, call.goarch, call.cpu, call.failed)
	}
	if !call.ok["github.com/jimichi-org/jimichi/relay"] || !call.ok["github.com/jimichi-org/jimichi/wire"] {
		t.Fatalf("ok lines %v", call.ok)
	}
	if len(call.lines) != 4 {
		t.Fatalf("%d benchmark lines, want 4", len(call.lines))
	}
	first, wrap := call.lines[0], call.lines[3]
	if first.name != "BenchmarkSetupAtNode/c25519/keys=1/keymem=all" || first.procs != 1 || first.pkg != "github.com/jimichi-org/jimichi/relay" ||
		first.metrics["ns/op"] != 86065 || first.metrics["B/op"] != 6968 || first.metrics["allocs/op"] != 99 {
		t.Fatalf("first line %+v", first)
	}
	if wrap.name != "BenchmarkWrap/c25519/pos=entry" || wrap.pkg != "github.com/jimichi-org/jimichi/wire" || wrap.metrics["ns/op"] != 920 || wrap.metrics["MB/s"] != 556.52 {
		t.Fatalf("wrap line %+v", wrap)
	}
	call, err = parseBench(strings.NewReader(realCPU8))
	if err != nil || len(call.lines) != 1 {
		t.Fatalf("%v, %d lines", err, len(call.lines))
	}
	if l := call.lines[0]; l.name != "BenchmarkSetupAtNode/c25519/keys=1/keymem=all" || l.procs != 8 {
		t.Fatalf("suffixed line: name %q, procs %d, want the name without -8 and procs 8", l.name, l.procs)
	}
}

// a synthetic call: both suites of two leaves in relay and one in wire, an
// extra metric, and a change of package in the middle
func syntheticCall(c25519, gost float64, okWire bool, skipLeaf bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "goos: windows\ngoarch: amd64\npkg: github.com/jimichi-org/jimichi/relay\ncpu: test\n")
	fmt.Fprintf(&b, "BenchmarkSetupAtNode/c25519/keys=1/keymem=heap \t 1 \t %v ns/op \t 10 B/op \t 2 allocs/op\n", c25519)
	fmt.Fprintf(&b, "BenchmarkSetupAtNode/gost/keys=1/keymem=heap \t 1 \t %v ns/op \t 30 B/op \t 6 allocs/op\n", gost)
	fmt.Fprintf(&b, "PASS\nok  \tgithub.com/jimichi-org/jimichi/relay\t0.1s\n")
	fmt.Fprintf(&b, "goos: windows\ngoarch: amd64\npkg: github.com/jimichi-org/jimichi/wire\ncpu: test\n")
	fmt.Fprintf(&b, "BenchmarkSeal/c25519/hops=1 \t 1 \t %v ns/op \t 5.5 MB/s \t 1 B/op \t 1 allocs/op\n", c25519/10)
	if !skipLeaf {
		fmt.Fprintf(&b, "BenchmarkSeal/gost/hops=1 \t 1 \t %v ns/op \t 2.5 MB/s \t 1 B/op \t 1 allocs/op\n", gost/10)
	}
	if okWire {
		fmt.Fprintf(&b, "PASS\nok  \tgithub.com/jimichi-org/jimichi/wire\t0.1s\n")
	} else {
		fmt.Fprintf(&b, "signal: killed\n")
	}
	return b.String()
}

func parsedCalls(t *testing.T, texts ...string) map[int]benchCall {
	t.Helper()
	out := map[int]benchCall{}
	for i, s := range texts {
		c, err := parseBench(strings.NewReader(s))
		if err != nil {
			t.Fatal(err)
		}
		out[i+1] = c
	}
	return out
}

func benchRowNamed(t *testing.T, rep benchReport, name string) benchRow {
	t.Helper()
	for _, r := range rep.Rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no row %s", name)
	return benchRow{}
}

// c25519 {100, 110} and gost {300, 330} in calls 1 and 2: the ratio per call is
// {3, 3}, median 3. Call 3 has no ok line for wire and call 4 lacks one leaf:
// both are dropped, and the samples come from calls 1 and 2 alone
func TestBenchPairsCompleteCallsOnly(t *testing.T) {
	calls := parsedCalls(t,
		syntheticCall(100, 300, true, false),
		syntheticCall(110, 330, true, false),
		syntheticCall(999, 1, false, false),
		syntheticCall(999, 1, true, true),
	)
	rep, err := summariseBench(calls, 22*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Calls != 2 || rep.DroppedCalls != 2 {
		t.Fatalf("%d calls, %d dropped, want 2 and 2", rep.Calls, rep.DroppedCalls)
	}
	setup := benchRowNamed(t, rep, "BenchmarkSetupAtNode/c25519/keys=1/keymem=heap")
	if !nearAll(setup.SamplesNs, []float64{100, 110}) || *setup.MedianNs != 105 || setup.Suite != "c25519" || setup.Params != "keys=1/keymem=heap" {
		t.Fatalf("setup row %+v", setup)
	}
	seal := benchRowNamed(t, rep, "BenchmarkSeal/gost/hops=1")
	if !nearAll(seal.SamplesNs, []float64{30, 33}) || seal.OtherMedians["MB/s"] != 2.5 || *seal.BytesPerOp != 1 {
		t.Fatalf("seal row %+v", seal)
	}
	var found bool
	for _, r := range rep.SuiteRatio {
		if r.Num == "BenchmarkSetupAtNode/gost/keys=1/keymem=heap" {
			found = true
			if !nearAll(r.values, []float64{3, 3}) || *r.Ratio.Median != 3 || r.Ratio.Low != nil {
				t.Fatalf("suite ratio %+v, want {3, 3}, median 3, no interval at 2 pairs", r)
			}
		}
	}
	if !found {
		t.Fatal("no suite ratio for the setup")
	}
}

// with 10 calls the order interval of the median at 0.95 is x(2)..x(9):
// P(K <= 1) = 11/1024 <= 0.025 < P(K <= 2) = 56/1024
func TestBenchIntervalAtTenCalls(t *testing.T) {
	var texts []string
	for i := 1; i <= 10; i++ {
		texts = append(texts, syntheticCall(100, float64(300+i), true, false))
	}
	rep, err := summariseBench(parsedCalls(t, texts...), 22*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.SuiteRatio {
		if r.Num == "BenchmarkSetupAtNode/gost/keys=1/keymem=heap" {
			// ratios 3.01 .. 3.10: x(2) = 3.02, x(9) = 3.09
			if !near(*r.Ratio.Low, 3.02) || !near(*r.Ratio.High, 3.09) {
				t.Fatalf("interval [%v, %v], want [3.02, 3.09]", *r.Ratio.Low, *r.Ratio.High)
			}
			return
		}
	}
	t.Fatal("no suite ratio")
}

// keys=1 100 and keys=2 200 at duty 22/60: 100 + (22/60)*100 = 136.67
func TestBenchExpectedSetup(t *testing.T) {
	text := "goos: linux\npkg: github.com/jimichi-org/jimichi/relay\n" +
		"BenchmarkSetupAtNode/c25519/keys=1/keymem=nolock \t 1 \t 100 ns/op\n" +
		"BenchmarkSetupAtNode/c25519/keys=2/layer=current/keymem=nolock \t 1 \t 190 ns/op\n" +
		"BenchmarkSetupAtNode/c25519/keys=2/layer=previous/keymem=nolock \t 1 \t 210 ns/op\n" +
		"BenchmarkSetupAtNode/c25519/keys=1/keymem=all \t 1 \t 100 ns/op\n" +
		"BenchmarkSetupAtNode/c25519/keys=2/layer=current/keymem=all \t 1 \t 200 ns/op\n" +
		"BenchmarkSetupAtNode/c25519/keys=2/layer=previous/keymem=all \t 1 \t 200 ns/op\n" +
		"ok  \tgithub.com/jimichi-org/jimichi/relay\t0.1s\nok  \tgithub.com/jimichi-org/jimichi/wire\t0.1s\n"
	rep, err := summariseBench(parsedCalls(t, text), 22*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Expected) != 2 {
		t.Fatalf("%d expected rows, want 2", len(rep.Expected))
	}
	for _, e := range rep.Expected {
		if !nearEps(*e.ExpectedNs, 136.6667, 1e-3) || !e.ModelUniform {
			t.Fatalf("expected %+v, want 136.67", e)
		}
	}
	if len(rep.MlockRatio) != 3 || len(rep.KeysRatio) != 4 {
		t.Fatalf("%d mlock and %d keys ratios, want 3 and 4", len(rep.MlockRatio), len(rep.KeysRatio))
	}
}

func TestBenchRefusesNolockWithoutAllOnLinux(t *testing.T) {
	text := "goos: linux\npkg: github.com/jimichi-org/jimichi/relay\n" +
		"BenchmarkSetupAtNode/c25519/keys=1/keymem=nolock \t 1 \t 100 ns/op\n" +
		"ok  \tgithub.com/jimichi-org/jimichi/relay\t0.1s\nok  \tgithub.com/jimichi-org/jimichi/wire\t0.1s\n"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "call-1.txt"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := command([]string{"-set", "bench", "-bench-in", dir, "-rev", strings.Repeat("a", 40), "-out", t.TempDir()}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "keymem=all skipped") {
		t.Fatalf("exit %d, stderr %q, want 1 and the skipped level named", code, errOut.String())
	}
}

func TestBenchWritesItsReport(t *testing.T) {
	dir := t.TempDir()
	for k, s := range []string{syntheticCall(100, 300, true, false), syntheticCall(110, 330, true, false)} {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("call-%d.txt", k+1)), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := command([]string{"-set", "bench", "-bench-in", dir, "-rev", strings.Repeat("b", 40), "-out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if files, _ := filepath.Glob(filepath.Join(out, "bench-*.json")); len(files) != 1 {
		t.Fatalf("%d bench reports, want 1", len(files))
	}
}

func near(a, b float64) bool { return nearEps(a, b, 1e-9) }

func nearEps(a, b, eps float64) bool {
	d := a - b
	return d < eps && d > -eps
}

func nearAll(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !near(a[i], b[i]) {
			return false
		}
	}
	return true
}
