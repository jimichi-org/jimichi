package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/lab"
)

// the configuration a row of a correlation set must carry, as the report
// writes it
type setRow struct {
	traffic, mode, rate, cover, relay string
}

// runs one correlation set through the command on three flows over the given
// number of relays and suite, for 300 ms each, and checks what it prints and writes: one row per variant
// and window in the order of the set, every row with the configuration of its
// variant and of the flags, the detail of every run and a summary line per
// row. Timing decides the scores, so only the structure is checked, and that
// a run without protection carries no frame beyond the messages sent
func runSet(t *testing.T, set string, hops int, suiteName string, want []setRow) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs a live chain for every variant of the set")
	}
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	status := command([]string{"-set", set, "-flows", "3", "-hops", strconv.Itoa(hops), "-suite", suiteName,
		"-duration", "300ms", "-send", "30ms", "-bins", "50ms,100ms", "-seed", "3", "-rev", "abc", "-out", dir}, &out, &errOut)
	if status != 0 || errOut.Len() != 0 {
		t.Fatalf("status %d, stderr %q", status, errOut.String())
	}

	names := reports(t, dir)
	named := regexp.MustCompile(`^(correlation|detail|summary)-` + set + `-(\d{8}-\d{6})\.json$`)
	files := map[string]string{}
	stamps := map[string]bool{}
	for _, n := range names {
		m := named.FindStringSubmatch(n)
		if m == nil {
			t.Fatalf("report %s does not name its kind and the set %s", n, set)
		}
		files[m[1]] = filepath.Join(dir, n)
		stamps[m[2]] = true
	}
	if len(names) != 3 || len(files) != 3 || len(stamps) != 1 {
		t.Fatalf("reports %v, want a correlation, a detail and a summary of one run of the command", names)
	}
	read := func(kind string, v any) {
		t.Helper()
		raw, err := os.ReadFile(files[kind])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !strings.Contains(out.String(), "report: "+files[kind]) {
			t.Errorf("the path of the %s report is not printed", kind)
		}
	}

	var rows []result
	read("correlation", &rows)
	bins := []string{"50ms", "100ms"}
	if len(rows) != len(want)*len(bins) {
		t.Fatalf("%d rows, want %d variants at %d windows", len(rows), len(want), len(bins))
	}
	for i, r := range rows {
		w, bin := want[i/len(bins)], bins[i%len(bins)]
		got := setRow{r.Traffic, r.Mode, r.Rate, r.CoverEvery, r.RelayPeriod}
		if got != w || r.Bin != bin {
			t.Errorf("row %d: %+v at %s, want %+v at %s", i, got, r.Bin, w, bin)
		}
		if r.Flows != 3 || r.Hops != hops || r.Duration != "300ms" || r.Send != "30ms" || r.Rev != "abc" ||
			r.Suite != suiteName || r.BaseSeed != 3 || r.Seed != lab.Derive(3, 0) || r.Repeat != 0 {
			t.Errorf("row %d does not carry the flags: %s", i, encode(t, r))
		}
		if r.Messages == 0 || r.Cells == 0 {
			t.Errorf("row %d: %d messages in %d cells", i, r.Messages, r.Cells)
		}
		// both windows score the same run, and its cost does not depend on them
		if first := rows[i-i%len(bins)]; r.Messages != first.Messages || r.Cells != first.Cells || r.RelayMultiplier != first.RelayMultiplier {
			t.Errorf("row %d: the windows of one run count %d and %d messages, %d and %d cells, x%v and x%v between relays",
				i, first.Messages, r.Messages, first.Cells, r.Cells, first.RelayMultiplier, r.RelayMultiplier)
		}
		if r.Traffic == "none" && (r.Multiplier > 1 || r.RelayMultiplier > 1) {
			t.Errorf("row %d: x%v at the entry and x%v between relays without protection, want no frame beyond the messages",
				i, r.Multiplier, r.RelayMultiplier)
		}
	}

	var details []detail
	read("detail", &details)
	if len(details) != len(rows) {
		t.Fatalf("%d details for %d rows", len(details), len(rows))
	}
	for i, d := range details {
		if d.Traffic != rows[i].Traffic || d.Bin != rows[i].Bin || len(d.Entry) != 3 || len(d.Exit) != 3 || len(d.Scores) != 3 {
			t.Errorf("detail %d: %s at %s with %d entry, %d exit and %d score rows; want the row %s at %s and 3 of each",
				i, d.Traffic, d.Bin, len(d.Entry), len(d.Exit), len(d.Scores), rows[i].Traffic, rows[i].Bin)
		}
	}

	var sum []summary
	read("summary", &sum)
	if len(sum) != len(rows) {
		t.Fatalf("%d summary lines for %d rows", len(sum), len(rows))
	}
	for i, s := range sum {
		if s.Traffic != rows[i].Traffic || s.Bin != rows[i].Bin || s.Suite != suiteName || s.Runs != 1 {
			t.Errorf("summary line %d: %s", i, encode(t, s))
		}
	}

	printed := map[string]int{}
	for _, l := range strings.Split(out.String(), "\n") {
		if f := strings.Fields(l); len(f) > 1 {
			printed[f[0]+" "+f[1]]++
		}
	}
	for _, w := range want {
		for _, bin := range bins {
			// once as a row of the run and once in the summary
			if n := printed[w.traffic+" "+bin]; n != 2 {
				t.Errorf("%s at %s printed %d times, want 2:\n%s", w.traffic, bin, n, out.String())
			}
		}
	}
}

func TestMainSetFromTheCommandLine(t *testing.T) {
	runSet(t, "main", 2, "gost", []setRow{
		{"none", "immediate", "0s", "0s", "0s"},
		{"add-0.5x", "immediate", "0s", "400ms", "0s"},
		{"add-1x", "immediate", "0s", "200ms", "0s"},
		{"add-2x", "immediate", "0s", "100ms", "0s"},
		{"fixed-1x", "constant-rate", "200ms", "0s", "0s"},
		{"fixed-2x", "constant-rate", "100ms", "0s", "0s"},
		{"fixed-4x", "constant-rate", "50ms", "0s", "0s"},
	})
}

func TestRatesSetFromTheCommandLine(t *testing.T) {
	runSet(t, "rates", 4, "c25519", []setRow{
		{"none", "immediate", "0s", "0s", "0s"},
		{"fixed-200ms", "constant-rate", "200ms", "0s", "0s"},
		{"fixed-140ms", "constant-rate", "140ms", "0s", "0s"},
		{"fixed-100ms", "constant-rate", "100ms", "0s", "0s"},
		{"fixed-70ms", "constant-rate", "70ms", "0s", "0s"},
		{"fixed-50ms", "constant-rate", "50ms", "0s", "0s"},
		{"fixed-35ms", "constant-rate", "35ms", "0s", "0s"},
		{"fixed-25ms", "constant-rate", "25ms", "0s", "0s"},
	})
}

// relays tick 5% faster than the client: 70 ms * 0.95 = 66.5 ms and
// 35 ms * 0.95 = 33.25 ms
func TestPacedSetFromTheCommandLine(t *testing.T) {
	runSet(t, "paced", 3, "c25519", []setRow{
		{"none", "immediate", "0s", "0s", "0s"},
		{"fixed-70ms", "constant-rate", "70ms", "0s", "0s"},
		{"relay-70ms", "immediate", "0s", "0s", "66.5ms"},
		{"both-70ms", "constant-rate", "70ms", "0s", "66.5ms"},
		{"fixed-35ms", "constant-rate", "35ms", "0s", "0s"},
		{"relay-35ms", "immediate", "0s", "0s", "33.25ms"},
		{"both-35ms", "constant-rate", "35ms", "0s", "33.25ms"},
	})
}

// two training and two claim runs of each level on three flows for a second:
// the structure of the reports, and that every run is clean and its labels
// agree, which every value of the set rests on. A host whose clock moves in
// coarse steps is refused by the set, so the test does not run there
func TestCoverSetFromTheCommandLine(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live chain for every run of the set")
	}
	start := time.Now()
	if step := clockStep(func() time.Duration { return time.Since(start) }, 20); step > coverClockLimit {
		t.Skipf("the monotonic clock moves in steps of %v, above %v", step, coverClockLimit)
	}
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	status := command([]string{"-set", "cover", "-flows", "3", "-hops", "3", "-suite", "c25519", "-duration", "1s",
		"-send", "200ms", "-train", "2", "-repeats", "2", "-seed", "3", "-rev", "abc", "-out", dir}, &out, &errOut)
	if status != 0 || errOut.Len() != 0 {
		t.Fatalf("status %d, stderr %q", status, errOut.String())
	}

	names := reports(t, dir)
	named := regexp.MustCompile(`^(cells|summary)-cover-(\d{8}-\d{6})\.json$`)
	files := map[string]string{}
	stamps := map[string]bool{}
	for _, n := range names {
		m := named.FindStringSubmatch(n)
		if m == nil {
			t.Fatalf("report %s", n)
		}
		files[m[1]] = filepath.Join(dir, n)
		stamps[m[2]] = true
	}
	if len(names) != 2 || len(files) != 2 || len(stamps) != 1 {
		t.Fatalf("reports %v, want the cells and the summary of one run of the command", names)
	}
	read := func(kind string, v any) {
		t.Helper()
		raw, err := os.ReadFile(files[kind])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !strings.Contains(out.String(), "report: "+files[kind]) {
			t.Errorf("the path of the %s report is not printed", kind)
		}
	}

	var rows []coverRow
	read("cells", &rows)
	if len(rows) != 8 {
		t.Fatalf("%d rows, want 8", len(rows))
	}
	step := rows[0].ClockStep
	if d, err := time.ParseDuration(step); err != nil || d <= 0 || d > coverClockLimit {
		t.Errorf("clock step %q", step)
	}
	for i, r := range rows {
		traffic, mode := "add-1x", "immediate"
		if i >= 4 {
			traffic, mode = "fixed-2x", "constant-rate"
		}
		role, rep, seed := "training", i%4, lab.Derive(3, lab.StreamTraining, uint64(i%4))
		if i%4 >= 2 {
			role, rep, seed = "claim", i%4-2, lab.Derive(3, uint64(i%4-2))
		}
		if r.Role != role || r.Traffic != traffic || r.Mode != mode || r.Repeat != rep || r.Seed != seed || r.BaseSeed != 3 ||
			r.Flows != 3 || r.Hops != 3 || r.Duration != "1s" || r.Send != "200ms" || r.Suite != "c25519" || r.Rev != "abc" ||
			r.ClockStep != step {
			t.Errorf("row %d does not carry the flags: %s", i, encode(t, r))
		}
		if r.broken() || r.limited() {
			t.Fatalf("row %d is not clean: %s", i, encode(t, r))
		}
		if r.LabelMismatch || r.PayloadLabels != r.Messages-int(r.Dropped) {
			t.Fatalf("row %d: labels disagree: %s", i, encode(t, r))
		}
		if r.PayloadCells == nil || r.CoverCells == nil || r.UndefinedCells == nil ||
			*r.PayloadCells+*r.CoverCells+*r.UndefinedCells != r.Cells || *r.PayloadCells == 0 || *r.CoverCells == 0 {
			t.Errorf("row %d: cells %d against %s payload, %s cover and %s undefined",
				i, r.Cells, dashInt(r.PayloadCells), dashInt(r.CoverCells), dashInt(r.UndefinedCells))
		}
		if (r.AUC == nil) != (r.Degenerate != "") || r.AUC != nil && (*r.AUC < 0 || *r.AUC > 1) {
			t.Errorf("row %d: lda_auc %s with degenerate %q", i, dash(r.AUC), r.Degenerate)
		}
	}

	var sum coverSummary
	read("summary", &sum)
	if sum.Set != "cover" || sum.ClockStep != step || len(sum.Levels) != 2 || len(sum.Tests) != 7 {
		t.Fatalf("summary %s", encode(t, sum))
	}
	for i, l := range sum.Levels {
		if l.TrainingRuns != 2 || l.Runs != 2 || l.EquivalenceClaim != (i == 1) ||
			l.CorridorLow != nil || l.CorridorHigh != nil || l.Corridor != nil {
			t.Errorf("level %d: %s", i, encode(t, l))
		}
	}
	families := map[string]int{}
	for _, c := range sum.Tests {
		families[c.Family]++
	}
	if families["null"] != 4 || families["modes"] != 3 {
		t.Errorf("tests %v, want 4 against the null and 3 between the modes", families)
	}

	printed := map[string]int{}
	for _, l := range strings.Split(out.String(), "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) > 2 && (f[0] == "training" || f[0] == "claim"):
			printed[f[0]+" "+f[1]+" "+f[2]]++
		case len(f) > 1 && (f[0] == "level" || f[0] == "test"):
			printed[f[0]]++
		case strings.HasPrefix(l, "clock step "):
			printed["clock"]++
		}
	}
	if printed["clock"] != 1 || printed["level"] != 2 || printed["test"] != 7 {
		t.Errorf("printed %v:\n%s", printed, out.String())
	}
	for _, r := range rows {
		if n := printed[r.Role+" "+r.Traffic+" "+strconv.Itoa(r.Repeat)]; n != 1 {
			t.Errorf("%s %s %d printed %d times", r.Role, r.Traffic, r.Repeat, n)
		}
	}
}
