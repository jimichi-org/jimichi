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
