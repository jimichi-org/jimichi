//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimichi-org/jimichi/lab/perf"
)

// a runner with few CPUs and SMT has nothing left for the load once the
// controller's core and the siblings are reserved; that is a skip, not a fault
func TestPerfNodeFromTheCommandLine(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a pinned child for seconds")
	}
	if _, err := perf.Topology(1); errors.Is(err, perf.ErrCoresUnavailable) {
		t.Skipf("cores_unavailable: %v", err)
	} else if err != nil {
		t.Fatalf("Topology: %v", err)
	}
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	args := []string{"-set", "perf", "-perf-parts", "node", "-perf-cores", "1", "-perf-circuits", "1,2", "-perf-keymem", "nolock",
		"-duration", "1s", "-perf-warmup", "100ms", "-perf-inflight", "2", "-repeats", "1", "-rev", testRev, "-out", dir}
	if code := command(args, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "perf-*.json"))
	if len(files) != 1 {
		t.Fatalf("reports %v", files)
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2*2+1 {
		t.Fatalf("%d rows, want 4 and a warmup", len(rows))
	}
	for _, r := range rows {
		if r["affinity_ok"] != true || r["bound"] == "" || r["bound"] == nil {
			t.Fatalf("row affinity %v, bound %v", r["affinity_ok"], r["bound"])
		}
		if r["node_dumpable"] != 0.0 || r["noise_checked"] != true {
			t.Fatalf("row node_dumpable %v, noise_checked %v: want a hardened child and a read host load", r["node_dumpable"], r["noise_checked"])
		}
	}
}
