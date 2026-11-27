//go:build linux

package perf

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/lab"
)

func TestParseListKnownAnswer(t *testing.T) {
	got, err := parseList("0-2,5,7-8\n")
	if err != nil || !slices.Equal(got, []int{0, 1, 2, 5, 7, 8}) {
		t.Fatalf("parseList = %v, %v, want [0 1 2 5 7 8]", got, err)
	}
}

func TestChildPinsAndReports(t *testing.T) {
	allowed := Allowed()
	if len(allowed) < 2 {
		t.Skipf("%d allowed cpus, the test needs 2", len(allowed))
	}
	cpu := allowed[len(allowed)-1]
	dir := t.TempDir()
	child, err := Spawn(context.Background(), ChildConfig{Suite: jcrypto.SuiteC25519, KeyMem: "nolock", CPUs: []int{cpu}, Dir: dir})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	defer child.Kill()
	ready := child.Ready()
	if !ready.AffinityOK || ready.GOMAXPROCS != 1 || !slices.Equal(ready.CPUs, []int{cpu}) {
		t.Fatalf("ready %+v, want affinity on cpu %d and gomaxprocs 1", ready, cpu)
	}
	before, err := child.Snap()
	if err != nil {
		t.Fatalf("Snap: %v", err)
	}
	node := child.Node()
	if _, err := lab.Execute(lab.Config{Hops: 1, Flows: 2, Window: 2, Duration: 300 * time.Millisecond, Exit: &node, Seed: 2}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	after, err := child.Snap()
	if err != nil {
		t.Fatalf("Snap: %v", err)
	}
	final, err := child.Close()
	if err != nil {
		t.Fatalf("Close: %v; %s", err, child.Stderr())
	}
	for _, s := range []Snapshot{before, after, final} {
		if !s.AffinityOK || s.GOMAXPROCS != 1 {
			t.Fatalf("snapshot %+v: every thread on cpu %d with gomaxprocs 1 expected", s, cpu)
		}
	}
	if after.Counters.Delivered <= before.Counters.Delivered || after.MonoNs <= before.MonoNs || after.CPUNs < before.CPUNs || final.MonoNs < after.MonoNs {
		t.Fatalf("snapshots do not grow: %+v, %+v, %+v", before, after, final)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("the child left %d entries in its working directory (%v)", len(entries), err)
	}
}

func TestChildLockedUnderAll(t *testing.T) {
	if budget, err := secmem.MemlockBudget(); err != nil || budget < 1<<20 {
		t.Skipf("memlock budget %d below 1 MiB (%v)", budget, err)
	}
	for _, c := range []struct {
		level  string
		locked bool
	}{{"all", true}, {"nolock", false}} {
		child, err := Spawn(context.Background(), ChildConfig{Suite: jcrypto.SuiteC25519, KeyMem: c.level})
		if err != nil {
			t.Fatalf("%s: Spawn: %v", c.level, err)
		}
		locked := child.Ready().Locked
		if _, err := child.Close(); err != nil {
			t.Fatalf("%s: Close: %v", c.level, err)
		}
		if locked != c.locked {
			t.Fatalf("%s: locked %v, want %v", c.level, locked, c.locked)
		}
	}
}

func TestHostTimesMonotone(t *testing.T) {
	cpus := Allowed()
	a, ok := HostTimes(cpus)
	cpuA, okA := ProcessCPU()
	if !ok || !okA {
		t.Fatal("HostTimes or ProcessCPU unreadable on linux")
	}
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
	}
	b, ok := HostTimes(cpus)
	cpuB, okB := ProcessCPU()
	if !ok || !okB {
		t.Fatal("HostTimes or ProcessCPU unreadable on linux")
	}
	d := b.Sub(a)
	for name, v := range map[string]time.Duration{"user": d.User, "nice": d.Nice, "system": d.System, "irq": d.Irq, "softirq": d.Softirq, "steal": d.Steal, "process": cpuB - cpuA} {
		if v < 0 {
			t.Fatalf("%s went back by %v", name, -v)
		}
	}
}

func TestVirtualizedReads(t *testing.T) {
	if _, ok := Virtualized(); !ok {
		t.Fatal("Virtualized could not read /proc/cpuinfo")
	}
}

func TestTopologyLeavesTheFirstCoreAlone(t *testing.T) {
	topo, err := Topology(1)
	if err != nil {
		t.Skipf("Topology(1): %v", err)
	}
	first := Allowed()[0]
	for _, c := range append(append(slices.Clone(topo.Node), topo.Siblings...), topo.Load...) {
		if c == first {
			t.Fatalf("cpu %d, the smallest allowed, was handed out: %+v", first, topo)
		}
	}
	if len(topo.Node) != 1 || len(topo.Load) < 1 {
		t.Fatalf("topology %+v: one node cpu and some load expected", topo)
	}
}
