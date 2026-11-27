package perf

import (
	"context"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab"
)

// the protocol without pinning, on any system: the child serves a chain of one
// node, its counters and clocks only grow, and the final snapshot comes on EOF
func TestChildServesAChainOfOneNode(t *testing.T) {
	child, err := Spawn(context.Background(), ChildConfig{Suite: jcrypto.SuiteC25519, KeyMem: "nolock", Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	defer child.Kill()
	before, err := child.Snap()
	if err != nil {
		t.Fatalf("Snap: %v; %s", err, child.Stderr())
	}
	node := child.Node()
	run, err := lab.Execute(lab.Config{Hops: 1, Flows: 2, Window: 2, FullPayload: true, Duration: 300 * time.Millisecond, Exit: &node, Seed: 1})
	if err != nil {
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
	if len(run.Latency) == 0 || run.LocalRelays != 0 {
		t.Fatalf("%d echoes and %d local relays, want echoes through the child alone", len(run.Latency), run.LocalRelays)
	}
	if after.Counters.Delivered <= before.Counters.Delivered || final.Counters.Delivered < after.Counters.Delivered {
		t.Fatalf("delivered %d, %d, %d: want growth", before.Counters.Delivered, after.Counters.Delivered, final.Counters.Delivered)
	}
	if after.MonoNs <= before.MonoNs || final.MonoNs < after.MonoNs || after.CPUNs < before.CPUNs {
		t.Fatalf("clocks %d, %d, %d and cpu %d, %d: want growth", before.MonoNs, after.MonoNs, final.MonoNs, before.CPUNs, after.CPUNs)
	}
}

func TestMaybeRunChildRefusesExtraArguments(t *testing.T) {
	if handled, code := MaybeRunChild([]string{childArg, "x"}); !handled || code != 2 {
		t.Fatalf("MaybeRunChild with an extra argument = %v, %d, want true, 2", handled, code)
	}
	if handled, _ := MaybeRunChild([]string{"-set", "perf"}); handled {
		t.Fatal("MaybeRunChild took ordinary arguments")
	}
}
