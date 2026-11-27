//go:build linux

package lab

import (
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestKeyMemReachesTheRelays(t *testing.T) {
	if budget, err := secmem.MemlockBudget(); err != nil || budget < 1<<20 {
		t.Skipf("memlock budget %d below 1 MiB (%v)", budget, err)
	}
	nolock := secmem.Policy{OffHeap: true, DontDump: true, Zero: true}
	for _, c := range []struct {
		policy secmem.Policy
		locked bool
	}{{secmem.Protected, true}, {nolock, false}} {
		run, err := Execute(Config{Hops: 2, Flows: 1, Duration: 100 * time.Millisecond, SendEvery: 20 * time.Millisecond, KeyMem: &c.policy, Seed: 12})
		if err != nil {
			t.Fatalf("%v: Execute: %v", c.policy, err)
		}
		if run.KeysLocked != c.locked || run.LocalRelays != 2 {
			t.Fatalf("%v: KeysLocked %v with %d relays, want %v with 2", c.policy, run.KeysLocked, run.LocalRelays, c.locked)
		}
	}
}
