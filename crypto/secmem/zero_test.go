package secmem_test

import (
	"runtime/metrics"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// FreeOSMemory forces a collection, and the runtime counts those apart from
// the ones it starts itself
func forcedCollections() uint64 {
	s := []metrics.Sample{{Name: "/gc/cycles/forced:gc-cycles"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}

func TestReturnFreedOnlyUnderZeroing(t *testing.T) {
	defer func() { _ = secmem.SetPolicy(secmem.Protected) }()
	for _, tc := range []struct {
		policy secmem.Policy
		want   uint64
	}{
		{secmem.Protected, 1},
		{secmem.Policy{Zero: true}, 1},
		{secmem.Policy{OffHeap: true, Lock: true, DontDump: true}, 0},
		{secmem.Baseline, 0},
	} {
		if err := secmem.SetPolicy(tc.policy); err != nil {
			t.Fatal(err)
		}
		before := forcedCollections()
		secmem.ReturnFreed()
		if got := forcedCollections() - before; got != tc.want {
			t.Fatalf("ReturnFreed under %v forced %d collections, want %d", tc.policy, got, tc.want)
		}
	}
}
