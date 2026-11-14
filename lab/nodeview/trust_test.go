package nodeview

import (
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestDelayedContactOrphanIsExactRegisteredException(t *testing.T) {
	c := Config{Set: Compromise, Phase: Structural, Suite: jcrypto.SuiteC25519, Revision: strings.Repeat("a", 40)}
	for _, row := range foreignTrustCoordinates() {
		got := registeredOrphan(c, row)
		want := row.ID == "trust-peer-honest-k1-m1" || row.ID == "trust-peer-honest-k1-m2"
		if got != want {
			t.Fatalf("unexpected orphan availability for %s", row.ID)
		}
		for _, phase := range []Phase{Train, Pilot, Primary} {
			other := c
			other.Phase = phase
			if registeredOrphan(other, row) {
				t.Fatal("orphan exception escaped structural phase")
			}
		}
	}
}

func TestDefaultsControlOffsetsAreExactlyRegistered(t *testing.T) {
	// each active ten-second segment has fifty offsets, 0.1+0.2*j seconds
	offsets := defaultsOffsets()
	if len(offsets) != 100 || offsets[0] != 100000000 || offsets[49] != 9900000000 || offsets[50] != 20100000000 || offsets[99] != 29900000000 {
		t.Fatal("defaults control cardinality or endpoints changed")
	}
	for i, offset := range offsets {
		if offset < 0 || offset >= 30000000000 || offset >= 10000000000 && offset < 20000000000 || i > 0 && offset <= offsets[i-1] {
			t.Fatal("invalid defaults source offset")
		}
		if i != 0 && i != 50 && offset-offsets[i-1] != 200000000 {
			t.Fatal("defaults period changed")
		}
	}
}
