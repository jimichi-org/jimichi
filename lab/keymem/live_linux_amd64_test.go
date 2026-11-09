//go:build linux && amd64

package keymem

import (
	"context"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestKeymemLiveOptimized(t *testing.T) {
	if testing.Short() {
		t.Skip("optimized live gate runs separately")
	}
	if raceEnabled {
		t.Skip("race instrumentation changes the observed heap")
	}
	for _, suite := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		report, err := Run(context.Background(), Config{Suite: suite, Repeats: 1, Seed: 1, Revision: strings.Repeat("0", 40)})
		if len(report.Trials) != 6 {
			t.Fatal("missing planned conditions")
		}
		for _, policy := range []string{"none", "all"} {
			for _, checkpoint := range []string{"active", "closed-now", "closed-1s"} {
				t.Run(suite.String()+"/"+policy+"/"+checkpoint, func(t *testing.T) {
					var row *Trial
					for i := range report.Trials {
						r := &report.Trials[i]
						if r.Policy == policy && r.Checkpoint == checkpoint {
							if row != nil {
								t.Fatal("duplicate condition")
							}
							row = r
						}
					}
					if row == nil {
						t.Fatal("missing condition")
					}
					if row.Status != "evaluated" {
						t.Fatalf("status %s", row.Status)
					}
					if row.EchoOK == nil || !*row.EchoOK || row.PositiveOK == nil || !*row.PositiveOK || row.NegativeOK == nil || !*row.NegativeOK || row.ParseComplete == nil || !*row.ParseComplete || row.Protection == nil || !validProtection(*row.Protection, policy, true) {
						t.Fatal("missing successful gates")
					}
					if row.AEADUses == nil || *row.AEADUses != [3]uint64{1, 1, 1} || row.ReleasedLengths == nil || *row.ReleasedLengths != [3]uint64{} {
						t.Fatal("incomplete production lifecycle")
					}
				})
			}
		}
		if err != nil {
			t.Error("suite unavailable")
		}
	}
}
