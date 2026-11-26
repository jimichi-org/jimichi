package scenario

import (
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func runVault(t *testing.T, p cheap, containers, resamples int) VaultReport {
	t.Helper()
	rep, err := Vault(p, VaultConfig{Containers: containers, Resamples: resamples, Seed: 5, Dir: t.TempDir(), Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestVaultRefusesTooFewResamples(t *testing.T) {
	_, err := Vault(cheap{realProvider(t, vaultSuites[0])}, VaultConfig{Containers: 4, Resamples: VaultMinResamples - 1, Dir: t.TempDir(), Random: rand.Reader})
	if err == nil {
		t.Fatal("accepted a tail of the interval without a resample")
	}
}

// the strings a report may carry; anything longer is a value the set must
// not write, such as a password or a card
func checkStrings(t *testing.T, rep VaultReport) {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []uint64{groupPopulation, groupTrace, groupIntegrity, groupCost} {
		for i := range uint64(2 * rep.Containers) {
			for vol := range uint64(2) {
				pw, err := newPassword(rep.Seed, streamPassword, group, i, vol)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), string(pw.Bytes())) {
					t.Fatalf("the report carries the password of %d/%d/%d", group, i, vol)
				}
				pw.Release()
			}
		}
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				walk(k, x)
			}
		case []any:
			for _, x := range v {
				walk(key, x)
			}
		case string:
			if key != "cpu_model" && len(v) > 48 {
				t.Errorf("%s: a string of %d bytes", key, len(v))
			}
		}
	}
	walk("", tree)
}

// a small population on both suites: the controls that hold at any size hold,
// integrity refuses what it must, and the cost has its rows
func TestVaultSetOnASmallPopulation(t *testing.T) {
	for _, st := range vaultSuites {
		t.Run(st.String(), func(t *testing.T) {
			t.Parallel()
			rep := runVault(t, cheap{realProvider(t, st)}, 4, 120)
			if rep.Set != "vault" || rep.Suite != st.String() || rep.Containers != 4 || rep.Resamples != 120 || rep.Level != VaultLevel ||
				rep.Stretch == "" || rep.Workers < 1 {
				t.Fatalf("header %+v", rep)
			}
			k1 := rep.Controls.K1
			// four areas of zeroes against four random ones: the chi-square of
			// zeroes is 1044480 and of a random area about 255, so every negative
			// scores above every positive and AUC = 0, |0 - 0.5| = 0.5
			if !k1.Passed || k1.Best != featureChi || *k1.Distance != 0.5 || len(k1.Features) != 3 {
				t.Fatalf("K1 %+v", k1)
			}
			if c := rep.Controls.K3; !c.Passed || c.Resealed != (SnapshotCount{8, 15}) || c.OneVolume != (SnapshotCount{0, 15}) {
				t.Fatalf("K3 %+v", c)
			}
			if rep.Trace == nil || rep.Trace.TwoVolume != (SnapshotCount{0, 15}) || rep.Trace.Verdict != "states equal" {
				t.Fatalf("trace %+v", rep.Trace)
			}
			if (rep.A2 != nil) != rep.Controls.K2.Passed || (rep.A1 != nil) != rep.Controls.K2.Passed {
				t.Fatalf("A2 %v and A1 %v with K2 passed %v", rep.A2 != nil, rep.A1 != nil, rep.Controls.K2.Passed)
			}
			if rep.Controls.K2.Passed != (rep.Status == statusPassed) {
				t.Fatalf("status %q with K2 passed %v", rep.Status, rep.Controls.K2.Passed)
			}
			flips := 0
			for _, c := range rep.Integrity {
				if !c.Holds {
					t.Errorf("integrity %s with the %s password: %v, want all %s", c.Case, c.Password, c.Outcomes, c.Want)
				}
				if strings.HasPrefix(c.Case, "flip_") {
					flips += c.Trials
				}
				if c.Case == "flip_other_area" && c.Refused != 0 || c.Case == "flip_salt" && c.Refused != 1 {
					t.Errorf("%s refused %v", c.Case, c.Refused)
				}
			}
			if flips != 100 || len(rep.Integrity) != 9 {
				t.Errorf("%d flips in %d cases", flips, len(rep.Integrity))
			}
			// a cheap open takes less than a tick of some clocks, so only the
			// shape of the cost is checked
			if c := rep.Cost; c.Runs != 30 || c.RightWall.P95 < c.RightWall.Median || c.WrongWall.P95 < c.WrongWall.Median {
				t.Errorf("cost %+v", c)
			} else if c.WrongCore != nil && c.WrongCore.Median > 0 && len(c.GuessTime) != 3 {
				t.Errorf("guess time %+v", c.GuessTime)
			}
			checkStrings(t, rep)
		})
	}
}

// at the size of a series K2 holds as section 14 and the power test of
// lab/metrics calculate, so A2 and A1 come out; only K1 and K2 decide that
func TestVaultSetAtTheSizeOfASeries(t *testing.T) {
	if testing.Short() {
		t.Skip("600 containers")
	}
	rep := runVault(t, cheap{realProvider(t, vaultSuites[0])}, 300, 2000)
	k2 := rep.Controls.K2.LearnedBit
	if !rep.Controls.K1.Passed || !rep.Controls.K2.Passed || *k2.Bit != 0 || *k2.Direction != -1 ||
		k2.Positives != 150 || k2.Negatives != 150 || k2.Trained != 300 {
		t.Fatalf("controls %+v", rep.Controls)
	}
	if rep.A2 == nil || rep.A1 == nil || len(rep.A2.Features) != 3 || rep.A1.Features[0].Positives != 600 || rep.Verdict == "" {
		t.Fatalf("A2 %+v, A1 %+v", rep.A2, rep.A1)
	}
	checkStrings(t, rep)
}

func gated() vaultRun {
	half, yes := 0.5, true
	f := VaultFeature{Name: featureChi, AUC: &half}
	return vaultRun{
		k1:    VaultK1{Passed: true},
		k2:    VaultK2{Passed: true},
		k3:    VaultK3{Passed: true},
		a2:    &VaultVariant{Features: []VaultFeature{f}},
		a1:    &VaultVariant{Features: []VaultFeature{f, {Name: featureLearned, Excludes: &yes}}},
		trace: VaultTrace{Verdict: "states equal"},
	}
}

// AUC of A2 and A1 only with K1 and K2 passed, the trace only with K3, and
// "controls failed" with the failed names otherwise
func TestVaultReportGatesOnTheControls(t *testing.T) {
	for _, c := range []struct {
		k1, k2, k3     bool
		auc, trace     bool
		status, failed string
	}{
		{true, true, true, true, true, statusPassed, ""},
		{false, true, true, false, true, statusFailed, "K1"},
		{true, false, true, false, true, statusFailed, "K2"},
		{true, true, false, true, false, statusFailed, "K3"},
		{false, false, false, false, false, statusFailed, "K1 K2 K3"},
	} {
		r := gated()
		r.k1.Passed, r.k2.Passed, r.k3.Passed = c.k1, c.k2, c.k3
		rep := r.report()
		if (rep.A2 != nil) != c.auc || (rep.A1 != nil) != c.auc || (rep.Verdict != "") != c.auc || (rep.Trace != nil) != c.trace ||
			rep.Status != c.status || strings.Join(rep.Failed, " ") != c.failed {
			t.Errorf("K1 %v, K2 %v, K3 %v: %+v", c.k1, c.k2, c.k3, rep)
		}
		raw, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"a2"`) != c.auc || strings.Contains(string(raw), `"trace"`) != c.trace {
			t.Errorf("K1 %v, K2 %v, K3 %v: %s", c.k1, c.k2, c.k3, raw)
		}
		if c.auc && (rep.A2.Verdict != "does not distinguish" || rep.A1.Verdict != "distinguishes" || rep.Verdict != rep.A2.Verdict) {
			t.Errorf("verdicts %q, %q, %q", rep.A2.Verdict, rep.A1.Verdict, rep.Verdict)
		}
	}
	r := gated()
	if r.report(); r.a2.Verdict != "" {
		t.Fatal("the report wrote its verdict into the run")
	}
}

// the halves keep the classes apart and the seed alone decides them
func TestSplitHalvesEachClass(t *testing.T) {
	truth := []bool{true, false, true, false, true, false, true, true, false}
	h := split(truth, 3, variantA2)
	again := split(truth, 3, variantA2)
	if !slices.Equal(h.train, again.train) || !slices.Equal(h.test, again.test) {
		t.Fatal("one seed gave two splits")
	}
	pos, neg := 0, 0
	for _, i := range h.train {
		if truth[i] {
			pos++
		} else {
			neg++
		}
	}
	// 5 positives and 4 negatives: 2 and 2 train, 3 and 2 are scored
	if pos != 2 || neg != 2 || len(h.test) != 5 {
		t.Fatalf("train %v, test %v", h.train, h.test)
	}
}
