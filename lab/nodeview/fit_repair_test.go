package nodeview

import (
	"math"
	"testing"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func assertFitWitnessZero(t *testing.T, w *MailboxFitWitness) {
	t.Helper()
	if w == nil {
		return
	}
	if w.FeatureVersion != "" || w.Count != 0 || w.ClassCount != [2]int{} || w.Kept != nil || w.Unused != nil {
		t.Fatal("actual failed witness retained fixed fields")
	}
	for i := range mailboxFeatureCount {
		if w.Sum[i] != 0 || w.ClassSum[0][i] != 0 || w.ClassSum[1][i] != 0 || w.Minimum[i] != 0 || w.Maximum[i] != 0 || w.Scale[i] != 0 {
			t.Fatal("actual failed witness retained fixed numerical arrays")
		}
		for j := range mailboxFeatureCount {
			if w.Cross[i][j] != 0 || w.Scatter[i][j] != 0 || w.Cholesky[i][j] != 0 {
				t.Fatal("actual failed witness retained a fixed matrix")
			}
		}
	}
}

func assertFitModelZero(t *testing.T, m *metrics.Discriminant) {
	t.Helper()
	if m == nil {
		return
	}
	if m.Normalizer != 0 || m.Weights != nil || m.Center != nil || m.Kept != nil || m.Unused != nil {
		t.Fatal("actual failed model retained scalar or slice fields")
	}
}

func TestFitCertificateGuardDecisions(t *testing.T) {
	s := testFitCertificate(t)
	tau := math.Float64frombits(0x3e112e0be826d695)
	down, up := math.Nextafter(tau, 0), math.Nextafter(tau, math.Inf(1))
	for _, c := range []struct {
		bounds   fitBounds
		retained bool
		want     fitProofStatus
	}{
		{fitPoint(tau), false, fitProofSensitive}, {fitBounds{down, tau}, false, fitProofSensitive}, {fitBounds{tau, up}, true, fitProofSensitive},
		{fitPoint(down), false, fitProofStable}, {fitPoint(up), true, fitProofStable}, {fitPoint(down), true, fitProofSensitive}, {fitPoint(up), false, fitProofSensitive},
		{fitPoint(tau - 0x1p-40), false, fitProofStable}, {fitPoint(tau + 0x1p-40), true, fitProofStable}, {fitBounds{0, math.Inf(1)}, true, fitProofSensitive}, {fitBounds{1, 0}, false, fitProofInvalid},
	} {
		s.reset()
		if got := fitPivotDecision(c.bounds, c.retained, s); got != c.want {
			t.Fatal("actual pivot decision differs from the exact cutoff oracle")
		}
	}
	s.reset()
	b := s.sub(fitPoint(1), fitPoint(tau))
	assertFitBits(t, b, 0x3fefffffff768fa0, 0x3fefffffff768fa1, true)
	difference := s.sub(fitPoint(1), b)
	assertFitBits(t, difference, 0x3e112e0be0000000, 0x3e112e0c00000000, true)
	if !mailboxSame(1, b.hi) || fitMeanDecision(fitPoint(1), b, false, true, s) != fitProofSensitive {
		t.Fatal("actual mean guard accepted the directed subtraction overlap")
	}
	if fitMeanDecision(fitPoint(1), fitPoint(1), true, true, s) != fitProofStable || fitMeanDecision(fitPoint(1), fitPoint(1), true, false, s) != fitProofSensitive || fitMeanDecision(fitPoint(1), fitPoint(0), false, false, s) != fitProofStable || fitMeanDecision(fitPoint(1), fitPoint(0), false, true, s) != fitProofSensitive {
		t.Fatal("mean exact-equality or point-branch agreement changed")
	}
	q := s.rational(1, 10)
	y := s.sub(s.mul(fitPoint(3), q), fitPoint(.3))
	pointQ := float64(1) / 10
	product := float64(3 * pointQ)
	pointY := float64(product - .3)
	if pointY != 0x1p-54 || pointY*pointY != 0x1p-108 || pointY*pointY < 0x1p-1022 {
		t.Fatal("source-order RN normalizer reference is not positive and normal")
	}
	if y.lo != -0x1p-54 || y.hi != 0x1p-54 {
		t.Fatal("independent normalizer rounding graph changed")
	}
	normalizer := s.add(fitPoint(0), s.square(y))
	if normalizer.lo != 0 || normalizer.hi != 0x1p-108 || fitDirectionDecision(normalizer, true, s) != fitProofSensitive {
		t.Fatal("actual positivity guard accepted a rounded-zero normalizer")
	}
	for _, c := range []struct {
		bounds  fitBounds
		nonzero bool
		want    fitProofStatus
	}{{fitPoint(0x1p-108), true, fitProofStable}, {fitPoint(0), true, fitProofSensitive}, {fitBounds{-0x1p-108, 0x1p-108}, true, fitProofSensitive}, {fitBounds{1, math.Inf(1)}, true, fitProofSensitive}, {fitPoint(1), false, fitProofSensitive}, {fitBounds{1, 0}, true, fitProofInvalid}} {
		s.reset()
		if fitDirectionDecision(c.bounds, c.nonzero, s) != c.want {
			t.Fatal("actual normalizer/nonzero decision changed")
		}
	}
}

func assertFitBackingZero(t *testing.T, values []float64) {
	t.Helper()
	for _, x := range values[:cap(values)] {
		if math.Float64bits(x) != 0 {
			t.Fatal("actual failed numerical backing was not cleared")
		}
	}
}

func TestMailboxFitFailureOwnerCapacities(t *testing.T) {
	for _, name := range []string{"sensitivity", "model-mismatch", "score-length", "degenerate", "success"} {
		t.Run(name, func(t *testing.T) {
			n := 16384
			if name == "sensitivity" {
				n = 108784
			}
			budget := memoryBudget{limit: controllerArenaBytes}
			charge := uint64(n)*(512+42) + 8<<20
			if budget.reserve(charge) != nil {
				t.Fatal("bounded failure owner admission failed")
			}
			defer budget.release(charge)
			fixture := "small-dependent"
			if name == "sensitivity" {
				fixture = "cutoff-full-row"
			}
			rows := fitKnownRows(t, fixture)
			defer clear(rows[:cap(rows)])
			if name == "degenerate" {
				for i := range rows {
					rows[i].Values = encodedMailboxRow{}
				}
			}
			s := testFitCertificate(t)
			defer s.close()
			owner := mailboxFitOwner{}
			defer owner.close()
			prepareMailboxTraining(&owner, rows, featureVersion, true, true, s)
			histogram, headers, truth, backing := owner.histogram, owner.train, owner.truth, owner.backing
			point, replay, witness := &owner.model, &owner.replayed, owner.witness
			pw, pc, pk, pu := point.Weights, point.Center, point.Kept, point.Unused
			rw, rc, rk, ru := replay.Weights, replay.Center, replay.Kept, replay.Unused
			scores0, scores1, y, v := owner.scores[0], owner.scores[1], owner.replayWork.y, owner.replayWork.v
			var wk, wu []int
			if witness != nil {
				wk, wu = witness.Kept, witness.Unused
			}
			if histogram == nil || len(headers) != n || len(truth) != n || len(backing) != 18*n {
				t.Fatal("test did not retain actual allocated training owners")
			}
			if name == "model-mismatch" {
				owner.model.Center[4] = math.Nextafter(owner.model.Center[4], 1)
			}
			if name == "score-length" {
				owner.scores[0] = owner.scores[0][:len(owner.scores[0])-1]
			}
			out := finalizeMailboxTraining(&owner)
			defer wipeMailboxTraining(&out)
			assertFitBackingZero(t, backing)
			assertFitBackingZero(t, scores0)
			assertFitBackingZero(t, scores1)
			assertFitBackingZero(t, rw)
			assertFitBackingZero(t, rc)
			assertFitBackingZero(t, y)
			assertFitBackingZero(t, v)
			for _, row := range headers[:cap(headers)] {
				if row != nil {
					t.Fatal("actual failed training header backing was not cleared")
				}
			}
			for _, x := range truth[:cap(truth)] {
				if x {
					t.Fatal("actual failed truth backing was not cleared")
				}
			}
			for class := 0; class < 2; class++ {
				for _, x := range histogram[class][:] {
					if x != 0 {
						t.Fatal("actual support histogram backing was not cleared")
					}
				}
			}
			for _, list := range [][]int{rk, ru} {
				for _, x := range list[:cap(list)] {
					if x != 0 {
						t.Fatal("actual replay list backing was not cleared")
					}
				}
			}
			if name == "success" {
				if !out.Releasable || out.Model != point || out.Witness != witness || len(pw) == 0 || len(pk) == 0 || point.Normalizer <= 0 || witness.Count != n {
					t.Fatal("success cleanup damaged its transferred aliases")
				}
				wipeMailboxTraining(&out)
			} else {
				want := string(ReasonConformance)
				if name == "sensitivity" {
					want = string(ReasonFitSensitive)
				}
				if name == "degenerate" {
					want = string(ReasonTraining)
				}
				if out.Reason != want || out.Support.RAMConformance != (name == "sensitivity") || out.Support.Stable {
					t.Fatal("failure owner changed its original reason/conformance boundary")
				}
				assertFitSuppressed(t, out)
			}
			assertFitBackingZero(t, pw)
			assertFitBackingZero(t, pc)
			assertFitWitnessZero(t, witness)
			assertFitModelZero(t, point)
			assertFitModelZero(t, replay)
			for _, list := range [][]int{pk, pu, wk, wu} {
				for _, x := range list[:cap(list)] {
					if x != 0 {
						t.Fatal("actual failed model/witness list backing was not cleared")
					}
				}
			}
			if point.Normalizer != 0 || replay.Normalizer != 0 || witness != nil && (witness.Count != 0 || witness.Kept != nil || witness.Unused != nil) || owner.train != nil || owner.truth != nil || owner.backing != nil || owner.histogram != nil {
				t.Fatal("actual failure owner retained fixed fields or aliases")
			}
		})
	}
}

func TestFitScalarGuardSensitiveFinalizer(t *testing.T) {
	for _, name := range []string{"mean-rounding", "normalizer-rounding"} {
		t.Run(name, func(t *testing.T) {
			s := testFitCertificate(t)
			owner := mailboxFitOwner{}
			defer owner.close()
			rows := mailboxTrainingFixture()
			defer clear(rows)
			prepareMailboxTraining(&owner, rows, featureVersion, true, true, s)
			if !owner.replayOK || !owner.stable || len(owner.scores[0]) != len(rows) {
				t.Fatal("scalar mapping lacks a real point/replay baseline")
			}
			decision := fitProofInvalid
			if name == "mean-rounding" {
				b := s.sub(fitPoint(1), fitPoint(1e-9))
				decision = fitMeanDecision(fitPoint(1), b, false, true, s)
			} else {
				q := s.rational(1, 10)
				y := s.sub(s.mul(fitPoint(3), q), fitPoint(.3))
				decision = fitDirectionDecision(s.add(fitPoint(0), s.square(y)), true, s)
			}
			if decision != fitProofSensitive {
				t.Fatal("scalar rounding graph did not reach the real sensitive decision")
			}
			// this tests scalar status mapping after a genuine fit, not an encoded mean-sensitive corpus
			owner.stable = decision == fitProofStable
			out := finalizeMailboxTraining(&owner)
			if out.Reason != string(ReasonFitSensitive) || !out.Support.RAMConformance || out.Support.Stable {
				t.Fatal("shared finalizer changed sensitive scalar status mapping")
			}
			assertFitSuppressed(t, out)
		})
	}
}

func TestFitRepairOwnerControlUpper(t *testing.T) {
	if unsafe.Sizeof(mailboxFitOwner{}) > 640 || unsafe.Sizeof(mailboxReplayWork{}) != 48 || 640+4*128+4*128+38*8 > 2048 || 16384-(12288+640+4*128+4*128+38*8) < 2048 {
		t.Fatal("phased ownership controls exceed the unchanged registered envelope")
	}
}
