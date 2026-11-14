package nodeview

import (
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func fitKnownRows(t *testing.T, name string) []encodedTrainingRow {
	t.Helper()
	n, put := 16384, 8192
	switch name {
	case "large-dependent", "independent-columns":
		n, put = 65536, 32768
	case "general-68572":
		n, put = 68572, 8891
	case "general-68574":
		n, put = 68574, 8893
	case "cutoff-full-row":
		n, put = 108784, 54392
	case "fallback", "cleanup-suppression":
		n, put = 512, 256
	}
	rows := make([]encodedTrainingRow, n)
	t.Cleanup(func() { clear(rows[:cap(rows)]) })
	for i := range rows {
		x := int16(0)
		if i >= n-put {
			x = 1
		}
		r := &rows[i]
		r.Positive, r.Conversation, r.OriginalSeal = x != 0, uint16(i%4), x == 0
		if strings.HasPrefix(name, "general-") {
			r.Values[0], r.Values[1] = x, 3*x
		} else if name == "cutoff-full-row" {
			value := int16(651)
			if x != 0 {
				value = 3443
			}
			z := int16(0)
			if i%(n/2) < 53 {
				z = 1
			} else if i%(n/2) < 106 {
				z = -1
			}
			r.Values[0], r.Values[1], r.Values[2], r.Values[3], r.Values[4] = 1, 3, value, value+z, 1
		} else {
			r.Values[0], r.Values[1], r.Values[4], r.Values[5] = 1, 3, x, x
			if name == "independent-columns" {
				r.Values[5] = int16(i % 2)
			} else if name == "fallback" {
				r.Values[5] = int16(boolInt(i%3 == 0))
			}
		}
		if !validEncodedMailboxRow(r.Values) {
			t.Fatal("predetermined numerical row violates the encoded schema")
		}
	}
	return rows
}

func fitTestInputs(t *testing.T, rows []encodedTrainingRow) ([][]float64, []bool) {
	t.Helper()
	train, truth := make([][]float64, len(rows)), make([]bool, len(rows))
	backing := make([]float64, len(rows)*18)
	t.Cleanup(func() { clear(backing[:cap(backing)]); clear(train[:cap(train)]); clear(truth[:cap(truth)]) })
	for i := range rows {
		train[i] = backing[i*18 : (i+1)*18]
		for j, x := range rows[i].Values {
			train[i][j] = float64(x)
		}
		truth[i] = rows[i].Positive
	}
	return train, truth
}

func assertFitSuppressed(t *testing.T, training MailboxTraining) {
	t.Helper()
	if training.Releasable || training.Model != nil || training.Witness != nil {
		t.Fatal("failed training retained released fitting state")
	}
	b, err := json.Marshal(training)
	if err != nil {
		t.Fatal("fixed failure could not serialize")
	}
	defer clear(b[:cap(b)])
	for _, field := range []string{"weights", "Weights", "class_sum", "cross", "minimum", "maximum", "scatter", "digest", "interval", "mode", "residual"} {
		if strings.Contains(string(b), field) {
			t.Fatal("failed training disclosed fitting state")
		}
	}
}

func TestMailboxFitCertificateKnownAnswers(t *testing.T) {
	for _, name := range []string{"small-dependent", "large-dependent", "general-68572", "general-68574", "cutoff-full-row", "independent-columns", "fallback", "cleanup-suppression"} {
		t.Run(name, func(t *testing.T) {
			rows := fitKnownRows(t, name)
			s := testFitCertificate(t)
			train, truth := fitTestInputs(t, rows)
			point, ok := metrics.FitDiscriminant(train, truth)
			defer wipeMailboxModel(&point)
			if !ok {
				t.Fatal("predetermined point fit failed")
			}
			w := mailboxMoments(rows)
			defer wipeMailboxWitness(&w)
			replayed, stable, ok := checkMailboxFit(train, truth, &w, s)
			defer wipeMailboxModel(&replayed)
			if !ok || !sameMailboxModel(point, replayed) || s.scalars[33] != uint64(len(rows)) || s.scalars[32] == 0 {
				t.Fatal("complete source-order point and certificate replay failed")
			}
			a, b := point.Scores(train), replayed.Scores(train)
			defer clear(a[:cap(a)])
			defer clear(b[:cap(b)])
			if len(a) != len(rows) || len(b) != len(rows) {
				t.Fatal("score stream was incomplete")
			}
			for i := range a {
				if math.Float64bits(a[i]) != math.Float64bits(b[i]) {
					t.Fatal("score bits or ties changed")
				}
			}
			if name == "cutoff-full-row" {
				// A=108784*1396^2=211999999744; 212 extra squares put the real pivot next to tau
				if stable || w.Scatter[2][2] != 211999999744 || w.Scatter[2][3] != 211999999744 || w.Scatter[3][3] != 211999999956 {
					t.Fatal("true cutoff fixture or sensitivity changed")
				}
				assertFitBits(t, s.vectors[8][3], 0x3e112e0a80000000, 0x3e112e0d80000000, true)
				if !fitContains(s.vectors[8][3], 1e-9) {
					t.Fatal("genuine cutoff overlap was lost")
				}
			} else if !stable {
				t.Fatal("predetermined safe fit did not certify")
			}
			if name == "small-dependent" || name == "large-dependent" {
				// each row contributes 1/4; powers-of-two roots give exact score halves
				if !slices.Equal(point.Kept, []int{4}) || point.Weights[4] != 4/float64(len(rows)) || point.Normalizer != 4/float64(len(rows)) || point.Center[4] != .5 || s.vectors[8][4] != fitPoint(1) || s.vectors[8][5] != fitPoint(0) || s.scalars[34] != 3 {
					t.Fatal("exact dependent known answer changed")
				}
				for i, score := range a {
					want := -.5
					if truth[i] {
						want = .5
					}
					if math.Float64bits(score) != math.Float64bits(want) {
						t.Fatal("exact score half changed")
					}
				}
			}
			if strings.HasPrefix(name, "general-") {
				if !slices.Equal(point.Kept, []int{0}) || s.scalars[34] != 0 || s.vectors[8][0].lo < .99999999999 || s.vectors[8][0].hi > 1.00000000001 || s.vectors[8][1].lo < -2e-11 || s.vectors[8][1].hi > 2e-11 || s.vectors[7][0].lo < .00012 || s.vectors[7][0].hi > .00014 || s.work[0].lo < .00012 || s.work[0].hi > .00014 {
					t.Fatal("general-n capability did not use the proved broad row path")
				}
				old := legacyDependentPivot(w.Count, w.Sum[0], w.Sum[1], w.Cross[0][0], w.Cross[1][0], w.Cross[1][1], w.Minimum[0], w.Maximum[0], w.Minimum[1], w.Maximum[1])
				if old.lo > 1e-9 || old.hi < 1e-9 {
					t.Fatal("general-n fixture did not force the old coarse refusal")
				}
			}
			out := trainMailbox(rows, MailboxFeatureVersion, true, true, s)
			defer wipeMailboxTraining(&out)
			if !out.Support.RAMConformance {
				t.Fatal("training did not complete bit conformance")
			}
			if name == "cutoff-full-row" {
				if out.Support.Stable || out.Reason != string(ReasonFitSensitive) {
					t.Fatal("true boundary did not produce the fixed sensitivity result")
				}
				assertFitSuppressed(t, out)
			} else if !out.Releasable || !sameMailboxModel(point, *out.Model) {
				t.Fatal("safe original model did not release unchanged")
			}
			if name == "cleanup-suppression" {
				weights, center, kept, unused := out.Model.Weights, out.Model.Center, out.Model.Kept, out.Model.Unused
				witness := out.Witness
				wipeMailboxTraining(&out)
				if !slices.Equal(weights, make([]float64, len(weights))) || !slices.Equal(center, make([]float64, len(center))) || !slices.Equal(kept, make([]int, len(kept))) || !slices.Equal(unused, make([]int, len(unused))) || witness.Count != 0 || witness.Kept != nil {
					t.Fatal("owned released backing did not clear")
				}
				failed := trainMailbox(rows, featureVersion, false, true, s)
				assertFitSuppressed(t, failed)
				failed.Model = &point
				if _, err := json.Marshal(failed); err == nil {
					t.Fatal("forbidden failure attachment serialized")
				}
			}
		})
	}
}

func legacyDependentPivot(n int, sum0, sum1, cross00, cross10, cross11 int64, lo0, hi0, lo1, hi1 int16) fitInterval {
	mu0, mu1 := float64(sum0)/float64(n), float64(sum1)/float64(n)
	gamma := float64(n+4) * 0x1p-53 / (1 - float64(n+4)*0x1p-53)
	d0 := max(1, math.Abs(float64(lo0)-mu0), math.Abs(float64(hi0)-mu0))
	d1 := max(1, math.Abs(float64(lo1)-mu1), math.Abs(float64(hi1)-mu1))
	a := exactMailboxScatter(sum0, sum0, cross00, n)
	b := exactMailboxScatter(sum1, sum0, cross10, n)
	c := exactMailboxScatter(sum1, sum1, cross11, n)
	x, y, z := 8*gamma*float64(n)*d0*d0, 8*gamma*float64(n)*d1*d0, 8*gamma*float64(n)*d1*d1
	aa, bb, cc := outwardFit(a-x, a+x), outwardFit(b-y, b+y), outwardFit(c-z, c+z)
	sa, sc := sqrtFit(aa), sqrtFit(cc)
	first := divFit(divFit(aa, sa), sa)
	coefficient := divFit(divFit(divFit(bb, sc), sa), sqrtFit(first))
	return subFit(divFit(divFit(cc, sc), sc), mulFit(coefficient, coefficient))
}

func TestFitCertificatePinnedResourceAndBoundaryContracts(t *testing.T) {
	if n, err := fitCertificateBytes(); err != nil || n != 81920 || unsafe.Sizeof(fitCertificateScratch{}) != 65536 || 1615171+n != 1697091 || 8388608-(1615171+n) != 6691517 {
		t.Fatal("new fixed fitter ownership or historical baseline changed")
	}
	if 2*uint64(maxTrainingRows)*uint64(unsafe.Sizeof(encodedTrainingRow{}))+uint64(maxTrainingRows)*512+8388608 != 86507520 {
		t.Fatal("full pool and sequential fitter phase charge changed")
	}
	for _, pivot := range []fitBounds{{1e-9, 1e-9}, {math.Nextafter(1e-9, 0), math.Nextafter(1e-9, math.Inf(1))}, {1e-9 - 0x1p-40, 1e-9 + 0x1p-40}} {
		if !fitContains(pivot, math.Float64frombits(0x3e112e0be826d695)) {
			t.Fatal("exact cutoff or adjacent boundary changed")
		}
	}
	if _, ok := fitIntersect(fitPoint(0), fitPoint(1)); ok || fitContains(fitBounds{1, 2}, 0) {
		t.Fatal("contradictory or noncontaining proof was accepted")
	}
	rows := mailboxTrainingFixture()
	train, truth := fitTestInputs(t, rows)
	s := testFitCertificate(t)
	w := mailboxMoments(rows)
	w.Sum[0]++
	if _, _, ok := checkMailboxFit(train, truth, &w, s); ok {
		t.Fatal("contradictory moments were accepted")
	}
	s.reset()
	w = mailboxMoments(rows)
	train[0][0] = 2
	if _, _, ok := checkMailboxFit(train, truth, &w, s); ok {
		t.Fatal("out-of-domain categorical row was accepted")
	}
	train[0][0] = 0
	s.close()
	w = mailboxMoments(rows)
	if _, _, ok := checkMailboxFit(train, truth, &w, s); ok {
		t.Fatal("closed certificate owner was accepted")
	}
}
