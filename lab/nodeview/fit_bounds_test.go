package nodeview

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"testing"
	"unsafe"
)

func testFitCertificate(t *testing.T) *fitCertificateScratch {
	t.Helper()
	s, err := acquireFitCertificate(func(n uint64) error {
		if n != 81920 {
			t.Fatal("certificate charge changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal("bounded certificate admission failed")
	}
	t.Cleanup(s.close)
	return s
}

func assertFitBits(t *testing.T, got fitBounds, lo, hi uint64, ok bool) {
	t.Helper()
	if !ok || math.Float64bits(got.lo) != lo || math.Float64bits(got.hi) != hi {
		t.Fatal("directed arithmetic differs from the manual exact answer")
	}
}

func TestFitBoundsManualKnownAnswers(t *testing.T) {
	s := testFitCertificate(t)
	v, ok := fitRational(false, 0, 1, 2, s)
	assertFitBits(t, v, 0x3fe0000000000000, 0x3fe0000000000000, ok)
	v, ok = fitRational(false, 0, 1, 3, s)
	assertFitBits(t, v, 0x3fd5555555555555, 0x3fd5555555555556, ok)
	v, ok = fitRational(true, 0, 1, 3, s)
	assertFitBits(t, v, 0xbfd5555555555556, 0xbfd5555555555555, ok)
	v, ok = fitAdd(fitPoint(1), fitPoint(0x1p-53), s)
	assertFitBits(t, v, 0x3ff0000000000000, 0x3ff0000000000001, ok)
	v, ok = fitSub(fitPoint(1), fitPoint(1), s)
	assertFitBits(t, v, 0, 0, ok)
	v, ok = fitMul(fitPoint(math.SmallestNonzeroFloat64), fitPoint(.5), s)
	assertFitBits(t, v, 0, 1, ok)
	v, ok = fitSub(fitPoint(0x1p-1022), fitPoint(math.SmallestNonzeroFloat64), s)
	assertFitBits(t, v, 0x000fffffffffffff, 0x000fffffffffffff, ok)
	v, ok = fitSqrt(fitPoint(4), s)
	assertFitBits(t, v, 0x4000000000000000, 0x4000000000000000, ok)
	v, ok = fitSqrt(fitPoint(2), s)
	assertFitBits(t, v, 0x3ff6a09e667f3bcc, 0x3ff6a09e667f3bcd, ok)
	v, ok = fitSquare(fitBounds{-2, 3}, s)
	assertFitBits(t, v, 0, 0x4022000000000000, ok)
	for _, signs := range [][2]float64{{1, 3}, {-1, 3}, {1, -3}, {-1, -3}} {
		v, ok = fitDiv(fitPoint(signs[0]), fitPoint(signs[1]), s)
		if !ok || !fitContains(v, signs[0]/signs[1]) || v.hi-v.lo > 0x1p-53 {
			t.Fatal("division sign or exact remainder changed")
		}
		v, ok = fitMul(fitPoint(signs[0]), fitPoint(signs[1]), s)
		if !ok || v.lo != signs[0]*signs[1] || v.lo != v.hi {
			t.Fatal("signed integer product was widened")
		}
	}
	v, ok = fitDiv(fitPoint(math.MaxFloat64), fitPoint(math.MaxFloat64), s)
	assertFitBits(t, v, 0x3ff0000000000000, 0x3ff0000000000000, ok)
	v, ok = fitRational(false, 1, 0, 1<<63, s)
	assertFitBits(t, v, 0x4000000000000000, 0x4000000000000000, ok)
	v, ok = fitRational(false, 0, 1<<54-1, 1<<54, s)
	assertFitBits(t, v, 0x3fefffffffffffff, 0x3ff0000000000000, ok)
	v, ok = fitMul(fitBounds{-2, 3}, fitBounds{-5, -4}, s)
	assertFitBits(t, v, 0xc02e000000000000, 0x4024000000000000, ok)
	v, ok = fitDiv(fitBounds{-2, 3}, fitBounds{-5, -4}, s)
	assertFitBits(t, v, 0xbfe8000000000000, 0x3fe0000000000000, ok)
	v, ok = fitAdd(fitPoint(0x1p44), fitPoint(0x1p-138), s)
	if !ok || s.scalars[0] > 3 || s.scalars[1] > 3 || !fitContains(v, 0x1p44) {
		t.Fatal("encoded row grid did not use at most three active limbs")
	}
	if _, ok = fitAdd(fitPoint(math.MaxFloat64), fitPoint(math.MaxFloat64), s); ok || s.flags[1] != 1 {
		t.Fatal("finite-range overflow was accepted or mislabeled")
	}
	if _, ok = fitAdd(fitPoint(math.NaN()), fitPoint(0), s); ok || s.flags[1] != 2 {
		t.Fatal("invalid conformance did not dominate an unavailable finite range")
	}
	s.reset()
	if _, ok = fitDiv(fitPoint(1), fitBounds{-1, 1}, s); ok || s.flags[1] != 1 {
		t.Fatal("zero-containing divisor was accepted or mislabeled")
	}
	s.reset()
	if _, ok = fitRational(false, 0, 1, 0, s); ok || s.flags[1] != 2 {
		t.Fatal("malformed rational denominator was accepted")
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		s.reset()
		if _, ok = fitAdd(fitPoint(bad), fitPoint(0), s); ok || s.flags[1] != 2 {
			t.Fatal("nonfinite endpoint was accepted")
		}
	}
}

func clearFitRat(r *big.Rat) {
	clear(r.Num().Bits())
	clear(r.Denom().Bits())
	r.SetInt64(0)
}

func TestFitBoundsIndependentRationalAndFMA(t *testing.T) {
	s := testFitCertificate(t)
	// each fixed case owns at most six 4608-bit rationals; the complete finite history is below 1 MiB
	const referenceOwner = 1 << 20
	if 6*576*48 >= referenceOwner {
		t.Fatal("bounded exact-reference owner changed")
	}
	for _, xyz := range [][3]float64{{1, 0x1p-53, -1}, {0x1.0000000000001p0, 0x1.fffffffffffffp-1, -1}, {0x1p-1022, .5, math.SmallestNonzeroFloat64}, {-4095, 0x1.fffffffffffffp-4, 4095}, {0x1p500, 0x1p-500, -1}} {
		a, b, c := new(big.Rat).SetFloat64(xyz[0]), new(big.Rat).SetFloat64(xyz[1]), new(big.Rat).SetFloat64(xyz[2])
		exact := new(big.Rat).Mul(a, b)
		exact.Add(exact, c)
		product, ok := fitMul(fitPoint(xyz[0]), fitPoint(xyz[1]), s)
		if !ok {
			t.Fatal("finite independent product failed")
		}
		got, ok := fitAdd(product, fitPoint(xyz[2]), s)
		lo, hi := new(big.Rat).SetFloat64(got.lo), new(big.Rat).SetFloat64(got.hi)
		if !ok || lo.Cmp(exact) > 0 || hi.Cmp(exact) < 0 || !fitContains(got, xyz[0]*xyz[1]+xyz[2]) || !fitContains(got, math.FMA(xyz[0], xyz[1], xyz[2])) {
			t.Fatal("directed expression missed exact, separate or fused arithmetic")
		}
		clearFitRat(a)
		clearFitRat(b)
		clearFitRat(c)
		clearFitRat(exact)
		clearFitRat(lo)
		clearFitRat(hi)
	}
}

func TestFitCertificateOwnerAdmissionAndErasure(t *testing.T) {
	calls := 0
	for _, amount := range []uint64{81919, 81920} {
		s, err := acquireFitCertificate(func(n uint64) error {
			calls++
			if n > amount {
				return fail(ReasonLimit)
			}
			return nil
		})
		if amount < 81920 {
			if s != nil || reasonOf(err) != ReasonLimit {
				t.Fatal("one-byte deficit allocated a proof owner")
			}
			continue
		}
		if err != nil || s == nil {
			t.Fatal("exact proof owner admission failed")
		}
		body := unsafe.Slice((*byte)(unsafe.Pointer(s)), 65536)
		for i := range body {
			body[i] = 0xa5
		}
		s.flags[0], s.flags[3] = 1, 0
		if !s.reset() {
			t.Fatal("admitted owner could not reset")
		}
		for i, x := range body {
			if i != 24752 && i != 24754 && x != 0 {
				t.Fatal("reset retained a prior body or padding byte")
			}
		}
		s.close()
		s.close()
		for _, x := range body {
			if x != 0 {
				t.Fatal("close retained a proof byte")
			}
		}
		if s.reset() {
			t.Fatal("closed owner was resurrected")
		}
	}
	if calls != 2 {
		t.Fatal("proof allocation was not admitted exactly once")
	}
	if s, err := acquireFitCertificate(nil); s != nil || err == nil {
		t.Fatal("nil admission created a proof owner")
	}
	if s, err := acquireFitCertificate(func(uint64) error { return fail(ReasonUnsupported) }); s != nil || reasonOf(err) != ReasonUnsupported {
		t.Fatal("unsupported host created a proof owner")
	}
	s := testFitCertificate(t)
	if n := testing.AllocsPerRun(20, func() {
		s.reset()
		fitMul(fitPoint(3), fitPoint(7), s)
		fitDiv(fitPoint(1), fitPoint(3), s)
		fitSqrt(fitPoint(2), s)
	}); n != 0 {
		t.Fatal("proof reuse or arithmetic allocated")
	}
	fitWordsSet(s, 0, 1, 0, 2048)
	fitWordsSet(s, 0, 0, 7, 0)
	if fitWordsBits(s, 0) != 3 {
		t.Fatal("word reuse retained stale high limbs")
	}
	if fitWordsSet(s, 0, 0, 1, 4608) || s.flags[1] != 2 {
		t.Fatal("checked word overflow was accepted")
	}
	s.reset()
	for _, x := range []any{s, fitPoint(1)} {
		if _, err := json.Marshal(x); err == nil || fmt.Sprintf("%v", x) != "nodeview: private" || fmt.Sprintf("%#v", x) != "nodeview: private" {
			t.Fatal("private proof state was serializable")
		}
	}
}

func TestFitLatticeExactnessConditions(t *testing.T) {
	// 2^26*2^27=2^53 is exact; the next integer product exceeds the sufficient bound
	if !fitLatticeEligible(1, 1<<26, 1<<27) || fitLatticeEligible(1, 1<<26, 1<<27+1) || fitLatticeEligible(2, 1<<26, 1<<27) || fitLatticeEligible(1, 1<<53+1, 0) || fitLatticeEligible(0, 0, 0) {
		t.Fatal("lattice exactness boundary or checked product changed")
	}
	s := testFitCertificate(t)
	rows := mailboxTrainingFixture()
	for i := range rows {
		rows[i].Values[7] = 1
		rows[i].Values[10] = int16(i%5 - 2)
	}
	train, truth := fitTestInputs(t, rows)
	w := mailboxMoments(rows)
	replay, _, ok := checkMailboxFit(train, truth, &w, s)
	defer wipeMailboxModel(&replay)
	defer wipeMailboxWitness(&w)
	if !ok || s.scalars[34] == 0 {
		t.Fatal("mixed-sign exact lattice was not checked")
	}
	// S=2/3; with b=RN(1/3), T-S=3*(1/3-b)^2, so rounded means cannot be replaced by exact means
	b := new(big.Rat).SetFloat64(1. / 3.)
	m := new(big.Rat).SetFrac64(1, 3)
	d := new(big.Rat).Sub(m, b)
	correction := new(big.Rat).Mul(d, d)
	correction.Mul(correction, big.NewRat(3, 1))
	if correction.Sign() <= 0 {
		t.Fatal("rounded-mean S/T displacement vanished")
	}
	clearFitRat(b)
	clearFitRat(m)
	clearFitRat(d)
	clearFitRat(correction)
}
