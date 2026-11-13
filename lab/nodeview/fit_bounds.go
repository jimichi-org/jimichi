package nodeview

import (
	"math"
	"math/bits"
)

type fitBounds struct{ lo, hi float64 }

func (fitBounds) MarshalJSON() ([]byte, error) { return nil, ErrRawSerialization }
func (fitBounds) String() string               { return "nodeview: private" }
func (fitBounds) GoString() string             { return "nodeview: private" }

func fitPoint(x float64) fitBounds { return fitBounds{x, x} }

func fitFault(s *fitCertificateScratch, fault uint8) bool {
	if s != nil && s.flags[0] == 1 && s.flags[1] < fault {
		s.flags[1] = fault
	}
	return false
}

func fitReady(s *fitCertificateScratch) bool {
	return s != nil && s.flags[0] == 1 && s.flags[1] != 2
}

func fitFinite(a fitBounds) bool {
	return a.lo <= a.hi && !math.IsInf(a.lo, 0) && !math.IsInf(a.hi, 0)
}

func fitOperands(a, b fitBounds, s *fitCertificateScratch) bool {
	if !fitReady(s) || !fitFinite(a) || !fitFinite(b) {
		return fitFault(s, 2)
	}
	return true
}

func fitDecode(x float64) (negative bool, mantissa uint64, exponent int) {
	u := math.Float64bits(x)
	negative = u>>63 != 0
	e := int(u>>52) & 2047
	mantissa = u & (1<<52 - 1)
	exponent = -1074
	if e != 0 {
		mantissa |= 1 << 52
		exponent = e - 1075
	}
	if mantissa != 0 {
		shift := bits.TrailingZeros64(mantissa)
		mantissa >>= uint(shift)
		exponent += shift
	}
	return
}

func fitWordsClear(s *fitCertificateScratch, bank int) {
	n := int(s.scalars[bank])
	if n < 0 || n > len(s.words[bank]) {
		fitFault(s, 2)
		return
	}
	clear(s.words[bank][:n])
	s.scalars[bank] = 0
}

func fitWordsSet(s *fitCertificateScratch, bank int, hi, lo uint64, shift int) bool {
	fitWordsClear(s, bank)
	if shift < 0 || shift > 4607 {
		return fitFault(s, 2)
	}
	if hi == 0 && lo == 0 {
		return true
	}
	n := shift / 64
	b := uint(shift % 64)
	if n+2 >= 72 {
		return fitFault(s, 2)
	}
	s.words[bank][n] = lo << b
	if b == 0 {
		s.words[bank][n+1] = hi
	} else {
		s.words[bank][n+1] = hi<<b | lo>>(64-b)
		s.words[bank][n+2] = hi >> (64 - b)
	}
	s.scalars[bank] = uint64(n + 3)
	fitWordsTrim(s, bank)
	return true
}

func fitWordsTrim(s *fitCertificateScratch, bank int) {
	n := int(s.scalars[bank])
	for n > 0 && s.words[bank][n-1] == 0 {
		n--
	}
	s.scalars[bank] = uint64(n)
}

func fitWordsBits(s *fitCertificateScratch, bank int) int {
	n := int(s.scalars[bank])
	if n == 0 {
		return 0
	}
	return 64*(n-1) + bits.Len64(s.words[bank][n-1])
}

func fitWordsCompare(s *fitCertificateScratch, a, b int) int {
	na, nb := int(s.scalars[a]), int(s.scalars[b])
	if na < nb {
		return -1
	}
	if na > nb {
		return 1
	}
	for i := na - 1; i >= 0; i-- {
		if s.words[a][i] < s.words[b][i] {
			return -1
		}
		if s.words[a][i] > s.words[b][i] {
			return 1
		}
	}
	return 0
}

func fitWordsAdd(s *fitCertificateScratch, a, b int) bool {
	n := max(int(s.scalars[a]), int(s.scalars[b]))
	carry := uint64(0)
	for i := 0; i < n; i++ {
		s.words[a][i], carry = bits.Add64(s.words[a][i], s.words[b][i], carry)
	}
	if carry != 0 {
		if n == 72 {
			return fitFault(s, 2)
		}
		s.words[a][n], n = carry, n+1
	}
	s.scalars[a] = uint64(n)
	return true
}

func fitWordsSubtract(s *fitCertificateScratch, a, b int) bool {
	if fitWordsCompare(s, a, b) < 0 {
		return fitFault(s, 2)
	}
	borrow := uint64(0)
	for i := 0; i < int(s.scalars[a]); i++ {
		s.words[a][i], borrow = bits.Sub64(s.words[a][i], s.words[b][i], borrow)
	}
	if borrow != 0 {
		return fitFault(s, 2)
	}
	fitWordsTrim(s, a)
	return true
}

func fitWordsBit(s *fitCertificateScratch, bank, bit int) uint64 {
	if bit < 0 || bit/64 >= int(s.scalars[bank]) {
		return 0
	}
	return s.words[bank][bit/64] >> uint(bit%64) & 1
}

func fitWordsLow(s *fitCertificateScratch, bank, count int) bool {
	if count <= 0 {
		return false
	}
	n := min(count/64, int(s.scalars[bank]))
	for i := 0; i < n; i++ {
		if s.words[bank][i] != 0 {
			return true
		}
	}
	return count/64 < int(s.scalars[bank]) && count%64 != 0 && s.words[bank][count/64]&(uint64(1)<<uint(count%64)-1) != 0
}

func fitCompose(q uint64, exponent int, remainder, negative bool, s *fitCertificateScratch) (fitBounds, bool) {
	if q > 1<<53 || q == 1<<53 && remainder {
		return fitBounds{}, fitFault(s, 2)
	}
	lo := math.Ldexp(float64(q), exponent)
	hi := lo
	if remainder {
		hi = math.Ldexp(float64(q+1), exponent)
	}
	if math.IsInf(lo, 0) || math.IsInf(hi, 0) {
		return fitBounds{}, fitFault(s, 1)
	}
	if negative {
		return fitBounds{-hi, -lo}, true
	}
	return fitBounds{lo, hi}, true
}

func fitWordsRound(s *fitCertificateScratch, bank, exponent int, negative bool) (fitBounds, bool) {
	n := fitWordsBits(s, bank)
	if n == 0 {
		return fitPoint(0), true
	}
	e := n - 1 + exponent
	if e > 1023 {
		return fitBounds{}, fitFault(s, 1)
	}
	quantum := max(e-52, -1074)
	shift := quantum - exponent
	q := uint64(0)
	if shift < 0 {
		if n-shift > 53 {
			return fitBounds{}, fitFault(s, 2)
		}
		q = s.words[bank][0] << uint(-shift)
	} else {
		index, offset := shift/64, uint(shift%64)
		if index < int(s.scalars[bank]) {
			q = s.words[bank][index] >> offset
			if offset != 0 && index+1 < int(s.scalars[bank]) {
				q |= s.words[bank][index+1] << (64 - offset)
			}
		}
	}
	return fitCompose(q, quantum, fitWordsLow(s, bank, shift), negative, s)
}

func fitDyadicCompare(ah, al uint64, ae int, bh, bl uint64, be int, s *fitCertificateScratch) int {
	e := min(ae, be)
	if !fitWordsSet(s, 4, ah, al, ae-e) || !fitWordsSet(s, 5, bh, bl, be-e) {
		return 0
	}
	return fitWordsCompare(s, 4, 5)
}

func fitScalarAdd(a, b float64, s *fitCertificateScratch) (fitBounds, bool) {
	na, ma, ea := fitDecode(a)
	nb, mb, eb := fitDecode(b)
	if ma == 0 {
		return fitPoint(b), true
	}
	if mb == 0 {
		return fitPoint(a), true
	}
	e := min(ea, eb)
	if !fitWordsSet(s, 0, 0, ma, ea-e) || !fitWordsSet(s, 1, 0, mb, eb-e) {
		return fitBounds{}, false
	}
	if na == nb {
		if !fitWordsAdd(s, 0, 1) {
			return fitBounds{}, false
		}
		return fitWordsRound(s, 0, e, na)
	}
	if fitWordsCompare(s, 0, 1) >= 0 {
		if !fitWordsSubtract(s, 0, 1) {
			return fitBounds{}, false
		}
		return fitWordsRound(s, 0, e, na)
	}
	if !fitWordsSubtract(s, 1, 0) {
		return fitBounds{}, false
	}
	return fitWordsRound(s, 1, e, nb)
}

func fitScalarMul(a, b float64, s *fitCertificateScratch) (fitBounds, bool) {
	na, ma, ea := fitDecode(a)
	nb, mb, eb := fitDecode(b)
	hi, lo := bits.Mul64(ma, mb)
	if !fitWordsSet(s, 0, hi, lo, 0) {
		return fitBounds{}, false
	}
	return fitWordsRound(s, 0, ea+eb, na != nb)
}

func fitRatio(negative bool, hi, lo, den uint64, exponent int, s *fitCertificateScratch) (fitBounds, bool) {
	if den == 0 || !fitReady(s) {
		return fitBounds{}, fitFault(s, 2)
	}
	if hi == 0 && lo == 0 {
		return fitPoint(0), true
	}
	n := bits.Len64(lo)
	if hi != 0 {
		n = 64 + bits.Len64(hi)
	}
	e := n - bits.Len64(den)
	if fitDyadicCompare(hi, lo, 0, 0, den, e, s) < 0 {
		e--
	}
	if e+exponent > 1023 {
		return fitBounds{}, fitFault(s, 1)
	}
	if e+exponent < -1074 {
		return fitCompose(0, -1074, true, negative, s)
	}
	quantum := max(e+exponent-52, -1074)
	shift := exponent - quantum
	if !fitWordsSet(s, 2, hi, lo, max(0, shift)) || !fitWordsSet(s, 3, 0, den, max(0, -shift)) {
		return fitBounds{}, false
	}
	q := uint64(0)
	top := fitWordsBits(s, 2) - fitWordsBits(s, 3)
	if top > 53 {
		return fitBounds{}, fitFault(s, 2)
	}
	for bit := top; bit >= 0; bit-- {
		if !fitWordsSet(s, 6, 0, den, max(0, -shift)+bit) {
			return fitBounds{}, false
		}
		if fitWordsCompare(s, 2, 6) >= 0 {
			if !fitWordsSubtract(s, 2, 6) {
				return fitBounds{}, false
			}
			q |= uint64(1) << uint(bit)
		}
	}
	return fitCompose(q, quantum, s.scalars[2] != 0, negative, s)
}

func fitRational(negative bool, hi, lo, den uint64, s *fitCertificateScratch) (fitBounds, bool) {
	return fitRatio(negative, hi, lo, den, 0, s)
}

func fitAdd(a, b fitBounds, s *fitCertificateScratch) (fitBounds, bool) {
	if !fitOperands(a, b, s) {
		return fitBounds{}, false
	}
	lo, ok := fitScalarAdd(a.lo, b.lo, s)
	if !ok {
		return fitBounds{}, false
	}
	hi, ok := fitScalarAdd(a.hi, b.hi, s)
	return fitBounds{lo.lo, hi.hi}, ok
}

func fitSub(a, b fitBounds, s *fitCertificateScratch) (fitBounds, bool) {
	return fitAdd(a, fitBounds{-b.hi, -b.lo}, s)
}

func fitMul(a, b fitBounds, s *fitCertificateScratch) (fitBounds, bool) {
	if !fitOperands(a, b, s) {
		return fitBounds{}, false
	}
	out := fitBounds{math.MaxFloat64, -math.MaxFloat64}
	for i := range 4 {
		x, y := a.lo, b.lo
		if i&1 != 0 {
			x = a.hi
		}
		if i&2 != 0 {
			y = b.hi
		}
		v, ok := fitScalarMul(x, y, s)
		if !ok {
			return fitBounds{}, false
		}
		out.lo, out.hi = min(out.lo, v.lo), max(out.hi, v.hi)
	}
	return out, true
}

func fitDiv(a, b fitBounds, s *fitCertificateScratch) (fitBounds, bool) {
	if !fitOperands(a, b, s) {
		return fitBounds{}, false
	}
	if b.lo <= 0 && b.hi >= 0 {
		return fitBounds{}, fitFault(s, 1)
	}
	out := fitBounds{math.MaxFloat64, -math.MaxFloat64}
	for i := range 4 {
		x, y := a.lo, b.lo
		if i&1 != 0 {
			x = a.hi
		}
		if i&2 != 0 {
			y = b.hi
		}
		nx, mx, ex := fitDecode(x)
		ny, my, ey := fitDecode(y)
		v, ok := fitRatio(nx != ny, 0, mx, my, ex-ey, s)
		if !ok {
			return fitBounds{}, false
		}
		out.lo, out.hi = min(out.lo, v.lo), max(out.hi, v.hi)
	}
	return out, true
}

func fitAbs(a fitBounds) fitBounds {
	lo, hi := min(math.Abs(a.lo), math.Abs(a.hi)), max(math.Abs(a.lo), math.Abs(a.hi))
	if a.lo <= 0 && a.hi >= 0 {
		lo = 0
	}
	return fitBounds{lo, hi}
}

func fitSquare(a fitBounds, s *fitCertificateScratch) (fitBounds, bool) {
	if !fitOperands(a, a, s) {
		return fitBounds{}, false
	}
	b := fitAbs(a)
	lo, ok := fitScalarMul(b.lo, b.lo, s)
	if !ok {
		return fitBounds{}, false
	}
	hi, ok := fitScalarMul(b.hi, b.hi, s)
	return fitBounds{lo.lo, hi.hi}, ok
}

func fitRootEndpoint(x float64, s *fitCertificateScratch) (fitBounds, bool) {
	_, mx, ex := fitDecode(x)
	lo, hi := uint64(0), uint64(0x7fefffffffffffff)
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		_, m, e := fitDecode(math.Float64frombits(mid))
		h, l := bits.Mul64(m, m)
		if fitDyadicCompare(h, l, 2*e, 0, mx, ex, s) <= 0 {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	_, m, e := fitDecode(math.Float64frombits(lo))
	h, l := bits.Mul64(m, m)
	hi = lo
	if fitDyadicCompare(h, l, 2*e, 0, mx, ex, s) != 0 {
		hi++
	}
	return fitBounds{math.Float64frombits(lo), math.Float64frombits(hi)}, s.flags[1] != 2
}

func fitSqrt(a fitBounds, s *fitCertificateScratch) (fitBounds, bool) {
	if !fitOperands(a, a, s) {
		return fitBounds{}, false
	}
	if a.lo < 0 {
		return fitBounds{}, fitFault(s, 1)
	}
	lo, ok := fitRootEndpoint(a.lo, s)
	if !ok {
		return fitBounds{}, false
	}
	hi, ok := fitRootEndpoint(a.hi, s)
	return fitBounds{lo.lo, hi.hi}, ok
}
