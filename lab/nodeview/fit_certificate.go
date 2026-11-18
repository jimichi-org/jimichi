package nodeview

import (
	"math"
	"math/bits"
	"slices"
	"unsafe"
)

type fitProofStatus uint8

const (
	fitProofStable fitProofStatus = iota
	fitProofSensitive
	fitProofInvalid
)

type fitLatticeColumn struct {
	coefficient int64
	exponent    int16
	reserved16  uint16
	reserved32  uint32
}

type fitCertificateScratch struct {
	rawDenied
	matrices   [3][18][18]fitBounds
	vectors    [9][18]fitBounds
	work       [16]fitBounds
	words      [8][72]uint64
	means      [3][18]float64
	lattice    [18]fitLatticeColumn
	scalars    [128]uint64
	flags      [64]uint8
	candidates [32]float64
	padding    [40464]byte
}

func fitCertificateBytes() (uint64, error) {
	if unsafe.Sizeof(fitBounds{}) != 16 || unsafe.Alignof(fitBounds{}) != 8 || unsafe.Sizeof(fitLatticeColumn{}) != 16 || unsafe.Sizeof(fitCertificateScratch{}) != 65536 || unsafe.Alignof(fitCertificateScratch{}) != 8 ||
		unsafe.Offsetof(fitCertificateScratch{}.matrices) != 0 || unsafe.Offsetof(fitCertificateScratch{}.vectors) != 15552 || unsafe.Offsetof(fitCertificateScratch{}.work) != 18144 || unsafe.Offsetof(fitCertificateScratch{}.words) != 18400 || unsafe.Offsetof(fitCertificateScratch{}.means) != 23008 || unsafe.Offsetof(fitCertificateScratch{}.lattice) != 23440 || unsafe.Offsetof(fitCertificateScratch{}.scalars) != 23728 || unsafe.Offsetof(fitCertificateScratch{}.flags) != 24752 || unsafe.Offsetof(fitCertificateScratch{}.candidates) != 24816 || unsafe.Offsetof(fitCertificateScratch{}.padding) != 25072 {
		return 0, fail(ReasonUnsupported)
	}
	return 81920, nil
}

func acquireFitCertificate(admit func(uint64) error) (*fitCertificateScratch, error) {
	if admit == nil {
		return nil, fail(ReasonContract)
	}
	n, err := fitCertificateBytes()
	if err != nil {
		return nil, err
	}
	if err = admit(n); err != nil {
		return nil, err
	}
	s := new(fitCertificateScratch)
	s.flags[0], s.flags[2] = 1, 1
	return s, nil
}

func (s *fitCertificateScratch) reset() bool {
	if s == nil || s.flags[0] != 1 || s.flags[3] != 0 {
		return false
	}
	clear(unsafe.Slice((*byte)(unsafe.Pointer(s)), 65536))
	s.flags[0], s.flags[2] = 1, 1
	return true
}

func (s *fitCertificateScratch) close() {
	if s != nil {
		clear(unsafe.Slice((*byte)(unsafe.Pointer(s)), 65536))
	}
}

func (s *fitCertificateScratch) add(a, b fitBounds) fitBounds {
	v, _ := fitAdd(a, b, s)
	return v
}
func (s *fitCertificateScratch) sub(a, b fitBounds) fitBounds {
	v, _ := fitSub(a, b, s)
	return v
}
func (s *fitCertificateScratch) mul(a, b fitBounds) fitBounds {
	v, _ := fitMul(a, b, s)
	return v
}
func (s *fitCertificateScratch) div(a, b fitBounds) fitBounds {
	v, _ := fitDiv(a, b, s)
	return v
}
func (s *fitCertificateScratch) square(a fitBounds) fitBounds {
	v, _ := fitSquare(a, s)
	return v
}
func (s *fitCertificateScratch) sqrt(a fitBounds) fitBounds {
	v, _ := fitSqrt(a, s)
	return v
}
func (s *fitCertificateScratch) rational(x int64, n int) fitBounds {
	negative := x < 0
	u := uint64(x)
	if negative {
		u = uint64(-(x + 1)) + 1
	}
	v, _ := fitRational(negative, 0, u, uint64(n), s)
	return v
}

func fitContains(a fitBounds, point float64) bool {
	return fitFinite(a) && point >= a.lo && point <= a.hi
}

func fitIntersect(a, b fitBounds) (fitBounds, bool) {
	v := fitBounds{max(a.lo, b.lo), min(a.hi, b.hi)}
	return v, fitFinite(a) && fitFinite(b) && fitFinite(v)
}

func (s *fitCertificateScratch) status(stable bool) fitProofStatus {
	if s.flags[1] == 2 {
		return fitProofInvalid
	}
	if !stable || s.flags[1] != 0 {
		return fitProofSensitive
	}
	return fitProofStable
}

func fitPivotDecision(pivot fitBounds, retained bool, s *fitCertificateScratch) fitProofStatus {
	if !fitReady(s) || pivot.lo > pivot.hi {
		fitFault(s, 2)
		return fitProofInvalid
	}
	return s.status(fitFinite(pivot) && !(pivot.lo <= 1e-9 && pivot.hi >= 1e-9) && (!retained || pivot.lo > 1e-9) && (retained || pivot.hi < 1e-9))
}

func fitMeanDecision(a, b fitBounds, rationalEqual, pointSame bool, s *fitCertificateScratch) fitProofStatus {
	if !fitOperands(a, b, s) {
		return fitProofInvalid
	}
	if rationalEqual {
		return s.status(pointSame)
	}
	d := fitAbs(s.sub(a, b))
	aa, bb := fitAbs(a), fitAbs(b)
	tolerance := s.mul(fitPoint(1e-9), fitBounds{max(aa.lo, bb.lo), max(aa.hi, bb.hi)})
	return s.status(d.hi <= tolerance.lo && pointSame || d.lo > tolerance.hi && !pointSame)
}

func fitDirectionDecision(normalizer fitBounds, nonzero bool, s *fitCertificateScratch) fitProofStatus {
	if !fitReady(s) || normalizer.lo > normalizer.hi {
		fitFault(s, 2)
		return fitProofInvalid
	}
	return s.status(nonzero && fitFinite(normalizer) && normalizer.lo > 0)
}

func prepareMailboxFacts(train [][]float64, truth []bool, w *MailboxFitWitness, s *fitCertificateScratch) bool {
	if !fitReady(s) || s.flags[2] != 1 || s.flags[3] != 0 || w == nil || len(train) == 0 || len(train) > maxTrainingRows || len(train) != len(truth) || w.Count != len(train) || w.FeatureVersion != MailboxFeatureVersion {
		return fitFault(s, 2)
	}
	s.flags[2], s.flags[3] = 0, 1
	for j := range mailboxFeatureCount {
		s.vectors[8][j] = fitBounds{4096, -4096}
	}
	for i, row := range train {
		if !validFitEncodedRow(row) {
			return fitFault(s, 2)
		}
		class := 0
		if truth[i] {
			class = 1
		}
		s.scalars[16+class]++
		for j, x := range row {
			s.means[0][j] += x
			s.means[1+class][j] += x
			s.vectors[8][j].lo = min(s.vectors[8][j].lo, x)
			s.vectors[8][j].hi = max(s.vectors[8][j].hi, x)
		}
	}
	if int(s.scalars[16]) != w.ClassCount[0] || int(s.scalars[17]) != w.ClassCount[1] || w.ClassCount[0] == 0 || w.ClassCount[1] == 0 {
		return fitFault(s, 2)
	}
	for j := range mailboxFeatureCount {
		if s.means[0][j] != float64(w.Sum[j]) || s.means[1][j] != float64(w.ClassSum[0][j]) || s.means[2][j] != float64(w.ClassSum[1][j]) || s.vectors[8][j].lo != float64(w.Minimum[j]) || s.vectors[8][j].hi != float64(w.Maximum[j]) {
			return fitFault(s, 2)
		}
		for class := range 3 {
			n := len(train)
			if class > 0 {
				n = w.ClassCount[class-1]
			}
			s.means[class][j] /= float64(n)
			x := w.Sum[j]
			if class > 0 {
				x = w.ClassSum[class-1][j]
			}
			s.vectors[class][j] = s.rational(x, n)
			if !fitContains(s.vectors[class][j], s.means[class][j]) {
				return fitFault(s, 2)
			}
		}
	}
	return s.flags[1] == 0
}

func validFitEncodedRow(row []float64) bool {
	if len(row) != mailboxFeatureCount {
		return false
	}
	for j, x := range row {
		if math.IsNaN(x) || math.IsInf(x, 0) || math.Trunc(x) != x {
			return false
		}
		switch j {
		case 0, 4, 5, 7, 9, 11, 12, 13, 14, 16:
			if x < 0 || x > 1 {
				return false
			}
		case 1:
			if x < 0 || x > 3 {
				return false
			}
		case 10:
			if x < -4095 || x > 4095 {
				return false
			}
		case 15:
			if x < 0 || x > 3000 {
				return false
			}
		default:
			if x < 0 || x > 4095 {
				return false
			}
		}
	}
	return !(row[0] == 0 && (row[1] != 0 || row[2] != 0 || row[3] != 0 || row[4] != 0 || row[5] != 0 || row[15] != 0 || row[16] != 0) || row[0] != 0 && row[1] == 0 || row[1] != 3 && (row[2] != 0 || row[3] != 0 || row[4] != 0) || row[4] == 0 && row[3] != 0 || row[7] == 0 && (row[6] != 0 || row[10] != 0) || row[9] == 0 && row[8] != 0 || row[16] == 0 && row[15] != 0 || row[11]+row[12]+row[13]+row[14] > 1)
}

func prepareFitLattice(w *MailboxFitWitness, s *fitCertificateScratch) {
	for j := range mailboxFeatureCount {
		negative, m, e := fitDecode(s.means[0][j])
		if m != 0 {
			t := bits.TrailingZeros64(m)
			m >>= uint(t)
			e += t
		} else {
			e = 0
		}
		if e > 0 {
			m <<= uint(e)
			e = 0
		}
		if e < -69 || m > 1<<53 {
			fitFault(s, 2)
			return
		}
		coefficient := int64(m)
		if negative {
			coefficient = -coefficient
		}
		s.lattice[j] = fitLatticeColumn{coefficient: coefficient, exponent: int16(e)}
		a := fitAbs(s.sub(fitPoint(float64(w.Minimum[j])), fitPoint(s.means[0][j])))
		b := fitAbs(s.sub(fitPoint(float64(w.Maximum[j])), fitPoint(s.means[0][j])))
		h := math.Ldexp(max(a.hi, b.hi), -e)
		if a.lo == a.hi && b.lo == b.hi && h <= 1<<53 && h == math.Trunc(h) {
			s.scalars[40+j] = uint64(h)
			s.flags[16+j] = 1
		}
	}
}

func fitMagnitude(x int64) (bool, uint64) {
	if x < 0 {
		return true, uint64(-(x + 1)) + 1
	}
	return false, uint64(x)
}

func fitLatticeTerm(s *fitCertificateScratch, negative *bool, hi, lo uint64, shift int, sign bool) bool {
	if !fitWordsSet(s, 6, hi, lo, shift) {
		return false
	}
	if s.scalars[7] == 0 {
		*negative = sign
	}
	if *negative == sign {
		return fitWordsAdd(s, 7, 6)
	}
	if fitWordsCompare(s, 7, 6) >= 0 {
		return fitWordsSubtract(s, 7, 6)
	}
	if !fitWordsSubtract(s, 6, 7) {
		return false
	}
	fitWordsClear(s, 7)
	copy(s.words[7][:int(s.scalars[6])], s.words[6][:int(s.scalars[6])])
	s.scalars[7], *negative = s.scalars[6], sign
	return true
}

func fitLatticeScatter(i, j int, w *MailboxFitWitness, exact fitBounds, s *fitCertificateScratch) (fitBounds, bool) {
	if s.flags[16+i] == 0 || s.flags[16+j] == 0 {
		return fitBounds{}, false
	}
	hi, hj := s.scalars[40+i], s.scalars[40+j]
	if !fitLatticeEligible(uint64(w.Count), hi, hj) {
		return fitBounds{}, false
	}
	qi, qj := int(s.lattice[i].exponent), int(s.lattice[j].exponent)
	base := qi + qj
	fitWordsClear(s, 7)
	negative := false
	nc, cross := fitMagnitude(w.Cross[i][j])
	if !fitLatticeTerm(s, &negative, 0, cross, -base, nc) {
		return fitBounds{}, false
	}
	ni, bi := fitMagnitude(s.lattice[i].coefficient)
	nj, bj := fitMagnitude(s.lattice[j].coefficient)
	nsj, sj := fitMagnitude(w.Sum[j])
	nsi, si := fitMagnitude(w.Sum[i])
	h, l := bits.Mul64(bi, sj)
	if !fitLatticeTerm(s, &negative, h, l, qi-base, ni == nsj) {
		return fitBounds{}, false
	}
	h, l = bits.Mul64(bj, si)
	if !fitLatticeTerm(s, &negative, h, l, qj-base, nj == nsi) {
		return fitBounds{}, false
	}
	h, l = bits.Mul64(bi, bj)
	upper, low := bits.Mul64(l, uint64(w.Count))
	overflow, high := bits.Mul64(h, uint64(w.Count))
	high, carry := bits.Add64(high, upper, 0)
	if overflow != 0 || carry != 0 || !fitLatticeTerm(s, &negative, high, low, 0, ni != nj) {
		fitFault(s, 2)
		return fitBounds{}, false
	}
	t, ok := fitWordsRound(s, 7, base, negative)
	if !ok || t.lo != t.hi || t.lo != w.Scatter[i][j] {
		fitFault(s, 2)
		return fitBounds{}, false
	}
	s.scalars[34]++
	return fitBounds{min(exact.lo, t.lo), max(exact.hi, t.hi)}, true
}

func fitLatticeEligible(n, hi, hj uint64) bool {
	if n == 0 || n > maxTrainingRows || hi > 1<<53 || hj > 1<<53 {
		return false
	}
	return hi == 0 || hj == 0 || hj <= (1<<53)/hi && n <= (1<<53)/(hi*hj)
}

func fitCoarseScatter(i, j int, w *MailboxFitWitness, s *fitCertificateScratch) fitBounds {
	numerator := int64(w.Count)*w.Cross[i][j] - w.Sum[i]*w.Sum[j]
	exact := s.rational(numerator, w.Count)
	k := fitPoint(float64(w.Count + 4))
	ku := s.mul(k, fitPoint(0x1p-53))
	gamma := s.div(ku, s.sub(fitPoint(1), ku))
	di := max(1, fitAbs(s.sub(fitPoint(float64(w.Minimum[i])), s.vectors[0][i])).hi, fitAbs(s.sub(fitPoint(float64(w.Maximum[i])), s.vectors[0][i])).hi)
	dj := max(1, fitAbs(s.sub(fitPoint(float64(w.Minimum[j])), s.vectors[0][j])).hi, fitAbs(s.sub(fitPoint(float64(w.Maximum[j])), s.vectors[0][j])).hi)
	b := s.mul(s.mul(s.mul(s.mul(fitPoint(8), gamma), fitPoint(float64(w.Count))), fitPoint(di)), fitPoint(dj))
	return fitBounds{s.sub(exact, fitPoint(b.hi)).lo, s.add(exact, fitPoint(b.hi)).hi}
}

func certifyMailboxFit(train [][]float64, truth []bool, w *MailboxFitWitness, s *fitCertificateScratch) fitProofStatus {
	if !fitReady(s) || s.flags[3] != 1 || w == nil || len(train) != w.Count || len(truth) != w.Count {
		fitFault(s, 2)
		return fitProofInvalid
	}
	prepareFitLattice(w, s)
	for _, row := range train {
		for i := range mailboxFeatureCount {
			if w.Minimum[i] != w.Maximum[i] {
				s.vectors[3][i] = s.sub(fitPoint(row[i]), s.vectors[0][i])
			}
		}
		for i := range mailboxFeatureCount {
			for j := range i + 1 {
				s.matrices[2][i][j].lo += row[i] * row[j]
				if w.Minimum[i] == w.Maximum[i] || w.Minimum[j] == w.Maximum[j] {
					continue
				}
				s.matrices[0][i][j] = s.add(s.matrices[0][i][j], s.mul(s.vectors[3][i], s.vectors[3][j]))
				s.scalars[32]++
			}
		}
	}
	s.scalars[33] = uint64(len(train))
	for i := range mailboxFeatureCount {
		for j := range i + 1 {
			if s.matrices[2][i][j].lo != float64(w.Cross[i][j]) || w.Cross[i][j] != w.Cross[j][i] {
				fitFault(s, 2)
				return fitProofInvalid
			}
			if w.Minimum[i] == w.Maximum[i] || w.Minimum[j] == w.Maximum[j] {
				continue
			}
			coarse := fitCoarseScatter(i, j, w, s)
			if s.flags[1] != 0 {
				return s.status(false)
			}
			exact := s.rational(int64(w.Count)*w.Cross[i][j]-w.Sum[i]*w.Sum[j], w.Count)
			if !fitContains(coarse, w.Scatter[i][j]) || !fitContains(s.matrices[0][i][j], w.Scatter[i][j]) || s.matrices[0][i][j].lo > exact.lo || s.matrices[0][i][j].hi < exact.hi {
				return fitProofInvalid
			}
			iv, ok := fitIntersect(coarse, s.matrices[0][i][j])
			if !ok {
				return fitProofInvalid
			}
			if lattice, available := fitLatticeScatter(i, j, w, exact, s); available {
				iv, ok = fitIntersect(iv, lattice)
				if !ok || !fitContains(iv, w.Scatter[i][j]) {
					return fitProofInvalid
				}
			}
			if s.flags[1] != 0 {
				return s.status(false)
			}
			s.matrices[0][i][j] = iv
		}
	}
	stable := true
	for i := range mailboxFeatureCount {
		if w.Minimum[i] == w.Maximum[i] {
			continue
		}
		if s.matrices[0][i][i].lo < 0x1p-1022 {
			return s.status(false)
		}
		s.vectors[4][i] = s.sqrt(s.matrices[0][i][i])
		pi := s.div(s.div(s.matrices[0][i][i], s.vectors[4][i]), s.vectors[4][i])
		p := 0
		for _, j := range w.Kept {
			if j >= i {
				break
			}
			ci := s.div(s.div(s.matrices[0][i][j], s.vectors[4][i]), s.vectors[4][j])
			for r := range p {
				ci = s.sub(ci, s.mul(s.matrices[1][i][r], s.matrices[1][j][r]))
			}
			s.matrices[1][i][p] = s.div(ci, s.matrices[1][j][p])
			pi = s.sub(pi, s.mul(s.matrices[1][i][p], s.matrices[1][i][p]))
			p++
		}
		s.vectors[8][i] = pi
		retained := slices.Contains(w.Kept, i)
		if fitPivotDecision(pi, retained, s) != fitProofStable {
			stable = false
		}
		if retained {
			if pi.lo <= 0 {
				return s.status(false)
			}
			s.matrices[1][i][p] = s.sqrt(pi)
		}
	}
	if s.flags[1] != 0 {
		return s.status(false)
	}
	different := false
	for _, j := range w.Kept {
		equal := w.ClassSum[1][j]*int64(w.ClassCount[0]) == w.ClassSum[0][j]*int64(w.ClassCount[1])
		a, b := s.vectors[2][j], s.vectors[1][j]
		same := mailboxSame(s.means[2][j], s.means[1][j])
		if fitMeanDecision(a, b, equal, same, s) != fitProofStable {
			stable = false
		}
		different = different || !same
	}
	if !different {
		return fitProofInvalid
	}
	for p, j := range w.Kept {
		difference := s.sub(s.vectors[2][j], s.vectors[1][j])
		if w.ClassSum[1][j]*int64(w.ClassCount[0]) == w.ClassSum[0][j]*int64(w.ClassCount[1]) {
			difference = fitPoint(0)
		}
		v := s.div(difference, s.vectors[4][j])
		for r := range p {
			v = s.sub(v, s.mul(s.matrices[1][j][r], s.vectors[5][r]))
		}
		s.vectors[5][p] = s.div(v, s.matrices[1][j][p])
	}
	nonzero := false
	for p := len(w.Kept) - 1; p >= 0; p-- {
		j := w.Kept[p]
		x := s.vectors[5][p]
		for r := p + 1; r < len(w.Kept); r++ {
			x = s.sub(x, s.mul(s.matrices[1][w.Kept[r]][p], s.vectors[6][r]))
		}
		s.vectors[6][p] = s.div(x, s.matrices[1][j][p])
		s.vectors[7][j] = s.div(s.vectors[6][p], s.vectors[4][j])
		nonzero = nonzero || s.vectors[7][j].lo > 0 || s.vectors[7][j].hi < 0
	}
	normalizer := fitPoint(0)
	for p := range w.Kept {
		normalizer = s.add(normalizer, s.square(s.vectors[5][p]))
	}
	s.work[0] = normalizer
	if fitDirectionDecision(normalizer, nonzero, s) != fitProofStable {
		stable = false
	}
	if s.flags[1] != 0 {
		return s.status(false)
	}
	// extrema enclose every training row without retaining a second score stream
	score := fitPoint(0)
	for _, j := range w.Kept {
		center := s.div(s.add(s.vectors[2][j], s.vectors[1][j]), fitPoint(2))
		values := fitBounds{float64(w.Minimum[j]), float64(w.Maximum[j])}
		score = s.add(score, s.mul(s.vectors[7][j], s.sub(values, center)))
	}
	score = s.div(score, normalizer)
	if !fitFinite(score) {
		stable = false
	}
	return s.status(stable)
}
