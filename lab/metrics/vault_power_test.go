package metrics

import (
	"math"
	"math/rand/v2"
	"testing"
)

const areaBits = 8 * 4096

// K2 zeroes the top bit of byte 0 of the second area of two-volume files, the
// positives, and FitLearnedBit trains on n positives and n negatives. the
// planted bit has positive frequency 0 and negative frequency X/n with X ~
// Bin(n, 1/2), so its difference is -X/n, about -0.5 with sd sqrt(0.25/n) =
// 0.041 at n = 150. each of the other 32767 bits differs by (A - B)/n with A, B
// ~ Bin(n, 1/2) independent, sd sqrt(2 x 0.25/n) = 0.058, and the expected
// largest of 32767 such moduli is about 0.058 x sqrt(2 ln 65534) = 0.058 x 4.71
// = 0.27. the planted bit is position 0 and wins ties, so the fit goes wrong
// only if some |A - B| > X; A - B + n = A + (n - B) ~ Bin(2n, 1/2), and the union
// bound gives P(wrong) <= sum over x of P(X = x) min(1, 32767 x 2 P(Bin(2n, 1/2)
// > n + x))
func wrongBitBound(n int) float64 {
	planted := binomialPMF(n, 0.5)
	diff := binomialPMF(2*n, 0.5)
	above := make([]float64, 2*n+2)
	for k := 2 * n; k >= 0; k-- {
		above[k] = above[k+1] + diff[k]
	}
	var p float64
	for x, px := range planted {
		p += px * math.Min(1, (areaBits-1)*2*above[n+x+1])
	}
	return p
}

// on the test half the positives score 0 and a negative scores -1 when
// its bit is 1, with probability 1/2, so AUC = p + (1 - p)/2 = 0.5 + p/2 for the
// share p of negatives with the bit set, sd 0.041/2 = 0.02 at n = 150. a point
// below t needs p < 2t - 1, that is X < n(2t - 1), passed as the integer bound
func lowPointProbability(n, below int) float64 {
	var p float64
	for _, px := range binomialPMF(n, 0.5)[:below] {
		p += px
	}
	return p
}

// M = 300 gives n = 150: the wrong bit has bound 2.2e-8 and a point below 0.65
// needs X < 45, P(Bin(150, 1/2) <= 44) = 2.2e-7, the normal P(Z < -4.98); both
// under 1e-6. for comparison M = 200 with threshold 0.7: n = 100, wrong bit
// bound 1.2e-4, and a point below 0.7 needs X < 40, P(Bin(100, 1/2) <= 39) =
// 1.8%, too often for a control that must pass every series
func TestLearnedBitPowerK2(t *testing.T) {
	if p := wrongBitBound(150); p >= 1e-6 {
		t.Fatalf("wrong bit at M = 300: %v, want < 1e-6", p)
	}
	if p := lowPointProbability(150, 45); p >= 1e-6 || p < 1e-7 {
		t.Fatalf("point below 0.65 at M = 300: %v, want about 2.2e-7", p)
	}
	if p := wrongBitBound(100); p >= 0.003 {
		t.Fatalf("wrong bit at M = 200: %v, want under 0.3%%", p)
	}
	if p := lowPointProbability(100, 40); p < 0.015 || p > 0.021 {
		t.Fatalf("point below 0.7 at M = 200: %v, want about 1.8%%", p)
	}
}

// one fixed draw of the K2 control at M = 300 through the real fit and the
// corrected interval: the planted bit must be found, the point must clear 0.65
// and the interval of level 1 - 0.05/3 must leave out 0.5
func TestLearnedBitFindsK2(t *testing.T) {
	rng := rand.New(rand.NewPCG(20, 5))
	area := func(positive bool) []byte {
		b := make([]byte, areaBits/8)
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		if positive {
			b[0] &^= 0x80
		}
		return b
	}
	const n = 150
	var train, test [][]byte
	var trainTruth, testTruth []bool
	for i := range 4 * n {
		positive := i%2 == 0
		if i < 2*n {
			train, trainTruth = append(train, area(positive)), append(trainTruth, positive)
		} else {
			test, testTruth = append(test, area(positive)), append(testTruth, positive)
		}
	}
	bit, ok := FitLearnedBit(train, trainTruth)
	if !ok || bit.Position != 0 || bit.Sign != -1 {
		t.Fatalf("fit = %+v %v, want the planted bit 0 with sign -1", bit, ok)
	}
	scores := make([]Score, len(test))
	for i, a := range test {
		scores[i] = Score{Entry: i, Value: bit.Score(a), True: testTruth[i]}
	}
	resamples := 10000
	if testing.Short() {
		resamples = 1000
	}
	ci := BootstrapAUCLevel(scores, len(scores), resamples, 1, 1-0.05/3)
	if ci.Point < 0.65 || !(ci.Low > 0.5 || ci.High < 0.5) {
		t.Fatalf("K2 gave %+v, want a point of at least 0.65 and 0.5 outside", ci)
	}
}
