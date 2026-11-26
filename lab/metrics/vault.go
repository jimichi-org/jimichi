package metrics

import (
	"bytes"
	"math"
)

func ChiSquareBytes(area []byte) float64 {
	if len(area) == 0 {
		return math.NaN()
	}
	var counts [256]int
	for _, b := range area {
		counts[b]++
	}
	expected := float64(len(area)) / 256
	var chi float64
	for _, c := range counts {
		d := float64(c) - expected
		chi += d * d / expected
	}
	return chi
}

// a short tail after the last whole chunk is not a chunk
func DuplicateChunks(area []byte) int {
	const size = 16
	seen := make(map[[size]byte]struct{}, len(area)/size)
	n := 0
	for i := 0; i+size <= len(area); i += size {
		chunk := [size]byte(area[i : i+size])
		if _, ok := seen[chunk]; ok {
			n++
			continue
		}
		seen[chunk] = struct{}{}
	}
	return n
}

// Position counts bits from the most significant bit of byte 0; Sign is the
// sign of the positive minus the negative frequency at that bit
type LearnedBit struct {
	Position int
	Sign     float64
}

// a tie in the size of the difference goes to the earliest position, so the
// fit is a function of the training half alone
func FitLearnedBit(train [][]byte, truth []bool) (LearnedBit, bool) {
	if len(train) == 0 || len(truth) != len(train) {
		return LearnedBit{}, false
	}
	width := len(train[0])
	var n1, n0 int
	for i, area := range train {
		if len(area) != width {
			return LearnedBit{}, false
		}
		if truth[i] {
			n1++
		} else {
			n0++
		}
	}
	if width == 0 || n1 == 0 || n0 == 0 {
		return LearnedBit{}, false
	}
	c1, c0 := make([]int, 8*width), make([]int, 8*width)
	for i, area := range train {
		counts := c0
		if truth[i] {
			counts = c1
		}
		for p := range counts {
			counts[p] += bitAt(area, p)
		}
	}
	// c1/n1 - c0/n0 scaled by n1*n0 stays an integer, so equal differences
	// compare equal instead of depending on rounding
	best, bestDiff := -1, 0
	for p := range c1 {
		d := c1[p]*n0 - c0[p]*n1
		if absInt(d) > absInt(bestDiff) {
			best, bestDiff = p, d
		}
	}
	if best < 0 {
		return LearnedBit{}, false
	}
	sign := 1.0
	if bestDiff < 0 {
		sign = -1
	}
	return LearnedBit{Position: best, Sign: sign}, true
}

func (b LearnedBit) Score(area []byte) float64 {
	if b.Position < 0 || b.Position >= 8*len(area) {
		return math.NaN()
	}
	if bitAt(area, b.Position) == 0 {
		return 0
	}
	return b.Sign
}

func LearnedBitScores(train [][]byte, truth []bool, test [][]byte) ([]float64, bool) {
	bit, ok := FitLearnedBit(train, truth)
	if !ok {
		return nil, false
	}
	out := make([]float64, len(test))
	for i, area := range test {
		out[i] = bit.Score(area)
	}
	return out, true
}

func bitAt(area []byte, p int) int {
	return int(area[p/8]>>(7-p%8)) & 1
}

// states are the successive contents of the area the cover password does not
// open; changed counts the pairs i < j whose contents differ
func SnapshotReveal(states [][]byte) (changed, pairs int) {
	for i := range states {
		for j := i + 1; j < len(states); j++ {
			pairs++
			if !bytes.Equal(states[i], states[j]) {
				changed++
			}
		}
	}
	return changed, pairs
}

// a uniform password of h bits is found on average after half of its 2^h
// candidates
func GuessTime(perGuess, h float64) float64 {
	return math.Exp2(h-1) * perGuess
}
