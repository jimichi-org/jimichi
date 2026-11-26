package metrics_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// 512 zeros against an expected 512/256 = 2 per value: the zero byte gives
// (512 - 2)^2 / 2 = 130050 and each of the other 255 values (0 - 2)^2 / 2 = 2,
// 130050 + 510 = 130560. two of each byte match the expectation exactly, 0.
// the K1 zero area of 4096 bytes: (4096 - 16)^2 / 16 + 255 x 16 = 1040400 +
// 4080 = 1044480
func TestChiSquareBytesKnownAnswer(t *testing.T) {
	if got := metrics.ChiSquareBytes(make([]byte, 512)); got != 130560 {
		t.Fatalf("512 zeros: %v, want 130560", got)
	}
	even := make([]byte, 0, 512)
	for v := range 256 {
		even = append(even, byte(v), byte(v))
	}
	if got := metrics.ChiSquareBytes(even); got != 0 {
		t.Fatalf("two of each byte: %v, want 0", got)
	}
	if got := metrics.ChiSquareBytes(make([]byte, 4096)); got != 1044480 {
		t.Fatalf("4096 zeros: %v, want 1044480", got)
	}
	if !math.IsNaN(metrics.ChiSquareBytes(nil)) {
		t.Fatal("an empty area must be undefined")
	}
}

// chunks A, B, A, C: only the third repeats an earlier chunk, 1. A, A, A: the
// second and the third, 2; a 15-byte tail equal to A is not a chunk
func TestDuplicateChunksKnownAnswer(t *testing.T) {
	a, b, c := bytes.Repeat([]byte{0xaa}, 16), bytes.Repeat([]byte{0xbb}, 16), bytes.Repeat([]byte{0xcc}, 16)
	if got := metrics.DuplicateChunks(bytes.Join([][]byte{a, b, a, c}, nil)); got != 1 {
		t.Fatalf("A B A C: %d, want 1", got)
	}
	if got := metrics.DuplicateChunks(bytes.Join([][]byte{a, a, a, a[:15]}, nil)); got != 2 {
		t.Fatalf("A A A and a tail: %d, want 2", got)
	}
	if got := metrics.DuplicateChunks(nil); got != 0 {
		t.Fatalf("empty: %d, want 0", got)
	}
}

// training: positives 00, 01, negatives 80, 81. the top bit of byte 0 has
// frequency 0 among positives and 1 among negatives, difference 0 - 1 = -1; the
// low bit has 1/2 in both, difference 0; the other bits are 0 in all four. so
// position 0 with sign minus. test: positives 02, 03 have the top bit 0, scores
// 0 and 0; negatives 84, 05 score -1 and 0. of the four positive-negative pairs
// two are ordered (0 > -1 twice) and two tie (0 = 0), AUC = (2 + 0.5 x 2)/4 =
// 0.75
func TestLearnedBitKnownAnswer(t *testing.T) {
	train := [][]byte{{0x00}, {0x01}, {0x80}, {0x81}}
	truth := []bool{true, true, false, false}
	bit, ok := metrics.FitLearnedBit(train, truth)
	if !ok || bit.Position != 0 || bit.Sign != -1 {
		t.Fatalf("fit = %+v %v, want position 0 sign -1", bit, ok)
	}
	test := [][]byte{{0x02}, {0x03}, {0x84}, {0x05}}
	values, ok := metrics.LearnedBitScores(train, truth, test)
	if !ok {
		t.Fatal("no scores")
	}
	want := []float64{0, 0, -1, 0}
	scores := make([]metrics.Score, len(test))
	for i, v := range values {
		if v != want[i] {
			t.Fatalf("score %d = %v, want %v", i, v, want[i])
		}
		scores[i] = metrics.Score{Entry: i, Value: v, True: truth[i]}
	}
	if got := metrics.AUC(scores); got != 0.75 {
		t.Fatalf("AUC = %v, want 0.75", got)
	}
}

// positives 00, 00 and negatives 01, 01: only the low bit differs, position 7,
// difference 0 - 1, sign minus. positives 40, 41 and negatives 01, 00: bit 1
// (0x40) differs by 1 - 0 and bit 7 by 1/2 - 1/2, position 1 sign plus. all
// four equal leaves no bit to learn
func TestLearnedBitPositionAndSign(t *testing.T) {
	truth := []bool{true, true, false, false}
	bit, ok := metrics.FitLearnedBit([][]byte{{0x00}, {0x00}, {0x01}, {0x01}}, truth)
	if !ok || bit.Position != 7 || bit.Sign != -1 {
		t.Fatalf("low bit: %+v %v, want position 7 sign -1", bit, ok)
	}
	bit, ok = metrics.FitLearnedBit([][]byte{{0x40}, {0x41}, {0x01}, {0x00}}, truth)
	if !ok || bit.Position != 1 || bit.Sign != 1 {
		t.Fatalf("second bit: %+v %v, want position 1 sign 1", bit, ok)
	}
	if bit.Score([]byte{0x40}) != 1 || bit.Score([]byte{0x00}) != 0 || !math.IsNaN(bit.Score(nil)) {
		t.Fatal("score is not sign x bit")
	}
	if _, ok := metrics.FitLearnedBit([][]byte{{0x5a}, {0x5a}, {0x5a}, {0x5a}}, truth); ok {
		t.Fatal("no difference must not fit")
	}
	if _, ok := metrics.FitLearnedBit([][]byte{{0x00}, {0x01}}, []bool{true, true}); ok {
		t.Fatal("one class must not fit")
	}
	if _, ok := metrics.FitLearnedBit([][]byte{{0x00}, {0x01, 0x02}}, []bool{true, false}); ok {
		t.Fatal("areas of different length must not fit")
	}
}

// six states give 6 x 5 / 2 = 15 pairs. one change between states 1 and 2
// separates {0, 1} from {2, 3, 4, 5}: the pairs with i <= 1 and j >= 2 differ,
// 2 x 4 = 8 of 15. no change: 0 of 15
func TestSnapshotRevealKnownAnswer(t *testing.T) {
	before, after := []byte{1, 2, 3}, []byte{1, 2, 4}
	states := [][]byte{before, before, after, after, after, after}
	if changed, pairs := metrics.SnapshotReveal(states); changed != 8 || pairs != 15 {
		t.Fatalf("one change: %d of %d, want 8 of 15", changed, pairs)
	}
	still := [][]byte{before, before, before, before, before, before}
	if changed, pairs := metrics.SnapshotReveal(still); changed != 0 || pairs != 15 {
		t.Fatalf("no change: %d of %d, want 0 of 15", changed, pairs)
	}
}

// 2^(40 - 1) x 0.25 = 549755813888 / 4 = 137438953472 s; over 365.25 x 86400 =
// 31557600 s a year that is about 4355 years
func TestGuessTimeKnownAnswer(t *testing.T) {
	got := metrics.GuessTime(0.25, 40)
	if got != 137438953472 {
		t.Fatalf("GuessTime(0.25, 40) = %v, want 137438953472", got)
	}
	if years := got / 31557600; years < 4355 || years > 4356 {
		t.Fatalf("%v years, want about 4355", years)
	}
}
