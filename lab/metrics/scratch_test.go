package metrics

import (
	"slices"
	"testing"
)

func TestAppendScratchScoresErasesDiscardedBacking(t *testing.T) {
	backing := make([]Score, 5)
	for i := range backing {
		backing[i] = Score{Entry: i + 1, Exit: i + 2, Value: float64(i) / 8, True: i%2 == 0}
	}
	before := slices.Clone(backing[:2])
	extra := []Score{{Entry: 21, Exit: 31, Value: .25}, {Entry: 22, Exit: 32, Value: .5}, {Entry: 23, Exit: 33, Value: .75}, {Entry: 24, Exit: 34, Value: 1}}
	extraBefore := slices.Clone(extra)
	want := append(before, extra...)
	result := appendScratchScores(backing[:2], extra...)
	if !slices.Equal(result, want) || !slices.Equal(extra, extraBefore) {
		t.Fatal("scratch growth changed scores or its separate input")
	}
	for _, score := range backing {
		if score != (Score{}) {
			t.Fatal("discarded scratch capacity retained a score")
		}
	}
	clear(result[:cap(result)])
}

func TestAppendScratchScoresPreservesLiveBackingWithoutGrowth(t *testing.T) {
	backing := make([]Score, 5)
	backing[0], backing[1], backing[4] = Score{Entry: 1, Value: .25}, Score{Entry: 2, Value: .5}, Score{Entry: 5, Value: .75}
	first, second, tail := backing[0], backing[1], backing[4]
	extra := Score{Entry: 3, Value: 1}
	result := appendScratchScores(backing[:2], extra)
	if &result[0] != &backing[0] || len(result) != 3 || result[0] != first || result[1] != second || result[2] != extra || backing[4] != tail {
		t.Fatal("in-place scratch append erased live capacity")
	}
	clear(result[:cap(result)])
}
