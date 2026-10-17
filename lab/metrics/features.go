package metrics

import (
	"math"
	"slices"
	"sort"
	"time"
)

const (
	GPrev = iota
	GNext
	Dev
	RNext
	RIdx
)

var FeatureNames = []string{"g_prev", "g_next", "dev", "r_next", "r_idx"}

// the cells of a run inside the window, flow by flow and in time order within
// a flow; Rows hold the features in FeatureNames order, in seconds, without
// r_idx when the replies cannot be told apart by index
type Cells struct {
	Rows      [][]float64
	Truth     []bool
	Flow      []int
	Undefined int
}

// entry holds the forward frames of each flow, its setup first, and labels
// one label per data frame with at most one more at the end; false when they
// do not line up or a trace goes back in time
func CellFeatures(entry, back [][]time.Duration, labels [][]bool, lo, hi time.Duration, byIndex bool) (Cells, bool) {
	if len(back) != len(entry) || len(labels) != len(entry) {
		return Cells{}, false
	}
	for f := range entry {
		if !slices.IsSorted(entry[f]) || !slices.IsSorted(back[f]) {
			return Cells{}, false
		}
		if len(entry[f]) == 0 {
			if len(labels[f]) != 0 {
				return Cells{}, false
			}
			continue
		}
		if n := len(entry[f]) - 1; len(labels[f]) < n || len(labels[f]) > n+1 {
			return Cells{}, false
		}
	}

	out := Cells{}
	for f := range entry {
		if len(entry[f]) == 0 {
			continue
		}
		x := entry[f][1:]
		n := len(x)
		var units []int
		var gaps []float64
		for k, at := range x {
			if at < lo || at >= hi {
				continue
			}
			units = append(units, k)
			if k >= 1 {
				gaps = append(gaps, (at - x[k-1]).Seconds())
			}
		}
		// taken before any unit is dropped for another feature, and without
		// labels, so no truth reaches a test cell through it
		m := Median(gaps)
		for _, k := range units {
			if k < 1 || k > n-2 {
				out.Undefined++
				continue
			}
			next := sort.Search(len(back[f]), func(i int) bool { return back[f][i] > x[k] })
			if next == len(back[f]) || byIndex && k >= len(back[f]) {
				out.Undefined++
				continue
			}
			gPrev := (x[k] - x[k-1]).Seconds()
			row := []float64{gPrev, (x[k+1] - x[k]).Seconds(), math.Abs(gPrev - m), (back[f][next] - x[k]).Seconds()}
			if byIndex {
				row = append(row, (back[f][k] - x[k]).Seconds())
			}
			out.Rows = append(out.Rows, row)
			out.Truth = append(out.Truth, labels[f][k])
			out.Flow = append(out.Flow, f)
		}
	}
	return out, true
}
