package metrics_test

import (
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func millis(v ...int) []time.Duration {
	out := make([]time.Duration, len(v))
	for i, x := range v {
		out[i] = time.Duration(x) * time.Millisecond
	}
	return out
}

func checkCells(t *testing.T, name string, got metrics.Cells, rows [][]float64, truth []bool, flow []int, undefined int) {
	t.Helper()
	if len(got.Rows) != len(rows) || len(got.Truth) != len(truth) || len(got.Flow) != len(flow) || got.Undefined != undefined {
		t.Fatalf("%s: %d rows, truth %v, flow %v, %d undefined; want %d rows, %v, %v, %d",
			name, len(got.Rows), got.Truth, got.Flow, got.Undefined, len(rows), truth, flow, undefined)
	}
	for i := range rows {
		if !nearAll(got.Rows[i], rows[i]) || got.Truth[i] != truth[i] || got.Flow[i] != flow[i] {
			t.Errorf("%s: row %d %v %v of flow %d, want %v %v of flow %d",
				name, i, got.Rows[i], got.Truth[i], got.Flow[i], rows[i], truth[i], flow[i])
		}
	}
}

// times in ms, features in s. Flow 0: data x = 10, 20, 35, 40, 60 after the
// setup at 0; in [15, 60) the units are k = 1, 2, 3 (10 is before, 60 on the
// close). g_prev 10, 15, 5, median 10, dev 0, 5, 5; g_next 15, 5, 20. r_next:
// the first back frame after 20 is 22, after 35 is 41, after 40 is 41: 2, 6, 1.
// r_idx back[k] - x_k: 22 - 20, 41 - 35, 43 - 40: 2, 6, 3. Flow 1: data 16,
// 30, 50, 70, units k = 0, 1, 2; k = 0 has no g_prev and is dropped; g_prev of
// the units 14 and 20, median 17. k = 1: g_next 20, dev 3, r_next 55 - 30 =
// 25, r_idx back[1] - 30 = 25. k = 2: g_next 20, dev 3, r_next 55 - 50 = 5,
// and no back[2], so it is dropped with r_idx and kept without
func TestCellFeaturesKnownAnswer(t *testing.T) {
	entry := [][]time.Duration{millis(0, 10, 20, 35, 40, 60), millis(5, 16, 30, 50, 70)}
	back := [][]time.Duration{millis(11, 22, 41, 43, 61), millis(17, 55)}
	labels := [][]bool{{false, true, false, true, false}, {false, false, true, true}}
	lo, hi := 15*time.Millisecond, 60*time.Millisecond

	withIndex := [][]float64{
		{0.010, 0.015, 0, 0.002, 0.002},
		{0.015, 0.005, 0.005, 0.006, 0.006},
		{0.005, 0.020, 0.005, 0.001, 0.003},
		{0.014, 0.020, 0.003, 0.025, 0.025},
	}
	got, ok := metrics.CellFeatures(entry, back, labels, lo, hi, true)
	if !ok {
		t.Fatal("aligned traces refused")
	}
	checkCells(t, "by index", got, withIndex, []bool{true, false, true, false}, []int{0, 0, 0, 1}, 2)

	var without [][]float64
	for _, r := range withIndex {
		without = append(without, r[:4])
	}
	// the median 17 of flow 1 stays: it is taken before any unit is dropped
	without = append(without, []float64{0.020, 0.020, 0.003, 0.005})
	got, ok = metrics.CellFeatures(entry, back, labels, lo, hi, false)
	if !ok {
		t.Fatal("aligned traces refused without r_idx")
	}
	checkCells(t, "without index", got, without, []bool{true, false, true, false, true}, []int{0, 0, 0, 1, 1}, 1)

	// the last seal of each flow had no frame: the same result
	trailing := [][]bool{{false, true, false, true, false, true}, {false, false, true, true, false}}
	got, ok = metrics.CellFeatures(entry, back, trailing, lo, hi, true)
	if !ok {
		t.Fatal("a trailing label refused")
	}
	checkCells(t, "trailing label", got, withIndex, []bool{true, false, true, false}, []int{0, 0, 0, 1}, 2)

	// window [0, 100): flow 0 units k = 0..4, median of 10, 15, 5, 20 is 12.5,
	// kept k = 1, 2, 3 with dev 2.5, 2.5, 7.5; flow 1 median of 14, 20, 20 is
	// 20, kept k = 1 with dev 6. With r_idx flow 0 drops k = 0 and 4, flow 1
	// k = 0, 2 and 3; without it flow 1 keeps k = 2, whose g_prev 20 is the
	// median
	wide := [][]float64{
		{0.010, 0.015, 0.0025, 0.002, 0.002},
		{0.015, 0.005, 0.0025, 0.006, 0.006},
		{0.005, 0.020, 0.0075, 0.001, 0.003},
		{0.014, 0.020, 0.006, 0.025, 0.025},
	}
	got, ok = metrics.CellFeatures(entry, back, labels, 0, 100*time.Millisecond, true)
	if !ok {
		t.Fatal("the wide window refused")
	}
	checkCells(t, "wide by index", got, wide, []bool{true, false, true, false}, []int{0, 0, 0, 1}, 5)
	var wideWithout [][]float64
	for _, r := range wide {
		wideWithout = append(wideWithout, r[:4])
	}
	wideWithout = append(wideWithout, []float64{0.020, 0.020, 0, 0.005})
	got, ok = metrics.CellFeatures(entry, back, labels, 0, 100*time.Millisecond, false)
	if !ok {
		t.Fatal("the wide window refused without r_idx")
	}
	checkCells(t, "wide without index", got, wideWithout, []bool{true, false, true, false, true}, []int{0, 0, 0, 1, 1}, 4)

	// a back frame at the cell's own moment is not after it: data 10, 20, 30,
	// unit k = 1 at 20, r_next 25 - 20, r_idx back[1] - 20
	got, ok = metrics.CellFeatures([][]time.Duration{millis(0, 10, 20, 30)}, [][]time.Duration{millis(20, 25)},
		[][]bool{{true, false, true}}, 15*time.Millisecond, 25*time.Millisecond, true)
	if !ok {
		t.Fatal("a reply on the cell's reading refused")
	}
	checkCells(t, "reply on the reading", got, [][]float64{{0.010, 0.010, 0, 0.005, 0.005}}, []bool{false}, []int{0}, 0)
}

func TestCellFeaturesRefusesMisalignedRuns(t *testing.T) {
	entry := [][]time.Duration{millis(0, 10, 20, 35, 40, 60), millis(5, 16, 30, 50, 70)}
	back := [][]time.Duration{millis(11, 22, 41, 43, 61), millis(17, 55)}
	flow1 := []bool{false, false, true, true}
	lo, hi := 15*time.Millisecond, 60*time.Millisecond
	for _, c := range []struct {
		name   string
		entry  [][]time.Duration
		back   [][]time.Duration
		labels [][]bool
	}{
		{"labels one short", entry, back, [][]bool{{false, true, false, true}, flow1}},
		{"two labels too many", entry, back, [][]bool{{false, true, false, true, false, true, true}, flow1}},
		{"three flows of entry against two of back", append(entry, millis(1, 2)), back, [][]bool{{false, true, false, true, false}, flow1, {true}}},
		{"no frame and one label", [][]time.Duration{nil}, [][]time.Duration{nil}, [][]bool{{true}}},
		{"entry back in time", [][]time.Duration{millis(0, 20, 10)}, [][]time.Duration{nil}, [][]bool{{true, false}}},
		{"back in time", [][]time.Duration{millis(0, 10, 20)}, [][]time.Duration{millis(15, 12)}, [][]bool{{true, false}}},
	} {
		if _, ok := metrics.CellFeatures(c.entry, c.back, c.labels, lo, hi, true); ok {
			t.Errorf("%s: accepted", c.name)
		}
	}
	for _, c := range []struct {
		name   string
		entry  [][]time.Duration
		labels [][]bool
	}{
		{"no frame and no label", [][]time.Duration{nil}, [][]bool{nil}},
		{"setup only", [][]time.Duration{millis(1)}, [][]bool{{}}},
	} {
		got, ok := metrics.CellFeatures(c.entry, [][]time.Duration{nil}, c.labels, 0, time.Second, true)
		if !ok || len(got.Rows) != 0 || got.Undefined != 0 {
			t.Errorf("%s: ok %v, %d rows, %d undefined; want accepted with no row", c.name, ok, len(got.Rows), got.Undefined)
		}
	}
}
