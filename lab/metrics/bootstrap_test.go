package metrics_test

import (
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

type bootstrapCase struct {
	name      string
	scores    []metrics.Score
	flows     int
	resamples int
	seed      int64
}

func bootstrapCases() []bootstrapCase {
	ties := make([][]float64, 5)
	for i := range ties {
		ties[i] = make([]float64, 5)
		for j := range ties[i] {
			ties[i][j] = float64((i*3+j*5)%4) / 4
		}
		ties[i][i] += 0.25
	}
	six := make([][]float64, 6)
	for i := range six {
		six[i] = make([]float64, 6)
		for j := range six[i] {
			six[i][j] = math.Round(math.Mod(float64(i*7+j*11)*0.137, 1)*100) / 100
		}
		six[i][i] += 0.2
	}
	brackets := [][]float64{
		{0.9, 0.2, 0.1, 0.3},
		{0.4, 0.3, 0.3, 0.2},
		{0.2, 0.5, 0.6, 0.1},
		{0.3, 0.1, 0.7, 0.7},
	}
	lcg := uint64(12345)
	twenty := make([][]float64, 20)
	for i := range twenty {
		twenty[i] = make([]float64, 20)
		for j := range twenty[i] {
			lcg = lcg*6364136223846793005 + 1442695040888963407
			twenty[i][j] = float64(lcg>>59) / 32
		}
		twenty[i][i] += 0.125
	}
	oneSided := []metrics.Score{
		{Entry: 0, Exit: 0, Value: 0.8, True: true},
		{Entry: 0, Exit: 1, Value: 0.4, True: true},
		{Entry: 1, Exit: 0, Value: 0.5},
		{Entry: 1, Exit: 1, Value: 0.3},
		{Entry: 2, Exit: 0, Value: 0.9},
		{Entry: 2, Exit: 1, Value: 0.1},
	}
	constant := make([][]float64, 4)
	for i := range constant {
		constant[i] = []float64{0.5, 0.5, 0.5, 0.5}
	}
	allTrue := []metrics.Score{{Entry: 0, Value: 0.3, True: true}, {Entry: 1, Value: 0.6, True: true}}
	return []bootstrapCase{
		{"ties", matrixScores(ties), 5, 400, 1},
		{"ties other seed", matrixScores(ties), 5, 1000, 99},
		{"six flows", matrixScores(six), 6, 2000, 7},
		{"brackets", matrixScores(brackets), 4, 10000, 1},
		{"twenty flows", matrixScores(twenty), 20, 3000, 11},
		{"twenty flows other seed", matrixScores(twenty), 20, 500, 12},
		{"two flows", matrixScores([][]float64{{0.5, 0.6}, {0.4, 0.45}}), 2, 300, 3},
		{"two flows perfect", matrixScores([][]float64{{1, 0}, {0, 1}}), 2, 500, 1},
		{"resamples without a class", oneSided, 3, 700, 5},
		{"all tied", matrixScores(constant), 4, 200, 2},
		{"undefined point", allTrue, 2, 100, 1},
		{"one flow", matrixScores([][]float64{{0.7, 0.4}}), 1, 100, 1},
		{"no resamples", matrixScores(ties), 5, 0, 1},
	}
}

// outputs of BootstrapAUC on main before the level became a parameter, so the
// refactor keeps every published interval bit for bit
var bootstrapPinned = map[string][3]uint64{
	"ties":                      {0x3fd0000000000000, 0x3fc3333333333333, 0x3fd6666666666666},
	"ties other seed":           {0x3fd0000000000000, 0x3fc3333333333333, 0x3fd6666666666666},
	"six flows":                 {0x3fe3e93e93e93e94, 0x3fdaaaaaaaaaaaab, 0x3feb05b05b05b05b},
	"brackets":                  {0x3fec000000000000, 0x3fe5000000000000, 0x3ff0000000000000},
	"twenty flows":              {0x3fe66216a2c31955, 0x3fe1e7748d1c3f24, 0x3fea44d907a68d5d},
	"twenty flows other seed":   {0x3fe66216a2c31955, 0x3fe1d9ec1d72a811, 0x3fea18fef24ba86f},
	"two flows":                 {0x3fe0000000000000, 0x0, 0x3ff0000000000000},
	"two flows perfect":         {0x3ff0000000000000, 0x3ff0000000000000, 0x3ff0000000000000},
	"resamples without a class": {0x3fe4000000000000, 0x3fe0000000000000, 0x3fe8000000000000},
	"all tied":                  {0x3fe0000000000000, 0x3fe0000000000000, 0x3fe0000000000000},
	"undefined point":           {0x7ff8000000000001, 0x7ff8000000000001, 0x7ff8000000000001},
	"one flow":                  {0x3ff0000000000000, 0x7ff8000000000001, 0x7ff8000000000001},
	"no resamples":              {0x3fd0000000000000, 0x7ff8000000000001, 0x7ff8000000000001},
}

func TestBootstrapAUCPinned(t *testing.T) {
	for _, c := range bootstrapCases() {
		want, ok := bootstrapPinned[c.name]
		if !ok {
			t.Fatalf("%s: no pinned output", c.name)
		}
		ci := metrics.BootstrapAUC(c.scores, c.flows, c.resamples, c.seed)
		got := [3]uint64{math.Float64bits(ci.Point), math.Float64bits(ci.Low), math.Float64bits(ci.High)}
		if got != want || ci.Method != "bca" {
			t.Fatalf("%s: got %#x %q, want %#x", c.name, got, ci.Method, want)
		}
	}
}

func TestBootstrapAUCLevelWidens(t *testing.T) {
	for _, c := range bootstrapCases() {
		base := metrics.BootstrapAUC(c.scores, c.flows, c.resamples, c.seed)
		wide := metrics.BootstrapAUCLevel(c.scores, c.flows, c.resamples, c.seed, 1-0.05/3)
		if math.Float64bits(wide.Point) != math.Float64bits(base.Point) {
			t.Fatalf("%s: the level moved the point", c.name)
		}
		if math.IsNaN(base.Low) {
			if !math.IsNaN(wide.Low) || !math.IsNaN(wide.High) {
				t.Fatalf("%s: undefined at 0.95 but %+v at the corrected level", c.name, wide)
			}
			continue
		}
		if c.name == "twenty flows" && (wide.Low >= base.Low || wide.High <= base.High) {
			t.Fatalf("%s: the corrected level did not widen [%v, %v]", c.name, base.Low, base.High)
		}
		if wide.Low > base.Low || wide.High < base.High {
			t.Fatalf("%s: [%v, %v] does not contain [%v, %v]", c.name, wide.Low, wide.High, base.Low, base.High)
		}
		same := metrics.BootstrapAUCLevel(c.scores, c.flows, c.resamples, c.seed, 0.95)
		if !near(same.Low, base.Low) || !near(same.High, base.High) {
			t.Fatalf("%s: level 0.95 gave %+v, want %+v", c.name, same, base)
		}
	}
}

func TestBootstrapAUCLevelRejectsLevelOutsideUnitInterval(t *testing.T) {
	scores := []metrics.Score{{Entry: 0, True: true, Value: 1}, {Entry: 1, Value: 0}, {Entry: 2, True: true, Value: 2}, {Entry: 3, Value: -1}}
	for _, level := range []float64{0, -0.5, 1, 1.5, math.NaN()} {
		got := metrics.BootstrapAUCLevel(scores, 4, 100, 1, level)
		if got.Point != 1 || !math.IsNaN(got.Low) || !math.IsNaN(got.High) {
			t.Fatalf("level %v: got %+v, want point 1 and no interval", level, got)
		}
	}
}
