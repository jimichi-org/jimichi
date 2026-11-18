package metrics

import (
	"math"
	"slices"
	"sort"
)

type Discriminant struct {
	Weights    []float64
	Center     []float64
	Normalizer float64
	Kept       []int
	Unused     []int
}

// total scatter, not within-class: the same direction as Fisher's when S_w is
// invertible, and still defined when a combination of features is constant
// within each training class and differs between them
func FitDiscriminant(train [][]float64, truth []bool) (Discriminant, bool) {
	if len(train) == 0 || len(truth) != len(train) {
		return Discriminant{}, false
	}
	width := len(train[0])
	if width == 0 || !finiteRows(train, width) {
		return Discriminant{}, false
	}
	n1 := 0
	for _, t := range truth {
		if t {
			n1++
		}
	}
	n0 := len(train) - n1
	if n1 == 0 || n0 == 0 {
		return Discriminant{}, false
	}

	mu1, mu0 := make([]float64, width), make([]float64, width)
	for i, row := range train {
		for j, v := range row {
			if truth[i] {
				mu1[j] += v
			} else {
				mu0[j] += v
			}
		}
	}
	for j := range width {
		mu1[j] /= float64(n1)
		mu0[j] /= float64(n0)
	}
	fit, ok := fitColumns(train)
	if !ok {
		return Discriminant{}, false
	}
	scale, chol, kept := fit.scale, fit.chol, fit.kept
	if !slices.ContainsFunc(kept, func(j int) bool { return !same(mu1[j], mu0[j]) }) {
		return Discriminant{}, false
	}

	y := make([]float64, len(kept))
	for p, j := range kept {
		v := (mu1[j] - mu0[j]) / scale[j]
		for r := range p {
			v -= chol[j][r] * y[r]
		}
		y[p] = v / chol[j][p]
	}
	w := make([]float64, width)
	v := make([]float64, len(kept))
	for p := len(kept) - 1; p >= 0; p-- {
		j := kept[p]
		x := y[p]
		for r := p + 1; r < len(kept); r++ {
			x -= chol[kept[r]][p] * v[r]
		}
		v[p] = x / chol[j][p]
		w[j] = v[p] / scale[j]
	}
	wd := 0.0
	for _, x := range y {
		wd += x * x
	}
	if !(wd > 0) || math.IsInf(wd, 0) {
		return Discriminant{}, false
	}
	center := make([]float64, width)
	unused := []int{}
	for j := range width {
		center[j] = (mu1[j] + mu0[j]) / 2
		if !slices.Contains(kept, j) {
			unused = append(unused, j)
			// unused columns never entered the legacy score, even if their midpoint overflowed
			if math.IsNaN(center[j]) || math.IsInf(center[j], 0) {
				center[j] = 0
			}
		}
	}
	model := Discriminant{Weights: w, Center: center, Normalizer: wd, Kept: kept, Unused: unused}
	if !model.valid() {
		return Discriminant{}, false
	}
	return model, true
}

func (d Discriminant) valid() bool {
	width := len(d.Weights)
	if width == 0 || len(d.Center) != width || !finite(d.Weights) || !finite(d.Center) || !(d.Normalizer > 0) || math.IsInf(d.Normalizer, 0) || len(d.Kept) == 0 || len(d.Kept)+len(d.Unused) != width {
		return false
	}
	seen := make([]bool, width)
	for _, columns := range [][]int{d.Kept, d.Unused} {
		previous := -1
		for _, j := range columns {
			if j < 0 || j >= width || j <= previous || seen[j] {
				return false
			}
			seen[j], previous = true, j
		}
	}
	for _, j := range d.Unused {
		if d.Weights[j] != 0 {
			return false
		}
	}
	return slices.ContainsFunc(d.Kept, func(j int) bool { return d.Weights[j] != 0 })
}

func (d Discriminant) Scores(test [][]float64) []float64 {
	if !d.valid() || len(test) == 0 || !finiteRows(test, len(d.Weights)) {
		return nil
	}

	// the training class means score +1/2 and -1/2, so scores keep one scale
	// whatever the units of the features and the size of the training set
	scores := make([]float64, len(test))
	for t, row := range test {
		s := 0.0
		for _, j := range d.Kept {
			s += d.Weights[j] * (row[j] - d.Center[j])
		}
		s /= d.Normalizer
		if math.IsNaN(s) || math.IsInf(s, 0) {
			clear(scores)
			return nil
		}
		scores[t] = s
	}
	return scores
}

func DiscriminantScores(train [][]float64, truth []bool, test [][]float64) []float64 {
	fit, ok := FitDiscriminant(train, truth)
	if !ok {
		return nil
	}
	return fit.Scores(test)
}

// the column rule of DiscriminantScores, which depends on the training rows
// alone: the scale and the Cholesky rows of the columns it keeps, in order
type columnFit struct {
	scale []float64
	chol  [][]float64
	kept  []int
}

func fitColumns(train [][]float64) (columnFit, bool) {
	if len(train) == 0 {
		return columnFit{}, false
	}
	width := len(train[0])
	if width == 0 || !finiteRows(train, width) {
		return columnFit{}, false
	}
	mu := make([]float64, width)
	lo, hi := slices.Clone(train[0]), slices.Clone(train[0])
	for _, row := range train {
		for j, v := range row {
			mu[j] += v
			lo[j], hi[j] = math.Min(lo[j], v), math.Max(hi[j], v)
		}
	}
	varying := make([]bool, width)
	for j := range width {
		mu[j] /= float64(len(train))
		varying[j] = !same(lo[j], hi[j])
	}

	scatter := make([][]float64, width)
	for i := range scatter {
		scatter[i] = make([]float64, width)
	}
	for _, row := range train {
		for i := range width {
			if !varying[i] {
				continue
			}
			di := row[i] - mu[i]
			for j := range i + 1 {
				if varying[j] {
					scatter[i][j] += di * (row[j] - mu[j])
				}
			}
		}
	}
	scale := make([]float64, width)
	for j := range width {
		if !varying[j] {
			continue
		}
		scale[j] = math.Sqrt(scatter[j][j])
		// a subnormal S_t,jj has lost digits, and the scores would move with the
		// units of the feature
		if !(scatter[j][j] >= 0x1p-1022) || math.IsInf(scale[j], 0) {
			return columnFit{}, false
		}
	}

	var kept []int
	chol := make([][]float64, width)
	for i := range width {
		if !varying[i] {
			continue
		}
		row := make([]float64, len(kept)+1)
		pivot := scatter[i][i] / scale[i] / scale[i]
		for p, j := range kept {
			c := scatter[i][j] / scale[i] / scale[j]
			for r := range p {
				c -= row[r] * chol[j][r]
			}
			row[p] = c / chol[j][p]
			pivot -= row[p] * row[p]
		}
		// 1 - R^2 at most 1e-9 marks a dependent or constant column; a
		// combination spread below about 1e-4 sd is lost with it
		if pivot <= 1e-9 {
			continue
		}
		row[len(kept)] = math.Sqrt(pivot)
		chol[i] = row
		kept = append(kept, i)
	}
	return columnFit{scale: scale, chol: chol, kept: kept}, true
}

// the columns DiscriminantScores leaves out on this training set: constant, or
// a linear function of the columns before them, which may be every column.
// nil when it refuses the rows themselves: none, no columns, ragged, not
// finite, or a varying column whose scatter is subnormal, zero or infinite
func UnusedColumns(train [][]float64) []int {
	fit, ok := fitColumns(train)
	if !ok {
		return nil
	}
	unused := []int{}
	for j := range len(train[0]) {
		if !slices.Contains(fit.kept, j) {
			unused = append(unused, j)
		}
	}
	return unused
}

// the null level of KSDistance and TotalVariation: each flow's labels turned
// round by its offset, which keeps the group sizes and the clustering of
// messages in time and breaks only the link between labels and features
func CircularShift(truth []bool, flow []int, offsets []int) []bool {
	if len(truth) != len(flow) {
		return nil
	}
	members := make([][]int, len(offsets))
	for i, f := range flow {
		if f < 0 || f >= len(offsets) {
			return nil
		}
		members[f] = append(members[f], i)
	}
	out := make([]bool, len(truth))
	for f, rows := range members {
		n := len(rows)
		if n == 0 {
			continue
		}
		k := (offsets[f]%n + n) % n
		for j, i := range rows {
			out[i] = truth[rows[(j+k)%n]]
		}
	}
	return out
}

func finiteRows(rows [][]float64, width int) bool {
	for _, row := range rows {
		if len(row) != width || !finite(row) {
			return false
		}
	}
	return true
}

func finite(v []float64) bool {
	for _, x := range v {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return false
		}
	}
	return true
}

type labelled struct {
	value float64
	inA   bool
}

func pool(a, b []float64) []labelled {
	out := make([]labelled, 0, len(a)+len(b))
	for _, v := range a {
		out = append(out, labelled{v, true})
	}
	for _, v := range b {
		out = append(out, labelled{v, false})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].value < out[j].value })
	return out
}

func KSDistance(a, b []float64) float64 {
	n, m := len(a), len(b)
	if n == 0 || m == 0 || !finite(a) || !finite(b) {
		return math.NaN()
	}
	pooled := pool(a, b)
	i, j, best := 0, 0, 0
	for k := 0; k < len(pooled); {
		start := pooled[k].value
		for ; k < len(pooled) && same(pooled[k].value, start); k++ {
			if pooled[k].inA {
				i++
			} else {
				j++
			}
		}
		best = max(best, absInt(i*m-j*n))
	}
	return float64(best) / float64(n*m)
}

func TotalVariation(a, b []float64, bins int) float64 {
	n, m := len(a), len(b)
	if n == 0 || m == 0 || bins < 2 || !finite(a) || !finite(b) {
		return math.NaN()
	}
	pooled := pool(a, b)
	// at N bins every tie group has a bin of its own, and more change nothing
	bins = min(bins, len(pooled))
	ca, cb := make([]int, bins), make([]int, bins)
	for k := 0; k < len(pooled); {
		bin := bins * k / len(pooled)
		start := pooled[k].value
		for ; k < len(pooled) && same(pooled[k].value, start); k++ {
			if pooled[k].inA {
				ca[bin]++
			} else {
				cb[bin]++
			}
		}
	}
	sum := 0
	for k := range ca {
		sum += absInt(ca[k]*m - cb[k]*n)
	}
	return float64(sum) / float64(2*n*m)
}
