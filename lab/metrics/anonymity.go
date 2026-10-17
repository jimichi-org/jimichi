package metrics

import (
	"math"
	"slices"
	"sort"
)

type Anonymity struct {
	Entropy float64 // bits
	Degree  float64
	Size    float64
}

func undefinedAnonymity() Anonymity {
	nan := math.NaN()
	return Anonymity{Entropy: nan, Degree: nan, Size: nan}
}

// H <= log2 F over F candidates: an excess is rounding or the Miller-Madow
// correction of a near-uniform estimate, and Exp2(Log2(3)) is above 3
func anonymity(entropy float64, candidates int) Anonymity {
	top := math.Log2(float64(candidates))
	if entropy >= top {
		return Anonymity{Entropy: top, Degree: 1, Size: float64(candidates)}
	}
	return Anonymity{Entropy: entropy, Degree: entropy / top, Size: math.Exp2(entropy)}
}

func targets(scores []Score) (exits [][]Score, ok bool) {
	index := map[int]int{}
	var groups [][]Score
	for _, s := range scores {
		if math.IsNaN(s.Value) {
			return nil, false
		}
		g, seen := index[s.Exit]
		if !seen {
			g = len(groups)
			index[s.Exit] = g
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], s)
	}
	for _, g := range groups {
		switch trues := countTrue(g); {
		case trues == 1:
			exits = append(exits, g)
		case trues > 1:
			return nil, false
		}
	}
	return exits, true
}

func countTrue(scores []Score) int {
	n := 0
	for _, s := range scores {
		if s.True {
			n++
		}
	}
	return n
}

func trueValue(exit []Score) float64 {
	for _, s := range exit {
		if s.True {
			return s.Value
		}
	}
	return math.NaN()
}

func candidates(exits [][]Score) (int, bool) {
	f := len(exits[0])
	for _, e := range exits {
		if len(e) != f {
			return 0, false
		}
	}
	return f, f >= 2
}

func RankCounts(scores []Score) []float64 {
	exits, ok := targets(scores)
	if !ok || len(exits) == 0 {
		return nil
	}
	f, ok := candidates(exits)
	if !ok {
		return nil
	}
	counts := make([]float64, f)
	for _, e := range exits {
		v := trueValue(e)
		above, tied := 0, 0
		for _, s := range e {
			switch {
			case s.True:
			case s.Value > v:
				above++
			case s.Value == v:
				tied++
			}
		}
		// a tie spreads the true entry over the places it shares, as a random
		// pick among equals would
		for r := above; r <= above+tied; r++ {
			counts[r] += 1 / float64(tied+1)
		}
	}
	return counts
}

func TrueRank(scores []Score) float64 {
	exits, ok := targets(scores)
	if !ok || len(exits) == 0 {
		return math.NaN()
	}
	total := 0
	for _, e := range exits {
		v := trueValue(e)
		for _, s := range e {
			if s.Value >= v {
				total++
			}
		}
	}
	return float64(total) / float64(len(exits))
}

func RankAnonymity(counts []float64) (plugIn, corrected Anonymity) {
	f := len(counts)
	if f < 2 {
		return undefinedAnonymity(), undefinedAnonymity()
	}
	var total float64
	observed := 0
	for _, c := range counts {
		if !(c >= 0) || math.IsInf(c, 0) {
			return undefinedAnonymity(), undefinedAnonymity()
		}
		total += c
		if c > 0 {
			observed++
		}
	}
	if !(total > 0) || math.IsInf(total, 0) {
		return undefinedAnonymity(), undefinedAnonymity()
	}
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			q := c / total
			h -= q * math.Log2(q)
		}
	}
	mm := h + float64(observed-1)/(2*total*math.Ln2)
	return anonymity(h, f), anonymity(mm, f)
}

type block struct {
	start      float64
	pos, total int
}

func calibrate(train []Score) []block {
	sorted := slices.Clone(train)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value < sorted[j].Value })
	if trues := countTrue(sorted); trues == 0 || trues == len(sorted) {
		return nil
	}
	// one true pair below and one false pair above all scores leave a true and
	// a false pair in every block, so no odds are 0 or infinite
	blocks := []block{{start: math.Inf(-1), pos: 1, total: 1}}
	push := func(b block) {
		blocks = append(blocks, b)
		for len(blocks) > 1 {
			prev, last := blocks[len(blocks)-2], blocks[len(blocks)-1]
			if last.pos*prev.total >= prev.pos*last.total {
				break
			}
			blocks = append(blocks[:len(blocks)-2], block{start: prev.start, pos: prev.pos + last.pos, total: prev.total + last.total})
		}
	}
	for i := 0; i < len(sorted); {
		b := block{start: sorted[i].Value}
		for ; i < len(sorted) && sorted[i].Value == b.start; i++ {
			b.total++
			if sorted[i].True {
				b.pos++
			}
		}
		push(b)
	}
	push(block{start: math.Inf(1), total: 1})
	return blocks
}

func odds(blocks []block, value float64) float64 {
	b := blocks[sort.Search(len(blocks), func(i int) bool { return blocks[i].start > value })-1]
	return float64(b.pos) / float64(b.total-b.pos)
}

func PosteriorAnonymity(train, test []Score) (a Anonymity, crossEntropy float64) {
	undefined, nan := undefinedAnonymity(), math.NaN()
	for _, s := range slices.Concat(train, test) {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			return undefined, nan
		}
	}
	blocks := calibrate(train)
	if blocks == nil {
		return undefined, nan
	}
	exits, ok := targets(test)
	if !ok || len(exits) == 0 {
		return undefined, nan
	}
	f, ok := candidates(exits)
	if !ok {
		return undefined, nan
	}
	var entropy, cross float64
	o := make([]float64, f)
	for _, e := range exits {
		sum, truth := 0.0, 0
		for i, s := range e {
			o[i] = odds(blocks, s.Value)
			sum += o[i]
			if s.True {
				truth = i
			}
		}
		h := 0.0
		for _, x := range o {
			p := x / sum
			h -= p * math.Log2(p)
		}
		entropy += h
		cross -= math.Log2(o[truth] / sum)
	}
	n := float64(len(exits))
	return anonymity(entropy/n, f), cross / n
}
