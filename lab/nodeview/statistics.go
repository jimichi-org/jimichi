package nodeview

import (
	"context"
	"math"
	"math/rand"
	"sort"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

const (
	nodeFamilySize         = 13
	nodeAlpha              = .05
	nodeDelta              = .05
	nodePower              = .8
	nodePowerSimulations   = 10000
	nodeBootstrapResamples = 2000
	nodeMaxPairs           = 512
)

type ModelClaim struct {
	ID       string  `json:"id"`
	Row      string  `json:"row"`
	Kind     string  `json:"kind"`
	Mean     float64 `json:"mean"`
	Variance float64 `json:"variance"`
}

func ModelRegistry() []ModelClaim {
	return []ModelClaim{
		{"E1.touched", "E1", "binary", 3. / 5, 6. / 25},
		{"E1.content", "E1", "binary", 1. / 5, 4. / 25},
		{"E1.R", "E1", "mean", 2. / 5, 23. / 200},
		{"E2.ends", "E2", "binary", 1. / 10, 9. / 100},
		{"E2.touched", "E2", "binary", 9. / 10, 9. / 100},
		{"E2.content", "E2", "binary", 2. / 5, 6. / 25},
		{"E2.R", "E2", "mean", 27. / 40, 121. / 1600},
		{"H1.touched", "H1", "binary", 1. / 2, 1. / 4},
		{"H1.R", "H1", "mean", 5. / 12, 3. / 16},
		{"H2.touched", "H2", "binary", 5. / 6, 5. / 36},
		{"H2.R", "H2", "mean", 13. / 18, 41. / 324},
		{"M2.ends", "M2", "binary", 1. / 4, 3. / 16},
		{"M2.R", "M2", "mean", 7. / 12, 11. / 144},
	}
}

func DifferenceRegistry() []string {
	return []string{"node-F5-L0", "node-F5-L1", "node-F5-L2", "node-F10-L0", "node-F10-L1", "node-F10-L2", "node-F20-L0", "node-F20-L1", "node-F20-L2", "mail-P0-request", "mail-P0-record", "mail-P33250000-request", "mail-P33250000-record"}
}

type ModelSamplePlan struct {
	Row   string       `json:"row"`
	Slots int          `json:"slots"`
	Power []ModelPower `json:"power"`
}

type ModelPower struct {
	ID    string  `json:"id"`
	Power float64 `json:"power"`
}

func ExactWilsonPower(n int, p, margin, level float64) (float64, bool) {
	if n < 1 || n > 1048576 || !(p > 0 && p < 1) || !(margin > 0 && margin < 1) || !(level > 0 && level < 1) {
		return 0, false
	}
	first := sort.Search(n+1, func(k int) bool { return metrics.WilsonInterval(k, n, level).Low >= p-margin })
	last := sort.Search(n+1, func(k int) bool { return metrics.WilsonInterval(k, n, level).High > p+margin }) - 1
	if first > last || first > n || last < 0 {
		return 0, true
	}
	mode := int(math.Floor(float64(n+1) * p))
	mode = min(mode, n)
	var all, hits, allCorrection, hitsCorrection float64
	add := func(k int, v float64) {
		y := v - allCorrection
		next := all + y
		allCorrection = (next - all) - y
		all = next
		if k >= first && k <= last {
			y = v - hitsCorrection
			next = hits + y
			hitsCorrection = (next - hits) - y
			hits = next
		}
	}
	add(mode, 1)
	v := 1.0
	for k := mode; k > 0; k-- {
		v *= float64(k) / float64(n-k+1) * (1 - p) / p
		add(k-1, v)
	}
	v = 1
	for k := mode; k < n; k++ {
		v *= float64(n-k) / float64(k+1) * p / (1 - p)
		add(k+1, v)
	}
	if !(all > 0) || math.IsInf(all, 0) {
		return 0, false
	}
	return hits / all, true
}

func PlanModelSlots(ctx context.Context) ([]ModelSamplePlan, error) {
	claims := ModelRegistry()
	out := make([]ModelSamplePlan, 0, 6)
	for _, row := range []string{"E1", "E2", "H1", "H2", "M1", "M2"} {
		if row == "M1" {
			out = append(out, ModelSamplePlan{Row: row, Slots: 32})
			continue
		}
		slots := 2048
		for _, c := range claims {
			if c.Row != row {
				continue
			}
			n, ok := metrics.EquivalenceSize(math.Sqrt(c.Variance), nodeDelta, nodeFamilySize, nodePower)
			if !ok {
				return nil, fail(ReasonModelPower)
			}
			slots = max(slots, n)
		}
		slots = (slots + 31) / 32 * 32
		for ; slots <= 1048576; slots += 32 {
			if err := ctx.Err(); err != nil {
				return nil, fail(ReasonPlanning)
			}
			powers := []ModelPower{}
			passed := true
			for _, c := range claims {
				if c.Row != row || c.Kind != "binary" {
					continue
				}
				p, ok := ExactWilsonPower(slots, c.Mean, nodeDelta, 1-nodeAlpha/nodeFamilySize)
				if !ok {
					return nil, fail(ReasonModelPower)
				}
				powers = append(powers, ModelPower{ID: c.ID, Power: p})
				passed = passed && p >= nodePower
			}
			if passed {
				out = append(out, ModelSamplePlan{Row: row, Slots: slots, Power: powers})
				break
			}
		}
		if slots > 1048576 {
			return nil, fail(ReasonModelPower)
		}
	}
	return out, nil
}

type PowerEstimate struct {
	Positions              int    `json:"positions"`
	Candidates             int    `json:"candidates"`
	Simulations            int    `json:"simulations"`
	MaximumSubsetAdditions uint64 `json:"maximum_subset_additions"`
	MaximumDPBytes         uint64 `json:"maximum_dp_bytes"`
	PrefixBytes            uint64 `json:"prefix_bytes"`
	MemoEntries            int    `json:"memo_entries"`
}

func PairedPowerEstimate() PowerEstimate {
	var additions uint64
	for n := 30; n <= nodeMaxPairs; n++ {
		additions += uint64(n) * uint64(n*(n+1)) * nodePowerSimulations * nodeFamilySize
	}
	return PowerEstimate{Positions: nodeFamilySize, Candidates: nodeMaxPairs - 29, Simulations: nodePowerSimulations, MaximumSubsetAdditions: additions, MaximumDPBytes: uint64(nodeMaxPairs*(nodeMaxPairs+1)+1) * 8, PrefixBytes: nodePowerSimulations * nodeMaxPairs, MemoEntries: 131072}
}

type PairedPowerPoint struct {
	N           int     `json:"n"`
	Successes   int     `json:"successes"`
	Simulations int     `json:"simulations"`
	Power       float64 `json:"power"`
	Low         float64 `json:"low"`
	High        float64 `json:"high"`
}

type PairedPowerPlan struct {
	Seed            int64              `json:"seed"`
	SelectedN       int                `json:"selected_n"`
	Reason          Reason             `json:"reason,omitempty"`
	Estimate        PowerEstimate      `json:"estimate"`
	Search          []PairedPowerPoint `json:"search"`
	ExactCalls      uint64             `json:"exact_calls"`
	SubsetAdditions uint64             `json:"subset_additions"`
}

type planningRankKey struct {
	Counts      [5]uint16
	PositiveSum uint32
}

type planningCounts struct{ counts, positive [5]uint16 }

type pairedPlanner struct {
	prefixes         []byte
	atoms            [5]float64
	order            [5]int
	sign             [5]bool
	states           []planningCounts
	memo             map[planningRankKey]float64
	calls, additions uint64
}

func newPairedPlanner(x, y []float64, seed int64) (*pairedPlanner, bool) {
	if len(x) != 5 || len(y) != 5 {
		return nil, false
	}
	var z [5]float64
	c, b := 0.0, 0.0
	for i := range 5 {
		if math.IsNaN(x[i]) || math.IsNaN(y[i]) || x[i] < 0 || x[i] > 1 || y[i] < 0 || y[i] > 1 {
			return nil, false
		}
		z[i] = x[i] - y[i]
		c += z[i]
		b += (x[i] + y[i]) / 2
	}
	c /= 5
	b /= 5
	sign := 1.0
	if b > .5 {
		sign = -1
	}
	for i := range z {
		z[i] = z[i] - c + sign*nodeDelta
	}
	p := &pairedPlanner{prefixes: make([]byte, nodePowerSimulations*nodeMaxPairs), states: make([]planningCounts, nodePowerSimulations), memo: make(map[planningRankKey]float64)}
	p.atoms = z
	for i := range p.order {
		p.order[i] = i
		p.sign[i] = z[i] > 0
	}
	sort.Slice(p.order[:], func(i, j int) bool { return math.Abs(z[p.order[i]]) < math.Abs(z[p.order[j]]) })
	rng := rand.New(rand.NewSource(seed))
	for i := range p.prefixes {
		p.prefixes[i] = byte(rng.Intn(5))
	}
	return p, true
}

func (p *pairedPlanner) release() {
	clear(p.prefixes)
	clear(p.states)
	clear(p.memo)
	clear(p.atoms[:])
	clear(p.order[:])
	clear(p.sign[:])
}

// tolerance ties start at the smallest occupied atom, not the complete pilot
func (p *pairedPlanner) ranked(state planningCounts) (planningRankKey, [5]int, int, int) {
	var key planningRankKey
	var ranks [5]int
	count, positive, group := 0, 0, 0
	for i := 0; i < len(p.order); {
		anchor := p.order[i]
		if state.counts[anchor] == 0 || mailboxSame(p.atoms[anchor], 0) {
			i++
			continue
		}
		j, tied, plus := i, 0, 0
		for j < len(p.order) && mailboxSame(math.Abs(p.atoms[p.order[j]]), math.Abs(p.atoms[anchor])) {
			index := p.order[j]
			tied += int(state.counts[index])
			plus += int(state.positive[index])
			j++
		}
		key.Counts[group] = uint16(tied)
		ranks[group] = 2*count + tied + 1
		positive += plus * ranks[group]
		count += tied
		group++
		i = j
	}
	key.PositiveSum = uint32(positive)
	return key, ranks, count, positive
}

func (p *pairedPlanner) point(ctx context.Context, n, previous int) (PairedPowerPoint, bool) {
	out := PairedPowerPoint{N: n, Simulations: nodePowerSimulations}
	for simulation := range nodePowerSimulations {
		if simulation%64 == 0 && ctx.Err() != nil {
			return out, false
		}
		state := &p.states[simulation]
		for j := previous; j < n; j++ {
			index := p.prefixes[simulation*nodeMaxPairs+j]
			if mailboxSame(p.atoms[index], 0) {
				continue
			}
			state.counts[index]++
			if p.sign[index] {
				state.positive[index]++
			}
		}
		key, ranks, count, positive := p.ranked(*state)
		pv, exists := p.memo[key]
		if !exists {
			var ok bool
			pv, ok = p.tail(ctx, key.Counts, ranks, count, positive)
			if !ok {
				return out, false
			}
			if len(p.memo) < 131072 {
				p.memo[key] = pv
			}
		}
		if pv <= nodeAlpha/nodeFamilySize {
			out.Successes++
		}
	}
	out.Power = float64(out.Successes) / nodePowerSimulations
	iv := metrics.WilsonInterval(out.Successes, nodePowerSimulations, .95)
	out.Low, out.High = iv.Low, iv.High
	return out, true
}

func (p *pairedPlanner) tail(ctx context.Context, counts [5]uint16, ranks [5]int, n, positive int) (float64, bool) {
	p.calls++
	if n == 0 {
		return 1, true
	}
	total := n * (n + 1)
	mean := total / 2
	dev := positive - mean
	if dev < 0 {
		dev = -dev
	}
	if dev == 0 {
		return 1, true
	}
	if positive == 0 || positive == total {
		return math.Ldexp(2, -n), true
	}
	dp := make([]float64, total+1)
	dp[0] = 1
	reach := 0
	for g, k := range counts {
		for range k {
			r := ranks[g]
			reach += r
			for s := reach; s >= r; s-- {
				dp[s] += dp[s-r]
				p.additions++
			}
			if ctx.Err() != nil {
				return 0, false
			}
		}
	}
	var hits, all float64
	for s, v := range dp {
		all += v
		distance := s - mean
		if distance < 0 {
			distance = -distance
		}
		if distance >= dev {
			hits += v
		}
	}
	if n > 100 {
		return math.Min(1, hits/math.Ldexp(1, n)), true
	}
	return hits / all, true
}

func PlanPairedPower(ctx context.Context, pilotX, pilotY []float64, seed int64) (PairedPowerPlan, error) {
	out := PairedPowerPlan{Seed: seed, Estimate: PairedPowerEstimate()}
	p, ok := newPairedPlanner(pilotX, pilotY, seed)
	if !ok {
		out.Reason = ReasonPilot
		return out, fail(ReasonPilot)
	}
	defer p.release()
	previous := 0
	for n := 30; n <= nodeMaxPairs; n++ {
		point, ok := p.point(ctx, n, previous)
		previous = n
		out.ExactCalls, out.SubsetAdditions = p.calls, p.additions
		if !ok {
			out.Reason = ReasonPlanning
			return out, fail(ReasonPlanning)
		}
		out.Search = append(out.Search, point)
		if point.Power >= nodePower {
			out.SelectedN = n
			return out, nil
		}
	}
	out.Reason = ReasonPower
	return out, fail(ReasonPower)
}

func PairedPowerAtN(ctx context.Context, pilotX, pilotY []float64, seed int64, n int) (PairedPowerPoint, error) {
	if n < 30 || n > nodeMaxPairs {
		return PairedPowerPoint{}, ErrInvalid
	}
	p, ok := newPairedPlanner(pilotX, pilotY, seed)
	if !ok {
		return PairedPowerPoint{}, fail(ReasonPilot)
	}
	defer p.release()
	point, ok := p.point(ctx, n, 0)
	if !ok {
		return point, fail(ReasonPlanning)
	}
	return point, nil
}

type PairedInference struct {
	Pairs       int          `json:"pairs"`
	Test        metrics.Test `json:"test"`
	MedianDelta float64      `json:"median_delta"`
}

func AnalyzePaired(x, y []float64) (PairedInference, error) {
	if len(x) < 1 || len(x) > nodeMaxPairs || len(x) != len(y) {
		return PairedInference{}, ErrInvalid
	}
	test, ok := metrics.WilcoxonExact(x, y, nodeMaxPairs)
	if !ok || test.Method != "exact" && test.Method != "degenerate" {
		return PairedInference{}, fail(ReasonIncomplete)
	}
	d := make([]float64, len(x))
	defer clear(d)
	for i := range d {
		d[i] = x[i] - y[i]
	}
	return PairedInference{Pairs: len(x), Test: test, MedianDelta: metrics.Median(d)}, nil
}
