package nodeview

import (
	"math"
	"time"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func connection(v nodeView, g uint32) (connectionView, bool) {
	for _, c := range v.connections {
		if c.generation == g {
			return c, true
		}
	}
	return connectionView{}, false
}
func outgoing(v nodeView, s setupView) (connectionView, bool) {
	if s.outConnection == 0 {
		return connectionView{}, false
	}
	return connection(v, s.outConnection)
}

func predict(views viewSet, public publicConfig, frozen frozenTraining) (out predictions, resultErr error) {
	defer func() {
		if resultErr != nil {
			out.wipe()
		}
	}()
	if len(views.nodes) == 0 {
		return out, nil
	}
	if len(views.nodes) > 2 || public.n != 5 || public.h != 3 || public.binNS != 100000000 {
		return out, ErrInvalid
	}
	methods := 0
	if len(views.nodes) == 2 {
		methods = 4 + 2*len(public.windowsNS)
	}
	for _, node := range views.nodes {
		if len(node.mailbox) > 0 {
			methods += boolInt(frozen.request != nil) + boolInt(frozen.record != nil)
		}
	}
	if methods > 0 {
		out.methods = make([]predictedMethod, 0, methods)
	}
	if len(views.nodes) == 2 {
		first, second := views.nodes[0], views.nodes[1]
		predictStructuralMethods(&out, first, second, public)
		for _, window := range public.windowsNS {
			for _, raw := range []bool{false, true} {
				predictWindowMethod(&out, first, second, public, window, raw)
			}
		}
	}
	for ni, node := range views.nodes {
		if len(node.mailbox) == 0 || frozen.request == nil && frozen.record == nil {
			continue
		}
		if e := predictMailboxNode(&out, node, ni, public, frozen); e != nil {
			return out, e
		}
	}
	return out, nil
}

func appendPredictedMethod(out *predictions, name string, window int64, scores []metrics.Score, flows int) {
	for _, s := range scores {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			return
		}
	}
	m := predictedMethod{method: name, windowNS: window, values: make([]pairValue, len(scores)), matches: make([]metrics.ViewEdge, 0, flows)}
	for i, s := range scores {
		m.values[i] = pairValue{s.Entry, s.Exit, s.Value}
	}
	links := metrics.BestMatches(scores, flows, 0)
	defer clear(links[:cap(links)])
	for i, j := range links {
		if j >= 0 {
			m.matches = append(m.matches, metrics.ViewEdge{First: i, Second: j})
		}
	}
	out.methods = append(out.methods, m)
}

func predictStructuralMethods(out *predictions, first, second nodeView, public publicConfig) {
	a, b := make([]time.Duration, len(first.setups)), make([]time.Duration, len(second.setups))
	ca, cb := make([]time.Duration, len(a)), make([]time.Duration, len(b))
	la, lb := make([]metrics.Link, len(a)), make([]metrics.Link, len(b))
	defer clear(a)
	defer clear(b)
	defer clear(ca)
	defer clear(cb)
	defer clear(la)
	defer clear(lb)
	for i, s := range first.setups {
		a[i] = time.Duration(s.opened)
		ca[i] = -1
		if s.released > 0 && s.released <= public.cutoffNS {
			ca[i] = time.Duration(s.released)
		}
		if c, ok := outgoing(first, s); ok {
			la[i] = metrics.Link{Local: loopback(c.localPort), Remote: loopback(c.remotePort)}
		}
	}
	for i, s := range second.setups {
		b[i] = time.Duration(s.opened)
		cb[i] = -1
		if s.released > 0 && s.released <= public.cutoffNS {
			cb[i] = time.Duration(s.released)
		}
		if c, ok := connection(second, s.connection); ok && c.authenticated {
			lb[i] = metrics.Link{Local: loopback(c.localPort), Remote: loopback(c.remotePort)}
		}
	}
	setup := metrics.SetupLagScores(a, b, nil)
	shared := metrics.SharedLinkScores(la, lb, nil)
	defer clear(setup)
	defer clear(shared)
	appendPredictedMethod(out, "setup", 0, setup, len(a))
	addCloseMethod(out, ca, cb)
	appendPredictedMethod(out, "shared", 0, shared, len(a))
	mixed := make([]metrics.Score, len(setup))
	copy(mixed, setup)
	defer clear(mixed)
	for i := range mixed {
		x, y := first.setups[mixed[i].Entry], second.setups[mixed[i].Exit]
		switch {
		case x.index == y.index:
			mixed[i].Value = -3
		case int(y.index) == int(x.index)+1:
			mixed[i].Value = shared[i].Value
		case int(x.index) == int(y.index)+1:
			left, right := outgoing(second, y)
			in, ok := connection(first, x.connection)
			if right && ok {
				v := metrics.SharedLinkScores([]metrics.Link{{Local: loopback(left.localPort), Remote: loopback(left.remotePort)}}, []metrics.Link{{Local: loopback(in.localPort), Remote: loopback(in.remotePort)}}, nil)
				mixed[i].Value = v[0].Value
				clear(v)
			} else {
				mixed[i].Value = -2
			}
		case x.index > y.index:
			v := metrics.SetupLagScores([]time.Duration{b[mixed[i].Exit]}, []time.Duration{a[mixed[i].Entry]}, nil)
			mixed[i].Value = v[0].Value
			clear(v)
		}
	}
	appendPredictedMethod(out, "mixed", 0, mixed, len(a))
}

func addCloseMethod(out *predictions, first, second []time.Duration) {
	scores := metrics.CloseLagScores(first, second, nil)
	defer clear(scores)
	appendPredictedMethod(out, "close", 0, scores, len(first))
}

func setupBins(node nodeView, s setupView, public publicConfig, window int64, raw bool) []float64 {
	selected := func(connection, hop uint32, dir, kind byte, stages uint16, stamp int64) bool {
		return connection == s.connection && dir == 0 && stamp >= public.epochNS && stamp < public.epochNS+window && (raw && hop == 0 || !raw && s.hop != 0 && hop == s.hop && kind == 1 && stages&stageInput != 0)
	}
	n := 0
	for _, cell := range node.cells {
		if selected(cell.connection, cell.hop, cell.dir, cell.kind, cell.stages, cell.inputTime) {
			n++
		}
	}
	for _, cell := range node.samples {
		if selected(cell.connection, cell.hop, cell.dir, cell.kind, cell.stages, cell.time) {
			n++
		}
	}
	times := make([]time.Duration, 0, n)
	for _, cell := range node.cells {
		if selected(cell.connection, cell.hop, cell.dir, cell.kind, cell.stages, cell.inputTime) {
			times = append(times, time.Duration(cell.inputTime-public.epochNS))
		}
	}
	for _, cell := range node.samples {
		if selected(cell.connection, cell.hop, cell.dir, cell.kind, cell.stages, cell.time) {
			times = append(times, time.Duration(cell.time-public.epochNS))
		}
	}
	return binOwnedTimes(times, time.Duration(window), time.Duration(public.binNS))
}

func binOwnedTimes(times []time.Duration, window, bin time.Duration) []float64 {
	defer clear(times[:cap(times)])
	return metrics.Bin(times, window, bin)
}

func nodeBins(node nodeView, public publicConfig, window int64, raw bool) [][]float64 {
	bins := make([][]float64, len(node.setups))
	for i, s := range node.setups {
		bins[i] = setupBins(node, s, public, window, raw)
	}
	return bins
}

func wipeBins(bins [][]float64) {
	for _, bin := range bins {
		clear(bin[:cap(bin)])
	}
	clear(bins[:cap(bins)])
}

func predictWindowMethod(out *predictions, first, second nodeView, public publicConfig, window int64, raw bool) {
	left := nodeBins(first, public, window, raw)
	right := nodeBins(second, public, window, raw)
	name := "cells"
	if raw {
		name = "frames"
	}
	appendOwnedBins(out, name, window, left, right)
}

func appendOwnedBins(out *predictions, name string, window int64, left, right [][]float64) {
	defer wipeBins(left)
	defer wipeBins(right)
	scores := metrics.ScorePairs(left, right, nil)
	defer clear(scores)
	appendPredictedMethod(out, name, window, scores, len(left))
}

func predictMailboxNode(out *predictions, node nodeView, ni int, public publicConfig, frozen frozenTraining) error {
	rows, e := boundedMailboxRows(node, public.settings.RateNS)
	if e != nil {
		return e
	}
	defer func(rows []encodedMailboxRow) {
		for i := range rows {
			rows[i].wipe()
		}
	}(rows)
	for _, population := range []struct {
		name  string
		model *metrics.Discriminant
	}{{"request", frozen.request}, {"record", frozen.record}} {
		if population.model == nil {
			continue
		}
		m, e := predictMailboxPopulation(node, ni, rows, public, population.name, population.model)
		if e != nil {
			return e
		}
		out.methods = append(out.methods, m)
	}
	for i := range rows {
		rows[i].wipe()
	}
	return nil
}

func predictMailboxPopulation(node nodeView, ni int, rows []encodedMailboxRow, public publicConfig, name string, model *metrics.Discriminant) (predictedMethod, error) {
	selected := func(o mailboxObservation) bool {
		return o.CallNS >= public.epochNS && o.CallNS < public.cutoffNS && (name != "record" || o.HasPut && o.RecordKind == 3)
	}
	n := 0
	for _, o := range node.mailbox {
		if selected(o) {
			n++
		}
	}
	x := make([][]float64, n)
	indices := make([]int, n)
	backing := make([]float64, 18*n)
	defer clear(x)
	defer clear(indices)
	defer clear(backing)
	at := 0
	for i, row := range rows {
		if selected(node.mailbox[i]) {
			x[at] = backing[at*18 : (at+1)*18]
			indices[at] = i
			for j, z := range row {
				x[at][j] = float64(z)
			}
			at++
		}
	}
	scores := model.Scores(x)
	defer clear(scores[:cap(scores)])
	if len(scores) != n {
		return predictedMethod{}, fail(ReasonTraining)
	}
	m := predictedMethod{method: name, windowNS: public.cutoffNS - public.epochNS, values: make([]pairValue, n)}
	for i, v := range scores {
		m.values[i] = pairValue{indices[i], ni, v}
	}
	return m, nil
}
