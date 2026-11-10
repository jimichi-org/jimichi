//go:build linux && amd64

package nodeview

import "github.com/jimichi-org/jimichi/lab/metrics"

type predictionLayoutCounts struct {
	first, second, total int
}

func countPredictionLayout(views viewSet, p publicConfig, f frozenTraining) (predictionLayoutCounts, error) {
	var count predictionLayoutCounts
	if len(views.nodes) > 2 {
		return count, fail(ReasonLimit)
	}
	if len(views.nodes) == 2 {
		count.first, count.second = len(views.nodes[0].setups), len(views.nodes[1].setups)
		if count.first > 128 || count.second > 128 {
			return count, fail(ReasonLimit)
		}
		count.total = 14 * count.first * count.second
	}
	for _, node := range views.nodes {
		for _, o := range node.mailbox {
			if o.CallNS < p.epochNS || o.CallNS >= p.cutoffNS {
				continue
			}
			if f.request != nil {
				count.total++
			}
			if f.record != nil && o.HasPut && o.RecordKind == 3 {
				count.total++
			}
		}
	}
	if count.total > 491520 {
		return count, fail(ReasonLimit)
	}
	return count, nil
}

func makePredictionLayout(views viewSet, p publicConfig, f frozenTraining) (*predictionLayout, error) {
	if _, err := countPredictionLayout(views, p, f); err != nil {
		return nil, err
	}
	l := &predictionLayout{mailWindow: p.cutoffNS - p.epochNS, linking: len(views.nodes) == 2, classifiers: [2]bool{f.request != nil, f.record != nil}}
	if l.linking {
		l.first, l.second = len(views.nodes[0].setups), len(views.nodes[1].setups)
		l.total = 14 * l.first * l.second
	}
	for pop := range 2 {
		l.mail[pop] = make([][]int, len(views.nodes))
		model := f.request
		if pop == 1 {
			model = f.record
		}
		for ni, node := range views.nodes {
			l.mail[pop][ni] = make([]int, len(node.mailbox))
			for i, o := range node.mailbox {
				l.mail[pop][ni][i] = -1
				if model == nil || o.CallNS < p.epochNS || o.CallNS >= p.cutoffNS || pop == 1 && (!o.HasPut || o.RecordKind != 3) {
					continue
				}
				l.mail[pop][ni][i] = l.total
				l.total++
			}
		}
	}
	return l, nil
}

func preparePredictionStorage(p *predictions) {
	l := p.layout
	p.methods = make([]predictedMethod, 0, 16)
	add := func(name string, window int64, values, matches int) {
		p.methods = append(p.methods, predictedMethod{method: name, windowNS: window, values: make([]pairValue, 0, values), matches: make([]metrics.ViewEdge, 0, matches)})
	}
	if l.linking || l.first > 0 || l.second > 0 {
		for _, name := range []string{"setup", "close", "shared", "mixed"} {
			add(name, 0, l.first*l.second, l.first)
		}
		for _, window := range []int64{1000000000, 2000000000, 5000000000, 10000000000, 20000000000} {
			for _, name := range []string{"cells", "frames"} {
				add(name, window, l.first*l.second, l.first)
			}
		}
	}
	for pop, name := range []string{"request", "record"} {
		if !l.classifiers[pop] {
			continue
		}
		count := 0
		for _, rows := range l.mail[pop] {
			for _, index := range rows {
				if index >= 0 {
					count++
				}
			}
		}
		add(name, l.mailWindow, count, 0)
	}
	if p.seen == nil {
		p.seen = make([]uint64, (l.total+63)/64)
	}
}

func completePredictionMethods(p *predictions) error {
	if p.layout == nil {
		return fail(ReasonIPC)
	}
	expected := make([]predictedMethod, 0, 16)
	if p.layout.linking || p.layout.first > 0 || p.layout.second > 0 {
		for _, name := range []string{"setup", "close", "shared", "mixed"} {
			expected = append(expected, predictedMethod{method: name})
		}
		for _, window := range []int64{1000000000, 2000000000, 5000000000, 10000000000, 20000000000} {
			for _, name := range []string{"cells", "frames"} {
				expected = append(expected, predictedMethod{method: name, windowNS: window})
			}
		}
	}
	for i, name := range []string{"request", "record"} {
		if p.layout.classifiers[i] {
			expected = append(expected, predictedMethod{method: name, windowNS: p.layout.mailWindow})
		}
	}
	matched := 0
	for i := range expected {
		found := 0
		for _, m := range p.methods {
			if m.method == expected[i].method && m.windowNS == expected[i].windowNS {
				expected[i] = m
				found++
				matched++
			}
		}
		if found > 1 {
			clear(expected)
			return fail(ReasonIPC)
		}
	}
	if matched != len(p.methods) {
		clear(expected)
		return fail(ReasonIPC)
	}
	clear(p.methods[:cap(p.methods)])
	p.methods = expected
	return nil
}
func (l *predictionLayout) index(method, window byte, first, second int) (int, bool) {
	if first < 0 || second < 0 {
		return 0, false
	}
	if method >= 1 && method <= 6 {
		if first >= l.first || second >= l.second {
			return 0, false
		}
		ordinal := -1
		if method <= 4 && window == 0 {
			ordinal = int(method) - 1
		} else if method >= 5 && window >= 1 && window <= 5 {
			ordinal = 4 + (int(window)-1)*2 + int(method) - 5
		}
		if ordinal < 0 {
			return 0, false
		}
		return ordinal*l.first*l.second + first*l.second + second, true
	}
	if method < 7 || method > 8 || windowValue(window) != l.mailWindow {
		return 0, false
	}
	pop := int(method) - 7
	if second >= len(l.mail[pop]) || first >= len(l.mail[pop][second]) {
		return 0, false
	}
	index := l.mail[pop][second][first]
	return index, index >= 0
}

func sendPredictions(w *protocolWriter, p predictions) error {
	body := encoder{}
	body.u16(0)
	count := 0
	flush := func() error {
		if count == 0 {
			return nil
		}
		body.b[0], body.b[1] = byte(count>>8), byte(count)
		if e := w.send(opPredictions, body); e != nil {
			return e
		}
		body = encoder{}
		body.u16(0)
		count = 0
		return nil
	}
	for _, m := range p.methods {
		for _, v := range m.values {
			body.u8(methodIndex(m.method))
			body.u8(windowIndex(m.windowNS))
			body.u16(uint16(v.first))
			body.u16(uint16(v.second))
			body.f64(v.value)
			matched := false
			for _, edge := range m.matches {
				if edge.First == v.first && edge.Second == v.second {
					matched = true
					break
				}
			}
			body.bool(matched)
			count++
			if count == 256 {
				if e := flush(); e != nil {
					return e
				}
			}
		}
	}
	return flush()
}

func validatePredictions(p predictions) error {
	if p.layout == nil || p.received != p.layout.total {
		return fail(ReasonIPC)
	}
	for _, m := range p.methods {
		if e := validatePredictionMethod(p, m); e != nil {
			return e
		}
	}
	return nil
}

func validatePredictionMethod(p predictions, m predictedMethod) error {
	if m.method == "request" || m.method == "record" {
		if len(m.matches) != 0 {
			return fail(ReasonIPC)
		}
		return nil
	}
	scores := make([]metrics.Score, len(m.values))
	defer clear(scores)
	for i, v := range m.values {
		scores[i] = metrics.Score{Entry: v.first, Exit: v.second, Value: v.value}
	}
	links := metrics.BestMatches(scores, p.layout.first, 0)
	defer clear(links)
	n := 0
	for i, j := range links {
		if j < 0 {
			continue
		}
		n++
		found := false
		for _, edge := range m.matches {
			if edge.First == i && edge.Second == j {
				found = true
			}
		}
		if !found {
			return fail(ReasonIPC)
		}
	}
	if n != len(m.matches) {
		return fail(ReasonIPC)
	}
	return nil
}
