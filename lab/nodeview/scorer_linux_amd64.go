//go:build linux && amd64

package nodeview

import (
	"time"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

var methodNames = []string{"setup", "close", "shared", "mixed", "cells", "frames", "request", "record"}

func methodIndex(name string) byte {
	for i, v := range methodNames {
		if v == name {
			return byte(i + 1)
		}
	}
	return 0
}
func windowIndex(ns int64) byte {
	for i, v := range []int64{0, 1000000000, 2000000000, 5000000000, 10000000000, 20000000000, 30000000000} {
		if v == ns {
			return byte(i)
		}
	}
	return 255
}
func windowValue(index byte) int64 {
	a := []int64{0, 1000000000, 2000000000, 5000000000, 10000000000, 20000000000, 30000000000}
	if int(index) >= len(a) {
		return -1
	}
	return a[index]
}

func encodeModel(w *encoder, m *metrics.Discriminant) {
	w.bool(m != nil)
	if m == nil {
		return
	}
	if len(m.Weights) != 18 || len(m.Center) != 18 {
		w.bad = true
		return
	}
	for _, v := range m.Weights {
		w.f64(v)
	}
	for _, v := range m.Center {
		w.f64(v)
	}
	w.f64(m.Normalizer)
	w.u16(uint16(len(m.Kept)))
	for _, j := range m.Kept {
		w.u8(byte(j))
	}
	w.u16(uint16(len(m.Unused)))
	for _, j := range m.Unused {
		w.u8(byte(j))
	}
}
func decodeModel(r *decoder) *metrics.Discriminant {
	if !r.bool() {
		return nil
	}
	m := &metrics.Discriminant{Weights: make([]float64, 18), Center: make([]float64, 18)}
	for i := range m.Weights {
		m.Weights[i] = r.f64()
	}
	for i := range m.Center {
		m.Center[i] = r.f64()
	}
	m.Normalizer = r.f64()
	n := int(r.u16())
	if n > 18 {
		r.bad = true
		return m
	}
	for range n {
		m.Kept = append(m.Kept, int(r.u8()))
	}
	n = int(r.u16())
	if n > 18 {
		r.bad = true
		return m
	}
	for range n {
		m.Unused = append(m.Unused, int(r.u8()))
	}
	if len(m.Scores([][]float64{make([]float64, 18)})) != 1 {
		r.bad = true
	}
	return m
}

func scorerChild(c *childIO) error {
	w := encoder{}
	w.u8(roleScorer)
	w.u8(byte(c.suite))
	w.u16(0)
	w.u8(1)
	if e := c.status.send(opBoot, w); e != nil {
		return e
	}
	a, e := newArena(4096)
	if e != nil {
		return e
	}
	defer a.close()
	var views viewSet
	var public publicConfig
	var frozen frozenTraining
	header := false
	current := -1
	for {
		r, e := c.receive(opPredict)
		if e != nil {
			return e
		}
		if len(r.b) == 0 {
			return fail(ReasonIPC)
		}
		kind := r.b[0]
		switch kind {
		case 0:
			if header {
				return fail(ReasonIPC)
			}
			header = true
			_ = r.u8()
			public.suite = r.u8()
			public.n, public.h = int(r.u8()), int(r.u8())
			n := int(r.u8())
			if n > 2 {
				return fail(ReasonIPC)
			}
			for range n {
				public.controlled = append(public.controlled, int(r.u8()))
			}
			for i := range public.roster {
				public.roster[i] = r.u16()
			}
			public.settings = decodeSettings(r)
			public.binNS = r.i64()
			public.epochNS, public.cutoffNS = r.i64(), r.i64()
			public.population = r.ascii(16)
			for range 5 {
				public.windowsNS = append(public.windowsNS, r.i64())
			}
			frozen.request, frozen.record = decodeModel(r), decodeModel(r)
			if r.end() != nil || public.suite != byte(c.suite) || public.settings.validate(public.population == "peer") != nil {
				return fail(ReasonIPC)
			}
		case 6:
			if !header || len(views.nodes) >= 2 {
				return fail(ReasonIPC)
			}
			_ = r.u8()
			position := r.u8()
			if position >= 5 || r.end() != nil {
				return fail(ReasonIPC)
			}
			views.nodes = append(views.nodes, nodeView{position: position, arena: a, scorerProjection: true})
			current = len(views.nodes) - 1
		case 255:
			_ = r.u8()
			if !header || r.end() != nil {
				return fail(ReasonIPC)
			}
			roster := map[uint16]int{}
			for i, port := range public.roster {
				if port == 0 {
					return fail(ReasonIPC)
				}
				roster[port] = i
			}
			if len(roster) != 5 {
				return fail(ReasonIPC)
			}
			for _, node := range views.nodes {
				if e := validateViewBindings(node, roster); e != nil {
					return e
				}
			}
			pred, e := predict(views, public, frozen)
			if e != nil {
				return e
			}
			if e = sendPredictions(c.view, pred); e != nil {
				return e
			}
			if e = c.terminal(Counts{}, ReasonNone); e != nil {
				return e
			}
			pred.wipe()
			for i := range views.nodes {
				views.nodes[i].wipe()
			}
			a.close()
			return c.cleaned()
		default:
			if current < 0 {
				return fail(ReasonIPC)
			}
			if e := receiveView(r, &views.nodes[current]); e != nil {
				return e
			}
		}
	}
}

func receivePrediction(r *decoder, p *predictions) error {
	n := int(r.u16())
	if n < 1 || n > 256 || len(r.b) != 2+15*n || p.layout == nil || p.lastBatch > 0 && p.lastBatch < 256 {
		return fail(ReasonIPC)
	}
	type item struct {
		method, window byte
		value          pairValue
		matched        bool
		ordinal        int
	}
	var storage [256]item
	items := storage[:n]
	defer clear(storage[:])
	local := map[int]bool{}
	defer clear(local)
	for i := range items {
		x := item{method: r.u8(), window: r.u8(), value: pairValue{first: int(r.u16()), second: int(r.u16()), value: r.f64()}, matched: r.bool()}
		ordinal, ok := p.layout.index(x.method, x.window, x.value.first, x.value.second)
		if !ok || ordinal/64 >= len(p.seen) || x.method >= 7 && x.matched || local[ordinal] || p.seen[ordinal/64]&(1<<uint(ordinal%64)) != 0 {
			return fail(ReasonIPC)
		}
		x.ordinal = ordinal
		local[ordinal] = true
		items[i] = x
	}
	if r.end() != nil {
		return fail(ReasonIPC)
	}
	if p.methods == nil {
		return fail(ReasonIPC)
	}
	var values, matches [16]int
	defer clear(values[:])
	defer clear(matches[:])
	for _, x := range items {
		index := -1
		for i, m := range p.methods {
			if m.method == methodNames[x.method-1] && m.windowNS == windowValue(x.window) {
				index = i
				break
			}
		}
		if index < 0 {
			return fail(ReasonIPC)
		}
		values[index]++
		if x.matched {
			matches[index]++
		}
	}
	for i, m := range p.methods {
		if len(m.values)+values[i] > cap(m.values) || len(m.matches)+matches[i] > cap(m.matches) {
			return fail(ReasonIPC)
		}
	}
	for _, x := range items {
		index := 0
		for p.methods[index].method != methodNames[x.method-1] || p.methods[index].windowNS != windowValue(x.window) {
			index++
		}
		m := &p.methods[index]
		m.values = append(m.values, x.value)
		if x.matched {
			m.matches = append(m.matches, metrics.ViewEdge{First: x.value.first, Second: x.value.second})
		}
		p.seen[x.ordinal/64] |= 1 << uint(x.ordinal%64)
		p.received++
	}
	p.lastBatch = n
	return nil
}

func (f *fixture) score(views viewSet, public publicConfig, frozen frozenTraining) (predictions, error) {
	if public.settings.ControlProfile != 0 && (frozen.request != nil || frozen.record != nil) {
		return predictions{}, fail(ReasonContract)
	}
	var stream streamSize
	for _, node := range views.nodes {
		size, err := selectedStreamSize(node, 0, false)
		if err != nil {
			return predictions{}, err
		}
		stream.bytes += size.bytes + 32
		stream.frames += size.frames + 1
	}
	// the public header, two models and final marker fit in this fixed reservation
	stream.bytes += 2048
	stream.frames += 2
	if stream.bytes > controllerArenaBytes || stream.frames > maxIPCMessages {
		return predictions{}, fail(ReasonLimit)
	}
	counts, e := countPredictionLayout(views, public, frozen)
	if e != nil {
		return predictions{}, e
	}
	counted := predictionLayout{total: counts.total}
	reservation, e := scorerMemoryEstimate(views, &counted, frozen)
	if e != nil {
		return predictions{}, e
	}
	if e = f.budget.reserve(reservation); e != nil {
		return predictions{}, e
	}
	if e = f.budget.checkAllocation(reservation); e != nil {
		f.budget.release(reservation)
		return predictions{}, e
	}
	f.scorerReservation += reservation
	ownedReservation := true
	defer func() {
		if ownedReservation {
			f.budget.release(reservation)
			f.scorerReservation -= reservation
		}
	}()
	layout, e := makePredictionLayout(views, public, frozen)
	if e != nil {
		return predictions{}, e
	}
	pending := predictions{layout: layout}
	defer pending.wipe()
	preparePredictionStorage(&pending)
	if predictionBackingBytes(pending) > reservation {
		return predictions{}, fail(ReasonLimit)
	}
	started := len(f.children)
	ch, e := f.spawn(roleScorer, false)
	if len(f.children) != started {
		ownedReservation = false
	}
	if e != nil {
		return predictions{}, e
	}
	ch.dataMu.Lock()
	ch.predictions = pending
	pending = predictions{}
	ch.dataMu.Unlock()
	defer func() { ch.writer.forcedOpcode = 0 }()
	r, e := ch.expect(f.ctx, opBoot, time.Now().Add(30*time.Second))
	if e != nil {
		return predictions{}, e
	}
	if r.u8() != roleScorer || r.u8() != byte(f.suite) || r.u16() != 0 || r.u8() != 1 || r.end() != nil {
		return predictions{}, fail(ReasonIPC)
	}
	w := encoder{budget: f.budget}
	w.u8(0)
	w.u8(public.suite)
	w.u8(byte(public.n))
	w.u8(byte(public.h))
	w.u8(byte(len(public.controlled)))
	for _, v := range public.controlled {
		w.u8(byte(v))
	}
	for _, port := range public.roster {
		w.u16(port)
	}
	encodeSettings(&w, public.settings)
	w.i64(public.binNS)
	w.i64(public.epochNS)
	w.i64(public.cutoffNS)
	w.ascii(public.population, 16)
	for _, v := range public.windowsNS {
		w.i64(v)
	}
	encodeModel(&w, frozen.request)
	encodeModel(&w, frozen.record)
	if e := ch.writer.send(opPredict, w); e != nil {
		return predictions{}, e
	}
	for _, v := range views.nodes {
		w := encoder{budget: f.budget}
		w.u8(6)
		w.u8(v.position)
		if e := ch.writer.send(opPredict, w); e != nil {
			return predictions{}, e
		}
		ch.writer.forcedOpcode = opPredict
		fake := &collector{view: v, arena: v.arena}
		if e = sendView(&childIO{view: ch.writer}, fake); e != nil {
			return predictions{}, e
		}
		ch.writer.forcedOpcode = 0
	}
	w = encoder{budget: f.budget}
	w.u8(255)
	if e := ch.writer.send(opPredict, w); e != nil {
		return predictions{}, e
	}
	if e = f.finishOne(ch); e != nil {
		return predictions{}, e
	}
	retained := predictionBackingBytes(ch.predictions)
	if retained > reservation {
		return predictions{}, fail(ReasonLimit)
	}
	f.budget.release(reservation - retained)
	f.scorerReservation -= reservation - retained
	return ch.predictions, nil
}

func (f *fixture) finishOne(ch *ownedChild) error {
	until := time.Now().Add(30 * time.Second)
	r, e := ch.expect(f.ctx, opEnd, until)
	if e != nil {
		return e
	}
	status := r.u8()
	reason := decodeReason(r)
	statusFrames := r.u64()
	views, truths := r.u64(), r.u64()
	ch.counts = decodeCounts(r)
	if r.end() != nil || statusFrames != ch.statusConsumed || status != 0 || reason != ReasonNone {
		return fail(ReasonIPC)
	}
	if ch.role >= roleTrainer && (views != 1 || truths != 0 || ch.counts != (Counts{})) {
		return fail(ReasonIPC)
	}
	if ch.role >= roleTrainer {
		e = f.waitFitResult(ch, until)
	} else {
		e = waitFrames(f.ctx, &ch.viewFrames, views, ch.viewProgress, until)
	}
	if e != nil {
		return e
	}
	if e = waitFrames(f.ctx, &ch.truthFrames, truths, ch.truthProgress, until); e != nil {
		return e
	}
	if ch.role >= roleTrainer {
		ch.dataMu.Lock()
		valid := validCommittedFitResult(ch)
		readerErr := observedFitReaderError(ch)
		ch.dataMu.Unlock()
		if !valid || readerErr != nil {
			return fail(ReasonIPC)
		}
	}
	if ch.role == roleScorer {
		if e = completePredictionMethods(&ch.predictions); e != nil {
			return e
		}
		if e = validatePredictions(ch.predictions); e != nil {
			return e
		}
	}
	w := encoder{budget: f.budget}
	w.u8(0)
	if e := ch.writer.send(opAck, w); e != nil {
		return e
	}
	ch.command.Close()
	r, e = ch.expect(f.ctx, opCleaned, until)
	if e != nil {
		return e
	}
	if !r.bool() || !r.bool() || r.end() != nil {
		return fail(ReasonIPC)
	}
	return f.reap(ch, until)
}
