//go:build linux && amd64

package nodeview

import (
	"io"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func sendView(c *childIO, col *collector) error {
	if _, e := selectedStreamSize(col.view, len(col.transports), false); e != nil {
		return e
	}
	for _, v := range col.view.connections {
		w := encoder{budget: c.view.budget}
		w.u8(1)
		w.u16(1)
		w.u32(v.generation)
		w.i64(v.closed)
		w.u32(v.generation)
		w.u8(byte(boolInt(v.initiator)))
		w.u16(v.localPort)
		w.u16(v.remotePort)
		w.u8(v.peer)
		w.u16(v.selectorPort)
		w.bool(v.authenticated)
		if e := c.view.send(opView, w); e != nil {
			return e
		}
	}
	for _, s := range col.view.setups {
		w := encoder{budget: c.view.budget}
		w.u8(2)
		w.u16(1)
		w.u32(s.generation)
		w.i64(s.opened)
		w.u32(s.connection)
		w.u32(s.generation)
		w.u32(s.hop)
		w.u8(s.index)
		w.u64(s.circuit)
		w.u64(s.nextCircuit)
		w.u64(s.first)
		w.u16(s.nextPort)
		w.u16(s.stages)
		w.i64(s.released)
		w.u32(s.outConnection)
		if e := c.view.send(opView, w); e != nil {
			return e
		}
	}
	for at := 0; at < len(col.view.cells); {
		w := encoder{budget: c.view.budget}
		w.u8(3)
		n := min(256, len(col.view.cells)-at)
		w.u16(uint16(n))
		for _, v := range col.view.cells[at : at+n] {
			encodeCell(&w, v)
		}
		if e := c.view.send(opView, w); e != nil {
			return e
		}
		at += n
	}
	for at := 0; at < len(col.transports); {
		w := encoder{budget: c.view.budget}
		w.u8(3)
		n := min(256, len(col.transports)-at)
		w.u16(uint16(n))
		for _, t := range col.transports[at : at+n] {
			v, e := transportProjection(t, col.view.frames, col.cutoff)
			if e != nil {
				w.wipe()
				return e
			}
			encodeCell(&w, v)
		}
		if e := c.view.send(opView, w); e != nil {
			return e
		}
		at += n
	}
	for at := 0; at < len(col.view.mailbox); {
		w := encoder{budget: c.view.budget}
		w.u8(4)
		n := min(128, len(col.view.mailbox)-at)
		w.u16(uint16(n))
		for _, m := range col.view.mailbox[at : at+n] {
			w.u32(m.Order)
			w.i64(m.CallNS)
			w.u32(m.Circuit)
			w.u16(m.Tag)
			w.u32(m.PutQueue)
			w.u32(m.FetchQueue)
			w.u32(m.RecordAlias)
			w.bool(m.HasPut)
			w.bytes(col.arena.bytes(m.record), 392)
			w.u8(m.RecordKind)
			w.u32(m.RecordNumber)
			w.u8(m.ReplyStatus)
			w.i64(m.ReturnNS - m.CallNS)
			w.bool(m.Complete)
		}
		if e := c.view.send(opView, w); e != nil {
			return e
		}
		at += n
	}
	for at := 0; at < len(col.view.releases); {
		w := encoder{budget: c.view.budget}
		w.u8(5)
		n := min(256, len(col.view.releases)-at)
		w.u16(uint16(n))
		for _, v := range col.view.releases[at : at+n] {
			w.u32(v.hop)
			w.i64(v.time)
			w.u32(v.hop)
			w.u32(v.connection)
			w.u8(v.kind)
			w.bool(v.late)
			w.bool(v.cleanup)
		}
		if e := c.view.send(opView, w); e != nil {
			return e
		}
		at += n
	}
	return nil
}

func transportProjection(t transportView, frames []frameView, cutoff int64) (cellView, error) {
	v := cellView{generation: t.generation, connection: t.connection, kind: byte(t.header.Kind), dir: t.direction, circuit: t.header.Circuit, counter: t.header.Counter, localTime: t.time, outTransport: -1, terminal: terminalNoWrite}
	if t.direction == 0 {
		v.stages = stageInput
	} else {
		v.stages = stageSealed
		v.sealTime = t.time
	}
	if t.partial {
		v.stages |= stagePartial
	}
	if t.failed {
		v.terminal = terminalWriteFailed
	} else if cutoff > 0 && t.time >= cutoff {
		v.terminal = terminalCutoff
	}
	if t.matched {
		if t.frameIndex < 0 || t.frameIndex >= len(frames) {
			return v, fail(ReasonContract)
		}
		frame := frames[t.frameIndex]
		if !frame.matched || frame.connection != t.connection || frame.direction != t.direction {
			return v, fail(ReasonContract)
		}
		v.inputTime = frame.time
		if t.direction == 1 {
			v.stages |= stageWritten
			v.writeTime = frame.time
		}
		if !t.failed {
			v.terminal = terminalForwarded
		}
	}
	return v, nil
}

func encodeCell(w *encoder, v cellView) {
	w.u32(v.generation)
	w.i64(v.inputTime)
	w.u32(v.connection)
	w.u32(v.hop)
	w.u32(v.generation)
	w.u8(v.kind)
	w.u8(v.dir)
	w.u8(v.index)
	w.u64(v.circuit)
	w.u64(v.counter)
	w.u16(v.stages)
	w.i64(v.localTime)
	w.i64(v.writeTime)
	w.u64(v.outputCounter)
	w.u8(v.terminal)
	w.bool(v.cover)
	w.bool(v.noDeliver)
	w.bool(v.nilReply)
	w.i64(v.sealTime)
}
func decodeCell(r *decoder) cellView {
	v := cellView{generation: r.u32(), inputTime: r.i64(), connection: r.u32(), hop: r.u32()}
	if r.u32() != v.generation {
		r.bad = true
	}
	v.kind, v.dir, v.index = r.u8(), r.u8(), r.u8()
	v.circuit, v.counter = r.u64(), r.u64()
	v.stages = r.u16()
	v.localTime, v.writeTime = r.i64(), r.i64()
	v.outputCounter = r.u64()
	v.terminal = r.u8()
	v.cover, v.noDeliver, v.nilReply = r.bool(), r.bool(), r.bool()
	v.sealTime = r.i64()
	if v.kind != 1 && v.kind != 3 && v.kind != 4 || v.dir > 1 || v.index >= 8 || v.stages&^31 != 0 || v.terminal > terminalAmbiguous || v.kind == 1 && v.counter >= 1<<62 {
		r.bad = true
	}
	return v
}

func receiveView(r *decoder, v *nodeView) error {
	kind := r.u8()
	n := int(r.u16())
	if n == 0 || n > 512 {
		return fail(ReasonIPC)
	}
	switch kind {
	case 1:
		if len(v.connections)+n > maxConnections {
			return recordBound(boundViewConnections, len(v.connections), n, maxConnections)
		}
		var e error
		v.connections, e = appendCapacity(v.connections, n, v.budget)
		if e != nil {
			return e
		}
		for range n {
			g, t := r.u32(), r.i64()
			if r.u32() != g {
				r.bad = true
			}
			dir := r.u8()
			x := connectionView{generation: g, closed: t, initiator: dir == 1, localPort: r.u16(), remotePort: r.u16(), peer: r.u8(), selectorPort: r.u16(), authenticated: r.bool()}
			if dir > 1 || x.localPort == 0 || x.remotePort == 0 || x.peer != 255 && x.peer >= 5 {
				r.bad = true
			}
			v.connections = append(v.connections, x)
		}
	case 2:
		if len(v.setups)+n > maxContexts {
			return recordBound(boundViewSetups, len(v.setups), n, maxContexts)
		}
		var e error
		v.setups, e = appendCapacity(v.setups, n, v.budget)
		if e != nil {
			return e
		}
		for range n {
			g, t := r.u32(), r.i64()
			s := setupView{generation: g, opened: t, connection: r.u32()}
			if r.u32() != g {
				r.bad = true
			}
			s.hop = r.u32()
			s.index = r.u8()
			s.circuit, s.nextCircuit, s.first = r.u64(), r.u64(), r.u64()
			s.nextPort = r.u16()
			s.stages = r.u16()
			s.released = r.i64()
			s.outConnection = r.u32()
			if s.index >= 3 || s.stages&^31 != 0 {
				r.bad = true
			}
			v.setups = append(v.setups, s)
		}
	case 3:
		if len(v.cells)+len(v.samples)+n > maxLifecycles*3 {
			return recordBound(boundViewCells, len(v.cells)+len(v.samples), n, maxLifecycles*3)
		}
		var e error
		if v.scorerProjection {
			v.samples, e = appendCapacity(v.samples, n, v.budget)
		} else {
			v.cells, e = appendCapacity(v.cells, n, v.budget)
		}
		if e != nil {
			return e
		}
		for range n {
			cell := decodeCell(r)
			if r.bad {
				return fail(ReasonIPC)
			}
			if e := validateCellTimes(cell); e != nil {
				return e
			}
			if v.scorerProjection {
				v.samples = append(v.samples, cellSample{connection: cell.connection, hop: cell.hop, time: cell.inputTime, sealTime: cell.sealTime, kind: cell.kind, dir: cell.dir, stages: cell.stages})
			} else {
				v.cells = append(v.cells, cell)
			}
		}
	case 4:
		if len(v.mailbox)+n > maxTruthRecords {
			return recordBound(boundViewMailbox, len(v.mailbox), n, maxTruthRecords)
		}
		var e error
		v.mailbox, e = appendCapacity(v.mailbox, n, v.budget)
		if e != nil {
			return e
		}
		for range n {
			order, call := r.u32(), r.i64()
			m := mailboxObservation{Order: order, CallNS: call, Circuit: r.u32(), Tag: r.u16(), PutQueue: r.u32(), FetchQueue: r.u32(), RecordAlias: r.u32(), HasPut: r.bool()}
			record := r.bytes(392)
			if len(record) != 0 && len(record) != 392 || m.HasPut != (len(record) == 392) {
				r.bad = true
			}
			if len(record) > 0 && !v.scorerProjection {
				if v.arena == nil {
					return fail(ReasonIPC)
				}
				var copyErr error
				m.record, copyErr = v.arena.copyChecked(record)
				if copyErr != nil {
					return carryBoundReason(copyErr, ReasonLimit)
				}
			}
			m.RecordKind, m.RecordNumber, m.ReplyStatus = r.u8(), r.u32(), r.u8()
			if m.HasPut {
				kind, number, e := mailboxRecordHeader(record)
				if e != nil || kind != m.RecordKind || number != m.RecordNumber {
					return fail(ReasonIPC)
				}
			}
			elapsed := r.i64()
			m.Complete = r.bool()
			if elapsed < 0 {
				r.bad = true
			}
			m.ReturnNS = call + elapsed
			if m.ReturnNS < call {
				r.bad = true
			}
			v.mailbox = append(v.mailbox, m)
		}
	case 5:
		if len(v.releases)+n > maxLifecycles {
			return recordBound(boundViewReleases, len(v.releases), n, maxLifecycles)
		}
		var e error
		v.releases, e = appendCapacity(v.releases, n, v.budget)
		if e != nil {
			return e
		}
		for range n {
			g, t := r.u32(), r.i64()
			x := releaseView{time: t, hop: r.u32(), connection: r.u32(), kind: r.u8(), late: r.bool(), cleanup: r.bool()}
			if g != x.hop || x.kind < 1 || x.kind > 2 {
				r.bad = true
			}
			v.releases = append(v.releases, x)
		}
	default:
		return fail(ReasonIPC)
	}
	return r.end()
}

func validateCellTimes(v cellView) error {
	if v.inputTime < 0 || v.localTime < 0 || v.sealTime < 0 || v.writeTime < 0 {
		return fail(ReasonClock)
	}
	sealed, written := v.stages&stageSealed != 0, v.stages&stageWritten != 0
	if sealed != (v.sealTime > 0) || written != (v.writeTime > 0) || written && !sealed {
		return fail(ReasonContract)
	}
	if v.stages&stageInput != 0 && v.inputTime == 0 || v.stages&stageLocal != 0 && v.localTime == 0 || v.stages&stagePartial != 0 && !sealed {
		return fail(ReasonContract)
	}
	if v.stages&stageInput != 0 && v.inputTime > v.localTime {
		return fail(ReasonClock)
	}
	if sealed && v.localTime > v.sealTime || written && v.sealTime > v.writeTime {
		return fail(ReasonClock)
	}
	return nil
}

func sendFragments(c *childIO, col *collector) error {
	for at := 0; at < len(col.fragments); {
		w := encoder{budget: c.truth.budget}
		w.u8(5)
		n := min(64, len(col.fragments)-at)
		w.u16(uint16(n))
		for _, f := range col.fragments[at : at+n] {
			w.u32(f.hop)
			w.u8(f.kind)
			w.bytes(col.arena.bytes(f.data), 512)
		}
		if e := c.truth.send(opTruth, w); e != nil {
			return e
		}
		at += n
	}
	return nil
}
func sendTruth(c *childIO, t *privateTruth) error {
	size, e := truthStreamSize(*t)
	if e != nil || size.bytes > clientArenaBytes || size.frames > maxIPCMessages {
		return fail(ReasonLimit)
	}
	for _, m := range t.messages {
		w := encoder{budget: c.truth.budget}
		w.u8(1)
		w.u16(1)
		w.u16(m.side)
		w.raw(t.arena.bytes(m.body))
		w.bool(m.sent)
		w.bool(m.replied)
		if e := c.truth.send(opTruth, w); e != nil {
			return e
		}
	}
	for _, s := range t.setups {
		w := encoder{budget: c.truth.budget}
		w.u8(2)
		w.u16(1)
		w.u16(s.side)
		w.u8(s.hop)
		w.u64(s.circuit)
		w.u8(s.roster)
		if e := c.truth.send(opTruth, w); e != nil {
			return e
		}
	}
	for at := 0; at < len(t.seals); {
		w := encoder{budget: c.truth.budget}
		w.u8(3)
		n := min(128, len(t.seals)-at)
		w.u16(uint16(n))
		for _, s := range t.seals[at : at+n] {
			w.u16(s.side)
			w.u32(s.generation)
			w.raw(t.arena.bytes(s.record))
			w.bool(s.real)
		}
		if e := c.truth.send(opTruth, w); e != nil {
			return e
		}
		at += n
	}
	for at := 0; at < len(t.requests); {
		w := encoder{budget: c.truth.budget}
		w.u8(4)
		n := min(128, len(t.requests)-at)
		w.u16(uint16(n))
		for _, q := range t.requests[at : at+n] {
			w.u16(q.side)
			w.u32(q.generation)
			w.u16(q.tag)
			w.bytes(t.arena.bytes(q.record), 392)
			w.u8(q.eligibility)
			w.bool(q.success)
		}
		if e := c.truth.send(opTruth, w); e != nil {
			return e
		}
		at += n
	}
	return nil
}
func receiveTruth(r *decoder, t *privateTruth) error {
	kind := r.u8()
	n := int(r.u16())
	if n == 0 || n > 128 {
		return fail(ReasonIPC)
	}
	var copyFailure error
	copyRaw := func(b []byte) arenaRef {
		x, err := t.arena.copyChecked(b)
		if err != nil {
			r.bad = true
			if _, ok := boundEvidence(copyFailure); !ok {
				copyFailure = err
			}
		}
		return x
	}
	switch kind {
	case 1:
		if len(t.messages)+n > maxMessages {
			return recordBound(boundTruthMessages, len(t.messages), n, maxMessages)
		}
		var e error
		t.messages, e = appendCapacity(t.messages, n, t.budget)
		if e != nil {
			return e
		}
		for range n {
			m := actualMessage{side: r.u16(), body: copyRaw(r.take(128)), sent: r.bool(), replied: r.bool()}
			t.messages = append(t.messages, m)
		}
	case 2:
		if len(t.setups)+n > maxTruthRecords {
			return recordBound(boundTruthSetups, len(t.setups), n, maxTruthRecords)
		}
		var e error
		t.setups, e = appendCapacity(t.setups, n, t.budget)
		if e != nil {
			return e
		}
		for range n {
			s := actualSetup{r.u16(), r.u8(), r.u64(), r.u8()}
			if s.hop >= 3 || s.roster >= 5 {
				r.bad = true
			}
			t.setups = append(t.setups, s)
		}
	case 3:
		if len(t.seals)+n > maxTruthRecords {
			return recordBound(boundTruthSeals, len(t.seals), n, maxTruthRecords)
		}
		var e error
		t.seals, e = appendCapacity(t.seals, n, t.budget)
		if e != nil {
			return e
		}
		for range n {
			t.seals = append(t.seals, actualSeal{r.u16(), r.u32(), copyRaw(r.take(392)), r.bool()})
		}
	case 4:
		if len(t.requests)+n > maxTruthRecords {
			return recordBound(boundTruthRequests, len(t.requests), n, maxTruthRecords)
		}
		var e error
		t.requests, e = appendCapacity(t.requests, n, t.budget)
		if e != nil {
			return e
		}
		for range n {
			q := actualRequest{side: r.u16(), generation: r.u32(), tag: r.u16(), record: copyRaw(r.bytes(392)), eligibility: r.u8(), success: r.bool()}
			if q.record.size != 0 && q.record.size != 392 || q.eligibility < 1 || q.eligibility > 4 {
				r.bad = true
			}
			t.requests = append(t.requests, q)
		}
	case 5:
		if len(t.fragments)+n > maxSelectedCells {
			return recordBound(boundTruthFragments, len(t.fragments), n, maxSelectedCells)
		}
		var e error
		t.fragments, e = appendCapacity(t.fragments, n, t.budget)
		if e != nil {
			return e
		}
		for range n {
			t.fragments = append(t.fragments, contentFragment{r.u32(), r.u8(), copyRaw(r.bytes(512))})
		}
	default:
		return fail(ReasonIPC)
	}
	if err := r.end(); err != nil {
		if _, ok := boundEvidence(copyFailure); ok {
			return carryBoundReason(copyFailure, reasonOf(err))
		}
		return err
	}
	return nil
}

func readOutput(reader *protocolReader, opcode byte, accept func(*decoder) error) error {
	defer reader.close()
	for {
		op, r, e := reader.next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if op != opcode {
			return fail(ReasonIPC)
		}
		if e = accept(r); e != nil {
			return e
		}
		secmem.Zero(r.b)
	}
}
