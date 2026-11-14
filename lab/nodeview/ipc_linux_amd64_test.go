//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/wire"
	"math"
	"testing"
)

func TestSetupCodecExplicitSuccessorRoundTrip(t *testing.T) {
	s := setupView{generation: 4, connection: 2, hop: 3, outConnection: 5, index: 1, circuit: 11, nextCircuit: 12, first: 7, nextPort: 1001, opened: 101, released: 127, stages: stageInput | stageLocal}
	var wire bytes.Buffer
	writer := protocolWriter{w: &wire, limit: relayArenaBytes}
	if e := sendView(&childIO{view: &writer}, &collector{view: nodeView{setups: []setupView{s}}}); e != nil {
		t.Fatal(e)
	}
	// 3 kind/count bytes plus 65 setup bytes and 30 framing bytes total 98
	if wire.Len() != 98 || binary.BigEndian.Uint32(wire.Bytes()[:4]) != 94 {
		t.Fatal("setup record size changed")
	}
	body := wire.Bytes()[30:]
	if len(body) != 68 {
		t.Fatal("setup body size")
	}
	var decoded nodeView
	if e := receiveView(&decoder{b: body}, &decoded); e != nil {
		t.Fatal(e)
	}
	if len(decoded.setups) != 1 || decoded.setups[0].outConnection != 5 || decoded.setups[0].released != 127 || decoded.setups[0].circuit != 11 {
		t.Fatal("explicit binding changed")
	}
	for at := 0; at < len(body); at++ {
		if e := receiveView(&decoder{b: body[:at]}, &nodeView{}); e == nil {
			t.Fatal("truncated setup accepted")
		}
	}
	s.outConnection = 0
	wire.Reset()
	writer = protocolWriter{w: &wire, limit: relayArenaBytes}
	if e := sendView(&childIO{view: &writer}, &collector{view: nodeView{setups: []setupView{s}}}); e != nil {
		t.Fatal(e)
	}
	decoded = nodeView{}
	if e := receiveView(&decoder{b: wire.Bytes()[30:]}, &decoded); e != nil || decoded.setups[0].outConnection != 0 {
		t.Fatal("explicit zero changed")
	}
}

func TestWorkloadGrantStrictWholeSyntaxBeforeCopy(t *testing.T) {
	a := outcomeTestArena(t)
	ref := outcomeTestCopy(t, a, bytes.Repeat([]byte{7}, 128))
	grant, e := sourceAttemptCeiling()
	if e != nil {
		t.Fatal(e)
	}
	plan := workloadPlan{side: 1, route: [3]uint8{0, 1, 4}, gapSeed: 7, lifetimeSeed: 8, phaseSeed: 9, topology: 2, sourceLimit: grant, bodyArena: a, bodies: []arenaRef{ref}}
	encoded := encodeWorkload(plan)
	defer encoded.wipe()
	if len(encoded.b) != 167 {
		t.Fatal("private plan is not the old 163-byte prefix plus mandatory u32 grant")
	}
	for _, limit := range []uint32{1, 128, grant} {
		plan.sourceLimit = limit
		w := encodeWorkload(plan)
		dst := outcomeTestArena(t)
		decoded, e := decodeWorkload(&decoder{b: w.b}, dst)
		w.wipe()
		if e != nil || decoded.sourceLimit != limit || decoded.side != plan.side || len(decoded.bodies) != 1 || !bytes.Equal(dst.bytes(decoded.bodies[0]), a.bytes(ref)) {
			t.Fatal("valid private grant changed plan/body bytes")
		}
	}
	for _, limit := range []uint32{0, grant + 1, ^uint32(0)} {
		plan.sourceLimit = limit
		w := encodeWorkload(plan)
		dst := outcomeTestArena(t)
		if _, e := decodeWorkload(&decoder{b: w.b}, dst); reasonOf(e) != ReasonIPC || dst.used != 0 {
			t.Fatal("invalid grant copied a declared body")
		}
		w.wipe()
	}
	for n := 0; n < len(encoded.b); n++ {
		dst := outcomeTestArena(t)
		if _, e := decodeWorkload(&decoder{b: encoded.b[:n]}, dst); reasonOf(e) != ReasonIPC || dst.used != 0 {
			t.Fatal("truncated/legacy plan copied a body or supplied a default grant")
		}
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return append(b, 1) },
		func(b []byte) []byte { b[4] = b[3]; return b },
		func(b []byte) []byte { b[160] = 3; return b },
		func(b []byte) []byte { binary.BigEndian.PutUint16(b[30:32], 129); return b },
	} {
		dst := outcomeTestArena(t)
		bad := mutate(bytes.Clone(encoded.b))
		if _, e := decodeWorkload(&decoder{b: bad}, dst); reasonOf(e) != ReasonIPC || dst.used != 0 {
			t.Fatal("malformed whole plan left a partial copy")
		}
		clear(bad)
	}
	plan.topology, plan.sourceLimit = 1, 0
	w := encodeWorkload(plan)
	if _, e := decodeWorkload(&decoder{b: w.b}, outcomeTestArena(t)); e != nil {
		t.Fatal("echo zero grant rejected")
	}
	w.wipe()
	plan.sourceLimit = 1
	w = encodeWorkload(plan)
	if _, e := decodeWorkload(&decoder{b: w.b}, outcomeTestArena(t)); reasonOf(e) != ReasonIPC {
		t.Fatal("echo peer grant admitted")
	}
	w.wipe()
}

func TestWorkloadBeginRejectsSignedWrapBeforeSourceStart(t *testing.T) {
	const duration = int64(30000000000)
	for _, epoch := range []int64{1, 1234567890, math.MaxInt64 - duration} {
		w := encoder{}
		w.i64(epoch)
		w.i64(duration)
		w.i64(epoch + duration)
		if got, cutoff, e := decodeWorkloadBegin(&decoder{b: w.b}, duration); e != nil || got != epoch || cutoff != epoch+duration {
			t.Fatal("representable half-open source window changed")
		}
		w.wipe()
	}
	for _, row := range [][3]int64{{0, duration, duration}, {-1, duration, duration - 1}, {1, 0, 1}, {1, -1, 0}, {math.MaxInt64 - 10, duration, math.MinInt64 + duration - 11}, {1, duration, 3}, {1, duration + 1, duration + 2}} {
		w := encoder{}
		for _, n := range row {
			w.i64(n)
		}
		if _, _, e := decodeWorkloadBegin(&decoder{b: w.b}, duration); reasonOf(e) != ReasonIPC {
			t.Fatal("invalid or wrapped Begin admitted")
		}
		w.wipe()
	}
	valid := encoder{}
	valid.i64(1)
	valid.i64(duration)
	valid.i64(duration + 1)
	defer valid.wipe()
	for n := 0; n < len(valid.b); n++ {
		if _, _, e := decodeWorkloadBegin(&decoder{b: valid.b[:n]}, duration); reasonOf(e) != ReasonIPC {
			t.Fatal("truncated Begin admitted")
		}
	}
	if _, _, e := decodeWorkloadBegin(&decoder{b: append(bytes.Clone(valid.b), 0)}, duration); reasonOf(e) != ReasonIPC {
		t.Fatal("trailing Begin data admitted")
	}
}

func TestClientTruthBorrowedPacketMatchesLegacyBytesAndRejectsDrift(t *testing.T) {
	p := capacityTestCapture(t)
	ref := outcomeTestCopy(t, p.truth.arena, bytes.Repeat([]byte{5}, 128))
	if _, e := p.sourceMessage(ref); e != nil {
		t.Fatal(e)
	}
	for i, hop := range []uint8{2, 1, 0} {
		appendSetupSeal(p, hop, uint64(i+1))
	}
	for i := range 129 {
		out := make([]byte, 392)
		out[0] = 3
		binary.BigEndian.PutUint32(out[1:5], uint32(i))
		tag := keyTag{purpose: "e2e/step/key"}
		tag.context[0] = byte(i)
		p.dummy[tag.context] = i%2 == 0
		p.afterSeal(tag, nil, out, nil)
		clear(out)
	}
	conv := &conversation.Conversation{}
	gate := make(chan struct{})
	close(gate)
	observed := observedCircuit{Circuit: &capacityCircuit{}, private: p, gate: gate, conversation: &conv, generation: 1}
	for i := range 129 {
		request := mailbox.Request{Tag: uint16(i), Put: [16]byte{1}, Record: [392]byte{3}}
		body := request.Bytes()
		if e := observed.Send(body); e != nil {
			t.Fatal(e)
		}
		clear(body)
	}
	if p.err != ReasonNone {
		t.Fatal("valid fixed capture refused")
	}
	legacy := p.truth
	legacy.client = false
	legacy.clientPacket = nil
	var oldWire, newWire bytes.Buffer
	oldWriter := &protocolWriter{w: &oldWire, limit: clientArenaBytes}
	if e := sendTruth(&childIO{truth: oldWriter}, &legacy); e != nil {
		t.Fatal(e)
	}
	packet := p.truth.clientPacket
	newWriter := &protocolWriter{w: &newWire, limit: clientArenaBytes, budget: &memoryBudget{beforeAllocation: func(uint64) error { t.Fatal("borrowed client packet allocated"); return nil }}}
	if e := sendTruth(&childIO{truth: newWriter}, &p.truth); e != nil || !bytes.Equal(newWire.Bytes(), oldWire.Bytes()) || newWriter.frames != oldWriter.frames || newWriter.bytes != oldWriter.bytes || &packet[0] != &p.truth.clientPacket[0] || !bytes.Equal(packet, make([]byte, len(packet))) {
		t.Fatal("prepaid encoding changed packet bytes, order, owner or wipe")
	}
	p.truth.capacity.wireBytes++
	newWire.Reset()
	if e := sendTruth(&childIO{truth: newWriter}, &p.truth); reasonOf(e) != ReasonContract || newWire.Len() != 0 {
		t.Fatal("freeze mismatch wrote a replacement stream")
	}
	if _, e := truthPacketEncoder(&p.truth, 65507, nil); reasonOf(e) != ReasonLimit {
		t.Fatal("oversized typed body began encoding")
	}
}

func TestNonapplicationEndStatusCountPrecedesAck(t *testing.T) {
	for _, role := range []byte{roleScorer, roleTrainer, roleFitAuditor} {
		for _, declared := range []uint64{0, 2, 256} {
			var output bytes.Buffer
			child := &ownedChild{role: role, status: make(chan statusFrame, 1), writer: &protocolWriter{w: &output, limit: 1 << 20}}
			body := encoder{}
			body.u8(0)
			body.u8(0)
			body.u64(declared)
			body.u64(0)
			body.u64(0)
			encodeCounts(&body, Counts{})
			child.status <- statusFrame{op: opEnd, body: body.b}
			f := fixture{ctx: context.Background()}
			if e := f.finishOne(child); e == nil || output.Len() != 0 {
				t.Fatal("bad status declaration reached ack")
			}
		}
	}
}

func TestTransportProjectionNeverInventsCompletedFrame(t *testing.T) {
	for _, transport := range []transportView{{direction: 1, time: 150, header: wire.Header{Kind: wire.KindData}}, {direction: 1, time: 150, partial: true, failed: true, header: wire.Header{Kind: wire.KindData}}} {
		for _, frames := range [][]frameView{nil, {{connection: 99, direction: 1, time: 999, matched: true}}} {
			cell, e := transportProjection(transport, frames, 200)
			if e != nil || cell.stages&stageWritten != 0 || cell.writeTime != 0 || cell.inputTime != 0 || cell.sealTime != 150 {
				t.Fatal("unmatched Seal acquired a frame or timestamp")
			}
			if transport.failed && cell.terminal != terminalWriteFailed {
				t.Fatal("failed write lost")
			}
		}
	}
	transport := transportView{direction: 1, connection: 3, time: 150, matched: true, failed: true, frameIndex: 0, header: wire.Header{Kind: wire.KindData}}
	cell, e := transportProjection(transport, []frameView{{connection: 3, direction: 1, time: 210, matched: true}}, 200)
	if e != nil || cell.stages&stageWritten == 0 || cell.writeTime != 210 || cell.sealTime != 150 || cell.terminal != terminalWriteFailed {
		t.Fatal("actual complete n+error stages changed")
	}
}

func TestPredictionBatchesPreserveRecordsAndLimits(t *testing.T) {
	for _, n := range []int{0, 1, 255, 256, 257, 5600, 14336} {
		p := predictions{methods: []predictedMethod{{method: "cells", windowNS: 1000000000}}}
		for i := range n {
			p.methods[0].values = append(p.methods[0].values, pairValue{i / 128, i % 128, float64(i%7 - 3)})
		}
		var b bytes.Buffer
		w := protocolWriter{w: &b, limit: relayArenaBytes}
		if e := sendPredictions(&w, p); e != nil {
			t.Fatal(e)
		}
		frames := (n + 255) / 256
		if int(w.frames) != frames || b.Len() != 15*n+32*frames {
			t.Fatalf("batch size %d: %d %d", n, w.frames, b.Len())
		}
		at, total := 0, 0
		for at < b.Len() {
			l := int(binary.BigEndian.Uint32(b.Bytes()[at : at+4]))
			body := b.Bytes()[at+30 : at+4+l]
			count := int(binary.BigEndian.Uint16(body[:2]))
			if count < 1 || count > 256 || len(body) != 2+15*count || total+count < n && count != 256 {
				t.Fatal("noncanonical batch")
			}
			total += count
			at += l + 4
		}
		if total != n {
			t.Fatal("prediction loss")
		}
	}
}

func TestPredictionBatchRejectsPartialCommitAndDuplicates(t *testing.T) {
	layout := &predictionLayout{first: 1, second: 1, total: 14}
	newPred := func() predictions {
		p := predictions{layout: layout, seen: make([]uint64, 1)}
		preparePredictionStorage(&p)
		return p
	}
	record := func() encoder {
		e := encoder{}
		e.u16(1)
		e.u8(1)
		e.u8(0)
		e.u16(0)
		e.u16(0)
		e.f64(.5)
		e.bool(false)
		return e
	}
	valid := record()
	p := newPred()
	if e := receivePrediction(&decoder{b: valid.b}, &p); e != nil {
		t.Fatal(e)
	}
	if e := receivePrediction(&decoder{b: valid.b}, &p); e == nil || p.received != 1 {
		t.Fatal("duplicate or partial terminal committed")
	}
	for at := 0; at < len(valid.b); at++ {
		p = newPred()
		if e := receivePrediction(&decoder{b: valid.b[:at]}, &p); e == nil || p.received != 0 {
			t.Fatal("truncated batch committed")
		}
	}
	for _, count := range []uint16{0, 257, 65535} {
		p = newPred()
		bad := append([]byte(nil), valid.b...)
		binary.BigEndian.PutUint16(bad, count)
		if e := receivePrediction(&decoder{b: bad}, &p); e == nil || p.received != 0 {
			t.Fatal("invalid count committed")
		}
	}
}
