//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/jimichi-org/jimichi/wire"
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
