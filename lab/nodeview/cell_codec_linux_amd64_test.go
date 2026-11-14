//go:build linux && amd64

package nodeview

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"
)

func TestCellSealTimeCodecAndProjection(t *testing.T) {
	for _, count := range []int{1, 256, 512} {
		w := encoder{}
		w.u8(3)
		w.u16(uint16(count))
		for i := 0; i < count; i++ {
			encodeCell(&w, cellView{generation: uint32(i + 1), kind: 1, dir: 0, localTime: 120, sealTime: 150, writeTime: 160, stages: stageLocal | stageSealed | stageWritten})
		}
		// A record is 81 bytes. Kind/count and the frame add 3 and 30 bytes.
		if len(w.b) != 3+81*count || len(w.b)+30 != 33+81*count {
			t.Fatal("cell framing changed")
		}
		for _, projection := range []bool{false, true} {
			node := nodeView{scorerProjection: projection}
			if e := receiveView(&decoder{b: w.b}, &node); e != nil {
				t.Fatal(e)
			}
			if projection {
				if len(node.samples) != count || node.samples[0].sealTime != 150 {
					t.Fatal("minimal projection lost Seal time")
				}
			} else {
				if len(node.cells) != count || node.cells[0].sealTime != 150 {
					t.Fatal("parent lost Seal time")
				}
				var out bytes.Buffer
				writer := &protocolWriter{w: &out, limit: relayArenaBytes}
				if e := sendView(&childIO{view: writer}, &collector{view: node}); e != nil {
					t.Fatal(e)
				}
				next := nodeView{scorerProjection: true}
				at := 0
				for at < out.Len() {
					raw := out.Bytes()[at:]
					n := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
					if e := receiveView(&decoder{b: raw[30 : 4+n]}, &next); e != nil {
						t.Fatal(e)
					}
					at += n + 4
				}
				if len(next.samples) != count || next.samples[0].sealTime != 150 {
					t.Fatal("second transfer leg lost Seal time")
				}
			}
		}
	}
	if unsafe.Sizeof(cellSample{}) != 32 {
		t.Fatal("scorer backing-size assumption changed")
	}
}

func TestCellSealCounterRoundTripCutoff(t *testing.T) {
	for _, dir := range []uint8{0, 1} {
		for _, seal := range []int64{150, 190, 200, 210} {
			for _, written := range []bool{false, true} {
				for _, exit := range []bool{false, true} {
					v := cellView{generation: 1, hop: 2, kind: 1, dir: dir, counter: 7, outputCounter: 12, inputTime: 110, localTime: 120, sealTime: seal, stages: stageInput | stageLocal | stageSealed}
					if written {
						v.writeTime = seal + 20
						v.stages |= stageWritten
					}
					col := collector{start: 100, cutoff: 200, view: nodeView{cells: []cellView{v}, setups: []setupView{{hop: 2, nextPort: 99}}}}
					if exit {
						col.view.setups[0].nextPort = 0
						col.view.setups[0].first = 7
					}
					col.checkCounters()
					w := encoder{}
					w.u8(3)
					w.u16(1)
					encodeCell(&w, v)
					node := nodeView{setups: col.view.setups}
					if e := receiveView(&decoder{b: w.b}, &node); e != nil {
						t.Fatal(e)
					}
					summary, e := selectedCaptureSummary(viewSet{nodes: []nodeView{node}}, 100, 200)
					if e != nil || !reflect.DeepEqual(summary.Counters, col.summary.Counters) {
						t.Fatal("counter evidence changed in transfer")
					}
					want := uint64(0)
					if !exit || dir == 0 {
						if dir == 1 || seal < 200 {
							want = 1
						}
					}
					if summary.Counters.Matched != want {
						t.Fatal("Seal window membership changed")
					}
				}
			}
		}
	}
}

func TestCellSealRejectsMissingAndContradictoryTimes(t *testing.T) {
	v := cellView{generation: 1, kind: 1, localTime: 120, sealTime: 150, writeTime: 160, stages: stageLocal | stageSealed | stageWritten}
	w := encoder{}
	w.u8(3)
	w.u16(1)
	encodeCell(&w, v)
	for n := 0; n < len(w.b); n++ {
		if e := receiveView(&decoder{b: w.b[:n]}, &nodeView{}); e == nil {
			t.Fatal("truncated cell accepted")
		}
	}
	for _, bad := range []cellView{
		{kind: 1, localTime: 120, sealTime: 150},
		{kind: 1, localTime: 120, stages: stageSealed},
		{kind: 1, localTime: 120, sealTime: -1, stages: stageSealed},
		{kind: 1, localTime: 170, sealTime: 150, stages: stageSealed},
		{kind: 1, localTime: 120, sealTime: 150, writeTime: 140, stages: stageSealed | stageWritten},
	} {
		if validateCellTimes(bad) == nil {
			t.Fatal("invalid stage timestamp accepted")
		}
	}
}
