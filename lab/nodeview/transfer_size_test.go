package nodeview

import (
	"math"
	"testing"
	"unsafe"
)

func TestTransferSizeSealedCellsAndBoundaryTruth(t *testing.T) {
	node := nodeView{cells: make([]cellView, 196608)}
	s, e := selectedStreamSize(node, 0, false)
	// 196608 records form 768 batches: 81*196608 + 33*768 = 15950592.
	if e != nil || s.bytes != 15950592 || s.frames != 768 {
		t.Fatal("cell stream size")
	}
	if unsafe.Sizeof(cellSample{}) != 32 {
		t.Fatal("minimal projection size")
	}
	truth := privateTruth{seals: make([]actualSeal, 1241), requests: make([]actualRequest, 1241), setups: make([]actualSetup, 189), messages: make([]actualMessage, 4)}
	for i := range truth.requests {
		truth.requests[i].record.size = 392
	}
	s, e = truthStreamSize(truth)
	// 1241*(399+404)+20*33+189*45+4*165 = 1006348 bytes in 213 frames.
	if e != nil || s.bytes != 1006348 || s.frames != 213 {
		t.Fatal("boundary truth size")
	}
	for _, n := range []uint64{65536, 196608, 262144} {
		if n*8 != map[uint64]uint64{65536: 524288, 196608: 1572864, 262144: 2097152}[n] {
			t.Fatal("Seal metadata increment")
		}
	}
}

func TestStreamSizeChecksOverflowAndLimit(t *testing.T) {
	for _, row := range [][3]uint64{{math.MaxUint64, 81, 256}, {1, math.MaxUint64, 256}, {1, 81, 0}} {
		s := streamSize{}
		if s.add(row[0], row[1], row[2]) == nil {
			t.Fatal("overflow accepted")
		}
	}
	s := streamSize{bytes: math.MaxUint64 - 10}
	if s.add(1, 81, 256) == nil {
		t.Fatal("cumulative overflow accepted")
	}
	node := nodeView{cells: make([]cellView, 500000)}
	if _, e := selectedStreamSize(node, 0, true); e == nil {
		t.Fatal("oversized stream accepted")
	}
}
