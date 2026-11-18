package nodeview

import (
	"bytes"
	"testing"
)

func TestFrameReassemblyEverySplit(t *testing.T) {
	var flight, frame [528]byte
	for i := range flight {
		flight[i] = byte(i)
		frame[i] = byte(i*7 + 3)
	}
	all := append(append([]byte(nil), flight[:]...), frame[:]...)
	for split := 0; split <= len(all); split++ {
		r := reassembler{flight: make([]byte, 528), frame: make([]byte, 528)}
		flights, frames := 0, 0
		onFlight := func(b []byte) {
			flights++
			if !bytes.Equal(b, flight[:]) {
				t.Fatal("flight changed")
			}
		}
		onFrame := func(b []byte) {
			frames++
			if !bytes.Equal(b, frame[:]) {
				t.Fatal("frame changed")
			}
		}
		r.add(all[:split], onFlight, onFrame)
		r.add(all[split:], onFlight, onFrame)
		if flights != 1 || frames != 1 || r.used != 0 {
			t.Fatalf("split %d: %d %d %d", split, flights, frames, r.used)
		}
	}
}

func TestFrameReassemblyFragmentCoalesceAndPartial(t *testing.T) {
	// 100+500+456 bytes contain one 528-byte flight and one 528-byte frame
	b := make([]byte, 1056)
	r := reassembler{flight: make([]byte, 528), frame: make([]byte, 528)}
	flight, frame := 0, 0
	onFlight := func([]byte) { flight++ }
	onFrame := func([]byte) { frame++ }
	r.add(b[:100], onFlight, onFrame)
	r.add(b[100:600], onFlight, onFrame)
	r.add(b[600:], onFlight, onFrame)
	if flight != 1 || frame != 1 {
		t.Fatalf("fragment totals %d %d", flight, frame)
	}
	r.add(make([]byte, 528*2+17), onFlight, onFrame)
	if flight != 1 || frame != 3 || r.used != 17 {
		t.Fatalf("coalesced totals %d %d %d", flight, frame, r.used)
	}
}
