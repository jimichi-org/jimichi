//go:build linux && amd64

package nodeview

import (
	"github.com/jimichi-org/jimichi/wire"
	"testing"
	"unsafe"
)

func TestSameAEADRetainsDistinctTransportLifecycles(t *testing.T) {
	c := providerIOCollector(t)
	for i := 0; i < 2; i++ {
		cell, e := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: 7, Counter: uint64(i)}, make([]byte, wire.BodySize))
		if e != nil {
			t.Fatal(e)
		}
		frame := make([]byte, 528)
		frame[0] = byte(i + 1)
		c.transport(99, false, frame, cell[:], int64(100+i))
	}
	if len(c.transports) != 2 || c.transports[0].aead != 99 || c.transports[1].aead != 99 || c.transports[0].generation == 0 || c.transports[0].generation == c.transports[1].generation {
		t.Fatal("AEAD identity replaced lifecycle identity")
	}
	for _, transport := range c.transports {
		cell, e := transportProjection(transport, nil, 200)
		if e != nil || cell.generation != transport.generation {
			t.Fatal("transport lifecycle changed in projection")
		}
		w := encoder{}
		encodeCell(&w, cell)
		r := decoder{b: w.b}
		decoded := decodeCell(&r)
		if r.end() != nil || decoded.generation != transport.generation || len(w.b) != 81 {
			t.Fatal("lifecycle changed codec size or identity")
		}
	}
	if unsafe.Sizeof(transportView{}) != 104 {
		t.Fatal("transport backing size changed")
	}
}
