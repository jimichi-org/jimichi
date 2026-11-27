package wire_test

import (
	"bytes"
	"fmt"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/wire"
)

func eachSuite(b *testing.B, run func(b *testing.B, p jcrypto.CryptoProvider)) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(s.String(), func(b *testing.B) { run(b, p) })
	}
}

func benchKeys(b *testing.B, p jcrypto.CryptoProvider, n int) []*secmem.Buffer {
	b.Helper()
	keys := make([]*secmem.Buffer, n)
	for i := range keys {
		k, err := secmem.New(p.KeySize())
		if err != nil {
			b.Fatalf("key %d: %v", i, err)
		}
		for j := range k.Bytes() {
			k.Bytes()[j] = byte(i*31 + j)
		}
		keys[i] = k
		b.Cleanup(k.Release)
	}
	return keys
}

var benchLinks = []uint64{101, 102, 103}

// a three-hop circuit and the relay side of each of its hops
type benchChain struct {
	circuit *wire.Circuit
	hops    []*wire.Hop
}

func newBenchChain(b *testing.B, p jcrypto.CryptoProvider, n int) benchChain {
	b.Helper()
	keys := benchKeys(b, p, n)
	c, err := wire.NewCircuit(p, keys, hopOffsets(n), benchLinks[:n])
	if err != nil {
		b.Fatalf("NewCircuit: %v", err)
	}
	b.Cleanup(c.Close)
	out := benchChain{circuit: c, hops: make([]*wire.Hop, n)}
	for i := range out.hops {
		h, err := wire.NewHop(p, keys[i], hopOffsets(n)[i], i)
		if err != nil {
			b.Fatalf("NewHop %d: %v", i, err)
		}
		b.Cleanup(h.Close)
		out.hops[i] = h
	}
	return out
}

const benchPool = 256

// cells as they reach hop `at` of a three-hop chain: sealed by the client and
// peeled by every hop before it, each carrying the circuit number of the link
// it arrives on, which is what the hop's nonce is built from
func forwardPool(b *testing.B, c benchChain, at int) []*wire.Cell {
	b.Helper()
	payload := bytes.Repeat([]byte("x"), c.circuit.MaxPayload())
	cells := make([]*wire.Cell, benchPool)
	for i := range cells {
		cell, err := c.circuit.Seal(uint64(i), payload)
		if err != nil {
			b.Fatalf("Seal: %v", err)
		}
		for h := 0; h < at; h++ {
			if cell, err = c.hops[h].Peel(cell); err != nil {
				b.Fatalf("Peel %d: %v", h, err)
			}
			cell.SetCircuit(benchLinks[h+1])
		}
		cells[i] = cell
	}
	return cells
}

// replies as they reach hop `at` on the way back: sealed by the exit and
// wrapped by every hop after `at`
func backwardPool(b *testing.B, c benchChain, at int) []*wire.Cell {
	b.Helper()
	exit := len(c.hops) - 1
	payload := bytes.Repeat([]byte("y"), 128)
	cells := make([]*wire.Cell, benchPool)
	for i := range cells {
		cell, err := c.hops[exit].SealReply(benchLinks[exit], uint64(i), payload)
		if err != nil {
			b.Fatalf("SealReply: %v", err)
		}
		for h := exit - 1; h > at; h-- {
			if cell, err = c.hops[h].Wrap(cell, benchLinks[h]); err != nil {
				b.Fatalf("Wrap %d: %v", h, err)
			}
		}
		cells[i] = cell
	}
	return cells
}

func timed(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(wire.CellSize)
	b.ResetTimer()
}

func BenchmarkSeal(b *testing.B) {
	eachSuite(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		for h := 1; h <= hops; h++ {
			b.Run(fmt.Sprintf("hops=%d", h), func(b *testing.B) {
				c := newBenchChain(b, p, h)
				payload := bytes.Repeat([]byte("x"), c.circuit.MaxPayload())
				timed(b)
				for i := 0; i < b.N; i++ {
					if _, err := c.circuit.Seal(uint64(i%256), payload); err != nil {
						b.Fatalf("Seal: %v", err)
					}
				}
			})
		}
	})
}

func BenchmarkPeel(b *testing.B) {
	eachSuite(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		for _, pos := range []struct {
			name string
			at   int
		}{{"pos=entry", 0}, {"pos=middle", 1}} {
			b.Run(pos.name, func(b *testing.B) {
				c := newBenchChain(b, p, hops)
				cells := forwardPool(b, c, pos.at)
				hop := c.hops[pos.at]
				timed(b)
				for i := 0; i < b.N; i++ {
					if _, err := hop.Peel(cells[i%len(cells)]); err != nil {
						b.Fatalf("Peel: %v", err)
					}
				}
			})
		}
	})
}

func BenchmarkOpenLast(b *testing.B) {
	eachSuite(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		c := newBenchChain(b, p, hops)
		cells := forwardPool(b, c, hops-1)
		hop := c.hops[hops-1]
		timed(b)
		for i := 0; i < b.N; i++ {
			if _, _, err := hop.OpenLast(cells[i%len(cells)]); err != nil {
				b.Fatalf("OpenLast: %v", err)
			}
		}
	})
}

func BenchmarkSealReply(b *testing.B) {
	eachSuite(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		c := newBenchChain(b, p, hops)
		hop := c.hops[hops-1]
		payload := bytes.Repeat([]byte("y"), 128)
		timed(b)
		for i := 0; i < b.N; i++ {
			if _, err := hop.SealReply(benchLinks[hops-1], uint64(i), payload); err != nil {
				b.Fatalf("SealReply: %v", err)
			}
		}
	})
}

func BenchmarkWrap(b *testing.B) {
	eachSuite(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		for _, pos := range []struct {
			name string
			at   int
		}{{"pos=middle", 1}, {"pos=entry", 0}} {
			b.Run(pos.name, func(b *testing.B) {
				c := newBenchChain(b, p, hops)
				cells := backwardPool(b, c, pos.at)
				hop := c.hops[pos.at]
				timed(b)
				for i := 0; i < b.N; i++ {
					if _, err := hop.Wrap(cells[i%len(cells)], benchLinks[pos.at]); err != nil {
						b.Fatalf("Wrap: %v", err)
					}
				}
			})
		}
	})
}

func BenchmarkOpenExit(b *testing.B) {
	eachSuite(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		b.Run(fmt.Sprintf("hops=%d", hops), func(b *testing.B) {
			c := newBenchChain(b, p, hops)
			cells := backwardPool(b, c, -1)
			timed(b)
			for i := 0; i < b.N; i++ {
				if _, _, err := c.circuit.OpenExit(cells[i%len(cells)], wire.Backward); err != nil {
					b.Fatalf("OpenExit: %v", err)
				}
			}
		})
	})
}
