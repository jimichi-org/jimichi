package relay_test

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

// the policies block 6 compares; they differ only in Lock. Off linux no policy
// changes where a buffer lives, so a single level runs there
func benchKeyMem() []string {
	if runtime.GOOS == "linux" {
		return []string{"all", "nolock"}
	}
	return []string{"heap"}
}

func withKeyMem(b *testing.B, level string) {
	b.Helper()
	var p secmem.Policy
	switch level {
	case "heap":
		return
	case "all":
		p = secmem.Protected
	case "nolock":
		p = secmem.Policy{OffHeap: true, DontDump: true, Zero: true}
	default:
		b.Fatalf("keymem level %q", level)
	}
	prev := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(p); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = secmem.SetPolicy(prev) })
	if level != "all" {
		return
	}
	buf, err := secmem.New(32)
	switch {
	case errors.Is(err, secmem.ErrNotLocked):
		b.Skip("keymem=all: memory locking unavailable, RLIMIT_MEMLOCK")
	case err != nil:
		b.Fatalf("probe: %v", err)
	}
	locked := buf.Locked()
	buf.Release()
	if !locked { // defensive, Protected never returns an unlocked buffer
		b.Skip("keymem=all: memory locking unavailable, RLIMIT_MEMLOCK")
	}
}

// the cryptographic work of Relay.setup at the first position of a chain: the
// ring opens the layer under every live key, then the hop key is made and the
// cell key released. No link, admission or extension is in it
func BenchmarkSetupAtNode(b *testing.B) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(s.String(), func(b *testing.B) {
			for _, c := range []struct {
				name  string
				keys  int
				layer string
			}{
				{"keys=1", 1, ""},
				{"keys=2/layer=current", 2, "current"},
				{"keys=2/layer=previous", 2, "previous"},
			} {
				for _, level := range benchKeyMem() {
					b.Run(c.name+"/keymem="+level, func(b *testing.B) {
						withKeyMem(b, level)
						setupAtNode(b, p, c.keys, c.layer)
					})
				}
			}
		})
	}
}

func setupAtNode(b *testing.B, p jcrypto.CryptoProvider, keys int, layer string) {
	if b.N > relay.MaxSetupCache {
		b.Fatalf("b.N %d above the setup cache bound %d", b.N, relay.MaxSetupCache)
	}
	idPriv, idPub, err := p.GenerateSigning()
	if err != nil {
		b.Fatal(err)
	}
	idPriv.Release()
	priv1, pub1, err := p.GenerateEphemeral()
	if err != nil {
		b.Fatal(err)
	}
	// one cell per iteration and a cache of b.N: no setup is a copy and the
	// cache never fills
	ring, err := relay.NewOnionRing(p, priv1, pub1, b.N)
	if err != nil {
		priv1.Release()
		b.Fatal(err)
	}
	b.Cleanup(ring.Close)
	target := pub1
	if keys == 2 {
		priv2, pub2, err := p.GenerateEphemeral()
		if err != nil {
			b.Fatal(err)
		}
		epoch, err := ring.Rotate(priv2, pub2)
		if err != nil {
			priv2.Release()
			b.Fatal(err)
		}
		e, pub := ring.Current()
		if e != 1 || epoch != 1 || !bytes.Equal(pub, pub2) {
			b.Fatalf("after Rotate: epoch %d and %d, current key matches the new one: %v", epoch, e, bytes.Equal(pub, pub2))
		}
		if layer == "current" {
			target = pub2
		}
	}
	cells := make([]*wire.Cell, b.N)
	for i := range cells {
		res, err := wire.BuildSetup(p, []wire.SetupHop{{StaticPub: target, Identity: idPub, Link: uint64(i + 1)}})
		if err != nil {
			b.Fatal(err)
		}
		for _, k := range res.CellKeys {
			k.Release()
		}
		cells[i] = res.Cell
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opened, err := ring.Open(p, idPub, cells[i])
		if err != nil {
			b.Fatalf("Open: %v", err)
		}
		hop, err := wire.NewHop(p, opened.CellKey, opened.Offsets, 0)
		opened.CellKey.Release()
		if err != nil {
			b.Fatalf("NewHop: %v", err)
		}
		hop.Close()
	}
}
