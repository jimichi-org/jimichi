package wire_test

import (
	"bytes"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/gost"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

// counts every provider call; the AEADs it hands out are not wrapped
type callCounter struct {
	p     jcrypto.CryptoProvider
	calls map[string]int
}

func (c *callCounter) n(name string) { c.calls[name]++ }

func (c *callCounter) Suite() jcrypto.Suite { c.n("Suite"); return c.p.Suite() }
func (c *callCounter) HandshakeInfo() jcrypto.HandshakeInfo {
	c.n("HandshakeInfo")
	return c.p.HandshakeInfo()
}
func (c *callCounter) NoiseDH(priv *secmem.Buffer, peerPub []byte) (*secmem.Buffer, error) {
	c.n("NoiseDH")
	return c.p.NoiseDH(priv, peerPub)
}
func (c *callCounter) NoiseKDF2(ck, input *secmem.Buffer) (*secmem.Buffer, *secmem.Buffer, error) {
	c.n("NoiseKDF2")
	return c.p.NoiseKDF2(ck, input)
}
func (c *callCounter) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	c.n("GenerateEphemeral")
	return c.p.GenerateEphemeral()
}
func (c *callCounter) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	c.n("Agree")
	return c.p.Agree(priv, peerPub, ctx)
}
func (c *callCounter) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	c.n("MixKey")
	return c.p.MixKey(chain, secret, ctx)
}
func (c *callCounter) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	c.n("DeriveKey")
	return c.p.DeriveKey(secret, purpose, ctx, size)
}
func (c *callCounter) KeySize() int { c.n("KeySize"); return c.p.KeySize() }
func (c *callCounter) DerivePair(secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, []byte, error) {
	c.n("DerivePair")
	return c.p.DerivePair(secret, ctx)
}
func (c *callCounter) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	c.n("PasswordKey")
	return c.p.PasswordKey(password, ctx)
}
func (c *callCounter) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	c.n("NewAEAD")
	return c.p.NewAEAD(key)
}
func (c *callCounter) GenerateSigning() (*secmem.Buffer, []byte, error) {
	c.n("GenerateSigning")
	return c.p.GenerateSigning()
}
func (c *callCounter) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	c.n("Sign")
	return c.p.Sign(priv, msg)
}
func (c *callCounter) Verify(pub, msg, sig []byte) bool {
	c.n("Verify")
	return c.p.Verify(pub, msg, sig)
}
func (c *callCounter) Hash(data ...[]byte) []byte { c.n("Hash"); return c.p.Hash(data...) }

// once a circuit and its hops hold their AEADs, a cell out and its reply back
// make no provider call at all, so no secmem buffer comes into being on the
// way. Known answer: 100 rounds add 0 to every count
func TestCellPathCreatesNoKey(t *testing.T) {
	for _, base := range []jcrypto.CryptoProvider{c25519.New(), gost.New()} {
		t.Run(base.Suite().String(), func(t *testing.T) {
			p := &callCounter{p: base, calls: make(map[string]int)}
			keys := hopKeys(t, p, hops)
			links := []uint64{101, 102, 103}
			circuit := newCircuit(t, p, keys, links...)
			nodes := make([]*wire.Hop, hops)
			for i := range nodes {
				h, err := wire.NewHop(p, keys[i], hopOffsets(hops)[i], i)
				if err != nil {
					t.Fatalf("NewHop %d: %v", i, err)
				}
				defer h.Close()
				nodes[i] = h
			}
			before := make(map[string]int, len(p.calls))
			for k, v := range p.calls {
				before[k] = v
			}
			payload := bytes.Repeat([]byte("x"), circuit.MaxPayload())
			for i := range 100 {
				cell, err := circuit.Seal(uint64(i), payload)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				for h := 0; h < hops-1; h++ {
					if cell, err = nodes[h].Peel(cell); err != nil {
						t.Fatalf("Peel %d: %v", h, err)
					}
					cell.SetCircuit(links[h+1])
				}
				if _, _, err := nodes[hops-1].OpenLast(cell); err != nil {
					t.Fatalf("OpenLast: %v", err)
				}
				back, err := nodes[hops-1].SealReply(links[hops-1], uint64(i), []byte("back"))
				if err != nil {
					t.Fatalf("SealReply: %v", err)
				}
				for h := hops - 2; h >= 0; h-- {
					if back, err = nodes[h].Wrap(back, links[h]); err != nil {
						t.Fatalf("Wrap %d: %v", h, err)
					}
				}
				if got, _, err := circuit.OpenExit(back, wire.Backward); err != nil || string(got) != "back" {
					t.Fatalf("OpenExit: %q, %v", got, err)
				}
			}
			for name, n := range p.calls {
				if n != before[name] {
					t.Errorf("%s: %d calls on the cell path, want 0", name, n-before[name])
				}
			}
		})
	}
}
