package noise

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

var faultError = errors.New("injected operation failure")

type faultProvider struct {
	jcrypto.CryptoProvider
	op              string
	skip            int
	opened          bool
	buffers         []*secmem.Buffer
	peak, peakPages int
	aeads           []*faultAEAD
}

func (p *faultProvider) hit(op string) bool {
	if p.op != op {
		return false
	}
	if p.skip > 0 {
		p.skip--
		return false
	}
	p.op = ""
	return true
}
func (p *faultProvider) keep(b *secmem.Buffer) *secmem.Buffer {
	if b != nil {
		p.buffers = append(p.buffers, b)
		live, pages := 0, 0
		for _, owned := range p.buffers {
			if owned.Bytes() != nil {
				live++
				pages += (owned.Len() + os.Getpagesize() - 1) / os.Getpagesize()
			}
		}
		if live > p.peak {
			p.peak = live
		}
		if pages > p.peakPages {
			p.peakPages = pages
		}
	}
	return b
}
func (p *faultProvider) allocate(n int) (*secmem.Buffer, error) {
	if p.hit("allocate") {
		return nil, faultError
	}
	b, err := secmem.New(n)
	return p.keep(b), err
}
func (p *faultProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	if p.hit("generate") {
		return nil, nil, faultError
	}
	b, pub, err := p.CryptoProvider.GenerateEphemeral()
	return p.keep(b), pub, err
}
func (p *faultProvider) NoiseDH(k *secmem.Buffer, pub []byte) (*secmem.Buffer, error) {
	if p.hit("dh") {
		return nil, faultError
	}
	b, err := p.CryptoProvider.NoiseDH(k, pub)
	return p.keep(b), err
}
func (p *faultProvider) NoiseKDF2(ck, in *secmem.Buffer) (*secmem.Buffer, *secmem.Buffer, error) {
	if p.hit("kdf") {
		return nil, nil, faultError
	}
	a, b, err := p.CryptoProvider.NoiseKDF2(ck, in)
	return p.keep(a), p.keep(b), err
}
func (p *faultProvider) Agree(k *secmem.Buffer, pub []byte, c jcrypto.Context) (*secmem.Buffer, error) {
	if p.hit("agree") {
		return nil, faultError
	}
	b, err := p.CryptoProvider.Agree(k, pub, c)
	return p.keep(b), err
}
func (p *faultProvider) MixKey(ck, in *secmem.Buffer, c jcrypto.Context) (*secmem.Buffer, error) {
	if p.hit("mix") {
		return nil, faultError
	}
	b, err := p.CryptoProvider.MixKey(ck, in, c)
	return p.keep(b), err
}
func (p *faultProvider) DeriveKey(k *secmem.Buffer, purpose string, c jcrypto.Context, n int) (*secmem.Buffer, error) {
	if p.hit("derive") {
		return nil, faultError
	}
	b, err := p.CryptoProvider.DeriveKey(k, purpose, c, n)
	return p.keep(b), err
}
func (p *faultProvider) Hash(parts ...[]byte) []byte {
	contextDH := len(parts) > 0 && bytes.Contains(parts[0], []byte("/transcript/noise/dh"))
	if p.hit("hash") || contextDH && p.hit("context") || p.opened && p.hit("hashAfterOpen") {
		return []byte{0}
	}
	return p.CryptoProvider.Hash(parts...)
}
func (p *faultProvider) NewAEAD(k *secmem.Buffer) (jcrypto.AEAD, error) {
	if p.hit("aead") {
		return nil, faultError
	}
	a, err := p.CryptoProvider.NewAEAD(k)
	if err != nil {
		return nil, err
	}
	w := &faultAEAD{AEAD: a, p: p}
	p.aeads = append(p.aeads, w)
	return w, nil
}

type faultAEAD struct {
	jcrypto.AEAD
	p         *faultProvider
	destroyed int
}

func (a *faultAEAD) Open(dst, n, c, ad []byte) ([]byte, error) {
	out, err := a.AEAD.Open(dst, n, c, ad)
	if err == nil {
		a.p.opened = true
	}
	return out, err
}
func (a *faultAEAD) Destroy() { a.destroyed++; a.AEAD.Destroy() }
func (p *faultProvider) live() int {
	n := 0
	for _, b := range p.buffers {
		if b.Bytes() != nil {
			n++
		}
	}
	return n
}
func (p *faultProvider) checkAEAD(t *testing.T) {
	t.Helper()
	for _, a := range p.aeads {
		if a.destroyed != 1 {
			t.Fatal("partial or temporary AEAD destruction count mismatch")
		}
	}
}
func secretBytes(b *secmem.Buffer) []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.Bytes())
}

type stateImage struct {
	h, ck, key, e, re, rs []byte
	ckp, kp, ep           *secmem.Buffer
	nonce                 uint64
	msg                   int
	split, closed         bool
}

func image(h *HandshakeState) stateImage {
	return stateImage{bytes.Clone(h.h), secretBytes(h.ck), secretBytes(h.key), secretBytes(h.e), bytes.Clone(h.re), bytes.Clone(h.rs), h.ck, h.key, h.e, h.nonce, h.msg, h.split, h.closed}
}
func assertImage(t *testing.T, h *HandshakeState, want stateImage) {
	t.Helper()
	if !reflect.DeepEqual(image(h), want) {
		t.Fatal("failed operation changed committed handshake state")
	}
}
func faultPair(t *testing.T, kind jcrypto.Suite, production bool, patterns ...Pattern) (*HandshakeState, *HandshakeState, *faultProvider, *faultProvider, *KeyPair, *KeyPair) {
	t.Helper()
	base, err := suite.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	pi, pr := &faultProvider{CryptoProvider: base}, &faultProvider{CryptoProvider: base}
	key := func(p *faultProvider) *KeyPair {
		b, pub, err := base.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		k := NewKeyPair(p, b, pub)
		t.Cleanup(k.Close)
		return k
	}
	si, sr := key(pi), key(pr)
	pattern := clonePattern(canonicalKK)
	if len(patterns) > 0 {
		pattern = clonePattern(patterns[0])
	}
	makeSide := func(p *faultProvider, ini bool, local, remote *KeyPair) *HandshakeState {
		var h *HandshakeState
		if production {
			h, err = newNoise(NoiseConfig{Provider: p, Pattern: pattern, Initiator: ini, Prologue: []byte("fault fixture"), Local: local, RemoteStatic: remote.Public()}, p.allocate)
		} else {
			h, err = New(Config{Provider: p, Pattern: pattern, Name: "test", Initiator: ini, Prologue: [][]byte{[]byte("fault fixture")}, Local: local, RemoteStatic: remote.Public()})
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(h.Close)
		return h
	}
	return makeSide(pi, true, si, sr), makeSide(pr, false, sr, si), pi, pr, si, sr
}
func TestMessageFaultRollbackAndOwnership(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, production := range []bool{false, true} {
			profile := "legacy"
			ops := []string{"generate", "agree", "agreeSecond", "mix", "derive", "aead", "hash", "context", "hashAfterOpen"}
			if production {
				profile = "noise"
				ops = []string{"generate", "dh", "dhSecond", "kdf", "kdfSecond", "aead", "hash", "hashAfterOpen"}
			}
			for _, stage := range []string{"write1", "read1", "write2", "read2"} {
				for _, op := range ops {
					writing := stage == "write1" || stage == "write2"
					if writing && op == "hashAfterOpen" || !writing && op == "generate" {
						continue
					}
					t.Run(kind.String()+"/"+profile+"/"+stage+"/"+op, func(t *testing.T) {
						ini, resp, pi, pr, si, sr := faultPair(t, kind, production)
						var message []byte
						var err error
						target, p := ini, pi
						if stage != "write1" {
							message, err = ini.WriteMessage(nil)
							if err != nil {
								t.Fatal(err)
							}
						}
						if stage == "write2" || stage == "read2" {
							if _, err = resp.ReadMessage(message); err != nil {
								t.Fatal(err)
							}
							target, p = resp, pr
						}
						if stage == "read1" {
							target, p = resp, pr
						}
						if stage == "read2" {
							message, err = resp.WriteMessage(nil)
							if err != nil {
								t.Fatal(err)
							}
							target, p = ini, pi
						}
						target.nonce = 37
						before := image(target)
						baseline := p.live()
						p.op, p.opened = op, false
						if op == "agreeSecond" {
							p.op = "agree"
							p.skip = 1
						}
						if op == "dhSecond" {
							p.op = "dh"
							p.skip = 1
						}
						if op == "kdfSecond" {
							p.op = "kdf"
							p.skip = 1
						}
						if writing {
							_, err = target.WriteMessage(nil)
						} else {
							_, err = target.ReadMessage(message)
						}
						if err == nil {
							t.Fatal("injected failure not reached")
						}
						assertImage(t, target, before)
						if p.live() != baseline {
							t.Fatal("staged buffers escaped failed message")
						}
						p.checkAEAD(t)
						p.op = ""
						p.opened = false
						if writing {
							_, err = target.WriteMessage(nil)
						} else {
							_, err = target.ReadMessage(message)
						}
						if err != nil {
							t.Fatalf("genuine retry: %v", err)
						}
						ini.Close()
						resp.Close()
						if pi.live() != 0 || pr.live() != 0 {
							t.Fatal("close retained owned secret")
						}
						pi.checkAEAD(t)
						pr.checkAEAD(t)
						if si.priv == nil || sr.priv == nil {
							t.Fatal("borrowed static released")
						}
						check, err := si.NoiseDH(sr.Public())
						if err != nil {
							t.Fatal("borrowed static no longer usable")
						}
						check.Release()
					})
				}
			}
		}
	}
}
func TestSplitFaultRollback(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, production := range []bool{false, true} {
			for _, transport := range []bool{false, true} {
				if transport && !production {
					continue
				}
				name := kind.String()
				if production {
					name += "/noise"
				} else {
					name += "/legacy"
				}
				if transport {
					name += "/transport"
				}
				t.Run(name, func(t *testing.T) {
					ini, resp, pi, pr, _, _ := faultPair(t, kind, production)
					first, _ := ini.WriteMessage(nil)
					if _, err := resp.ReadMessage(first); err != nil {
						t.Fatal(err)
					}
					second, _ := resp.WriteMessage(nil)
					if _, err := ini.ReadMessage(second); err != nil {
						t.Fatal(err)
					}
					before, baseline := image(ini), pi.live()
					pi.op = "derive"
					pi.skip = 1
					if production {
						pi.op = "kdf"
						pi.skip = 0
					}
					if transport {
						pi.op = "aead"
						pi.skip = 1
					}
					var err error
					if transport {
						_, _, _, err = ini.SplitTransport()
					} else {
						_, _, _, err = ini.Split()
					}
					if err == nil {
						t.Fatal("split failure not reached")
					}
					assertImage(t, ini, before)
					if pi.live() != baseline {
						t.Fatal("split failure retained output")
					}
					pi.checkAEAD(t)
					pi.op = ""
					pi.skip = 0
					if transport {
						a, b, _, err := ini.SplitTransport()
						if err != nil {
							t.Fatal(err)
						}
						a.Destroy()
						b.Destroy()
					} else {
						a, b, _, err := ini.Split()
						if err != nil {
							t.Fatal(err)
						}
						a.Release()
						b.Release()
					}
					ini.Close()
					resp.Close()
					if pi.live() != 0 || pr.live() != 0 {
						t.Fatal("split close retained secret")
					}
					pi.checkAEAD(t)
					pr.checkAEAD(t)
				})
			}
		}
	}
}
func TestConstructorAllocationRollback(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		base, _ := suite.New(kind)
		p := &faultProvider{CryptoProvider: base, op: "allocate"}
		cfg := NoiseConfig{Provider: p, Pattern: clonePattern(canonicalNN), Prologue: []byte("fixture")}
		if h, err := newNoise(cfg, p.allocate); h != nil || !errors.Is(err, faultError) {
			t.Fatal("constructor allocation error lost")
		}
		p.op = "hash"
		p.skip = 1
		if h, err := newNoise(cfg, p.allocate); h != nil || err == nil {
			t.Fatal("constructor hash error lost")
		}
		if p.live() != 0 {
			t.Fatal("constructor retained owned buffer")
		}
	}
}

func TestProductionOwnedBufferPeak(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, pattern := range []Pattern{canonicalNN, canonicalNK, canonicalKK} {
			_, name, _ := canonicalPattern(pattern)
			t.Run(kind.String()+"/"+name, func(t *testing.T) {
				i, r, pi, pr, _, _ := faultPair(t, kind, true, pattern)
				first, err := i.WriteMessage(nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := r.ReadMessage(first); err != nil {
					t.Fatal(err)
				}
				second, err := r.WriteMessage(nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := i.ReadMessage(second); err != nil {
					t.Fatal(err)
				}
				for role, hs := range []*HandshakeState{i, r} {
					a, b, _, err := hs.SplitTransport()
					if err != nil {
						t.Fatal(err)
					}
					a.Destroy()
					b.Destroy()
					p := []*faultProvider{pi, pr}[role]
					if p.live() != 0 {
						t.Fatal("transport split retained handshake secret")
					}
					t.Logf("role %d: peak owned secmem buffers=%d, page-rounded owned buffers=%d (borrowed statics and library internals excluded)", role, p.peak, p.peakPages)
				}
			})
		}
	}
}
