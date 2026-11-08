package noise

import (
	"bytes"
	"errors"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"math"
	"testing"
)

type productionOnly struct {
	jcrypto.CryptoProvider
	t *testing.T
}

func (p productionOnly) Agree(*secmem.Buffer, []byte, jcrypto.Context) (*secmem.Buffer, error) {
	p.t.Error("production called legacy Agree")
	return nil, faultError
}
func (p productionOnly) MixKey(*secmem.Buffer, *secmem.Buffer, jcrypto.Context) (*secmem.Buffer, error) {
	p.t.Error("production called legacy MixKey")
	return nil, faultError
}
func (p productionOnly) DeriveKey(*secmem.Buffer, string, jcrypto.Context, int) (*secmem.Buffer, error) {
	p.t.Error("production called legacy DeriveKey")
	return nil, faultError
}
func productionPair(t *testing.T, kind jcrypto.Suite, pattern Pattern) (*HandshakeState, *HandshakeState) {
	t.Helper()
	base, err := suite.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	p := productionOnly{base, t}
	static := func() *KeyPair {
		b, pub, err := base.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		k := NewKeyPair(p, b, pub)
		t.Cleanup(k.Close)
		return k
	}
	si, sr := static(), static()
	var localI, localR DHStatic
	var rsI, rsR []byte
	_, name, err := canonicalPattern(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if name != "NN" {
		localR = sr
		rsI = sr.Public()
	}
	if name == "KK" {
		localI = si
		rsR = si.Public()
	}
	ini, err := NewNoise(NoiseConfig{Provider: p, Pattern: pattern, Initiator: true, Prologue: []byte("production fixture"), Local: localI, RemoteStatic: rsI})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ini.Close)
	resp, err := NewNoise(NoiseConfig{Provider: p, Pattern: pattern, Prologue: []byte("production fixture"), Local: localR, RemoteStatic: rsR})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resp.Close)
	return ini, resp
}
func TestProductionMessageBounds(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, pattern := range []Pattern{canonicalNN, canonicalNK, canonicalKK} {
			_, name, _ := canonicalPattern(pattern)
			t.Run(kind.String()+"/"+name, func(t *testing.T) {
				ini, resp := productionPair(t, kind, clonePattern(pattern))
				for i := range 2 {
					writer, reader := ini, resp
					if i == 1 {
						writer, reader = resp, ini
					}
					overhead := writer.pubSize + 16
					if i == 0 && name == "NN" {
						overhead = writer.pubSize
					}
					before := image(writer)
					if out, err := writer.WriteMessage(make([]byte, 65536-overhead)); out != nil || !errors.Is(err, ErrMessageTooLarge) {
						t.Fatal("oversize production write accepted")
					}
					assertImage(t, writer, before)
					msg, err := writer.WriteMessage(make([]byte, 65535-overhead))
					if err != nil || len(msg) != 65535 {
						t.Fatalf("exact production write bound: %v", err)
					}
					before = image(reader)
					if out, err := reader.ReadMessage(append(bytes.Clone(msg), 0)); out != nil || !errors.Is(err, ErrMessageTooLarge) {
						t.Fatal("oversize production read accepted")
					}
					assertImage(t, reader, before)
					if _, err := reader.ReadMessage(msg); err != nil {
						t.Fatalf("exact production read bound: %v", err)
					}
				}
				a, b, _, err := ini.Split()
				if err != nil {
					t.Fatal(err)
				}
				a.Release()
				b.Release()
				if err := resp.MixHash(nil); !errors.Is(err, ErrState) {
					t.Fatal("production accepted external MixHash")
				}
				if _, err := resp.ReadMessageBound(nil, nil); !errors.Is(err, ErrState) {
					t.Fatal("production accepted Bound")
				}
			})
		}
	}
}
func TestProductionTransportBoundsAndNonce(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(kind.String(), func(t *testing.T) {
			ini, resp := productionPair(t, kind, clonePattern(canonicalKK))
			first, _ := ini.WriteMessage(nil)
			_, err := resp.ReadMessage(first)
			if err != nil {
				t.Fatal(err)
			}
			second, _ := resp.WriteMessage(nil)
			if _, err = ini.ReadMessage(second); err != nil {
				t.Fatal(err)
			}
			a, b, _, err := ini.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer a.Destroy()
			defer b.Destroy()
			ra, rb, _, err := resp.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer ra.Destroy()
			defer rb.Destroy()
			for _, pair := range [][2]*CipherState{{a, ra}, {rb, b}} {
				send, recv := pair[0], pair[1]
				if out, err := send.Encrypt(nil, make([]byte, 65520)); out != nil || !errors.Is(err, ErrMessageTooLarge) || send.nonce != 0 {
					t.Fatal("oversize transport encryption changed state")
				}
				out, err := send.Encrypt(nil, make([]byte, 65519))
				if err != nil || len(out) != 65535 {
					t.Fatal("exact transport bound failed")
				}
				if pt, err := recv.Decrypt(nil, append(bytes.Clone(out), 0)); pt != nil || !errors.Is(err, ErrMessageTooLarge) || recv.nonce != 0 {
					t.Fatal("oversize transport decryption changed state")
				}
				bad := bytes.Clone(out)
				bad[0] ^= 1
				if _, err := recv.Decrypt(nil, bad); err == nil || recv.nonce != 0 {
					t.Fatal("failed authentication advanced nonce")
				}
				pt, err := recv.Decrypt(nil, out)
				if err != nil || len(pt) != 65519 || recv.nonce != 1 {
					t.Fatal("exact transport ciphertext bound failed")
				}
				send.nonce = math.MaxUint64
				recv.nonce = math.MaxUint64
				if _, err := send.Encrypt(nil, nil); !errors.Is(err, ErrNonce) {
					t.Fatal("reserved encryption nonce accepted")
				}
				if _, err := recv.Decrypt(nil, out); !errors.Is(err, ErrNonce) {
					t.Fatal("reserved decryption nonce accepted")
				}
			}
		})
	}
}
func TestProductionConstructorCopiesInputs(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		base, _ := suite.New(kind)
		p := productionOnly{base, t}
		key := func() *KeyPair {
			b, pub, err := base.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			k := NewKeyPair(p, b, pub)
			t.Cleanup(k.Close)
			return k
		}
		si, sr := key(), key()
		pattern := clonePattern(canonicalKK)
		pro := []byte("immutable")
		remoteI, remoteR := sr.Public(), si.Public()
		ini, err := NewNoise(NoiseConfig{Provider: p, Pattern: pattern, Initiator: true, Prologue: pro, Local: si, RemoteStatic: remoteI})
		if err != nil {
			t.Fatal(err)
		}
		defer ini.Close()
		resp, err := NewNoise(NoiseConfig{Provider: p, Pattern: pattern, Prologue: pro, Local: sr, RemoteStatic: remoteR})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Close()
		pattern.Messages[0][0] = 99
		pattern.PreInitiator[0] = 99
		pro[0] ^= 1
		remoteI[0] ^= 1
		remoteR[0] ^= 1
		si.pub[0] ^= 1
		sr.pub[0] ^= 1
		first, err := ini.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resp.ReadMessage(first); err != nil {
			t.Fatal(err)
		}
		second, err := resp.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ini.ReadMessage(second); err != nil {
			t.Fatal(err)
		}
		a, b, ih, err := ini.Split()
		if err != nil {
			t.Fatal(err)
		}
		defer a.Release()
		defer b.Release()
		ra, rb, rh, err := resp.Split()
		if err != nil {
			t.Fatal(err)
		}
		defer ra.Release()
		defer rb.Release()
		if !bytes.Equal(ih, rh) || !a.Equal(ra) || !b.Equal(rb) {
			t.Fatal("mutable inputs changed handshake")
		}
	}
	old := NN
	NN = clonePattern(canonicalNN)
	NN.Messages[0][0] = 99
	defer func() { NN = old }()
	p, _ := suite.New(jcrypto.SuiteC25519)
	h, err := NewNoise(NoiseConfig{Provider: p, Pattern: clonePattern(canonicalNN)})
	if err != nil {
		t.Fatal("exported pattern mutation changed private canonical definitions")
	}
	h.Close()
}

func TestProductionRejectsStaticSizesBeforeAllocation(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, _ := suite.New(kind)
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		k := NewKeyPair(p, priv, pub)
		defer k.Close()
		wrong := staticSnapshot{raw: k, pub: bytes.Clone(pub[:len(pub)-1])}
		for _, cfg := range []NoiseConfig{
			{Provider: p, Pattern: clonePattern(canonicalKK), Local: wrong, RemoteStatic: pub},
			{Provider: p, Pattern: clonePattern(canonicalKK), Local: k, RemoteStatic: pub[:len(pub)-1]},
			{Provider: p, Pattern: clonePattern(canonicalKK), Local: k},
			{Provider: p, Pattern: clonePattern(canonicalKK), RemoteStatic: pub},
			{Provider: p, Pattern: clonePattern(canonicalNK), Initiator: true},
			{Provider: p, Pattern: clonePattern(canonicalNK)},
		} {
			calls := 0
			allocate := func(n int) (*secmem.Buffer, error) { calls++; return secmem.New(n) }
			if h, err := newNoise(cfg, allocate); h != nil || !errors.Is(err, ErrConfig) || calls != 0 {
				t.Fatal("invalid production static reached secret allocation")
			}
		}
	}
}
func TestProductionCipherStateRejectsReorderedFrames(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(kind.String(), func(t *testing.T) {
			initiator, responder := productionPair(t, kind, clonePattern(canonicalKK))
			first, err := initiator.WriteMessage(nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := responder.ReadMessage(first); err != nil {
				t.Fatal(err)
			}
			second, err := responder.WriteMessage(nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := initiator.ReadMessage(second); err != nil {
				t.Fatal(err)
			}
			i2r, r2i, _, err := initiator.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer i2r.Destroy()
			defer r2i.Destroy()
			responderI2R, responderR2I, _, err := responder.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer responderI2R.Destroy()
			defer responderR2I.Destroy()
			for _, direction := range []struct {
				name          string
				send, receive *CipherState
			}{
				{"initiator to responder", i2r, responderI2R},
				{"responder to initiator", responderR2I, r2i},
			} {
				t.Run(direction.name, func(t *testing.T) {
					payload0, payload1 := []byte{1, 2, 3}, []byte{4, 5, 6}
					c0, err := direction.send.Encrypt(nil, payload0)
					if err != nil {
						t.Fatal(err)
					}
					c1, err := direction.send.Encrypt(nil, payload1)
					if err != nil {
						t.Fatal(err)
					}
					if out, err := direction.receive.Decrypt(nil, c1); out != nil || !errors.Is(err, jcrypto.ErrOpen) || direction.receive.nonce != 0 {
						t.Fatal("reordered valid ciphertext accepted or advanced receive nonce")
					}
					for _, frame := range []struct{ ciphertext, payload []byte }{{c0, payload0}, {c1, payload1}} {
						out, err := direction.receive.Decrypt(nil, frame.ciphertext)
						if err != nil || !bytes.Equal(out, frame.payload) {
							t.Fatal("ordered genuine retry failed after rejected reorder")
						}
					}
					if direction.receive.nonce != 2 {
						t.Fatal("ordered frames advanced nonce incorrectly")
					}
				})
			}
		})
	}
}
