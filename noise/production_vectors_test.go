package noise_test

import (
	"bytes"
	"encoding/json"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
	"os"
	"testing"
)

type splitCapture struct {
	jcrypto.CryptoProvider
	enabled bool
	keys    []*secmem.Buffer
}

func (p *splitCapture) NewAEAD(k *secmem.Buffer) (jcrypto.AEAD, error) {
	if p.enabled {
		b, err := k.Clone()
		if err != nil {
			return nil, err
		}
		p.keys = append(p.keys, b)
	}
	return p.CryptoProvider.NewAEAD(k)
}

// fixtures were frozen by an independent composer using CryptoProvider without this engine
func TestProductionCompositionVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/production.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ Suite, Pattern, SI, SPubI, SR, SPubR, EI, EPubI, ER, EPubR, Prologue, Payload1, Payload2, First, Second, SID, I2R, R2I, TransportI, TransportR string }
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 6 {
		t.Fatal("missing production composition fixture")
	}
	for _, v := range vectors {
		t.Run(v.Suite+"/"+v.Pattern, func(t *testing.T) {
			kind := jcrypto.SuiteC25519
			if v.Suite == "gost" {
				kind = jcrypto.SuiteGOST
			}
			p, _ := suite.New(kind)
			makeStatic := func(priv, pub string) *noise.KeyPair {
				b, err := secmem.NewFrom(unhex(t, priv))
				if err != nil {
					t.Fatal(err)
				}
				k := noise.NewKeyPair(p, b, unhex(t, pub))
				t.Cleanup(k.Close)
				return k
			}
			si, sr := makeStatic(v.SI, v.SPubI), makeStatic(v.SR, v.SPubR)
			var localI, localR noise.DHStatic
			var remoteI, remoteR []byte
			pattern := noise.NN
			if v.Pattern != "NN" {
				pattern = noise.NK
				localR = sr
				remoteI = sr.Public()
			}
			if v.Pattern == "KK" {
				pattern = noise.KK
				localI = si
				remoteR = si.Public()
			}
			ci, cr := &splitCapture{CryptoProvider: p}, &splitCapture{CryptoProvider: p}
			pi := &fixedEphemeral{CryptoProvider: ci, t: t, keys: [][2]string{{v.EI, v.EPubI}}}
			pr := &fixedEphemeral{CryptoProvider: cr, t: t, keys: [][2]string{{v.ER, v.EPubR}}}
			ini, err := noise.NewNoise(noise.NoiseConfig{Provider: pi, Pattern: pattern, Initiator: true, Prologue: unhex(t, v.Prologue), Local: localI, RemoteStatic: remoteI})
			if err != nil {
				t.Fatal(err)
			}
			defer ini.Close()
			resp, err := noise.NewNoise(noise.NoiseConfig{Provider: pr, Pattern: pattern, Prologue: unhex(t, v.Prologue), Local: localR, RemoteStatic: remoteR})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Close()
			first := mustWrite(t, ini, unhex(t, v.Payload1))
			if !bytes.Equal(first, unhex(t, v.First)) {
				t.Fatal("first ciphertext mismatch")
			}
			if !bytes.Equal(mustRead(t, resp, first), unhex(t, v.Payload1)) {
				t.Fatal("first payload mismatch")
			}
			second := mustWrite(t, resp, unhex(t, v.Payload2))
			if !bytes.Equal(second, unhex(t, v.Second)) {
				t.Fatal("second ciphertext mismatch")
			}
			if !bytes.Equal(mustRead(t, ini, second), unhex(t, v.Payload2)) {
				t.Fatal("second payload mismatch")
			}
			ci.enabled = true
			cr.enabled = true
			a, b, h, err := ini.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer a.Destroy()
			defer b.Destroy()
			ra, rb, rh, err := resp.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer ra.Destroy()
			defer rb.Destroy()
			for _, c := range []*splitCapture{ci, cr} {
				if len(c.keys) != 2 {
					t.Fatal("split AEAD key count mismatch")
				}
				if !bytes.Equal(c.keys[0].Bytes(), unhex(t, v.I2R)) || !bytes.Equal(c.keys[1].Bytes(), unhex(t, v.R2I)) {
					t.Fatal("split key fixture mismatch")
				}
				for _, k := range c.keys {
					k.Release()
				}
				c.enabled = false
			}
			if !bytes.Equal(h, unhex(t, v.SID)) || !bytes.Equal(h, rh) {
				t.Fatal("final transcript mismatch")
			}
			for _, tc := range []struct {
				send, recv *noise.CipherState
				payload    []byte
				want       string
			}{{a, ra, []byte{7, 8, 9}, v.TransportI}, {rb, b, []byte{9, 10, 11}, v.TransportR}} {
				out, err := tc.send.Encrypt(nil, tc.payload)
				if err != nil || !bytes.Equal(out, unhex(t, tc.want)) {
					t.Fatal("transport ciphertext mismatch")
				}
				pt, err := tc.recv.Decrypt(nil, out)
				if err != nil || !bytes.Equal(pt, tc.payload) {
					t.Fatal("transport payload mismatch")
				}
			}
		})
	}
}
