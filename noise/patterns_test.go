package noise_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
)

// fixed keys are the KK inputs; h starts at T(noise/link/nn|nk,
// "link-pattern-vector", mode), and the two payloads are the strings below
// values were composed independently through CryptoProvider, without noise
func TestNNAndNKVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/patterns.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Suite, Pattern, First, Second, SID, I2R, R2I string
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("missing production vectors")
	}
	for _, v := range kkVectors {
		for _, pattern := range []string{"nn", "nk"} {
			t.Run(v.suite.String()+"/"+pattern, func(t *testing.T) {
				var expected int
				for i := range vectors {
					if vectors[i].Suite == v.suite.String() && vectors[i].Pattern == pattern {
						expected = i
						break
					}
					if i == len(vectors)-1 {
						t.Fatal("no matching production vector")
					}
				}
				want := vectors[expected]
				p := provider(t, v.suite)
				ni, nr := noise.NN, noise.NN
				mode := byte(0)
				var static noise.Static
				var remote []byte
				ki, kr := [][2]string{{v.eI, v.EI}}, [][2]string{{v.eR, v.ER}}
				if pattern == "nk" {
					ni, nr, mode = noise.NK, noise.NK, 1
					b := secretFrom(t, v.sR)
					pair := noise.NewKeyPair(p, b, unhex(t, v.SR))
					t.Cleanup(pair.Close)
					static, remote = pair, pair.Public()
				} else {
					// NN queries a public-key size and immediately releases its probe
					ki, kr = append(ki, ki[0]), append(kr, kr[0])
				}
				pro := [][]byte{[]byte("link-pattern-vector"), {mode}}
				ini, err := noise.New(noise.Config{
					Provider: &fixedEphemeral{CryptoProvider: p, t: t, keys: ki},
					Pattern:  ni, Name: "link/" + pattern, Initiator: true, Prologue: pro, RemoteStatic: remote,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer ini.Close()
				resp, err := noise.New(noise.Config{
					Provider: &fixedEphemeral{CryptoProvider: p, t: t, keys: kr},
					Pattern:  nr, Name: "link/" + pattern, Prologue: pro, Local: static,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Close()
				first := mustWrite(t, ini, []byte("first payload"))
				if !bytes.Equal(first, unhex(t, want.First)) || !bytes.Equal(mustRead(t, resp, first), []byte("first payload")) {
					t.Fatal("first message differs from the production known answer")
				}
				second := mustWrite(t, resp, []byte("second payload"))
				if !bytes.Equal(second, unhex(t, want.Second)) || !bytes.Equal(mustRead(t, ini, second), []byte("second payload")) {
					t.Fatal("second message differs from the production known answer")
				}
				for _, got := range []split{mustSplit(t, ini), mustSplit(t, resp)} {
					if !bytes.Equal(got.sid, unhex(t, want.SID)) || !bytes.Equal(got.i2r, unhex(t, want.I2R)) ||
						!bytes.Equal(got.r2i, unhex(t, want.R2I)) {
						t.Fatal("split differs from the production known answer")
					}
				}
			})
		}
	}
}

func TestNNAndNKRefusalReleasesSecrets(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, anonymous := range []bool{true, false} {
			name, pt := "nk", noise.NK
			if anonymous {
				name, pt = "nn", noise.NN
			}
			t.Run(name, func(t *testing.T) {
				tp := &trackingProvider{CryptoProvider: p}
				var local noise.Static
				var remote []byte
				if !anonymous {
					priv, pub, err := p.GenerateEphemeral()
					if err != nil {
						t.Fatal(err)
					}
					pair := noise.NewKeyPair(tp, priv, pub)
					t.Cleanup(pair.Close)
					local, remote = pair, pair.Public()
				}
				ini, err := noise.New(noise.Config{Provider: tp, Pattern: pt, Name: "test", Initiator: true,
					Prologue: prologue, RemoteStatic: remote})
				if err != nil {
					t.Fatal(err)
				}
				defer ini.Close()
				take := false
				resp, err := noise.New(noise.Config{Provider: tp, Pattern: pt, Name: "test",
					Prologue: prologue, Local: local, AcceptPayload: func([]byte) bool { return take }})
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Close()
				first := mustWrite(t, ini, nil)
				if _, err := resp.ReadMessage(first); !errors.Is(err, noise.ErrMessage) {
					t.Fatalf("refused first payload: %v", err)
				}
				take = true
				mustRead(t, resp, first)
				second := mustWrite(t, resp, nil)
				bad := bytes.Clone(second)
				bad[len(bad)-1] ^= 1
				if _, err := ini.ReadMessage(bad); !errors.Is(err, noise.ErrMessage) {
					t.Fatalf("altered second message: %v", err)
				}
				mustRead(t, ini, second)
				a, b := mustSplit(t, ini), mustSplit(t, resp)
				if !bytes.Equal(a.sid, b.sid) || !bytes.Equal(a.i2r, b.i2r) || !bytes.Equal(a.r2i, b.r2i) {
					t.Fatal("refused message changed the result")
				}
				ini.Close()
				resp.Close()
				if _, held := tp.live(); held != 0 {
					t.Fatalf("%d provider buffers retained after Split and Close", held)
				}
				if local != nil {
					priv, pub, err := p.GenerateEphemeral()
					if err != nil {
						t.Fatal(err)
					}
					defer priv.Release()
					ctx, err := jcrypto.NewContext(p, "test", []byte{1})
					if err != nil {
						t.Fatal(err)
					}
					check, err := local.Agree(pub, ctx)
					if err != nil {
						t.Fatal("handshake released its borrowed static")
					}
					check.Release()
				}
			})
		}
	})
}

func TestNKRefusesWrongStaticOrPrologue(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		local, other := staticKey(t, p), staticKey(t, p)
		for _, wrongKey := range []bool{true, false} {
			remote, pro := local.Public(), prologue
			if wrongKey {
				remote = other.Public()
			} else {
				pro = [][]byte{[]byte("a different prologue")}
			}
			ini, err := noise.New(noise.Config{Provider: p, Pattern: noise.NK, Name: "test", Initiator: true,
				Prologue: pro, RemoteStatic: remote})
			if err != nil {
				t.Fatal(err)
			}
			defer ini.Close()
			resp, err := noise.New(noise.Config{Provider: p, Pattern: noise.NK, Name: "test", Prologue: prologue, Local: local})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Close()
			if _, err := resp.ReadMessage(mustWrite(t, ini, nil)); !errors.Is(err, noise.ErrMessage) {
				t.Fatalf("wrong NK parameters: %v", err)
			}
		}
	})
}

func TestNKMandatoryStatics(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, initiator := range []bool{false, true} {
			if hs, err := noise.New(noise.Config{Provider: p, Pattern: noise.NK, Name: "test", Prologue: prologue,
				Initiator: initiator}); !errors.Is(err, noise.ErrConfig) || hs != nil {
				t.Fatalf("NK without its mandatory static: %v", err)
			}
		}
	})
}

func provider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return noSigning{CryptoProvider: p, t: t}
}

func secretFrom(t *testing.T, s string) *secmem.Buffer {
	t.Helper()
	b, err := secmem.NewFrom(unhex(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
