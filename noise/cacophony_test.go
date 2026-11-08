//go:build noisevectors

package noise

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/noisevector"
)

type standardVector struct {
	Name             string `json:"protocol_name"`
	InitPrologue     string `json:"init_prologue"`
	RespPrologue     string `json:"resp_prologue"`
	InitEphemeral    string `json:"init_ephemeral"`
	RespEphemeral    string `json:"resp_ephemeral"`
	InitStatic       string `json:"init_static"`
	RespStatic       string `json:"resp_static"`
	InitRemoteStatic string `json:"init_remote_static"`
	RespRemoteStatic string `json:"resp_remote_static"`
	HandshakeHash    string `json:"handshake_hash"`
	Messages         []struct {
		Payload    string `json:"payload"`
		Ciphertext string `json:"ciphertext"`
	} `json:"messages"`
}

func standardVectors(t *testing.T) []standardVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/cacophony.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Source       string           `json:"source"`
		SourceSHA256 string           `json:"source_sha256"`
		Vectors      []standardVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Source != "https://github.com/haskell-cryptography/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt" ||
		corpus.SourceSHA256 != "3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae" || len(corpus.Vectors) != 3 {
		t.Fatal("unexpected cacophony source or vector subset")
	}
	return corpus.Vectors
}

func vectorBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid vector hex")
	}
	return b
}

func standardSide(t *testing.T, v standardVector, initiator bool) *HandshakeState {
	t.Helper()
	ephemeral, local, remote, prologue := v.RespEphemeral, v.RespStatic, v.RespRemoteStatic, v.RespPrologue
	if initiator {
		ephemeral, local, remote, prologue = v.InitEphemeral, v.InitStatic, v.InitRemoteStatic, v.InitPrologue
	}
	p, err := noisevector.NewProvider(vectorBytes(t, ephemeral))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var static DHStatic
	if local != "" {
		priv, pub, err := noisevector.Static(vectorBytes(t, local))
		if err != nil {
			t.Fatal(err)
		}
		pair := NewKeyPair(p, priv, pub)
		t.Cleanup(pair.Close)
		static = pair
	}
	var pattern Pattern
	switch {
	case strings.HasPrefix(v.Name, "Noise_NN_"):
		pattern = NN
	case strings.HasPrefix(v.Name, "Noise_NK_"):
		pattern = NK
	case strings.HasPrefix(v.Name, "Noise_KK_"):
		pattern = KK
	default:
		t.Fatal("unsupported vector pattern")
	}
	hs, err := NewNoise(NoiseConfig{
		Provider: p, Pattern: pattern, Initiator: initiator,
		Prologue: vectorBytes(t, prologue), Local: static, RemoteStatic: vectorBytes(t, remote),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hs.Close)
	return hs
}

func TestCacophonyVectors(t *testing.T) {
	for _, v := range standardVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			ini, resp := standardSide(t, v, true), standardSide(t, v, false)
			for i := range 2 {
				writer, reader := ini, resp
				if i == 1 {
					writer, reader = resp, ini
				}
				m := v.Messages[i]
				out, err := writer.WriteMessage(vectorBytes(t, m.Payload))
				if err != nil || !bytes.Equal(out, vectorBytes(t, m.Ciphertext)) {
					t.Fatalf("handshake message %d differs from cacophony: %v", i, err)
				}
				pt, err := reader.ReadMessage(out)
				if err != nil || !bytes.Equal(pt, vectorBytes(t, m.Payload)) {
					t.Fatalf("handshake payload %d differs from cacophony: %v", i, err)
				}
			}
			i2r, r2i, ih, err := ini.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer i2r.Destroy()
			defer r2i.Destroy()
			ri2r, rr2i, rh, err := resp.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer ri2r.Destroy()
			defer rr2i.Destroy()
			if !bytes.Equal(ih, vectorBytes(t, v.HandshakeHash)) || !bytes.Equal(ih, rh) {
				t.Fatal("handshake hash differs from cacophony")
			}
			for i, m := range v.Messages[2:] {
				send, recv := i2r, ri2r
				if i%2 != 0 {
					send, recv = rr2i, r2i
				}
				out, err := send.Encrypt(nil, vectorBytes(t, m.Payload))
				if err != nil || !bytes.Equal(out, vectorBytes(t, m.Ciphertext)) {
					t.Fatalf("split transport message %d differs from cacophony: %v", i, err)
				}
				pt, err := recv.Decrypt(nil, out)
				if err != nil || !bytes.Equal(pt, vectorBytes(t, m.Payload)) {
					t.Fatalf("split transport payload %d differs from cacophony: %v", i, err)
				}
			}
			i2r.nonce = math.MaxUint64
			if _, err := i2r.Encrypt(nil, nil); !errors.Is(err, ErrNonce) {
				t.Fatal("reserved transport nonce accepted")
			}
		})
	}
}

func TestCacophonyReadRollback(t *testing.T) {
	for _, v := range standardVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			ini, resp := standardSide(t, v, true), standardSide(t, v, false)
			for i := range 2 {
				writer, reader := ini, resp
				if i == 1 {
					writer, reader = resp, ini
				}
				m := v.Messages[i]
				out, err := writer.WriteMessage(vectorBytes(t, m.Payload))
				if err != nil {
					t.Fatal(err)
				}
				reader.nonce = 37
				ck, key, h := reader.ck, reader.key, bytes.Clone(reader.h)
				ckHash := reader.p.Hash(ck.Bytes())
				var keyHash []byte
				if key != nil {
					keyHash = reader.p.Hash(key.Bytes())
				}
				reader.accept = func([]byte) bool { return false }
				if _, err := reader.ReadMessage(out); !errors.Is(err, ErrMessage) {
					t.Fatalf("refused payload: %v", err)
				}
				if reader.ck != ck || reader.key != key || reader.nonce != 37 || reader.msg != i ||
					!bytes.Equal(reader.h, h) || !bytes.Equal(reader.p.Hash(ck.Bytes()), ckHash) ||
					(key != nil && !bytes.Equal(reader.p.Hash(key.Bytes()), keyHash)) {
					t.Fatal("failed read changed the hash, chaining key, cipher key or nonce")
				}
				reader.accept = nil
				pt, err := reader.ReadMessage(out)
				if err != nil || !bytes.Equal(pt, vectorBytes(t, m.Payload)) {
					t.Fatalf("genuine message after rollback: %v", err)
				}
			}
			for _, hs := range []*HandshakeState{ini, resp} {
				a, b, h, err := hs.Split()
				if err != nil {
					t.Fatal(err)
				}
				a.Release()
				b.Release()
				if !bytes.Equal(h, vectorBytes(t, v.HandshakeHash)) || hs.ck != nil || hs.key != nil || hs.e != nil {
					t.Fatal("rollback changed the final transcript or Split retained secrets")
				}
			}
		})
	}
}
