package providertest

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

//go:embed noise_vectors.json
var noiseVectors []byte

func testNoiseKnownAnswers(t *testing.T, p jcrypto.CryptoProvider) {
	t.Helper()
	var fixtures []struct{ Suite, First, Second, EmptyFirst, EmptySecond, Private, Public, DH string }
	if err := json.Unmarshal(noiseVectors, &fixtures); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, f := range fixtures {
		if f.Suite != p.Suite().String() {
			continue
		}
		ck := fixedSecret(t, 1, 32)
		defer ck.Release()
		in := fixedSecret(t, 33, 32)
		defer in.Release()
		for _, tc := range []struct {
			input         *secmem.Buffer
			first, second string
		}{{in, f.First, f.Second}, {nil, f.EmptyFirst, f.EmptySecond}} {
			a, b, err := p.NoiseKDF2(ck, tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a.Bytes(), decode(tc.first)) || !bytes.Equal(b.Bytes(), decode(tc.second)) {
				t.Fatal("bounded NoiseKDF2 fixture mismatch")
			}
			a.Release()
			b.Release()
		}
		if f.DH != "" {
			priv, err := secmem.NewFrom(decode(f.Private))
			if err != nil {
				t.Fatal(err)
			}
			defer priv.Release()
			out, err := p.NoiseDH(priv, decode(f.Public))
			if err != nil {
				t.Fatal(err)
			}
			defer out.Release()
			if !bytes.Equal(out.Bytes(), decode(f.DH)) {
				t.Fatal("fixed UKM=1 VKO composition fixture mismatch")
			}
		}
		return
	}
	t.Fatal("missing provider Noise fixture")
}

func testNoisePrimitives(t *testing.T, p jcrypto.CryptoProvider) {
	testNoiseKnownAnswers(t, p)
	h := p.HandshakeInfo()
	if !h.Valid() || h != p.HandshakeInfo() || h.KeySize != p.KeySize() {
		t.Fatal("invalid or unstable handshake metadata")
	}
	a, A := mustEphemeral(t, p)
	defer a.Release()
	b, B := mustEphemeral(t, p)
	defer b.Release()
	beforeA, beforeB, beforePub := bytes.Clone(a.Bytes()), bytes.Clone(b.Bytes()), bytes.Clone(B)
	x, err := p.NoiseDH(a, B)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Release()
	y, err := p.NoiseDH(b, A)
	if err != nil {
		t.Fatal(err)
	}
	defer y.Release()
	if x.Len() != 32 || !x.Equal(y) || !bytes.Equal(a.Bytes(), beforeA) || !bytes.Equal(b.Bytes(), beforeB) || !bytes.Equal(B, beforePub) {
		t.Fatal("agreement symmetry, size or borrowed input changed")
	}
	if x == a || x == b || x == y || &x.Bytes()[0] == &a.Bytes()[0] || &x.Bytes()[0] == &y.Bytes()[0] {
		t.Fatal("agreement output aliases an input or another output")
	}
	short, _ := secmem.New(1)
	defer short.Release()
	released, _ := secmem.New(32)
	released.Release()
	for _, bad := range []*secmem.Buffer{nil, short, released} {
		out, err := p.NoiseDH(bad, B)
		if out != nil || !errors.Is(err, jcrypto.ErrBadKeySize) {
			drop(out)
			t.Fatal("invalid private key accepted by NoiseDH")
		}
	}
	for _, bad := range [][]byte{nil, B[:len(B)-1], append(bytes.Clone(B), 0), make([]byte, len(B))} {
		out, err := p.NoiseDH(a, bad)
		if out != nil || !errors.Is(err, jcrypto.ErrBadPublicKey) {
			drop(out)
			t.Fatal("invalid public key accepted by NoiseDH")
		}
	}
	var weakPeers [][]byte
	if p.Suite() == jcrypto.SuiteC25519 {
		weak := make([]byte, h.PublicKeySize)
		weak[0] = 1
		weakPeers = append(weakPeers, weak)
	} else {
		for _, encoded := range smallOrderKeys[p.Suite()] {
			weak, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			weakPeers = append(weakPeers, weak)
		}
	}
	for _, weak := range weakPeers {
		out, err := p.NoiseDH(a, weak)
		if out != nil || !errors.Is(err, jcrypto.ErrBadPublicKey) {
			drop(out)
			t.Fatal("low-order peer accepted by NoiseDH")
		}
	}
	ck := fixedSecret(t, 1, 32)
	defer ck.Release()
	ckBefore, xBefore := bytes.Clone(ck.Bytes()), bytes.Clone(x.Bytes())
	for _, input := range []*secmem.Buffer{nil, x} {
		first, second, err := p.NoiseKDF2(ck, input)
		if err != nil {
			t.Fatal(err)
		}
		if first.Len() != 32 || second.Len() != 32 || first == second || first == ck || second == ck ||
			first.Equal(second) || &first.Bytes()[0] == &second.Bytes()[0] || &first.Bytes()[0] == &ck.Bytes()[0] || &second.Bytes()[0] == &ck.Bytes()[0] || !bytes.Equal(ck.Bytes(), ckBefore) || !bytes.Equal(x.Bytes(), xBefore) {
			t.Fatal("KDF output ownership, separation or borrowed input changed")
		}
		first.Release()
		second.Release()
	}
	for _, pair := range [][2]*secmem.Buffer{{nil, x}, {short, x}, {released, x}, {ck, short}, {ck, released}} {
		first, second, err := p.NoiseKDF2(pair[0], pair[1])
		if first != nil || second != nil || !errors.Is(err, jcrypto.ErrBadKeySize) {
			drop(first)
			drop(second)
			t.Fatal("invalid NoiseKDF2 input accepted")
		}
	}
}
