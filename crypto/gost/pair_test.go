package gost

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// 32 bytes little endian, as gogost reads a private key
func leBytes(k *big.Int) []byte {
	be := k.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[31-i] = be[i]
	}
	return out
}

func pow2(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

func plus(k *big.Int, d int64) *big.Int { return new(big.Int).Add(k, big.NewInt(d)) }

// the helper generate shares with DerivePair, on values that are not masked:
// generate passes it full 256-bit candidates
func TestScalarInRange(t *testing.T) {
	q := curve().Q
	all := new(big.Int).Sub(pow2(256), big.NewInt(1))
	for name, k := range map[string]*big.Int{
		"0": big.NewInt(0), "q": q, "q+1": plus(q, 1), "2^255": pow2(255), "2^256-1": all,
	} {
		if scalarInRange(q, leBytes(k)) {
			t.Fatalf("%s is taken as a scalar", name)
		}
	}
	for name, k := range map[string]*big.Int{"1": big.NewInt(1), "q-1": plus(q, -1)} {
		if !scalarInRange(q, leBytes(k)) {
			t.Fatalf("%s is refused", name)
		}
	}
}

// a stream of candidates of the test's own: the mask, the bounds and the
// number of draws, apart from the KDF
func TestPickScalarStream(t *testing.T) {
	q := curve().Q
	withTop := func(k *big.Int) []byte {
		b := leBytes(k)
		b[31] |= 0x80
		return b
	}
	for _, tc := range []struct {
		name   string
		stream [][]byte
		draws  int
		want   *big.Int
	}{
		{"0, then a valid one", [][]byte{leBytes(big.NewInt(0)), leBytes(big.NewInt(5))}, 2, big.NewInt(5)},
		{"q, then q-1", [][]byte{leBytes(q), leBytes(plus(q, -1))}, 2, plus(q, -1)},
		{"1", [][]byte{leBytes(big.NewInt(1))}, 1, big.NewInt(1)},
		{"q-1 with bit 255 set", [][]byte{withTop(plus(q, -1))}, 1, plus(q, -1)},
		{"2^255, which the mask makes 0", [][]byte{leBytes(pow2(255)), leBytes(big.NewInt(7))}, 2, big.NewInt(7)},
		{"q with bit 255 set, which the mask makes q", [][]byte{withTop(q), leBytes(big.NewInt(7))}, 2, big.NewInt(7)},
		{"2^255-1", [][]byte{leBytes(plus(pow2(255), -1)), leBytes(big.NewInt(9))}, 2, big.NewInt(9)},
	} {
		calls := 0
		dst := make([]byte, 32)
		err := pickScalar(q, dst, func(i int, d []byte) {
			if i != calls {
				t.Fatalf("%s: draw %d called with number %d", tc.name, calls, i)
			}
			if i >= len(tc.stream) {
				t.Fatalf("%s: draw %d past the %d candidates of the stream", tc.name, i, len(tc.stream))
			}
			copy(d, tc.stream[i])
			calls++
		})
		if err != nil || calls != tc.draws || !bytes.Equal(dst, leBytes(tc.want)) {
			t.Fatalf("%s: %v after %d draws, scalar %x; want %x after %d", tc.name, err, calls, dst, leBytes(tc.want), tc.draws)
		}
	}

	calls := 0
	err := pickScalar(q, make([]byte, 32), func(_ int, d []byte) {
		calls++
		if calls > 128 {
			t.Fatalf("a stream of zeros: draw %d, past the bound of 128", calls)
		}
		clear(d)
	})
	if !errors.Is(err, jcrypto.ErrNoScalar) || calls != pairDraws || pairDraws != 128 {
		t.Fatalf("a stream of zeros: %v after %d draws, want ErrNoScalar after 128", err, calls)
	}
}

func pairContext(t *testing.T, salt []byte, a byte) jcrypto.Context {
	t.Helper()
	ctx, err := jcrypto.NewContext(New(), "vault/identity", salt, []byte{a})
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func seqBytes(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

// the GOST rows of the golden pairs of providertest with every candidate
// refused before the one taken, computed by the Python reference: candidate i
// is KDF(K, label(pair/1), th || u8(i)) with bit 255 cleared, the private key
// is the first one below q, and the public key is gost3410's for it
func TestDerivePairCandidates(t *testing.T) {
	c := curve()
	label, err := jcrypto.Label(jcrypto.SuiteGOST, "pair/1")
	if err != nil {
		t.Fatal(err)
	}
	k := seqBytes(0x40, 32)
	for _, v := range []struct {
		salt    []byte
		a       byte
		refused []string
		priv    string
	}{
		{seqBytes(0x00, 32), 0x00, []string{
			"456961070f25afc23d25c23a5fd204edcfe25165f6aae836823c6d4ed1824d54",
			"4c74be43fc3b7f0361f2b63a3e3cf494482361ce91eb4871a26b7aec76e22e78",
			"b36230cde2e4c0f23ae1e84a0f289574e0f89996d8529818d7795d2b73583247",
		}, "e8a3416c63a889e2dcf22ae71da838920dd3ee719a74b6c9d4e23b2fe062601b"},
		{seqBytes(0x00, 32), 0x01, nil, "d42b367aec3deba70d679357712d7f911a93754b08002a1789474282cb6f7831"},
		{seqBytes(0x02, 32), 0x00, []string{
			"73de722b97bfa15b036d278bfcc015fbe89261fef483708e5f648e79a5bc4e64",
		}, "020c771982f5dd7abd36e896cdae404e1e3ee04974e05a14c1f6c3216dfb4902"},
	} {
		ctx := pairContext(t, v.salt, v.a)
		kdf := gost34112012256.NewKDF(k)
		for i := 0; i <= len(v.refused); i++ {
			cand := kdf.Derive(nil, label, append(ctx.Sum(), byte(i)))
			cand[31] &= 0x7f
			n := littleEndian(cand)
			if i < len(v.refused) {
				// every refusal here is a candidate not below q; none is zero
				if hex.EncodeToString(cand) != v.refused[i] || n.Sign() == 0 || n.Cmp(c.Q) < 0 {
					t.Fatalf("salt %x a %02x: candidate %d %x, want %s refused as not below q", v.salt[:1], v.a, i, cand, v.refused[i])
				}
				continue
			}
			if hex.EncodeToString(cand) != v.priv || !scalarInRange(c.Q, cand) {
				t.Fatalf("salt %x a %02x: candidate %d %x, want %s taken", v.salt[:1], v.a, i, cand, v.priv)
			}
		}

		secret, err := secmem.NewFrom(bytes.Clone(k))
		if err != nil {
			t.Fatal(err)
		}
		priv, pub, err := New().DerivePair(secret, ctx)
		secret.Release()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(priv.Bytes()) != v.priv {
			t.Fatalf("salt %x a %02x: DerivePair %x, want %s", v.salt[:1], v.a, priv.Bytes(), v.priv)
		}
		prv, err := gost3410.NewPrivateKey(c, priv.Bytes())
		priv.Release()
		if err != nil {
			t.Fatal(err)
		}
		want, err := prv.PublicKey()
		if err != nil || !bytes.Equal(want.Raw(), pub) {
			t.Fatalf("salt %x a %02x: the public key is not gost3410's for the private key: %v", v.salt[:1], v.a, err)
		}
	}
}

// how often the first candidate is taken, over 2000 fixed secrets u32be(j) ||
// 28 zero bytes under ctx = vault/identity(00..1f, [00]); the Python reference
// counts 1022. Expected 1000 at p = 1/2, sd of the share 0.0112, so [900,
// 1100] is 4.47 sd; the inputs are fixed, so every run gives the same count.
// Without the mask, or with the mask on another byte, the share is near 1/4;
// a mask of bit 254 leaves it near 1/2, and the vectors catch that one
func TestDerivePairFirstCandidateShare(t *testing.T) {
	c := curve()
	label, err := jcrypto.Label(jcrypto.SuiteGOST, "pair/1")
	if err != nil {
		t.Fatal(err)
	}
	seed := append(pairContext(t, seqBytes(0x00, 32), 0x00).Sum(), 0)
	first := 0
	for j := 0; j < 2000; j++ {
		secret := make([]byte, 32)
		binary.BigEndian.PutUint32(secret, uint32(j))
		draw := drawFrom(gost34112012256.NewKDF(secret), label, seed)
		dst := make([]byte, 32)
		draws := 0
		err := pickScalar(c.Q, dst, func(i int, d []byte) {
			draw(i, d)
			draws++
		})
		if err != nil {
			t.Fatalf("secret %d: %v", j, err)
		}
		if dst[31]&0x80 != 0 || !scalarInRange(c.Q, dst) {
			t.Fatalf("secret %d: scalar %x has bit 255 set or is out of range", j, dst)
		}
		if draws == 1 {
			first++
		}
	}
	if first != 1022 || first < 900 || first > 1100 {
		t.Fatalf("the first candidate was taken for %d secrets of 2000, the reference counts 1022", first)
	}
}

// the worst case of the sampling: 128 KDF calls whose candidates are all
// refused, which ends in ErrNoScalar
func BenchmarkPickScalarWorstCase(b *testing.B) {
	c := curve()
	label, err := jcrypto.Label(jcrypto.SuiteGOST, "pair/1")
	if err != nil {
		b.Fatal(err)
	}
	seed := make([]byte, jcrypto.ContextSize+1)
	draw := drawFrom(gost34112012256.NewKDF(seqBytes(0x40, 32)), label, seed)
	dst := make([]byte, 32)
	for b.Loop() {
		err := pickScalar(c.Q, dst, func(i int, d []byte) {
			draw(i, d)
			for k := range d {
				d[k] = 0xff
			}
		})
		if !errors.Is(err, jcrypto.ErrNoScalar) {
			b.Fatal(err)
		}
	}
}
