package providertest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func testDerivePair(t *testing.T, p jcrypto.CryptoProvider) {
	secret := fixedSecret(t, 0x40, p.KeySize())
	defer secret.Release()
	before := bytes.Clone(secret.Bytes())
	ctx := mustContext(t, p, "test", []byte("session-1"), []byte{0x00})

	priv, pub := mustPair(t, p, secret, ctx)
	defer priv.Release()
	if !bytes.Equal(secret.Bytes(), before) {
		t.Fatal("DerivePair changed the secret")
	}

	again, pubAgain := mustPair(t, p, secret, ctx)
	defer again.Release()
	if again == priv || !bytes.Equal(again.Bytes(), priv.Bytes()) || !bytes.Equal(pubAgain, pub) {
		t.Fatal("DerivePair must give one pair for one secret and context, in a buffer of its own")
	}

	ephPriv, ephPub := mustEphemeral(t, p)
	defer ephPriv.Release()
	if priv.Len() != ephPriv.Len() || len(pub) != len(ephPub) {
		t.Fatalf("pair of %d and %d bytes, an ephemeral one of %d and %d", priv.Len(), len(pub), ephPriv.Len(), len(ephPub))
	}

	// the pair agrees as a generated one does, both ways
	agreeCtx := mustContext(t, p, "test", pub, ephPub)
	ours, err := p.Agree(priv, ephPub, agreeCtx)
	if err != nil {
		t.Fatalf("Agree with the derived key: %v", err)
	}
	defer ours.Release()
	theirs, err := p.Agree(ephPriv, pub, agreeCtx)
	if err != nil {
		t.Fatalf("Agree with the derived public key: %v", err)
	}
	defer theirs.Release()
	if !bytes.Equal(ours.Bytes(), theirs.Bytes()) {
		t.Fatal("the derived pair does not agree with an ephemeral one")
	}

	seen := map[string]string{string(pub): "base"}
	differs := func(name string, s *secmem.Buffer, c jcrypto.Context) {
		t.Helper()
		k, other := mustPair(t, p, s, c)
		k.Release()
		if prev, ok := seen[string(other)]; ok {
			t.Fatalf("%s gave the public key of %s", name, prev)
		}
		seen[string(other)] = name
	}
	differs("another exchange", secret, mustContext(t, p, "test2", []byte("session-1"), []byte{0x00}))
	differs("another part byte", secret, mustContext(t, p, "test", []byte("session-1"), []byte{0x01}))
	for i := 0; i < p.KeySize(); i++ {
		flipped := bytes.Clone(before)
		flipped[i] ^= 1 << (i % 8)
		s, err := secmem.NewFrom(flipped)
		if err != nil {
			t.Fatal(err)
		}
		differs(fmt.Sprintf("bit %d of secret byte %d", i%8, i), s, ctx)
		s.Release()
	}
}

func testDerivePairBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	ctx := mustContext(t, p, "test", []byte("session-1"))
	short := fixedSecret(t, 0x40, p.KeySize()-1)
	defer short.Release()
	long := fixedSecret(t, 0x40, p.KeySize()+1)
	defer long.Release()
	secret := fixedSecret(t, 0x40, p.KeySize())
	defer secret.Release()
	released := fixedSecret(t, 0x40, p.KeySize())
	released.Release()

	for _, tc := range []struct {
		name   string
		secret *secmem.Buffer
		ctx    jcrypto.Context
		want   error
	}{
		{"nil secret", nil, ctx, jcrypto.ErrBadKeySize},
		{"released secret", released, ctx, jcrypto.ErrBadKeySize},
		{"short secret", short, ctx, jcrypto.ErrBadKeySize},
		{"long secret", long, ctx, jcrypto.ErrBadKeySize},
		{"zero context", secret, jcrypto.Context{}, jcrypto.ErrBadContext},
		{"context of another suite", secret, foreignContext(t, p), jcrypto.ErrBadContext},
		// the size of the secret is checked before the context, as in DeriveKey
		{"short secret and a zero context", short, jcrypto.Context{}, jcrypto.ErrBadKeySize},
	} {
		priv, pub, err := p.DerivePair(tc.secret, tc.ctx)
		if !errors.Is(err, tc.want) || priv != nil || pub != nil {
			drop(priv)
			t.Fatalf("DerivePair(%s): %v with a pair %v, want %v and none", tc.name, err, pub != nil, tc.want)
		}
	}
}

// Golden vectors of DerivePair. K = 40 41 .. 5f, ctx = NewContext(p,
// "vault/identity", salt, [a]):
//
//	T  = "jimichi/v2/<suite>/transcript/vault/identity" || 00 || 02 || 0020 || salt || 0001 || a     82 / 80 bytes
//
//	c25519  th   = SHA-256(T)
//	        raw  = HMAC-SHA256(K, "jimichi/v2/c25519/pair/1" || 00 || th || 01)
//	        priv = raw, priv[0] &= f8, priv[31] &= 7f, priv[31] |= 40;   pub = X25519(priv, 9)
//	gost    th   = Streebog-256(T), in the byte order of RFC 6986
//	        c_i  = HMAC-Streebog256(K, 01 || "jimichi/v2/gost/pair/1" || 00 || th || u8(i) || 01 00), c_i[31] &= 7f
//	        priv = the first c_i with 0 < LE(c_i) < q;   pub = LE(x) || LE(y) of LE(priv)·P on
//	        id-tc26-gost-3410-2012-256-paramSetA
//
// The c25519 values were computed with Python hashlib, hmac and the X25519 of
// the cryptography package, the clamping written out, so a wrong clamp shows
// in priv. The GOST values come from a Python implementation written from the
// standards (Streebog, HMAC and the KDF, affine arithmetic on paramSetA) that
// first reproduced RFC 6986 M1 and M2, the examples of RFC 7836 appendix B and
// every GOST value of kdf.go. The GOST rows take the first candidate, the
// second and the fourth, so the number in the seed is pinned too; crypto/gost
// lists the refused candidates.
type goldenPair struct {
	salt []byte
	a    byte
	th   string
	priv string
	pub  string
}

var goldenPairs = map[jcrypto.Suite][]goldenPair{
	jcrypto.SuiteC25519: {
		{
			salt: seq(0x00, 32), a: 0x00,
			th:   "7b01c9c61a91ec739730046422dee060d866c7a310cc9cd5cc4890ebec1bc36a",
			priv: "e8e63d279594802f6dfa444e28b3729e1a05441414a68bfa97257af799752258",
			pub:  "f57ef360cfffa16bcceebb1f7826f9fb0184c3f524c2b3f49b13103660528446",
		},
		{
			salt: seq(0x00, 32), a: 0x01,
			th:   "638fd2b2df9268b140648724b51e570ba8c23d2ed7d695672f6e9d38dc367e5f",
			priv: "d0807878d286f04711be6f7daa52b676221811d0d6a006a1874dd46f57150d4e",
			pub:  "b23ddae9359dfa8b9ae8afc90b79de4cc97d968d2b2c7640582a1d6b458aa149",
		},
	},
	jcrypto.SuiteGOST: {
		// the fourth candidate, i = 3
		{
			salt: seq(0x00, 32), a: 0x00,
			th:   "b49e663cda152048eb8c294b88a5b118f5d7b5286c0a940c2ecca3e9f5124f04",
			priv: "e8a3416c63a889e2dcf22ae71da838920dd3ee719a74b6c9d4e23b2fe062601b",
			pub: "8269380082c46735fe57e2df8f90ce1d9074e3d23978663ee8726ff9463a6c00" +
				"ba5e03fe7a77ffb987e965ec0f932d9facb490ea1600fd11a0b561183e465c27",
		},
		// the first candidate
		{
			salt: seq(0x00, 32), a: 0x01,
			th:   "ae3e481707b59f5207581c8a1a468a73b5da192b5ed9c3922c3fad1d6f3593e2",
			priv: "d42b367aec3deba70d679357712d7f911a93754b08002a1789474282cb6f7831",
			pub: "ed2dc1d556d48cf9977bcdace5502efb2d623dfde2e948365de138d68529ba6f" +
				"f4694c90b30456ab5affa81449aef04db2cf2c65e12c9962afa1b88cd8a2abfc",
		},
		// the second candidate
		{
			salt: seq(0x02, 32), a: 0x00,
			th:   "1080150ac7f632fa3f33bb3144d9f3b300c04f61fd8f9e5ced03658759343a87",
			priv: "020c771982f5dd7abd36e896cdae404e1e3ee04974e05a14c1f6c3216dfb4902",
			pub: "326922dd795c01ad889bbc4b26c740c546849eecd80ef6fe4202919a74ea055d" +
				"246a40187eca394baa97be3692d30cf9170b83f1d217a62597af7904ae63ebc8",
		},
	},
}

func testGoldenDerivePair(t *testing.T, p jcrypto.CryptoProvider) {
	rows, ok := goldenPairs[p.Suite()]
	if !ok || len(rows) == 0 {
		t.Fatalf("no golden pairs listed for suite %v", p.Suite())
	}
	k := fixedSecret(t, 0x40, 32)
	defer k.Release()
	for _, g := range rows {
		ctx := mustContext(t, p, "vault/identity", g.salt, []byte{g.a})
		if got := hex.EncodeToString(ctx.Sum()); got != g.th {
			t.Fatalf("th(salt %x, a %02x) = %s, want %s", g.salt[:1], g.a, got, g.th)
		}
		priv, pub := mustPair(t, p, k, ctx)
		gotPriv := hex.EncodeToString(priv.Bytes())
		priv.Release()
		if gotPriv != g.priv || hex.EncodeToString(pub) != g.pub {
			t.Fatalf("DerivePair(K, salt %x, a %02x) = %s, %x\nwant %s, %s", g.salt[:1], g.a, gotPriv, pub, g.priv, g.pub)
		}
	}
}

func mustPair(t *testing.T, p jcrypto.CryptoProvider, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, []byte) {
	t.Helper()
	priv, pub, err := p.DerivePair(secret, ctx)
	if err != nil {
		t.Fatalf("DerivePair: %v", err)
	}
	if priv == nil || len(pub) == 0 {
		t.Fatal("DerivePair returned an empty pair")
	}
	return priv, pub
}
