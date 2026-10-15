package vault

import (
	"bytes"
	"encoding/hex"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func seq(first byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buffer(t testing.TB, b []byte) *secmem.Buffer {
	t.Helper()
	k, err := secmem.NewFrom(bytes.Clone(b))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Release)
	return k
}

// the identity of a volume. W = 40 41 .. 5f stands for PasswordKey, salt = 00
// 01 .. 1f, s the area. In the notation of crypto/providertest, H the suite's
// hash (SHA-256, Streebog-256) and KDF(K, purpose, th) the formula of
// DeriveKey (HMAC-SHA256(K, label || 00 || th || 01) on c25519,
// HMAC-Streebog256(K, 01 || label || 00 || th || 01 00) on GOST):
//
//	ctx_s  = H("jimichi/v2/<suite>/transcript/vault/volume" || 00 || 02 || 0020 || salt || 0001 || s)
//	k_s    = KDF(W, "vault/volume", ctx_s), 32 bytes
//	th_id  = H("jimichi/v2/<suite>/transcript/vault/identity" || 00 || 02 || 0020 || salt || 0001 || s)
//	priv, pub = DerivePair(k_s, th_id), the recipe of GoldenDerivePair
//	F      = KDF(k_s, "vault/fetch", th_id), first 16 bytes
//
// The c25519 values were computed with Python hashlib, hmac and the X25519 of
// the cryptography package, the clamping written out; the GOST values with the
// Python implementation written from the standards (Streebog, HMAC, the KDF
// and paramSetA arithmetic) that gives the GOST vectors of
// crypto/providertest. A Go harness over x/crypto and gogost directly, not
// through the providers, gives the same lines
var goldenIdentity = map[jcrypto.Suite][]struct {
	s                        int
	ks, th, priv, pub, fetch string
}{
	jcrypto.SuiteC25519: {
		{
			s:     0,
			ks:    "ba4b8bb352fac6bc71075708c58d28d5ab2deef93eb9cd7701d16d87979138b6",
			th:    "7b01c9c61a91ec739730046422dee060d866c7a310cc9cd5cc4890ebec1bc36a",
			priv:  "98aca4ff76385c5e314e0a87430f643e7c2ef3b4e0c68565f7c4282d52465470",
			pub:   "32612529fbb315e4f048d8b8825cf7f5688cc34e64951fd7660ca14e65ab0747",
			fetch: "1e0c8b31855d0d800492e62cf4436128",
		},
		{
			s:     1,
			ks:    "f4a0ff57b0cc4a064ea4babcb2d9222e7fa26fc54297f95c9a8870c39e16218e",
			th:    "638fd2b2df9268b140648724b51e570ba8c23d2ed7d695672f6e9d38dc367e5f",
			priv:  "10b514af6d237522ef1fc7b79905555029aa45099f54086013a5e02e6bff304a",
			pub:   "87c877264cbdb46065760940b0882567d1e4e0a8e6f03fea21ac8a79a7ffd119",
			fetch: "1e88e6a18a1978d8d9224ca741dbe56d",
		},
	},
	jcrypto.SuiteGOST: {
		{
			s:    0,
			ks:   "214795170cadc4e7907199a7a1358b42290d027d87c9f0eded2507bd23baa1b5",
			th:   "b49e663cda152048eb8c294b88a5b118f5d7b5286c0a940c2ecca3e9f5124f04",
			priv: "3efd663f2199d07b2e1059fcce5e93683910d060e2007d1849fe9a903e04f90e",
			pub: "73a3e8e487ea1aedd5ec27137ea4e3e1681c89a829d7168b2deaa8b56d4a3bb4" +
				"688965d8da92054c8ee300d602acfbda4207cbd168e588f3faca08a453b316c7",
			fetch: "a7aa56b28501971de66fa3a2017ef406",
		},
		{
			s:    1,
			ks:   "9c9aae7eaedea68e60e7e035e9d4dc2c96d08d483cc0f095e1389faf0dd5c985",
			th:   "ae3e481707b59f5207581c8a1a468a73b5da192b5ed9c3922c3fad1d6f3593e2",
			priv: "6646e99acedfdf701af1df822501c070e367ed98d7811f8ea0e53a8a46cc093c",
			pub: "532993c5843a03ab89f9b3f6aa3c97eab01c99fa1191467f222c37bca834c487" +
				"8635ba4cbf2cac6a2b25af5ef24c8c1476fcf1dd8b7d0a4552492f40fb8f6550",
			fetch: "4be5c8d357e4058ac4c046209f609393",
		},
	},
}

func TestGoldenIdentity(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		rows := goldenIdentity[p.Suite()]
		if len(rows) != 2 {
			t.Fatalf("%d identity rows for %v", len(rows), p.Suite())
		}
		w, salt := buffer(t, seq(0x40, 32)), seq(0x00, SaltSize)
		for _, g := range rows {
			k, err := volumeKey(p, w, salt, g.s)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(k.Bytes()); got != g.ks {
				t.Fatalf("k_%d = %s, want %s", g.s, got, g.ks)
			}
			ctx, err := jcrypto.NewContext(p, exchangeIdentity, salt, []byte{byte(g.s)})
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(ctx.Sum()); got != g.th {
				t.Fatalf("th_id(%d) = %s, want %s", g.s, got, g.th)
			}
			id, err := deriveIdentity(p, k, salt, g.s)
			k.Release()
			if err != nil {
				t.Fatal(err)
			}
			priv, pub, fetch := id.Take()
			gotPriv, gotFetch := hex.EncodeToString(priv.Bytes()), hex.EncodeToString(fetch.Bytes())
			priv.Release()
			fetch.Release()
			if gotPriv != g.priv || hex.EncodeToString(pub) != g.pub || gotFetch != g.fetch {
				t.Fatalf("identity %d = %s, %x, %s\nwant %s, %s, %s", g.s, gotPriv, pub, gotFetch, g.priv, g.pub, g.fetch)
			}
		}
	})
}

// the areas of the container, under the W and salt of goldenIdentity or, for
// the empty volume, a given key:
//
//	th_b  = H("jimichi/v2/<suite>/transcript/vault/block" || 00 || 02 || 0001 || s || 0020 || r)     79 / 77 bytes
//	K_b   = KDF(k_s, "vault/block", th_b), 32 bytes
//	plain = u16be(L) || content || zeroes, 4048 bytes
//	area  = r || AEAD(K_b).Seal(nonce = zero, plain, ad = th_b), 4096 bytes
//
// AEAD is XChaCha20-Poly1305 with a nonce of 24 zero bytes on c25519 and
// Kuznyechik-MGM with 16 zero bytes on GOST. The c25519 rows were computed in
// Python with HChaCha20 written out and checked on draft-irtf-cfrg-xchacha
// 2.2.1 and XChaCha20-Poly1305 on its A.3.1, over the ChaCha20-Poly1305 of the
// cryptography package. The GOST rows come from a Go harness over gogost
// directly (Streebog-256, HMAC, Kuznyechik, MGM) with the transcript and the
// KDF input written out, which on c25519 gives the Python rows line for line.
// H(area) is the suite's hash of the whole area
var goldenAreas = map[jcrypto.Suite][]struct {
	k             string
	s             int
	r, content    []byte
	th, kb        string
	ct, tag, hash string
}{
	jcrypto.SuiteC25519: {
		{
			s: 0, r: seq(0x80, 32), content: []byte("jimichi vault area 0"),
			th:   "e8e89f1b49afaea4cbf77041776432e383cd380e36e1b01766bf07931161be39",
			kb:   "9eae30809a2474836d3dc1efd2a3b3f210b6dd83ec9b7913af224e8a377c8587",
			ct:   "851e70b545ff2db6e5773c2267a1a3b6ce2ddba26dee81db66b9afc5e0616796",
			tag:  "e8aa8bd0a0ce4e659197645b7604466d",
			hash: "e1f3e09771f06f76e59acf7bb89f2317af174218e150f826654804f35be0bb54",
		},
		{
			s: 1, r: seq(0xa0, 32), content: seq(0x00, 339),
			th:   "cd7f3ae87be27c0c0cf5163e9ce4459a20a147b48b7819d201d89366d0917ce2",
			kb:   "1ea169b22f31f767910e4837a4247fdcc20d5f8be49cf5fdfa6e0be506073db3",
			ct:   "e439226091d85f796939518220ef0d26cc1eac8e0a09719904e31e2302883d1d",
			tag:  "88b71bcc50f22827108289c06c5ad4e8",
			hash: "9e5bc8e5e8956caab550d7bbf156e8158b44c10a4d4337b2c716709593e88e3f",
		},
		{
			k: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
			s: 1, r: seq(0xe0, 32),
			th:   "bd85927c6750ba4244a2e336f85a4c3e6830730927ef940f339e979a52b74903",
			kb:   "f3492a5b3cfa2c1398b2f2d84355499abc67e95e7a5d0cf2964c23c73d063a3b",
			ct:   "d2ddbcf5c08795a140178572c94af1baff72178b434d0edcc23e704974ab1ff9",
			tag:  "db9a4cc44c49c7c07a11312c7ae349d3",
			hash: "68c3f75c51d2c956a5d11b87814e09acac2868ce502fc70044abe3400dc55205",
		},
	},
	jcrypto.SuiteGOST: {
		{
			s: 0, r: seq(0x80, 32), content: []byte("jimichi vault area 0"),
			th:   "cb16571bef883de5a681e349b0962cb5966019772442e57e2fa8b3e6b3a1838a",
			kb:   "e3a8e26f77615537bdc05bad56d19f74817d44eb1a1845e2dcd46f252de18768",
			ct:   "9d76037405fac45b616945dae861d77f02eb65f24394800a3fdb27c90830e54b",
			tag:  "65c2191ad4dfbde41ec270ff33692cc5",
			hash: "fd66de19bc3a4809ceb06732bab2ec93882270584b29faafecd627952a98ef86",
		},
		{
			s: 1, r: seq(0xa0, 32), content: seq(0x00, 339),
			th:   "510fef47c1dac1d571b7a5644e9338f903f57f06ab1056730a4820bb30935254",
			kb:   "d14435cadbc61eaf2df9ca75542889754e883134bcb77ad4f07174212e9439ed",
			ct:   "9b5ce3a7854f5724a362088817d51e2de5e18883a15a9934212aef3036d99921",
			tag:  "b69b01545e106e6d35238e23c4c6deb2",
			hash: "d75ceadfc9b9d81026e09d8b504680f81686475444e8e75be50d4f8ffeaf2b6e",
		},
		{
			k: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
			s: 1, r: seq(0xe0, 32),
			th:   "05bf4354239a2408930c242dfb61a75ac28514ee67e5d615a48507ad22898de7",
			kb:   "e7da829b8092ab8abfc35226b4b3e0705940a68f2f7e0005e86bb762f4565246",
			ct:   "43625a118ba6296276a5f20747f666c4fb1ec77c7ecc35be2f1fcebe18f70788",
			tag:  "18141c5a12d29afc8a3ccf6c0168fc44",
			hash: "7545490516510b3462d3fdd75cde3747288fd4337e123aa68c4d3f641765025e",
		},
	},
}

func TestGoldenAreas(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		rows := goldenAreas[p.Suite()]
		if len(rows) != 3 {
			t.Fatalf("%d area rows for %v", len(rows), p.Suite())
		}
		w, salt := buffer(t, seq(0x40, 32)), seq(0x00, SaltSize)
		for _, g := range rows {
			var k *secmem.Buffer
			if g.k != "" {
				k = buffer(t, unhex(t, g.k))
			} else {
				var err error
				if k, err = volumeKey(p, w, salt, g.s); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(k.Release)
			}
			ctx, err := jcrypto.NewContext(p, exchangeBlock, []byte{byte(g.s)}, g.r)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(ctx.Sum()); got != g.th {
				t.Fatalf("th_b(%d) = %s, want %s", g.s, got, g.th)
			}
			kb, err := p.DeriveKey(k, purposeBlock, ctx, keySize)
			if err != nil {
				t.Fatal(err)
			}
			gotKB := hex.EncodeToString(kb.Bytes())
			kb.Release()
			if gotKB != g.kb {
				t.Fatalf("K_b(%d) = %s, want %s", g.s, gotKB, g.kb)
			}

			plain, err := secmem.New(plainSize)
			if err != nil {
				t.Fatal(err)
			}
			defer plain.Release()
			n, err := fillContent(plain.Bytes(), nil, content(g.content))
			if err != nil || n != len(g.content) {
				t.Fatalf("fill: %d, %v", n, err)
			}
			area := make([]byte, RegionSize)
			if err := sealArea(p, k, g.s, g.r, plain.Bytes(), area); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(area[:rSize], g.r) ||
				hex.EncodeToString(area[rSize:rSize+32]) != g.ct ||
				hex.EncodeToString(area[RegionSize-tagSize:]) != g.tag ||
				hex.EncodeToString(p.Hash(area)) != g.hash {
				t.Fatalf("area %d: ct %x, tag %x, hash %x\nwant %s, %s, %s", g.s, area[rSize:rSize+32], area[RegionSize-tagSize:], p.Hash(area), g.ct, g.tag, g.hash)
			}

			back, err := secmem.New(plainSize)
			if err != nil {
				t.Fatal(err)
			}
			defer back.Release()
			ok, err := openArea(p, k, g.s, area, back.Bytes())
			if err != nil || !ok || !back.Equal(plain) {
				t.Fatalf("area %d does not open back: %v, %v", g.s, ok, err)
			}
			if ok, _ := openArea(p, k, 1-g.s, area, back.Bytes()); ok {
				t.Fatalf("area %d opens as area %d", g.s, 1-g.s)
			}
		}
	})
}
