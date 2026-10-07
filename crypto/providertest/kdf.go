package providertest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// every purpose the system derives under, with the size it takes
var purposes = []struct {
	name string
	size int
}{
	{"setup", 32},
	{"cell", 32},
	{"setup/replay", 16},
	{"counter/fwd", 8},
	{"counter/bwd", 8},
	{"link/i2r", 32},
	{"link/r2i", 32},
}

func testAgreeMatches(t *testing.T, p jcrypto.CryptoProvider) {
	aPriv, aPub := mustEphemeral(t, p)
	defer aPriv.Release()
	bPriv, bPub := mustEphemeral(t, p)
	defer bPriv.Release()

	ctx := mustContext(t, p, "test", aPub, bPub)

	aSecret, err := p.Agree(aPriv, bPub, ctx)
	if err != nil {
		t.Fatalf("Agree(a): %v", err)
	}
	defer aSecret.Release()

	bSecret, err := p.Agree(bPriv, aPub, ctx)
	if err != nil {
		t.Fatalf("Agree(b): %v", err)
	}
	defer bSecret.Release()

	if !bytes.Equal(aSecret.Bytes(), bSecret.Bytes()) {
		t.Fatal("both sides must agree on the same secret")
	}
	if aSecret.Len() != p.KeySize() || allZero(aSecret.Bytes()) {
		t.Fatalf("shared secret of %d bytes, or all zeroes", aSecret.Len())
	}
}

func testAgreeContext(t *testing.T, p jcrypto.CryptoProvider) {
	aPriv, _ := mustEphemeral(t, p)
	defer aPriv.Release()
	bPriv, bPub := mustEphemeral(t, p)
	defer bPriv.Release()

	first, err := p.Agree(aPriv, bPub, mustContext(t, p, "test", []byte("session-1")))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	defer first.Release()

	second, err := p.Agree(aPriv, bPub, mustContext(t, p, "test", []byte("session-2")))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	defer second.Release()

	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("different contexts must produce different secrets")
	}
}

func testAgreeBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	priv, pub := mustEphemeral(t, p)
	defer priv.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))
	short := fixedSecret(t, 1, 3)
	defer short.Release()

	for _, tc := range []struct {
		name string
		priv *secmem.Buffer
		pub  []byte
		ctx  jcrypto.Context
		want error
	}{
		{"nil private key", nil, pub, ctx, jcrypto.ErrBadKeySize},
		{"short private key", short, pub, ctx, jcrypto.ErrBadKeySize},
		{"short public key", priv, []byte{1, 2, 3}, ctx, jcrypto.ErrBadPublicKey},
		{"long public key", priv, append(bytes.Clone(pub), 0), ctx, jcrypto.ErrBadPublicKey},
		{"all-zero public key", priv, make([]byte, len(pub)), ctx, jcrypto.ErrBadPublicKey},
		{"zero context", priv, pub, jcrypto.Context{}, jcrypto.ErrBadContext},
		{"context of another suite", priv, pub, foreignContext(t, p), jcrypto.ErrBadContext},
		// the context is checked before the public key is looked at
		{"zero context and a bad public key", priv, []byte{1, 2, 3}, jcrypto.Context{}, jcrypto.ErrBadContext},
	} {
		if out, err := p.Agree(tc.priv, tc.pub, tc.ctx); !errors.Is(err, tc.want) {
			drop(out)
			t.Fatalf("Agree(%s): %v, want %v", tc.name, err, tc.want)
		}
	}
}

func testDeriveKey(t *testing.T, p jcrypto.CryptoProvider) {
	secret := fixedSecret(t, 0x40, p.KeySize())
	defer secret.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))

	forward := mustDerive(t, p, secret, "forward", ctx, p.KeySize())
	backward := mustDerive(t, p, secret, "backward", ctx, p.KeySize())
	if len(forward) != p.KeySize() {
		t.Fatalf("derived key size = %d, want %d", len(forward), p.KeySize())
	}
	if bytes.Equal(forward, backward) {
		t.Fatal("different purposes must produce different keys")
	}
	if !bytes.Equal(forward, mustDerive(t, p, secret, "forward", ctx, p.KeySize())) {
		t.Fatal("DeriveKey must be deterministic")
	}

	other := mustContext(t, p, "test", []byte("session-2"))
	if bytes.Equal(forward, mustDerive(t, p, secret, "forward", other, p.KeySize())) {
		t.Fatal("different contexts must produce different keys")
	}

	// wire derives a 16-byte replay tag and 8-byte offsets: every size up to
	// KeySize must work and is the prefix of the full block
	for size := 1; size <= p.KeySize(); size++ {
		short := mustDerive(t, p, secret, "forward", ctx, size)
		if len(short) != size || !bytes.Equal(short, forward[:size]) {
			t.Fatalf("size %d is not the prefix of the full key", size)
		}
	}
	if bytes.Equal(mustDerive(t, p, secret, "replay", ctx, 16), forward[:16]) {
		t.Fatal("different purposes must produce different outputs at a short size too")
	}
}

func testDeriveKeyBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	secret := fixedSecret(t, 0x40, p.KeySize())
	defer secret.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))
	short := fixedSecret(t, 0x40, p.KeySize()-1)
	defer short.Release()
	long := fixedSecret(t, 0x40, p.KeySize()+1)
	defer long.Release()

	for _, tc := range []struct {
		name    string
		secret  *secmem.Buffer
		purpose string
		ctx     jcrypto.Context
		size    int
		want    error
	}{
		{"size 0", secret, "cell", ctx, 0, jcrypto.ErrBadKeySize},
		{"negative size", secret, "cell", ctx, -1, jcrypto.ErrBadKeySize},
		{"size above KeySize", secret, "cell", ctx, p.KeySize() + 1, jcrypto.ErrBadKeySize},
		{"nil secret", nil, "cell", ctx, p.KeySize(), jcrypto.ErrBadKeySize},
		{"short secret", short, "cell", ctx, p.KeySize(), jcrypto.ErrBadKeySize},
		{"long secret", long, "cell", ctx, p.KeySize(), jcrypto.ErrBadKeySize},
		{"zero context", secret, "cell", jcrypto.Context{}, p.KeySize(), jcrypto.ErrBadContext},
		{"context of another suite", secret, "cell", foreignContext(t, p), p.KeySize(), jcrypto.ErrBadContext},
		{"purpose of Agree", secret, "agree", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"purpose of MixKey", secret, "mix", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"transcript prefix", secret, "transcript/test", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"empty purpose", secret, "", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"upper case", secret, "Cell", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"zero byte", secret, "cell\x00", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"empty segment", secret, "link//i2r", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"33 bytes", secret, strings.Repeat("a", 33), ctx, p.KeySize(), jcrypto.ErrBadLabel},
	} {
		if out, err := p.DeriveKey(tc.secret, tc.purpose, tc.ctx, tc.size); !errors.Is(err, tc.want) {
			drop(out)
			t.Fatalf("DeriveKey(%s): %v, want %v", tc.name, err, tc.want)
		}
	}
}

func testMixKey(t *testing.T, p jcrypto.CryptoProvider) {
	chain := fixedSecret(t, 0x40, p.KeySize())
	defer chain.Release()
	secret := fixedSecret(t, 0x60, p.KeySize())
	defer secret.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))

	mixed := mustMix(t, p, chain, secret, ctx)
	if len(mixed) != p.KeySize() {
		t.Fatalf("mixed key of %d bytes, want %d", len(mixed), p.KeySize())
	}
	if !bytes.Equal(mixed, mustMix(t, p, chain, secret, ctx)) {
		t.Fatal("MixKey must be deterministic")
	}
	if bytes.Equal(mixed, mustMix(t, p, secret, chain, ctx)) {
		t.Fatal("MixKey must depend on the order of its secrets")
	}
	if bytes.Equal(mixed, mustMix(t, p, chain, secret, mustContext(t, p, "test", []byte("session-2")))) {
		t.Fatal("MixKey must depend on the context")
	}
	if bytes.Equal(mixed, chain.Bytes()) || bytes.Equal(mixed, secret.Bytes()) {
		t.Fatal("MixKey returned one of its inputs")
	}

	// the result must depend on both secrets, not on one of them alone
	otherChain := fixedSecret(t, 0x41, p.KeySize())
	defer otherChain.Release()
	otherSecret := fixedSecret(t, 0x61, p.KeySize())
	defer otherSecret.Release()
	if bytes.Equal(mixed, mustMix(t, p, otherChain, secret, ctx)) {
		t.Fatal("MixKey ignores the chain key")
	}
	if bytes.Equal(mixed, mustMix(t, p, chain, otherSecret, ctx)) {
		t.Fatal("MixKey ignores the mixed secret")
	}
}

func testMixKeyBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	key := fixedSecret(t, 0x40, p.KeySize())
	defer key.Release()
	short := fixedSecret(t, 0x40, p.KeySize()-1)
	defer short.Release()
	long := fixedSecret(t, 0x40, 2*p.KeySize())
	defer long.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))

	for _, tc := range []struct {
		name          string
		chain, secret *secmem.Buffer
		ctx           jcrypto.Context
		want          error
	}{
		{"nil chain", nil, key, ctx, jcrypto.ErrBadKeySize},
		{"nil secret", key, nil, ctx, jcrypto.ErrBadKeySize},
		{"short chain", short, key, ctx, jcrypto.ErrBadKeySize},
		{"short secret", key, short, ctx, jcrypto.ErrBadKeySize},
		{"two keys glued as a chain", long, key, ctx, jcrypto.ErrBadKeySize},
		{"two keys glued as a secret", key, long, ctx, jcrypto.ErrBadKeySize},
		{"zero context", key, key, jcrypto.Context{}, jcrypto.ErrBadContext},
		{"context of another suite", key, key, foreignContext(t, p), jcrypto.ErrBadContext},
	} {
		if out, err := p.MixKey(tc.chain, tc.secret, tc.ctx); !errors.Is(err, tc.want) {
			drop(out)
			t.Fatalf("MixKey(%s): %v, want %v", tc.name, err, tc.want)
		}
	}
}

// a change of the exchange, of any part, of a boundary between parts or of
// their order must change everything derived under the context
func testTranscriptSeparates(t *testing.T, p jcrypto.CryptoProvider) {
	priv, _ := mustEphemeral(t, p)
	defer priv.Release()
	peer, pub := mustEphemeral(t, p)
	peer.Release()
	chain := fixedSecret(t, 0x40, p.KeySize())
	defer chain.Release()
	secret := fixedSecret(t, 0x60, p.KeySize())
	defer secret.Release()

	outputs := func(ctx jcrypto.Context) [][]byte {
		t.Helper()
		out := [][]byte{ctx.Sum(), mustMix(t, p, chain, secret, ctx)}
		agreed, err := p.Agree(priv, pub, ctx)
		if err != nil {
			t.Fatalf("Agree: %v", err)
		}
		out = append(out, bytes.Clone(agreed.Bytes()))
		agreed.Release()
		for _, pu := range purposes {
			out = append(out, mustDerive(t, p, chain, pu.name, ctx, pu.size))
		}
		return out
	}

	size := len(pub)
	base := [][]byte{{0x02}, {0x00}, {0, 0, 0, 0, 0, 0, 0, 200}, seq(0x80, size), seq(0x00, size)}
	want := outputs(mustContext(t, p, "setup", base...))

	differs := func(name, exchange string, parts [][]byte) {
		t.Helper()
		got := outputs(mustContext(t, p, exchange, parts...))
		for i := range want {
			if bytes.Equal(got[i], want[i]) {
				t.Fatalf("%s: output %d did not change", name, i)
			}
		}
	}

	differs("another exchange", "link", base)
	differs("a part appended", "setup", append(clone(base), []byte{0x00}))
	differs("the last part dropped", "setup", clone(base)[:4])

	swapped := clone(base)
	swapped[3], swapped[4] = swapped[4], swapped[3]
	differs("two keys swapped", "setup", swapped)

	// the same bytes in the same order, cut at other places
	moved := clone(base)
	moved[3], moved[4] = moved[3][:size-1], append([]byte{moved[3][size-1]}, moved[4]...)
	differs("a boundary moved", "setup", moved)
	merged := append(clone(base)[:3], append(bytes.Clone(base[3]), base[4]...))
	differs("two parts merged", "setup", merged)
	split := append(clone(base)[:4], base[4][:1], base[4][1:])
	differs("a part split", "setup", split)

	for i := range base {
		for _, bit := range []int{0, 8*len(base[i]) - 1} {
			flipped := clone(base)
			flipped[i][bit/8] ^= 1 << (bit % 8)
			differs("a bit of part "+string(rune('1'+i)), "setup", flipped)
		}
	}

	// every single bit of the version, the hop index, the link id and both keys
	cell := mustDerive(t, p, chain, "cell", mustContext(t, p, "setup", base...), p.KeySize())
	for i := range base {
		for bit := 0; bit < 8*len(base[i]); bit++ {
			flipped := clone(base)
			flipped[i][bit/8] ^= 1 << (bit % 8)
			ctx := mustContext(t, p, "setup", flipped...)
			if bytes.Equal(ctx.Sum(), want[0]) || bytes.Equal(mustDerive(t, p, chain, "cell", ctx, p.KeySize()), cell) {
				t.Fatalf("bit %d of part %d does not reach the derived key", bit, i+1)
			}
		}
	}
}

// Golden vectors of the key schedule. Common inputs: K = 40 41 .. 5f, P = the
// public key size of the suite (32 or 64), I = the identity key size of the
// suite (32, an Ed25519 key, or 64), version 02, link id 200.
//
//	G1  setup: 02, 00, 00000000000000c8, onion 80..(80+P-1), ephemeral 00..(P-1)
//	G2  link:  02, 01, ephI 00.., ephR 40.., static 80.. (P bytes each)
//	G3  link:  02, 00, ephI 00.., ephR 40..
//	G4  setup: the parts of G1, then identity c0..(c0+I-1)
//	G5  link:  the parts of G2, then identity c0..(c0+I-1)
//
// G1 to G3 are the transcripts of nodes that run without authentication, G4
// and G5 those of an authenticated node, which binds its identity key.
//
//	T  = "jimichi/v2/<suite>/transcript/<exchange>" || 00 || u8(n) || n times (u16be(len) || part)
//	th = Hash(T)
//
// T(G1) on c25519, 120 bytes, and T(G4), 154 bytes:
//
//	6a696d696368692f76322f6332353531392f7472616e7363726970742f7365747570 00 05
//	0001 02  0001 00  0008 00000000000000c8  0020 80..9f  0020 00..1f
//	6a696d696368692f76322f6332353531392f7472616e7363726970742f7365747570 00 06
//	0001 02  0001 00  0008 00000000000000c8  0020 80..9f  0020 00..1f  0020 c0..df
//
// How to recompute without this code, with label = "jimichi/v2/<suite>/<purpose>":
//
//	c25519  th: sha256sum over T
//	        DeriveKey(K, purpose, th, n) = HMAC-SHA256(K, label || 00 || th || 01)[:n]
//	          openssl dgst -sha256 -mac HMAC -macopt hexkey:<K>
//	        MixKey(chain, secret, th): PRK = HMAC-SHA256(chain, secret), then as DeriveKey
//	          under PRK with purpose mix
//	        Agree: Z = X25519(priv, pub), PRK = HMAC-SHA256(th, Z), then as DeriveKey under
//	          PRK with purpose agree
//	gost    th: Streebog-256 over T, in the byte order of RFC 6986
//	        DeriveKey(K, purpose, th, n) = HMAC-Streebog256(K, 01 || label || 00 || th || 01 00)[:n]
//	        MixKey(chain, secret, th) = HMAC-Streebog256(chain, 01 || label || 00 || th || secret || 01 00)
//	        Agree: UKM = th[0:8] little endian, KEK = VKO_GOSTR3410_2012_256(priv, pub, UKM),
//	          then as DeriveKey under KEK with purpose agree
//
// The c25519 values were computed with Python hashlib and hmac. The GOST values
// come from a second implementation written from the standards (Streebog, HMAC,
// VKO in affine coordinates) that first reproduced RFC 6986 M1 and the examples
// 7 (VKO) and 9 (KDF) of RFC 7836, appendix B. Those VKO examples are on the
// 512-bit paramSetA, so the primitives are held by the standard vectors in
// crypto/gost and these vectors pin the composition on the 256-bit paramSetA.
// Everything here but the KEK of the Agree vector is a hash or an HMAC, which
// openssl dgst with gost-engine (md_gost12_256) reproduces as well.
type goldenSuite struct {
	pubSize, idSize int
	th              [5]string
	derive          []goldenDerive
	// MixKey(K, 60..7f) under G2 and under G5
	mix   [2]string
	agree goldenAgree
}

type goldenDerive struct {
	ctx     int
	purpose string
	size    int
	want    string
}

// context: setup with 02, 00, link id 200, onion key = pubB, ephemeral = pubA
type goldenAgree struct {
	privA, pubA string
	privB, pubB string
	th          string
	secret      string
	setupKey    string
}

var golden = map[jcrypto.Suite]goldenSuite{
	jcrypto.SuiteC25519: {
		pubSize: 32,
		idSize:  32,
		th: [5]string{
			"b14c23db2eb7be7e6fb80d79859e002ef40b6c2262082d633aa6d44a2e00928c",
			"7b9ee2ddeffae097fbe33d8a86e4f800bad67ed18db7886ee15105fa47945c28",
			"9316cc227c129bc7bc39fe454668267767c8b86735e7d11e6b78de56fbdac044",
			"3f1268d9cdfeaff916445d4aa1648775fb3a3f290da1142fb0e9128c04422ecb",
			"bd1fd058596e45ce436a42fe19f45c2f64bef277aef7bcfd0f3353f6737ef7b3",
		},
		derive: []goldenDerive{
			{0, "setup", 32, "3be4d1bde0b01736abc783e3d09a8a40c2b36050fc0189d8b05e44be168d17c8"},
			{0, "cell", 32, "b8e38a217f8605cb0bdc75cf48da41c2237c9ec479d3e571b828629a0683c885"},
			{0, "setup/replay", 16, "a91ad345b318c5fade8f9b753b484c2e"},
			{0, "counter/fwd", 8, "5bdc9f320a581f9d"},
			{0, "counter/bwd", 8, "c0745a8762bbd942"},
			{1, "link/i2r", 32, "456d332a3c5d790b2f204d9470ffa5e478680913a59a246d5ca10abe37d15da4"},
			{1, "link/r2i", 32, "5afbc3ca7108d67951bab867139b78d9db283d00a7b8e61fdf80897067ac70ed"},
			{2, "link/i2r", 32, "7c3d311a20dfe55f3b1ac596a18cdec59daf83cf5d90dd7831c6204887cddc8f"},
			{2, "link/r2i", 32, "f339ccb189810853e16130ff3c0cdf7caf0209dcff9c78a82d6d716ed163a0bb"},
			{3, "setup", 32, "046a0567cda9fbc0126de5b10f515d7b0b9c62876c3eaa02532f34ab2599a888"},
			{3, "cell", 32, "2204363eb5c2b04ae91f46cfa71343babfa9fa1c4c0683eca43dbf4e102e0046"},
			{3, "setup/replay", 16, "8d794dcc9e796c57cdd5d68b7ca4dc2c"},
			{3, "counter/fwd", 8, "fa24c2e6990665f2"},
			{3, "counter/bwd", 8, "f6ca6ef42dae9b09"},
			{4, "link/i2r", 32, "921feb1700aaf54a43d61778e02ef58838f20ce387e635f7df69478f8da7766c"},
			{4, "link/r2i", 32, "9ca621f67bb3f1e9f5decebbc1e7b8c6fabcf16a5a85baa9e873cdfc4ce287c4"},
		},
		mix: [2]string{
			"afb0cba8f71ea59fc429db92ef6b09db684d2b4287136e84c1cd8b68316362aa",
			"8eb7f7bd81d2df19d759a0630d43ce3f61737815b574312b77bad9f2553c42f7",
		},
		// the keys of RFC 7748, 6.1, whose shared secret
		// Z = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
		// is published there, so no curve arithmetic is needed to recompute:
		// PRK = HMAC-SHA256(th, Z) =
		// 3e072338d211eb117a12d300b092c1d8b111e8cdb5ee100e02971c8feb5637e1
		agree: goldenAgree{
			privA:    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			pubA:     "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
			privB:    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
			pubB:     "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
			th:       "9a36822448c9656a7090ab79e3cc8b4d8b1acdf009a936970f883b852456625d",
			secret:   "0aad4e69e20b355b496adc24bc7c26ec1804a55b6df48c5af7771bb12b89f7d2",
			setupKey: "cf9dfbd0cfec9ab8a8ef01637d50d7eb8b3d927ccb2707baa589d55589f1412c",
		},
	},
	jcrypto.SuiteGOST: {
		pubSize: 64,
		idSize:  64,
		th: [5]string{
			"c4aff7e929db19a4171ed91d841bfe6ce2658d957a5fa5dc80ef69a76cae1080",
			"95d4af2336fd54e2bbcfbc13378c70c73107c3065996119a68aba055bcda8d76",
			"bafb88554bdd02d048d3d96a04233f38bedf2fdac0d69b1550dbf9ff5ead0d1a",
			"d7117c1346e610f6d636fed3a24a065a1ff72ada68631ad72a1bc2970cfdd646",
			"9e660f347729b9614cb118a0fbc0135beed6faecab74a0e0974c185049c8c5af",
		},
		derive: []goldenDerive{
			{0, "setup", 32, "8cb409e5dbc6ba5f515608fe4d84c235192992c3651f60e06ffd9c17b56de770"},
			{0, "cell", 32, "b0a575c9e02e28d89c4e55d04154bba2d1e2d194e8ace4a67a502ee0642b9890"},
			{0, "setup/replay", 16, "fe55f2aeb817f4121303e4a73e28387a"},
			{0, "counter/fwd", 8, "95a2d1cbcee19679"},
			{0, "counter/bwd", 8, "1235e4fa8c36603b"},
			{1, "link/i2r", 32, "9931e37dc573ede34bd3ad27c3106b7080f569ec55acaa223a24b6eb815a994f"},
			{1, "link/r2i", 32, "3df6c1576cda7f124b8695f706aeec28aed12509211b6418ebbceaaf58b396f0"},
			{2, "link/i2r", 32, "0d0b7044a27f118c322897659557627b3f04324c156422ced3283e8a0c3f5c10"},
			{2, "link/r2i", 32, "c90610d21c71acf2f1b7745e8dac22938128744c81069609423ad42e052d3e45"},
			{3, "setup", 32, "461de0c5c0903f5b8a80aa8750e825bbf2d1314e8f87859e608175cc4507a092"},
			{3, "cell", 32, "96c4f0df39cc40d21c65bd26133261e7be8318fbe2e9fbcb8a6ad422ed58ade2"},
			{3, "setup/replay", 16, "3962cc9064affa479f1d8152a1888239"},
			{3, "counter/fwd", 8, "21e06998e88f5a34"},
			{3, "counter/bwd", 8, "eeee7d74a91ab022"},
			{4, "link/i2r", 32, "67e7e5e5ff3071cf929f5301222d687f204c05936ae1eefc59c2bd021341e4bd"},
			{4, "link/r2i", 32, "6b1941655ac88a53101e939b3d971f8b092d79b98b3a0ccf007fdeaab381ccf8"},
		},
		mix: [2]string{
			"c0135e5bc83af1586c67367eda0e249e6c0a45e30e2259da474ed7d6939f87ba",
			"cf2f4b9dc41a6ffc371f61629ca322f056cc63efe79eb56af57cc7bb25d9e1e6",
		},
		// private keys 01..20 and 11..30 as little-endian scalars, both below q;
		// UKM = d45eab779d45b756 (th[0:8]),
		// KEK = db1d15909ad1f826e3b9d90415c62109049c866ca16527b1f948d6717da94a5d;
		// after the KEK everything is one HMAC
		agree: goldenAgree{
			privA: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			pubA: "000ad8811b8280e56a2c9b37b7170a3de04039df9151482097e3cc0669ecb7a0" +
				"623f29508cc68b124c3d15a4e2a26e3e71dc391fb2c62d558071878e6814f9a3",
			privB: "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
			pubB: "b6749ce1d202dd4550a1ad7a8797e16e47cfdb0a0b446465e447f56abb4dae1b" +
				"43cad001b96e51d4f10df16549327c9eea30e0a74adf0ce5a01c5934ec52edc6",
			th:       "d45eab779d45b756ba089fbd37b460605cce1d0134ffd35a427c890a0534cfab",
			secret:   "b74c9d0d1d398c730511412f208be70a2af2b00a6b805f2b80161dc965e41735",
			setupKey: "e862ff81e89e89d1d98c392bcfe08cdab52de9de8506d8ef01fbe2110408dfff",
		},
	},
}

func goldenFor(t *testing.T, p jcrypto.CryptoProvider) goldenSuite {
	t.Helper()
	g, ok := golden[p.Suite()]
	if !ok {
		t.Fatalf("no golden vectors listed for suite %v", p.Suite())
	}
	return g
}

func goldenContexts(t *testing.T, p jcrypto.CryptoProvider) [5]jcrypto.Context {
	t.Helper()
	g := goldenFor(t, p)
	n, id := g.pubSize, seq(0xc0, g.idSize)
	return [5]jcrypto.Context{
		mustContext(t, p, "setup", []byte{0x02}, []byte{0x00}, []byte{0, 0, 0, 0, 0, 0, 0, 200}, seq(0x80, n), seq(0x00, n)),
		mustContext(t, p, "link", []byte{0x02}, []byte{0x01}, seq(0x00, n), seq(0x40, n), seq(0x80, n)),
		mustContext(t, p, "link", []byte{0x02}, []byte{0x00}, seq(0x00, n), seq(0x40, n)),
		mustContext(t, p, "setup", []byte{0x02}, []byte{0x00}, []byte{0, 0, 0, 0, 0, 0, 0, 200}, seq(0x80, n), seq(0x00, n), id),
		mustContext(t, p, "link", []byte{0x02}, []byte{0x01}, seq(0x00, n), seq(0x40, n), seq(0x80, n), id),
	}
}

func testGoldenTranscript(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p)
	priv, pub := mustEphemeral(t, p)
	priv.Release()
	if len(pub) != g.pubSize {
		t.Fatalf("public key of %d bytes, the vectors assume %d", len(pub), g.pubSize)
	}
	signing, identity, err := p.GenerateSigning()
	if err != nil {
		t.Fatalf("GenerateSigning: %v", err)
	}
	signing.Release()
	if len(identity) != g.idSize {
		t.Fatalf("identity key of %d bytes, the vectors assume %d", len(identity), g.idSize)
	}
	for i, ctx := range goldenContexts(t, p) {
		if got := hex.EncodeToString(ctx.Sum()); got != g.th[i] {
			t.Fatalf("th(G%d) = %s, want %s", i+1, got, g.th[i])
		}
	}
}

func testGoldenDeriveKey(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p)
	ctxs := goldenContexts(t, p)
	k := fixedSecret(t, 0x40, 32)
	defer k.Release()
	for _, d := range g.derive {
		got := hex.EncodeToString(mustDerive(t, p, k, d.purpose, ctxs[d.ctx], d.size))
		if got != d.want {
			t.Fatalf("DeriveKey(K, %s, G%d, %d) = %s, want %s", d.purpose, d.ctx+1, d.size, got, d.want)
		}
	}
}

func testGoldenMixKey(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p)
	chain := fixedSecret(t, 0x40, 32)
	defer chain.Release()
	secret := fixedSecret(t, 0x60, 32)
	defer secret.Release()
	ctxs := goldenContexts(t, p)
	for i, ctx := range []int{1, 4} {
		got := hex.EncodeToString(mustMix(t, p, chain, secret, ctxs[ctx]))
		if got != g.mix[i] {
			t.Fatalf("MixKey(K, 60..7f, G%d) = %s, want %s", ctx+1, got, g.mix[i])
		}
	}
}

func testGoldenAgree(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p).agree
	pubA, pubB := unhex(t, g.pubA), unhex(t, g.pubB)
	ctx := mustContext(t, p, "setup", []byte{0x02}, []byte{0x00}, []byte{0, 0, 0, 0, 0, 0, 0, 200}, pubB, pubA)
	if got := hex.EncodeToString(ctx.Sum()); got != g.th {
		t.Fatalf("th = %s, want %s", got, g.th)
	}

	for _, side := range []struct {
		name string
		priv string
		pub  []byte
	}{
		{"Agree(a, B)", g.privA, pubB},
		{"Agree(b, A)", g.privB, pubA},
	} {
		priv, err := secmem.NewFrom(unhex(t, side.priv))
		if err != nil {
			t.Fatal(err)
		}
		secret, err := p.Agree(priv, side.pub, ctx)
		priv.Release()
		if err != nil {
			t.Fatalf("%s: %v", side.name, err)
		}
		if got := hex.EncodeToString(secret.Bytes()); got != g.secret {
			secret.Release()
			t.Fatalf("%s = %s, want %s", side.name, got, g.secret)
		}
		got := hex.EncodeToString(mustDerive(t, p, secret, "setup", ctx, 32))
		secret.Release()
		if got != g.setupKey {
			t.Fatalf("DeriveKey(%s, setup) = %s, want %s", side.name, got, g.setupKey)
		}
	}
}

// reports the other suite, so a context built through it carries a suite the
// provider under test must refuse
type otherSuite struct{ jcrypto.CryptoProvider }

func (o otherSuite) Suite() jcrypto.Suite {
	if o.CryptoProvider.Suite() == jcrypto.SuiteGOST {
		return jcrypto.SuiteC25519
	}
	return jcrypto.SuiteGOST
}

func foreignContext(t *testing.T, p jcrypto.CryptoProvider) jcrypto.Context {
	t.Helper()
	return mustContext(t, otherSuite{p}, "test", []byte("session-1"))
}

func mustContext(t *testing.T, p jcrypto.CryptoProvider, exchange string, parts ...[]byte) jcrypto.Context {
	t.Helper()
	ctx, err := jcrypto.NewContext(p, exchange, parts...)
	if err != nil {
		t.Fatalf("NewContext(%s): %v", exchange, err)
	}
	return ctx
}

func mustDerive(t *testing.T, p jcrypto.CryptoProvider, secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) []byte {
	t.Helper()
	key, err := p.DeriveKey(secret, purpose, ctx, size)
	if err != nil {
		t.Fatalf("DeriveKey(%s, %d): %v", purpose, size, err)
	}
	defer key.Release()
	return bytes.Clone(key.Bytes())
}

func mustMix(t *testing.T, p jcrypto.CryptoProvider, chain, secret *secmem.Buffer, ctx jcrypto.Context) []byte {
	t.Helper()
	key, err := p.MixKey(chain, secret, ctx)
	if err != nil {
		t.Fatalf("MixKey: %v", err)
	}
	defer key.Release()
	return bytes.Clone(key.Bytes())
}

func fixedSecret(t *testing.T, first byte, n int) *secmem.Buffer {
	t.Helper()
	b, err := secmem.NewFrom(seq(first, n))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func drop(b *secmem.Buffer) {
	if b != nil {
		b.Release()
	}
}

func seq(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

func clone(parts [][]byte) [][]byte {
	out := make([][]byte, len(parts))
	for i := range parts {
		out[i] = bytes.Clone(parts[i])
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
