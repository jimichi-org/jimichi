package e2e

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/wire"
)

// Full KK and the first records, both suites. Inputs: the static keys, e_I and
// e_R below, F_I = c0..cf, F_R = d0..df, mailbox relay-5.jimichi.svc.cluster.
// local:9000, zero handshake payloads, the body "hello" with flags 0.
//
//	T  = "jimichi/v2/<suite>/transcript/<exchange>" || 00 || u8(n) || n times (u16be(len) || part)
//	Q        = Hash(T(mailbox/queue, F))[0:16]
//	card     = 01 | suite | 26 | mailbox | Q | S
//	h0       = Hash(T(noise/e2e/kk, 01, card_I, card_R)); MixHash(S_I), MixHash(S_R)
//	MixHash  h = Hash(T(noise/hash, h, d))
//	kk1      MixHash(01), MixHash(E_I), es and ss under Hash(T(noise/dh, h, 04)) and
//	         (.., 06), ck = MixKey(es, ss), k1 = DeriveKey(ck, noise/key, Hash(T(noise/key, h))),
//	         c1 = AEAD(k1, nonce 0, zeroes, ad h), MixHash(c1); record 01 | E_I | c1
//	kk2      MixHash(02), MixHash(E_R), ee (03) and se (05) mixed into ck in turn,
//	         k2 and c2 as above; record 02 | E_R | c2
//	split    SID = h; i2r, r2i = DeriveKey(ck, noise/split/i2r|r2i, Hash(T(noise/split, h)))
//	step n   ctx = T(e2e/step, SID, d, u32be(n)); mk = DeriveKey(ck, e2e/step/key, ctx),
//	         ck' = DeriveKey(ck, e2e/step/next, ctx)
//	record   03 | u32be(n) | AEAD(mk, nonce 0, flags | u16be(len) | body | zeroes to 371, ad 03 | u32be(n))
//
// How to recompute without this code: c25519 Hash is sha256sum; Agree is
// HMAC(HMAC(key th, Z), label(agree) | 00 | th | 01) with Z = X25519 (for ss the
// Z of RFC 7748, 6.1); MixKey is HMAC(HMAC(key chain, secret), label(mix) | 00 |
// th | 01); DeriveKey is HMAC(secret, label | 00 | th | 01)[:size]; the AEAD is
// XChaCha20-Poly1305: subkey HChaCha20(k, 0^16), then ChaCha20-Poly1305 with
// nonce 0^12. GOST: the formulas next to the golden vectors of
// crypto/providertest (Streebog in the byte order of RFC 6986,
// KDF_GOSTR3411_2012_256, VKO with UKM = th[0:8]) and Kuznyechik-MGM with nonce
// 0^16.
//
// The c25519 values come from a Python implementation (hashlib, hmac, X25519
// and ChaCha20-Poly1305 from the cryptography package, HChaCha20 written out)
// that first reproduced every c25519 golden vector of providertest and the
// HChaCha20 example of draft-irtf-cfrg-xchacha-03, 2.2.1. The GOST values come
// from a composition harness over the providers of this module that reproduced
// every c25519 value of the Python one byte for byte; each GOST primitive is
// held by a standard example in crypto/gost and providertest. The KEK of each
// GOST agreement, for whoever recomputes VKO: es 7f7d0775.., ss c839e7ad..,
// ee a5846aae.., se 14e803b4...
type e2eVector struct {
	suite                  jcrypto.Suite
	sI, SI, sR, SR         string
	eI, EI, eR, ER         string
	queue0                 string
	qI, qR                 string
	cardHashI, cardHashR   string
	h0, hPre, hKind1, hE1  string
	es, ss, ck1, k1        string
	hKK1, hashKK1          string
	hE2, ee, se, ck2, k2   string
	hashKK2, sid, i2r, r2i string
	mk0I, ck1I, dataI      string
	mk0R, dataR, dummyI    string
	// mk_1..mk_3 of i2r and the record n = 3 with the body "hello"
	mkI   []string
	data3 string
	// GOST only: th[0:8] of the context of each DH token
	ukm []string
}

var e2eVectors = []e2eVector{
	{
		suite:     jcrypto.SuiteC25519,
		sI:        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
		SI:        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
		sR:        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
		SR:        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
		eI:        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		EI:        "d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66",
		eR:        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		ER:        "34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847",
		queue0:    "069cdb04a5dd31eb20f345b4a3c404f1",
		qI:        "1b76bac7bbf4ab62e913962b3ae233c1",
		qR:        "2bb76210f9e763355d2e7ceb5d405651",
		cardHashI: "f74f1d9262641938452a6c904f336237c83804d8db698a7cd54448d24a5ce293",
		cardHashR: "ca0098fbb33562ca5e68670fc7c68e9be483598671b9295ddc5bcbe60ce0354b",
		h0:        "a817a1d6182735a5ea59c89b6c004b96cd4959f6c80336519d734aa6420a6ea1",
		hPre:      "3cda4ca4d3228e328750a2aa1ae6544a3474a6fdb5329f84e78f22f37d8e0abb",
		hKind1:    "480275d06fd08bf554f4a9bfa8cdf519a8bdb549569f04d34f8835d2280c2e0f",
		hE1:       "059d479a71530676007b61d296449c02f5f8696ffa20c6ec0f1f606ed2fc703f",
		es:        "6a319471c6775cd93edaa9c6698b608d1e921b79ebc38ba336dc435a54577063",
		ss:        "61d68071d1006b18883e1338e7ca3aa7910e0e51a44cb502332ecb108a747244",
		ck1:       "f5b737e5f28c3fe6859fc2265539dfaf596cc60e111e1fda8a4690682163ded0",
		k1:        "1365b2d4c5c7e24d39c77682aa2ac882aaa97acdea931756e168e7f7cfd4d788",
		hKK1:      "8835c77861a785377ae0fafa5a6f6d4ce706c48b4f79fb9fc20b0a35831bf8a3",
		hashKK1:   "4cb85b369c9359ee95f5c4364ffc60f2709e15da84bf0f37add3a9271a9cd1ec",
		hE2:       "ca6268a656416b56f23026545b9321e6a6ccef638fc5c7cf9d1ef1237806cbef",
		ee:        "15a3f44aae16b038d4619dbdd7e943eec60ee589ce6e46ce9947e3ccc10208ea",
		se:        "2ccfeafe187281f157a1d204148d788efeca254ebe12eef73978790da2b29e98",
		ck2:       "6e99795cac9a2c71e1ae0657b402d4d93297b4343688dbc5bfbf8f22d78a15c4",
		k2:        "16aa15a8472fd1b5263a76395a76ead6523d0483492cfa2d4aa79ebdb5d60bf8",
		hashKK2:   "ec571492cfdd33881c728333790b4bd3e70b0931df797648d75f69b2bbfe473d",
		sid:       "7ed5c612162b432daf6426fa3d4a820c4f5edab007b23e451b4c21953bbdb071",
		i2r:       "727d332473e962fcc4ccf3f34a4710931857bc56acabef3a3da9f09451945077",
		r2i:       "27538a8958b44078934443a937f9933f19555b6360f9b24173c21ceefa25d5ef",
		mk0I:      "9249361e8b7d15054cbcace09e9763dc29531696cdb3700939a238c20627b1b2",
		ck1I:      "3756565956d5691538431491be104b5a0175cfe6116abc3d4cf099515001392c",
		dataI:     "971d4058a2679603a477549b2e684b8caf337e86e4bd28d62dd873e32e39c6cd",
		mk0R:      "5ff685ec0ca224ad438bb0c9c159be9c429f4641ebab5541313f67feab680395",
		dataR:     "afc04ee06b15ab7728e468b1a3d19ad5dfb9827e8d452a6729663168075d388a",
		dummyI:    "c96c48a947182f9efe65bd86a172b872f3235ecd42c468fb40f9108979f04206",
		mkI: []string{
			"4192eb345bb6c3fc356cf21f479f45aad979e93d24eed89f4d4e44dc95ecb9eb",
			"647c2a00fed555045ece00d92c35f671926f79be16d07f084caacaebf3140bae",
			"ffaff3d174c90c7ed6eb05b9626a283ca142eeda8562a649b0425aa65541379e",
		},
		data3: "ef79d5014616a4f4e9ab623ff99dd72d80526e9133d81addccea2d99ae2a6079",
	},
	{
		suite: jcrypto.SuiteGOST,
		sI:    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		SI: "000ad8811b8280e56a2c9b37b7170a3de04039df9151482097e3cc0669ecb7a0" +
			"623f29508cc68b124c3d15a4e2a26e3e71dc391fb2c62d558071878e6814f9a3",
		sR: "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
		SR: "b6749ce1d202dd4550a1ad7a8797e16e47cfdb0a0b446465e447f56abb4dae1b" +
			"43cad001b96e51d4f10df16549327c9eea30e0a74adf0ce5a01c5934ec52edc6",
		eI: "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
		EI: "53ddc6829b4cfc4049e8f4d6cac5b8824f0edcd3c14b5bd9a5ffa90e5e5ec868" +
			"fdcfa3dad8e37799a07ab5bcc646eb17cc69ed2753a4e5bd644300f0344e2053",
		eR: "12131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
		ER: "21e1563b5d5cd461ac52f42c9e84a1209ca6249301fb660047478298cb59847a" +
			"9b63caa62ac3e95124f43ce1c2f0ad056f589dcb0007679d5edd08e8520348d3",
		queue0:    "f0cac9c3b1105dc46c814d8db9af8d04",
		qI:        "43611fb8fd90df8a0e1e036177d0a24a",
		qR:        "68a5779ba1e5a07385e74bd9fa049055",
		cardHashI: "644a67e8f423a437c9cfe491cac7acd682d4ccd286777fefb9ae04a3d3cbb72d",
		cardHashR: "d5f7b34d623e3c44812a8e4ad7cceb2f57450d2f41d704bfe27c8a667ab5ba90",
		h0:        "de3790ff8c5561cce90c0ddbdde3382ac6e0b519db78ee56fc620d7f38874748",
		hPre:      "3911c346cec21021bac8aeca5b293dd21955bfd373ae907c9332a8953462df19",
		hKind1:    "9e9e33e5425e0cc3ebb3bebf309cfc6ab2b0c70d0bc405b42126c75c7ba660f4",
		hE1:       "49b36e4ce2d67c9d450f514d8018d629d906aa4e147d9dfdda2d6d583cf0d724",
		es:        "1c92b08958eb6c218e8e12d1824da7613d04cd6c096b58cc86f12beaa010f033",
		ss:        "7f6c9fa54124a3bd835fe650af9344882326e1033e1865547588c18f9074179e",
		ck1:       "802f63be870c9756048c10c71cef88c326d6cdb96f8761c201ee1f6dd840c926",
		k1:        "9f30a8d54e1d7b99c8d9524a3361ef1864b1a3d4a6393e9bccc5f2e280c54fb9",
		hKK1:      "728ee11dabbcd6063072c9fa0e50e82140f83afd7c2b93cbf55d5e1dc667e88c",
		hashKK1:   "f2ef61d932ede7c06faf6815165dc2d7d890e321f9116a6fd973aca3512b5c4e",
		hE2:       "20858267f35018578c90555289c9a590de087ae715825e1d405be6cec5ae001f",
		ee:        "3b0ed220e8bcca96d3ccfae946c8ca3d70b3c5f0d093c2aa4764e13f78009081",
		se:        "228a7903ade3dd7541335077dd15f2faa6e5d3450c8ecea55cd4f2dca28abe0d",
		ck2:       "66e0a7433ff42029034b029b7819229d7f1648dbff9f74f12600186b62129a1b",
		k2:        "f99b4a7bdf2fb0a0bd5719cb6faa9eb5aa5167542e1c04cafefbc485c83a59da",
		hashKK2:   "21ea722b084360498b89c77750530b574ee7261e0c7e619d9d1d9e1fde2fde65",
		sid:       "e76c7613a16acc2311d1c94a13dbe2e5def2923649beaec3f075cd331b7f4c96",
		i2r:       "0627700425ddd0e03c6ff7ca1770f1b7ac2e14efc716f783476822e5f9995dd8",
		r2i:       "e63eb7d326e264a65f53e359a561caba0151b03db17b9a0cc938514e476c9145",
		mk0I:      "d547da9e4c95b1933e8ed25327276dde521b0854177b4cd59af371a43cc78632",
		ck1I:      "fd4586335f1af03d58c5a901d3984e2a16b164c344792a9e90e474f5b5cfe656",
		dataI:     "a80522c14f601cc9a1e05fe0fee736097c39a2c7cf6ed6b7ae03f677bc3650ba",
		mk0R:      "a5387c37a9172ab4dc33bb8d12d68eec14b49382d31b2a65c62e04f89dd9ee7b",
		dataR:     "e57ddbd6672584c0b493b20a418540420ac6a7c53c440bf4bba2200b75bdab86",
		dummyI:    "41a370b92daccf577a987e4f927d11933397b35fd375c2c43534f15c1f3852cb",
		mkI: []string{
			"ba20d76ba46db5cf3e99b7a72b132b192c4ddbc3689cf5aef7de96907523c9ba",
			"d42fba82494bc853d61ac5a4c7198bde96f6e4690620889567ea136f46c01ed2",
			"c953a7fc202cbd2eaaf37e4879406877a0b7fcc8183886189d15a8e51664e893",
		},
		data3: "7e13ea02d6a0ab244d22fff3724013d353f7dafbd2228ff8b4d8ff075b2c3052",
		ukm:   []string{"ae5f80cf5ffbba5f", "966b79ddea83d676", "ef8d58f4fd7e2523", "cfb1ee753881644e"},
	},
}

// hands out the listed ephemeral keys in order, an empty one passing the call
// to the provider underneath: the session's key check draws first
type fixedEphemeral struct {
	jcrypto.CryptoProvider
	t    *testing.T
	keys [][2]string
}

func (f *fixedEphemeral) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	if len(f.keys) == 0 {
		f.t.Fatal("no fixed ephemeral key left")
	}
	k := f.keys[0]
	f.keys = f.keys[1:]
	if k[0] == "" {
		return f.CryptoProvider.GenerateEphemeral()
	}
	priv, err := secmem.NewFrom(unhexT(f.t, k[0]))
	if err != nil {
		return nil, nil, err
	}
	return priv, unhexT(f.t, k[1]), nil
}

func unhexT(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type vectorSide struct {
	tp *trackingProvider
	id *Identity
	s  *Session
}

func queueOf(t *testing.T, p jcrypto.CryptoProvider, f []byte) [QueueSize]byte {
	t.Helper()
	ctx, err := jcrypto.NewContext(p, "mailbox/queue", f)
	if err != nil {
		t.Fatal(err)
	}
	var q [QueueSize]byte
	copy(q[:], ctx.Sum())
	return q
}

func vectorSession(t *testing.T, p jcrypto.CryptoProvider, v e2eVector, initiator bool) vectorSide {
	t.Helper()
	priv, pub, eph, ephPub, peerPub, f, peerF := v.sI, v.SI, v.eI, v.EI, v.SR, seqBytes(0xc0, 16), seqBytes(0xd0, 16)
	if !initiator {
		priv, pub, eph, ephPub, peerPub, f, peerF = v.sR, v.SR, v.eR, v.ER, v.SI, peerF, f
	}
	tp := track(&fixedEphemeral{CryptoProvider: p, t: t, keys: [][2]string{{}, {eph, ephPub}}})
	b, err := secmem.NewFrom(unhexT(t, priv))
	if err != nil {
		t.Fatal(err)
	}
	kp := noise.NewKeyPair(tp, b, unhexT(t, pub))
	t.Cleanup(kp.Close)
	own := Card{Suite: v.suite, Mailbox: testMailbox, Queue: queueOf(t, p, f), Static: unhexT(t, pub)}
	peer := Card{Suite: v.suite, Mailbox: testMailbox, Queue: queueOf(t, p, peerF), Static: unhexT(t, peerPub)}
	id, err := NewIdentityFrom(tp, kp, own)
	if err != nil {
		t.Fatal(err)
	}
	return vectorSide{tp: tp, id: id, s: newSession(t, tp, id, peer, Options{})}
}

func seqBytes(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

func checkHex(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if h := hex.EncodeToString(got); h != want {
		t.Fatalf("%s = %s, want %s", what, h, want)
	}
}

func TestVectors(t *testing.T) {
	for _, v := range e2eVectors {
		t.Run(v.suite.String(), func(t *testing.T) {
			base, err := suite.New(v.suite)
			if err != nil {
				t.Fatal(err)
			}
			p := noSigning{CryptoProvider: base, t: t}
			// the size probe of wire draws an ephemeral key once per suite; it
			// must not take one of the fixed keys
			if _, err := wire.PublicKeySize(p); err != nil {
				t.Fatal(err)
			}
			q0 := queueOf(t, p, seqBytes(0, 16))
			checkHex(t, "QueueID(00..0f)", q0[:], v.queue0)

			ini, resp := vectorSession(t, p, v, true), vectorSession(t, p, v, false)
			cardI, cardR := ini.id.Card(), resp.id.Card()
			checkHex(t, "Q_I", cardI.Queue[:], v.qI)
			checkHex(t, "Q_R", cardR.Queue[:], v.qR)
			if raw := cardI.Bytes(); len(raw) != map[jcrypto.Suite]int{jcrypto.SuiteC25519: 89, jcrypto.SuiteGOST: 121}[v.suite] ||
				!bytes.Equal(raw[:3], []byte{1, byte(v.suite), 38}) {
				t.Fatalf("card_I %x", raw)
			}
			hI, _ := CardHash(p, cardI)
			hR, _ := CardHash(p, cardR)
			checkHex(t, "card_hash_I", hI, v.cardHashI)
			checkHex(t, "card_hash_R", hR, v.cardHashR)
			if ini.s.Role() != RoleInitiator || resp.s.Role() != RoleResponder {
				t.Fatal("the smaller key is not the initiator")
			}

			kk1 := mustHandshake(t, ini.s)
			checkHex(t, "E_I", kk1[1:1+len(v.EI)/2], v.EI)
			checkHex(t, "Hash(kk1)", p.Hash(kk1), v.hashKK1)
			ini.s.Stored(kk1)
			mustReceive(t, resp.s, kk1, EventSession)
			kk2 := mustHandshake(t, resp.s)
			checkHex(t, "E_R", kk2[1:1+len(v.ER)/2], v.ER)
			checkHex(t, "Hash(kk2)", p.Hash(kk2), v.hashKK2)
			mustReceive(t, ini.s, kk2, EventSession)

			for _, side := range []struct {
				name string
				vs   vectorSide
			}{{"initiator", ini}, {"responder", resp}} {
				checkHex(t, side.name+" SID", side.vs.s.sid, v.sid)
				// the transcript hashes are outputs of Hash, the secrets outputs of
				// Agree, MixKey and DeriveKey; both sides reach every one of them
				for _, h := range []struct{ name, want string }{
					{"h0", v.h0}, {"h after S_I, S_R", v.hPre}, {"h after kind 01", v.hKind1},
					{"h after E_I", v.hE1}, {"h after kk1", v.hKK1}, {"h after kind 02 and E_R", v.hE2},
				} {
					if !side.vs.tp.hashes[h.want] {
						t.Fatalf("%s: %s %s never computed", side.name, h.name, h.want)
					}
				}
				for _, k := range []struct{ name, want string }{
					{"es", v.es}, {"ss", v.ss}, {"ck1", v.ck1}, {"k1", v.k1}, {"ee", v.ee}, {"se", v.se},
					{"ck2", v.ck2}, {"k2", v.k2}, {"i2r", v.i2r}, {"r2i", v.r2i},
				} {
					if !side.vs.tp.keys[k.want] {
						t.Fatalf("%s: %s %s never derived", side.name, k.name, k.want)
					}
				}
				for _, u := range v.ukm {
					found := false
					for h := range side.vs.tp.hashes {
						found = found || strings.HasPrefix(h, u)
					}
					if !found {
						t.Fatalf("%s: no DH context starts with the UKM %s", side.name, u)
					}
				}
			}

			data := mustSeal(t, ini.s, "hello")
			checkHex(t, "Hash(data i2r n=0)", p.Hash(data), v.dataI)
			if ev := mustReceive(t, resp.s, data, EventMessage); string(ev.Body) != "hello" {
				t.Fatalf("body %q", ev.Body)
			}
			reply := mustSeal(t, resp.s, "hello")
			checkHex(t, "Hash(data r2i n=0)", p.Hash(reply), v.dataR)
			mustReceive(t, ini.s, reply, EventMessage)
			for _, k := range []struct {
				name, want string
				tp         *trackingProvider
			}{
				{"mk_0 i2r", v.mk0I, ini.tp}, {"ck_1 i2r", v.ck1I, ini.tp}, {"mk_0 i2r", v.mk0I, resp.tp},
				{"mk_0 r2i", v.mk0R, resp.tp}, {"mk_0 r2i", v.mk0R, ini.tp},
			} {
				if !k.tp.keys[k.want] {
					t.Fatalf("%s %s never derived", k.name, k.want)
				}
			}

			// the chain steps on from ck_1: three more records of i2r
			var last []byte
			for range 3 {
				last = mustSeal(t, ini.s, "hello")
				mustReceive(t, resp.s, last, EventMessage)
			}
			checkHex(t, "Hash(data i2r n=3)", p.Hash(last), v.data3)
			for i, want := range v.mkI {
				for _, side := range []vectorSide{ini, resp} {
					if !side.tp.keys[want] {
						t.Fatalf("mk_%d i2r %s never derived", i+1, want)
					}
				}
			}

			// the same inputs once more: the first record a dummy
			again, other := vectorSession(t, p, v, true), vectorSession(t, p, v, false)
			first := mustHandshake(t, again.s)
			mustReceive(t, other.s, first, EventSession)
			mustReceive(t, again.s, mustHandshake(t, other.s), EventSession)
			checkHex(t, "Hash(dummy i2r n=0)", p.Hash(sealDummy(t, again.s)), v.dummyI)
		})
	}
}
