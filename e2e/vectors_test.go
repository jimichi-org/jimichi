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
//	T  = "jimichi/v1/<suite>/transcript/<exchange>" || 00 || u8(n) || n times (u16be(len) || part)
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
// that first reproduced th(G1), the setup key and MixKey of providertest and the
// HChaCha20 example of draft-irtf-cfrg-xchacha-03, 2.2.1. The GOST values come
// from a composition harness over the providers of this module that reproduced
// every c25519 value of the Python one byte for byte; each GOST primitive is
// held by a standard example in crypto/gost and providertest. The KEK of each
// GOST agreement, for whoever recomputes VKO: es fb45561a.., ss 65306011..,
// ee 4c82b572.., se 1be307e8...
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
		queue0:    "c1bb8b397fabfb45cddcc6a5420ee110",
		qI:        "4271d9a52bde0983787e4ad2e3796413",
		qR:        "3972fefed5c3c4e10c22d9b8f524d6d8",
		cardHashI: "8e71760eeadd83bf6d79d524231e4171a8134b6aa6263b6f814f4034758cd5df",
		cardHashR: "47d6a4561787ff8c5f611d26861dc03a4168d1dd26101cb389672d06b4060eb8",
		h0:        "9c2e1c228d68902d2550e75df6c09b71720b60ec87f1d9bc543d5a997380538e",
		hPre:      "f0b074283cc7d36a322da64e6f94072b4b898dc25f09ce948fe8f119ecac0965",
		hKind1:    "ee1a87e277a0a512720bfd1f0f71f19456fbcb7029f0bf8e361e8e9401f16288",
		hE1:       "146e3310c1e9a11168b8bbb3c6912f51f08dc1f4dd44860404222dcc5448a6eb",
		es:        "1bd863dae7f8143618a30fb11a573b34fb51a1936c693d9ad682a37e688b1aa2",
		ss:        "8df642b076715f0b96a9537b965206116a6719cff5d4b749f7b1e2d51d7c954f",
		ck1:       "10bcf16ed896388a580c8938abc68ad04a8762da13af0ec1977e5cc006b1fce7",
		k1:        "089f5e1d540122a3aef5b27c798236d996c8bcbe63ae66cd9a6a57fe0b27d17e",
		hKK1:      "3b1e717ced49ede85e3081e64b360816e5b822cf64fe1b2b110afcd2b42b5835",
		hashKK1:   "4cd5085271325cff181f5c6073c6834d93010a0d4916b574453eec3e0f867f37",
		hE2:       "d120f7363992313c1ca59560322f5194f7bed512f9b54cb857d6586bc96bbf8e",
		ee:        "257203dd39e269b95d6f9916d50e2c5a31104cfbe87d153e78bf9256d906bf60",
		se:        "2191c7634c5b6de4044ca7da66b639b5bf0c6aee79c205a5dd37ee58d08d7983",
		ck2:       "5e7c06b27165ce755c22111d46db3c47b9a1bd800cf0d7cba5ef9f9ed0f65b41",
		k2:        "3667bfdf02c9901c2d7a3a3b326e0949c862eff8d1bf4a2ad83fc077db3741fd",
		hashKK2:   "9863a605538fd0d89bd7c8b8fc6f9e37f243099cde64b115b1a19bdeb4bc2bf5",
		sid:       "2b1f5ed3bf8835d02f8bbca7a82e3379d62170a19d2eb1f509b358027f56ed81",
		i2r:       "e4821a139f782cee9e3aecc301057c81b8a362fe4f74f6d5abbc771b26ad06f4",
		r2i:       "974ddf12cfa3deca66d73beaba397fad452e28e19b96722e332f8030d44eddf2",
		mk0I:      "490c9f56ae649d7f683bed4321a8ef1a9ff0ea5de5527814944b4a20ab464e8c",
		ck1I:      "e01490aa0c884dc3f0b384b918752a5a750c197eba58a1bfe5e940201f355cf9",
		dataI:     "f3820fa7b914c06059f31174ec307e41a0d56aab7819349658cddf57fb67e7d6",
		mk0R:      "3a96e87298f4fd11be764e4ed4c64067b1779a6e9a2be2a7918ba5fd7236da62",
		dataR:     "13c6d0cbdcc12a686252779575222fd6c8d8a647465bdad586802249b8c6d1b8",
		dummyI:    "312781c083588851255aa62d8b145c630b4ba3c7f444404a444db32d0ee9c998",
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
		queue0:    "c189467dc2f1dd011e48719b61c01eef",
		qI:        "2669ab3d5bb9f59f14a01b6c00172f2a",
		qR:        "ca6d05e3d7fd0cf58c593fa0c9564653",
		cardHashI: "a2ab7062b8ceb5d2d44a28d51d467c825d39a0b22af34c80f65cdfadac4f70e6",
		cardHashR: "3494902762c6790aee69d785dfda8d3ace8f6a8d99b6bc9d1f0d44721ebc1880",
		h0:        "a6ec498ccd8b7282d2f57c32bfe41eb9277315a1ed9c5552abfef6576c9910d7",
		hPre:      "1a3612f096af001ae10b406856f7d11d9d3209e5e3ff473bed36c8fed6ce90f3",
		hKind1:    "ed2223648bdf45aea3e14694b2f41051c8dcd9c51dbb77ed61e0bb31f8ee36ce",
		hE1:       "95951655fe5ad4ad996c0513544c3112d679a194eafca181f4a96403a01b37a2",
		es:        "0c11064a3c6c0213e839675bbacd4b515293f5054e4b8eeae543459dd64a6ec8",
		ss:        "c9e25edfdabb5b6c8c9dde6826c90c087aa4ec2861d00c99626831e0447659d8",
		ck1:       "f011d6893f757b9ffcd900bf7544a823bc1cfaeebb391680b0254a3390dc10e9",
		k1:        "1e0371bb10022c73bc446e0b75236ed6e75a65f949cb499dc104f0cec15d308d",
		hKK1:      "aee189b28ae33dbcb90ed2152055927b5f9985b639531f5b326ee26c6b427768",
		hashKK1:   "6963a2a0be4f12730db678fdb36a0b7e1311342c5798e218711508f08e1daa06",
		hE2:       "a32ae81c721765e36f2063d965a63340abca3ff17ef0ceedbc939015bd47f3e0",
		ee:        "3ff6d7be73ca38cece5adde347baf4c5cdadbfbec9001db422a73ec1f10cbc06",
		se:        "a16231d7d28170f36b589c7e9a86a4e915d2d7f12726ab9b37bd8de1b59dba58",
		ck2:       "3fae04a61210963acb96cc0925c91b0507c1c7b4921fdae88256789be504f2a6",
		k2:        "50eb275019a707325a3bcb4a30c7b54c1a9ced5d0bce753ae875b8ba0020c774",
		hashKK2:   "51c3dcdc4bc78b3d1d923217d8a23d5ee4bd49c29812b104d66d831a776acb09",
		sid:       "752bac32d996821886681d2e2f42b828f6dfde213e56b841b64eeb583c0045a3",
		i2r:       "f15eed6da151f33ba15f6f5a49dd78ad00f777b1688fd16dc568354cadda65b7",
		r2i:       "d0749f3ee364b04340c13ae693f7fce1508e3a6369ba2e815179d90e225e344b",
		mk0I:      "908bc0cf10c09d06a6f7ca088e754c303d0101330d7a0861391fcd8180047f85",
		ck1I:      "818f901105be490e53c5b38a919f4ec6e14c20610852cb717ff61a86a0c6f422",
		dataI:     "43a51ca88a664125cb144b4f61184771d3986a4368af1c53c38150e0271b7fbc",
		mk0R:      "3d2d0324bc8c895d940a38483d49558b05b4348bdaa4c26b6ac2ee81f247c7d4",
		dataR:     "fc625268f34e1dd66c812f3f4576ec8a7f40ea7496082631e64c1d829abf23f4",
		dummyI:    "32f002c7e4da7bfdb358d6d2a0d055a09d88996ae21eae1757564a6ba5b08dca",
		ukm:       []string{"8c28b12a7ae59d34", "5cdcfbf49dfd8ede", "7d62add7405b97c7", "7bd25ae59e89c4be"},
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
			p, err := suite.New(v.suite)
			if err != nil {
				t.Fatal(err)
			}
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

			// the same inputs once more: the first record a dummy
			again, other := vectorSession(t, p, v, true), vectorSession(t, p, v, false)
			first := mustHandshake(t, again.s)
			mustReceive(t, other.s, first, EventSession)
			mustReceive(t, again.s, mustHandshake(t, other.s), EventSession)
			checkHex(t, "Hash(dummy i2r n=0)", p.Hash(sealDummy(t, again.s)), v.dummyI)
		})
	}
}
