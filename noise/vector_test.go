package noise_test

import (
	"encoding/hex"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
)

// hands out the given ephemeral keys in order; the inputs of a vector are not
// a seam of the package, only of this provider
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
	priv, err := secmem.NewFrom(unhex(f.t, k[0]))
	if err != nil {
		return nil, nil, err
	}
	return priv, unhex(f.t, k[1]), nil
}

type kkVector struct {
	suite          jcrypto.Suite
	sI, SI, sR, SR string
	eI, EI, eR, ER string
	qI, qR         string
	hashKK1        string
	hashKK2        string
	sid, i2r, r2i  string
}

const addr = "relay-5.jimichi.svc.cluster.local:9000"

// the handshake of the e2e layer: prologue 01 and both cards, the record kind
// mixed in before each message, zero payloads filling a 392-byte record. The
// values come from a separate implementation, see e2e/vectors_test.go
var kkVectors = []kkVector{
	{
		suite: jcrypto.SuiteC25519,
		sI:    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
		SI:    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
		sR:    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
		SR:    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
		eI:    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		EI:    "d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66",
		eR:    "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		ER:    "34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847",
		qI:    "1b76bac7bbf4ab62e913962b3ae233c1",
		qR:    "2bb76210f9e763355d2e7ceb5d405651",

		hashKK1: "4cb85b369c9359ee95f5c4364ffc60f2709e15da84bf0f37add3a9271a9cd1ec",
		hashKK2: "ec571492cfdd33881c728333790b4bd3e70b0931df797648d75f69b2bbfe473d",
		sid:     "7ed5c612162b432daf6426fa3d4a820c4f5edab007b23e451b4c21953bbdb071",
		i2r:     "727d332473e962fcc4ccf3f34a4710931857bc56acabef3a3da9f09451945077",
		r2i:     "27538a8958b44078934443a937f9933f19555b6360f9b24173c21ceefa25d5ef",
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
		qI: "43611fb8fd90df8a0e1e036177d0a24a",
		qR: "68a5779ba1e5a07385e74bd9fa049055",

		hashKK1: "f2ef61d932ede7c06faf6815165dc2d7d890e321f9116a6fd973aca3512b5c4e",
		hashKK2: "21ea722b084360498b89c77750530b574ee7261e0c7e619d9d1d9e1fde2fde65",
		sid:     "e76c7613a16acc2311d1c94a13dbe2e5def2923649beaec3f075cd331b7f4c96",
		i2r:     "0627700425ddd0e03c6ff7ca1770f1b7ac2e14efc716f783476822e5f9995dd8",
		r2i:     "e63eb7d326e264a65f53e359a561caba0151b03db17b9a0cc938514e476c9145",
	},
}

func card(t *testing.T, s jcrypto.Suite, queue, static string) []byte {
	b := []byte{1, byte(s), byte(len(addr))}
	b = append(b, addr...)
	b = append(b, unhex(t, queue)...)
	return append(b, unhex(t, static)...)
}

func TestKKVectors(t *testing.T) {
	for _, v := range kkVectors {
		t.Run(v.suite.String(), func(t *testing.T) {
			base, err := suite.New(v.suite)
			if err != nil {
				t.Fatal(err)
			}
			p := noSigning{CryptoProvider: base, t: t}
			keyPair := func(priv, pub string) *noise.KeyPair {
				b, err := secmem.NewFrom(unhex(t, priv))
				if err != nil {
					t.Fatal(err)
				}
				kp := noise.NewKeyPair(p, b, unhex(t, pub))
				t.Cleanup(kp.Close)
				return kp
			}
			si, sr := keyPair(v.sI, v.SI), keyPair(v.sR, v.SR)
			pro := [][]byte{{0x01}, card(t, v.suite, v.qI, v.SI), card(t, v.suite, v.qR, v.SR)}
			payload := make([]byte, 392-1-len(unhex(t, v.SI))-16)

			ini, err := noise.New(noise.Config{Provider: &fixedEphemeral{CryptoProvider: p, t: t, keys: [][2]string{{v.eI, v.EI}}},
				Pattern: noise.KK, Name: "e2e/kk", Initiator: true, Prologue: pro, Local: si, RemoteStatic: sr.Public()})
			if err != nil {
				t.Fatal(err)
			}
			defer ini.Close()
			resp, err := noise.New(noise.Config{Provider: &fixedEphemeral{CryptoProvider: p, t: t, keys: [][2]string{{v.eR, v.ER}}},
				Pattern: noise.KK, Name: "e2e/kk", Prologue: pro, Local: sr, RemoteStatic: si.Public()})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Close()

			record := func(w, r *noise.HandshakeState, kind byte) []byte {
				if err := w.MixHash([]byte{kind}); err != nil {
					t.Fatal(err)
				}
				if err := r.MixHash([]byte{kind}); err != nil {
					t.Fatal(err)
				}
				rec := append([]byte{kind}, mustWrite(t, w, payload)...)
				mustRead(t, r, rec[1:])
				return rec
			}
			if got := hex.EncodeToString(p.Hash(record(ini, resp, 1))); got != v.hashKK1 {
				t.Fatalf("Hash(kk1) = %s, want %s", got, v.hashKK1)
			}
			if got := hex.EncodeToString(p.Hash(record(resp, ini, 2))); got != v.hashKK2 {
				t.Fatalf("Hash(kk2) = %s, want %s", got, v.hashKK2)
			}
			for name, s := range map[string]split{"initiator": mustSplit(t, ini), "responder": mustSplit(t, resp)} {
				for _, c := range []struct{ what, got, want string }{
					{"SID", hex.EncodeToString(s.sid), v.sid},
					{"i2r", hex.EncodeToString(s.i2r), v.i2r},
					{"r2i", hex.EncodeToString(s.r2i), v.r2i},
				} {
					if c.got != c.want {
						t.Fatalf("%s: %s = %s, want %s", name, c.what, c.got, c.want)
					}
				}
			}
		})
	}
}
