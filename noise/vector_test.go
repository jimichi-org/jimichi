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
		qI:    "4271d9a52bde0983787e4ad2e3796413",
		qR:    "3972fefed5c3c4e10c22d9b8f524d6d8",

		hashKK1: "4cd5085271325cff181f5c6073c6834d93010a0d4916b574453eec3e0f867f37",
		hashKK2: "9863a605538fd0d89bd7c8b8fc6f9e37f243099cde64b115b1a19bdeb4bc2bf5",
		sid:     "2b1f5ed3bf8835d02f8bbca7a82e3379d62170a19d2eb1f509b358027f56ed81",
		i2r:     "e4821a139f782cee9e3aecc301057c81b8a362fe4f74f6d5abbc771b26ad06f4",
		r2i:     "974ddf12cfa3deca66d73beaba397fad452e28e19b96722e332f8030d44eddf2",
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
		qI: "2669ab3d5bb9f59f14a01b6c00172f2a",
		qR: "ca6d05e3d7fd0cf58c593fa0c9564653",

		hashKK1: "6963a2a0be4f12730db678fdb36a0b7e1311342c5798e218711508f08e1daa06",
		hashKK2: "51c3dcdc4bc78b3d1d923217d8a23d5ee4bd49c29812b104d66d831a776acb09",
		sid:     "752bac32d996821886681d2e2f42b828f6dfde213e56b841b64eeb583c0045a3",
		i2r:     "f15eed6da151f33ba15f6f5a49dd78ad00f777b1688fd16dc568354cadda65b7",
		r2i:     "d0749f3ee364b04340c13ae693f7fce1508e3a6369ba2e815179d90e225e344b",
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
