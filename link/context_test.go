package link

import (
	"encoding/hex"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

func seq(from byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = from + byte(i)
	}
	return out
}

// the context the handshake builds, against the hash of the transcript written
// out here with every part as a literal, P being the public key size (32, 64)
// and the identity key of the same size:
//
//	"jimichi/v2/<suite>/transcript/link" || 00 || 05 || 0001 02 || 0001 01
//	  || u16be(P) 00..(P-1) || u16be(P) 40..(40+P-1) || u16be(P) 80..(80+P-1)
//	"jimichi/v2/<suite>/transcript/link" || 00 || 04 || 0001 02 || 0001 00
//	  || u16be(P) 00..(P-1) || u16be(P) 40..(40+P-1)
//	"jimichi/v2/<suite>/transcript/link" || 00 || 06 || 0001 02 || 0001 01
//	  || u16be(P) 00..(P-1) || u16be(P) 40..(40+P-1) || u16be(P) 80..(80+P-1)
//	  || u16be(P) c0..(c0+P-1)
//
// 143, 109 and 177 bytes on c25519, 237, 171 and 303 on GOST. The sums are
// SHA-256 (sha256sum over the bytes) and Streebog-256 in the byte order of
// RFC 6986; they are the vectors G2, G3 and G5 of crypto/providertest,
// computed there without this code. The anonymous mode binds no identity even
// when one is given: the initiator does not know whom it reached
func TestHandshakeContextKnownAnswer(t *testing.T) {
	for _, tc := range []struct {
		suite         jcrypto.Suite
		pub           int
		authenticated string
		anonymous     string
		identified    string
	}{
		{
			jcrypto.SuiteC25519, 32,
			"7b9ee2ddeffae097fbe33d8a86e4f800bad67ed18db7886ee15105fa47945c28",
			"9316cc227c129bc7bc39fe454668267767c8b86735e7d11e6b78de56fbdac044",
			"bd1fd058596e45ce436a42fe19f45c2f64bef277aef7bcfd0f3353f6737ef7b3",
		},
		{
			jcrypto.SuiteGOST, 64,
			"95d4af2336fd54e2bbcfbc13378c70c73107c3065996119a68aba055bcda8d76",
			"bafb88554bdd02d048d3d96a04233f38bedf2fdac0d69b1550dbf9ff5ead0d1a",
			"9e660f347729b9614cb118a0fbc0135beed6faecab74a0e0974c185049c8c5af",
		},
	} {
		p, err := suite.New(tc.suite)
		if err != nil {
			t.Fatal(err)
		}
		initiator, responder, static, identity := seq(0x00, tc.pub), seq(0x40, tc.pub), seq(0x80, tc.pub), seq(0xc0, tc.pub)
		for _, mode := range []struct {
			name     string
			mode     byte
			identity []byte
			want     string
		}{
			{"authenticated", 0x01, nil, tc.authenticated},
			{"anonymous", 0x00, nil, tc.anonymous},
			{"authenticated with an identity", 0x01, identity, tc.identified},
			{"anonymous with an identity", 0x00, identity, tc.anonymous},
		} {
			ctx, err := handshakeContext(p, mode.mode, initiator, responder, static, mode.identity)
			if err != nil {
				t.Fatalf("%v %s: %v", tc.suite, mode.name, err)
			}
			if got := hex.EncodeToString(ctx.Sum()); got != mode.want {
				t.Errorf("%v %s: context %s, want %s", tc.suite, mode.name, got, mode.want)
			}
		}
	}
}
