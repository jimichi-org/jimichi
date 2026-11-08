package link

import (
	"bytes"
	"encoding/binary"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/wire"
	"testing"
)

func TestHandshakePrologueFields(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, _ := suite.New(s)
		for mode, name := range []string{"nn", "nk", "kk"} {
			header := []byte{4, byte(mode), 0}
			if mode == 2 {
				header = append([]byte{4, 2, 9}, []byte("n.test:80")...)
			}
			want := append([]byte("jimichi/link/v1/"+s.String()+"/"+name), 0, wire.Version)
			want = binary.BigEndian.AppendUint16(want, uint16(len(header)))
			want = append(want, header...)
			want = append(want, 1, 0, 1, 0xaa, 2, 0, 1, 0xbb)
			got := handshakePrologue(p, byte(mode), header, []byte{0xaa}, []byte{0xbb})
			if !bytes.Equal(got, want) {
				t.Fatal("canonical prologue mismatch")
			}
			header[0] ^= 1
			if !bytes.Equal(got, want) {
				t.Fatal("prologue aliases header")
			}
			absent := handshakePrologue(p, byte(mode), header, nil, nil)
			if !bytes.HasSuffix(absent, []byte{1, 0, 0, 2, 0, 0}) {
				t.Fatal("missing empty identity lengths")
			}
		}
	}
}
