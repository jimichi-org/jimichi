package pki

import (
	"bytes"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

// whatever ParseMirror accepts has one spelling: the entries it returns encode
// to the same bytes, bundles and proofs alike
func FuzzParseMirror(f *testing.F) {
	for _, st := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(st)
		if err != nil {
			f.Fatal(err)
		}
		e := newEnv(f, p)
		b1 := e.node(f, "relay-1").bundle(f, t0, time.Hour)
		n2 := e.node(f, "relay-2")
		x, y := n2.bundle(f, t0, time.Hour), n2.bundle(f, t0.Add(time.Second), time.Hour)
		pr, err := NewProof(x, y)
		if err != nil {
			f.Fatal(err)
		}
		plain, err := MarshalMirror([]MirrorEntry{{Addr: addrOf("relay-1"), Bundle: b1}, {Addr: addrOf("relay-2"), Bundle: x}})
		if err != nil {
			f.Fatal(err)
		}
		withProof, err := MarshalMirror([]MirrorEntry{{Addr: addrOf("relay-1"), Bundle: b1}, {Addr: addrOf("relay-2"), Proof: pr}})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(plain)
		f.Add(withProof)
	}
	f.Add([]byte("[]"))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		entries, err := ParseMirror(raw)
		if err != nil {
			return
		}
		again, err := MarshalMirror(entries)
		if err != nil {
			t.Fatalf("%s is accepted and does not encode again: %v", raw, err)
		}
		if !bytes.Equal(again, raw) {
			t.Fatalf("%s is accepted and encodes again as %s", raw, again)
		}
	})
}
