package e2e

import (
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

func eachSuiteB(b *testing.B, run func(b *testing.B, p jcrypto.CryptoProvider)) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(s.String(), func(b *testing.B) { run(b, p) })
	}
}

// one handshake of both sides: two sessions with their key checks, kk1 and kk2
func BenchmarkKK(b *testing.B) {
	eachSuiteB(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		idI, idR := identities(b, p, p)
		for b.Loop() {
			ini, err := NewSession(p, idI, idR.Card(), Options{})
			if err != nil {
				b.Fatal(err)
			}
			resp, err := NewSession(p, idR, idI.Card(), Options{})
			if err != nil {
				b.Fatal(err)
			}
			kk1, _ := ini.Handshake()
			if _, err := resp.Receive(kk1); err != nil {
				b.Fatal(err)
			}
			kk2, _ := resp.Handshake()
			if _, err := ini.Receive(kk2); err != nil {
				b.Fatal(err)
			}
			ini.Close()
			resp.Close()
		}
	})
}

// one record: a step and a Seal at the sender, a step and an Open at the
// receiver
func BenchmarkRatchetStep(b *testing.B) {
	eachSuiteB(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		idI, idR := identities(b, p, p)
		pr := &pair{idI: idI, idR: idR}
		pr.ini = newSession(b, p, idI, idR.Card(), Options{})
		pr.resp = newSession(b, p, idR, idI.Card(), Options{})
		pr.handshake(b)
		body := make([]byte, MaxBody)
		for b.Loop() {
			rec, err := pr.ini.Seal(body)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := pr.resp.Receive(rec); err != nil {
				b.Fatal(err)
			}
		}
	})
}
