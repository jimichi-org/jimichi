//go:build linux && amd64

package nodeview

import (
	"bytes"
	"encoding/binary"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

func TestParentEnrollmentTypedGrammarBeforePKISemantics(t *testing.T) {
	for _, which := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, e := suite.New(which)
		if e != nil {
			t.Fatal(e)
		}
		id, e := pki.NewIdentity(p, "node1", "127.0.0.1:12345")
		if e != nil {
			t.Fatal(e)
		}
		defer id.Close()
		var nonce [pki.NonceSize]byte
		nonce[0] = 17
		signed, e := id.Request(nonce)
		if e != nil {
			t.Fatal(e)
		}
		w := encoder{}
		w.bytes(signed, 1024)
		request, e := decodeEnrollmentRequest(&decoder{b: w.b}, p, nonce, "node1", "127.0.0.1:12345")
		if e != nil || request == nil {
			t.Fatal("exact signed request was rejected")
		}
		member, e := pki.NewIdentity(p, "unlisted", "127.0.0.1:12345")
		if e != nil {
			t.Fatal(e)
		}
		defer member.Close()
		memberBytes, e := member.Request(nonce)
		if e != nil {
			t.Fatal(e)
		}
		memberBody := encoder{}
		memberBody.bytes(memberBytes, 1024)
		if request, e := decodeEnrollmentRequest(&decoder{b: memberBody.b}, p, nonce, "unlisted", "127.0.0.1:12345"); e != nil || request == nil {
			t.Fatal("membership parent name failed the shared real request path")
		}
		for at := 0; at < len(w.b); at++ {
			if request, e := decodeEnrollmentRequest(&decoder{b: w.b[:at]}, p, nonce, "node1", "127.0.0.1:12345"); request != nil || reasonOf(e) != ReasonIPC {
				t.Fatal("typed prefix became ordinary enrollment failure")
			}
		}
		tail := append(bytes.Clone(w.b), 1)
		over := bytes.Clone(w.b)
		binary.BigEndian.PutUint16(over[:2], 1025)
		for _, body := range [][]byte{tail, over} {
			if request, e := decodeEnrollmentRequest(&decoder{b: body}, p, nonce, "node1", "127.0.0.1:12345"); request != nil || reasonOf(e) != ReasonIPC {
				t.Fatal("malformed typed request produced a request eligible for Issue/Configure")
			}
		}
		bad := encoder{}
		bad.bytes([]byte{1, 2, 3}, 1024)
		if request, e := decodeEnrollmentRequest(&decoder{b: bad.b}, p, nonce, "node1", "127.0.0.1:12345"); request != nil || reasonOf(e) != ReasonEnrollment {
			t.Fatal("well-framed invalid PKI request lost its semantic failure")
		}
		nonce[0]++
		if request, e := decodeEnrollmentRequest(&decoder{b: w.b}, p, nonce, "node1", "127.0.0.1:12345"); request != nil || reasonOf(e) != ReasonEnrollment {
			t.Fatal("genuine signature/nonce rejection became IPC")
		}
	}
}
