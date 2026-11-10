//go:build linux && amd64

package nodeview

import (
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

func decodeEnrollmentRequest(r *decoder, p jcrypto.CryptoProvider, nonce [pki.NonceSize]byte, name, addr string) (*pki.Request, error) {
	bytes := r.bytes(1024)
	if e := r.end(); e != nil {
		return nil, e
	}
	request, e := pki.ParseRequest(bytes)
	if e != nil || request.Check(p, nonce, name, addr) != nil {
		return nil, fail(ReasonEnrollment)
	}
	return request, nil
}
