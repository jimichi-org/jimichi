package gost

import (
	"crypto/pbkdf2"
	"fmt"

	"github.com/pedroalbanese/gogost/gost34112012512"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// a one-off calibration on the testbed host put the processor time per guess
// within 0.8-1.25 of Argon2id in the c25519 suite; the count belongs to the
// purpose password/1
const passwordIterations = 2600

// PBKDF2 with HMAC_GOSTR3411_2012_512 (R 50.1.111-2016), since the suite has
// no memory-hard function; 32 bytes are the start of block T_1
func (p *Provider) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if password == nil || !jcrypto.ValidPassword(password.Bytes()) {
		return nil, jcrypto.ErrBadPassword
	}
	if !p.owns(ctx) {
		return nil, jcrypto.ErrBadContext
	}
	label, err := jcrypto.Label(p.Suite(), "password/1")
	if err != nil {
		return nil, err
	}
	salt := append(append(label, 0x00), ctx.Sum()...)
	key, err := pbkdf2Streebog(password.Bytes(), salt, passwordIterations, keySize)
	defer secmem.ReturnFreed()
	if err != nil {
		return nil, fmt.Errorf("gost: pbkdf2: %w", err)
	}
	out, err := secmem.NewFrom(key)
	if err != nil {
		secmem.Zero(key)
		return nil, err
	}
	return out, nil
}

// crypto/pbkdf2 takes the password as a string, an immutable copy on the heap;
// under GODEBUG=fips140=only it refuses Streebog
func pbkdf2Streebog(password, salt []byte, iter, size int) ([]byte, error) {
	return pbkdf2.Key(gost34112012512.New, string(password), salt, iter, size)
}
