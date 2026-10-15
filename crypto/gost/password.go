package gost

import (
	"crypto/pbkdf2"
	"fmt"
	"unsafe"

	"github.com/pedroalbanese/gogost/gost34112012512"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// a one-off calibration put the processor time per guess within 0.8-1.25 of
// Argon2id in the c25519 suite, for gogost's Streebog in the Linux containers
// of the testbed; the count belongs to the purpose password/1
const passwordIterations = 2600

// PBKDF2 with HMAC_GOSTR3411_2012_512 (R 50.1.111-2016), since the suite has
// no memory-hard function; 32 bytes are the start of block T_1
func (p *Provider) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	var pw []byte
	if password != nil {
		pw = password.Bytes()
	}
	if !jcrypto.ValidPassword(pw) {
		return nil, jcrypto.ErrBadPassword
	}
	if !p.owns(ctx) {
		return nil, jcrypto.ErrBadContext
	}
	label, err := jcrypto.Label(p.Suite(), "password/1")
	if err != nil {
		return nil, err
	}
	defer secmem.ReturnFreed()
	salt := append(append(label, 0x00), ctx.Sum()...)
	key, err := pbkdf2Streebog(pw, salt, passwordIterations, keySize)
	if err != nil {
		return nil, fmt.Errorf("gost: pbkdf2: %w", err)
	}
	// the library returns the start of the whole block T_1, whose tail checks
	// a password guess as well as the key does
	defer secmem.Zero(key[:cap(key)])
	return secmem.NewFrom(key)
}

// a variable so an internal test can see what goes into the stretch and what
// is left of its output. crypto/pbkdf2 takes the password as a string and uses
// it only during the call, so the string views the caller's bytes rather than
// being an immutable copy on the heap; under GODEBUG=fips140=only it refuses
// Streebog
var pbkdf2Streebog = func(password, salt []byte, iter, size int) ([]byte, error) {
	view := unsafe.String(unsafe.SliceData(password), len(password))
	return pbkdf2.Key(gost34112012512.New, view, salt, iter, size)
}
