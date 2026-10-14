package c25519

import (
	"golang.org/x/crypto/argon2"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// the second recommended option of RFC 9106 (section 4); the cost belongs to
// the purpose password/1
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// Argon2id with the label, a zero byte and the transcript hash as the salt,
// the bytes info gives the other derivations
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
	key := argon2id(pw, info(label, ctx.Sum()), argonTime, argonMemory, argonThreads, keySize)
	defer secmem.Zero(key[:cap(key)])
	return secmem.NewFrom(key)
}

// a variable so an internal test can see what goes into the stretch and what
// is left of its output
var argon2id = func(password, salt []byte, time, memory uint32, threads uint8, size uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, size)
}
