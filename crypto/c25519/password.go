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
	key := argon2id(password.Bytes(), info(label, ctx.Sum()), argonTime, argonMemory, argonThreads, keySize)
	defer secmem.ReturnFreed()
	out, err := secmem.NewFrom(key)
	if err != nil {
		secmem.Zero(key)
		return nil, err
	}
	return out, nil
}

func argon2id(password, salt []byte, time, memory uint32, threads uint8, size uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, size)
}
