package noise

import (
	"encoding/binary"
	"errors"
	"math"
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

var ErrNonce = errors.New("noise: nonce exhausted")

type CipherState struct {
	mu    sync.Mutex
	a     jcrypto.AEAD
	nonce uint64
}

func newCipherState(p jcrypto.CryptoProvider, key *secmem.Buffer, nonce uint64, i jcrypto.HandshakeInfo) (*CipherState, error) {
	a, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if a.NonceSize() != i.NonceSize || a.Overhead() != i.TagSize {
		a.Destroy()
		return nil, ErrConfig
	}
	return &CipherState{a: a, nonce: nonce}, nil
}

func (c *CipherState) Encrypt(ad, plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.a == nil {
		return nil, ErrClosed
	}
	if len(plaintext) > 65535-c.a.Overhead() {
		return nil, ErrMessageTooLarge
	}
	if c.nonce == math.MaxUint64 {
		return nil, ErrNonce
	}
	out := c.a.Seal(nil, cipherNonce(c.a.NonceSize(), c.nonce), plaintext, ad)
	c.nonce++
	return out, nil
}

func (c *CipherState) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.a == nil {
		return nil, ErrClosed
	}
	if len(ciphertext) > 65535 {
		return nil, ErrMessageTooLarge
	}
	if c.nonce == math.MaxUint64 {
		return nil, ErrNonce
	}
	out, err := c.a.Open(nil, cipherNonce(c.a.NonceSize(), c.nonce), ciphertext, ad)
	if err != nil {
		return nil, err
	}
	c.nonce++
	return out, nil
}

func cipherNonce(size int, n uint64) []byte {
	out := make([]byte, size)
	binary.LittleEndian.PutUint64(out[size-8:], n)
	return out
}

func (c *CipherState) Destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.a != nil {
		c.a.Destroy()
		c.a = nil
	}
}
