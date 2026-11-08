package noise

import (
	"bytes"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type noiseBackend struct {
	allocate func(int) (*secmem.Buffer, error)
	info     jcrypto.HandshakeInfo
}

func (b noiseBackend) initialize(cfg Config) (symmetricState, error) {
	h := make([]byte, 32)
	if len(cfg.Name) <= len(h) {
		copy(h, cfg.Name)
	} else {
		h = bytes.Clone(cfg.Provider.Hash([]byte(cfg.Name)))
		if len(h) != 32 {
			return symmetricState{}, ErrConfig
		}
	}
	ck, err := b.allocate(32)
	if err != nil {
		return symmetricState{}, err
	}
	copy(ck.Bytes(), h)
	h, err = b.mixHash(cfg.Provider, h, bytes.Join(cfg.Prologue, nil))
	if err != nil {
		ck.Release()
		return symmetricState{}, err
	}
	return symmetricState{h: h, ck: ck}, nil
}

func (noiseBackend) mixHash(p jcrypto.CryptoProvider, h, d []byte) ([]byte, error) {
	next := p.Hash(h, d)
	if len(next) != 32 {
		return nil, ErrConfig
	}
	return bytes.Clone(next), nil
}

func (noiseBackend) mixKey(p jcrypto.CryptoProvider, chain, secret *secmem.Buffer, _ jcrypto.Context) (*secmem.Buffer, *secmem.Buffer, error) {
	return p.NoiseKDF2(chain, secret)
}

func (noiseBackend) keyed(st symmetricState) bool { return st.key != nil }

func (b noiseBackend) encrypt(p jcrypto.CryptoProvider, st symmetricState, plaintext []byte) ([]byte, uint64, error) {
	c, err := newCipherState(p, st.key, st.nonce, b.info)
	if err != nil {
		return nil, st.nonce, err
	}
	defer c.Destroy()
	out, err := c.Encrypt(st.h, plaintext)
	return out, c.nonce, err
}

func (b noiseBackend) decrypt(p jcrypto.CryptoProvider, st symmetricState, ciphertext []byte) ([]byte, uint64, error) {
	c, err := newCipherState(p, st.key, st.nonce, b.info)
	if err != nil {
		return nil, st.nonce, err
	}
	defer c.Destroy()
	out, err := c.Decrypt(st.h, ciphertext)
	if err != nil {
		return nil, st.nonce, ErrMessage
	}
	return out, c.nonce, nil
}

func (noiseBackend) split(p jcrypto.CryptoProvider, st symmetricState) (*secmem.Buffer, *secmem.Buffer, error) {
	return p.NoiseKDF2(st.ck, nil)
}
