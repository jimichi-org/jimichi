//go:build noisevectors

// Package noisevector supplies fixed inputs and a standard cipher for Noise vectors.
package noisevector

import (
	"crypto/cipher"
	"errors"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type Provider struct {
	jcrypto.CryptoProvider
	ephemeral *secmem.Buffer
}

func NewProvider(ephemeral []byte) (*Provider, error) {
	key, err := secmem.NewFrom(ephemeral)
	if err != nil {
		return nil, err
	}
	return &Provider{CryptoProvider: c25519.New(), ephemeral: key}, nil
}
func (p *Provider) Close() {
	if p.ephemeral != nil {
		p.ephemeral.Release()
		p.ephemeral = nil
	}
}
func (p *Provider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	if p.ephemeral == nil {
		return nil, nil, errors.New("noisevector: fixed ephemeral already used")
	}
	pub, err := curve25519.X25519(p.ephemeral.Bytes(), curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	key := p.ephemeral
	p.ephemeral = nil
	return key, pub, nil
}
func (p *Provider) HandshakeInfo() jcrypto.HandshakeInfo {
	info := p.CryptoProvider.HandshakeInfo()
	info.CipherName = "ChaChaPoly"
	info.NonceSize = 12
	return info
}
func (p *Provider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	if key == nil || len(key.Bytes()) != 32 {
		return nil, jcrypto.ErrBadKeySize
	}
	a, err := chacha20poly1305.New(key.Bytes())
	if err != nil {
		return nil, err
	}
	return &aead{inner: a}, nil
}

type aead struct{ inner cipher.AEAD }

func (a *aead) NonceSize() int { return a.inner.NonceSize() }
func (a *aead) Overhead() int  { return a.inner.Overhead() }
func (a *aead) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return a.inner.Seal(dst, nonce, plaintext, ad)
}
func (a *aead) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	out, err := a.inner.Open(dst, nonce, ciphertext, ad)
	if err != nil {
		return nil, jcrypto.ErrOpen
	}
	return out, nil
}
func (a *aead) Destroy() { a.inner = nil }
func Static(private []byte) (*secmem.Buffer, []byte, error) {
	priv, err := secmem.NewFrom(private)
	if err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(priv.Bytes(), curve25519.Basepoint)
	if err != nil {
		priv.Release()
		return nil, nil, err
	}
	return priv, pub, nil
}
