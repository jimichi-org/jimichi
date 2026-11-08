package noise

import (
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type symmetricState struct {
	h     []byte
	ck    *secmem.Buffer
	key   *secmem.Buffer
	nonce uint64
}

type symmetricBackend interface {
	initialize(Config) (symmetricState, error)
	mixHash(jcrypto.CryptoProvider, []byte, []byte) ([]byte, error)
	mixKey(jcrypto.CryptoProvider, *secmem.Buffer, *secmem.Buffer, jcrypto.Context) (*secmem.Buffer, *secmem.Buffer, error)
	keyed(symmetricState) bool
	encrypt(jcrypto.CryptoProvider, symmetricState, []byte) ([]byte, uint64, error)
	decrypt(jcrypto.CryptoProvider, symmetricState, []byte) ([]byte, uint64, error)
	split(jcrypto.CryptoProvider, symmetricState) (*secmem.Buffer, *secmem.Buffer, error)
}

type legacyBackend struct{}

func (legacyBackend) initialize(cfg Config) (symmetricState, error) {
	ctx, err := jcrypto.NewContext(cfg.Provider, "noise/"+cfg.Name, cfg.Prologue...)
	if err != nil {
		return symmetricState{}, err
	}
	return symmetricState{h: ctx.Sum()}, nil
}

func (legacyBackend) mixHash(p jcrypto.CryptoProvider, h, d []byte) ([]byte, error) {
	parts := [][]byte{h}
	if len(d) > 0 {
		parts = append(parts, d)
	}
	ctx, err := jcrypto.NewContext(p, exchangeHash, parts...)
	if err != nil {
		return nil, err
	}
	return ctx.Sum(), nil
}

func (legacyBackend) mixKey(p jcrypto.CryptoProvider, chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, *secmem.Buffer, error) {
	if chain == nil {
		return secret, nil, nil
	}
	next, err := p.MixKey(chain, secret, ctx)
	return next, nil, err
}

func (legacyBackend) keyed(st symmetricState) bool { return st.ck != nil }

// one key per message and h as the associated data, so the zero nonce never
// repeats under a key
func (legacyBackend) aead(p jcrypto.CryptoProvider, st symmetricState) (jcrypto.AEAD, error) {
	if st.ck == nil {
		return nil, ErrNoKey
	}
	ctx, err := jcrypto.NewContext(p, exchangeKey, st.h)
	if err != nil {
		return nil, err
	}
	k, err := p.DeriveKey(st.ck, purposeKey, ctx, p.KeySize())
	if err != nil {
		return nil, err
	}
	defer k.Release()
	return p.NewAEAD(k)
}

func (b legacyBackend) encrypt(p jcrypto.CryptoProvider, st symmetricState, pt []byte) ([]byte, uint64, error) {
	a, err := b.aead(p, st)
	if err != nil {
		return nil, 0, err
	}
	defer a.Destroy()
	return a.Seal(nil, make([]byte, a.NonceSize()), pt, st.h), 0, nil
}

func (b legacyBackend) decrypt(p jcrypto.CryptoProvider, st symmetricState, c []byte) ([]byte, uint64, error) {
	a, err := b.aead(p, st)
	if err != nil {
		return nil, 0, err
	}
	defer a.Destroy()
	pt, err := a.Open(nil, make([]byte, a.NonceSize()), c, st.h)
	if err != nil {
		return nil, 0, ErrMessage
	}
	return pt, 0, nil
}

func (legacyBackend) split(p jcrypto.CryptoProvider, st symmetricState) (*secmem.Buffer, *secmem.Buffer, error) {
	ctx, err := jcrypto.NewContext(p, exchangeSplit, st.h)
	if err != nil {
		return nil, nil, err
	}
	i2r, err := p.DeriveKey(st.ck, purposeI2R, ctx, p.KeySize())
	if err != nil {
		return nil, nil, err
	}
	r2i, err := p.DeriveKey(st.ck, purposeR2I, ctx, p.KeySize())
	if err != nil {
		i2r.Release()
		return nil, nil, err
	}
	return i2r, r2i, nil
}
