package vault

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

var errTaken = errors.New("vault: identity taken or closed")

// what a volume's key gives; the Draft or Volume owns it until Take
type Identity struct {
	p   jcrypto.CryptoProvider
	pub []byte

	mu    sync.RWMutex
	priv  *secmem.Buffer
	fetch *secmem.Buffer
}

// the pair and the fetch capability are functions of the volume key and the
// place of the volume, so every open of the file gives them again
func deriveIdentity(p jcrypto.CryptoProvider, k *secmem.Buffer, salt []byte, s int) (*Identity, error) {
	ctx, err := jcrypto.NewContext(p, exchangeIdentity, salt, []byte{byte(s)})
	if err != nil {
		return nil, err
	}
	priv, pub, err := p.DerivePair(k, ctx)
	if err != nil {
		return nil, fmt.Errorf("vault: identity: %w", err)
	}
	fetch, err := p.DeriveKey(k, purposeFetch, ctx, fetchSize)
	if err != nil {
		priv.Release()
		return nil, fmt.Errorf("vault: fetch capability: %w", err)
	}
	if allZero(fetch.Bytes()) {
		priv.Release()
		fetch.Release()
		return nil, errZeroFetch
	}
	return &Identity{p: p, pub: bytes.Clone(pub), priv: priv, fetch: fetch}, nil
}

func (id *Identity) Public() []byte { return bytes.Clone(id.pub) }

// with Public it satisfies noise.Static, which vault does not import
func (id *Identity) Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	id.mu.RLock()
	defer id.mu.RUnlock()
	if id.priv == nil {
		return nil, errTaken
	}
	return id.p.Agree(id.priv, remote, ctx)
}

// borrowed: valid until Take or Close
func (id *Identity) Fetch() *secmem.Buffer {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.fetch
}

// moves the keys to the caller; after it Agree refuses and only Public answers
func (id *Identity) Take() (priv *secmem.Buffer, pub []byte, fetch *secmem.Buffer) {
	id.mu.Lock()
	defer id.mu.Unlock()
	priv, fetch = id.priv, id.fetch
	id.priv, id.fetch = nil, nil
	return priv, bytes.Clone(id.pub), fetch
}

func (id *Identity) close() {
	if id == nil {
		return
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.priv != nil {
		id.priv.Release()
		id.priv = nil
	}
	if id.fetch != nil {
		id.fetch.Release()
		id.fetch = nil
	}
}
