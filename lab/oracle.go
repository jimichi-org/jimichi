package lab

import (
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	purposeCell = "cell"
	dataAAD     = 11 // version, kind, counter, hop index
	coverBit    = 0x80
)

// labels a client's data cells from inside its provider, by the AEAD instance
// and never by length: on c25519 at three hops the entry's setup layer is as
// long as the innermost data layer
type oracle struct {
	jcrypto.CryptoProvider
	labels   *Labels
	mu       sync.Mutex
	cellKeys int
	exitKey  *secmem.Buffer
	hooked   bool
}

// setup derives the cell keys hop by hop from the entry, so the last one is
// the exit's
func (o *oracle) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	k, err := o.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	if err == nil && purpose == purposeCell {
		o.mu.Lock()
		o.cellKeys++
		o.exitKey = k
		o.mu.Unlock()
	}
	return k, err
}

func (o *oracle) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	a, err := o.CryptoProvider.NewAEAD(key)
	if err != nil {
		return a, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if key == nil || key != o.exitKey {
		return a, nil
	}
	if o.hooked {
		o.labels.markOdd()
		return a, nil
	}
	o.hooked = true
	return &labelling{AEAD: a, labels: o.labels, hop: byte(o.cellKeys - 1)}, nil
}

type labelling struct {
	jcrypto.AEAD
	labels *Labels
	hop    byte
}

// one branch for payload and cover alike, so the label adds no timing that
// depends on it; one bit of the plaintext is read and nothing is kept
func (l *labelling) Seal(dst, nonce, plaintext, ad []byte) []byte {
	if len(ad) == dataAAD && ad[0] == wire.Version && ad[1] == byte(wire.KindData) && ad[dataAAD-1] == l.hop && len(plaintext) > 0 {
		l.labels.add(plaintext[0]&coverBit == 0)
	} else {
		l.labels.markOdd()
	}
	return l.AEAD.Seal(dst, nonce, plaintext, ad)
}
