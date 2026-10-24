package pki

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

type Identity struct {
	p    jcrypto.CryptoProvider
	name string
	addr string
	pub  []byte

	mu      sync.Mutex
	priv    *secmem.Buffer
	cert    *Cert
	certRaw []byte
	link    []byte
	onion   []byte
	epoch   uint32
	// the published time never decreases within a process and never falls
	// below the floor: the consistency rules a peer applies to two descriptors
	// hold then under a wall clock set back, and with correct clocks neither
	// value is ever above now
	lastPublished int64
	floor         int64

	// kept encoded, so serving it never waits for a signature
	bundle atomic.Pointer[[]byte]
}

func NewIdentity(p jcrypto.CryptoProvider, name, addr string) (*Identity, error) {
	if !ValidName(name) || !ValidAddr(addr) {
		return nil, ErrFormat
	}
	priv, pub, err := p.GenerateSigning()
	if err != nil {
		return nil, err
	}
	return &Identity{p: p, name: name, addr: addr, pub: pub, priv: priv}, nil
}

func (id *Identity) Locked() bool {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.priv != nil && id.priv.Locked()
}

// the key every certificate of this node certifies; it lives as long as the
// Identity, so it stays the same when the node is enrolled again
func (id *Identity) Public() []byte { return bytes.Clone(id.pub) }

func (id *Identity) Fingerprint() string { return Fingerprint(id.p, id.pub) }

func (id *Identity) KeyHash() string { return KeyHash(id.p, id.pub) }

func (id *Identity) Request(nonce [NonceSize]byte) ([]byte, error) {
	r := &Request{Suite: id.p.Suite(), Nonce: nonce, Name: id.name, Addr: id.addr, Identity: id.pub}
	id.mu.Lock()
	defer id.mu.Unlock()
	sig, err := id.sign(requestDomain, r.body())
	if err != nil {
		return nil, err
	}
	r.Sig = sig
	return r.Marshal(), nil
}

// the CA signature is not checked here, the node does not know the anchor;
// whoever enrolls the node verifies the bundle it serves afterwards
func (id *Identity) Install(raw []byte, now time.Time) error {
	c, err := ParseCert(raw)
	if err != nil {
		return err
	}
	switch {
	case c.Suite != id.p.Suite():
		return ErrSuite
	case !bytes.Equal(c.Identity, id.pub):
		return ErrCertMismatch
	case c.Name != id.name || c.Addr != id.addr:
		return ErrRoster
	}
	if err := certWindow(c, now, Skew, true); err != nil {
		return err
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.priv == nil {
		return secmem.ErrReleased
	}
	id.cert, id.certRaw = c, bytes.Clone(raw)
	id.bundle.Store(nil)
	return nil
}

func (id *Identity) SetKeys(link, onion []byte, epoch uint32) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.link, id.onion, id.epoch = bytes.Clone(link), bytes.Clone(onion), epoch
}

// SetFloor keeps every descriptor signed from now on from being published
// before the given unix second: a node sets it at a rotation to the expiry of
// the epoch before the replaced one plus Skew, which the rules require of the
// new epoch and which a wall clock set back would otherwise miss
func (id *Identity) SetFloor(unix int64) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.floor = unix
}

// the descriptor never outlives the certificate; once the certificate has
// expired the bundle is withdrawn instead
func (id *Identity) Refresh(now time.Time, ttl time.Duration) error {
	if ttl <= 0 || ttl > MaxDescriptorLife {
		return ErrDescTime
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.priv == nil {
		return secmem.ErrReleased
	}
	if id.cert == nil {
		return ErrNoCert
	}
	size, err := wire.PublicKeySize(id.p)
	if err != nil {
		return err
	}
	if len(id.link) != size || len(id.onion) != size {
		return ErrKeySize
	}
	published := max(now.Unix(), id.lastPublished, id.floor)
	if published >= id.cert.NotAfter {
		id.bundle.Store(nil)
		return ErrCertTime
	}
	expires := min(published+int64(ttl/time.Second), id.cert.NotAfter)
	if expires <= published {
		return ErrDescTime
	}
	d := &Descriptor{
		Suite:     id.p.Suite(),
		Epoch:     id.epoch,
		Published: published,
		Expires:   expires,
		LinkPub:   id.link,
		OnionPub:  id.onion,
	}
	h := id.p.Hash(id.certRaw)
	if len(h) != HashSize {
		return errors.New("pki: hash size differs from the descriptor field")
	}
	copy(d.CertHash[:], h)
	if d.Sig, err = id.sign(descriptorDomain, d.body()); err != nil {
		return err
	}
	b := Bundle{V: Version, Suite: id.p.Suite().String(), Cert: id.certRaw, Descriptor: d.Marshal()}.Marshal()
	id.bundle.Store(&b)
	id.lastPublished = published
	return nil
}

func (id *Identity) Bundle() ([]byte, bool) {
	b := id.bundle.Load()
	if b == nil {
		return nil, false
	}
	return bytes.Clone(*b), true
}

func (id *Identity) Close() {
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.priv != nil {
		id.priv.Release()
		id.priv = nil
	}
	id.bundle.Store(nil)
}

// callers hold mu, so Close cannot release the key during a signature
func (id *Identity) sign(domain string, body []byte) ([]byte, error) {
	if id.priv == nil {
		return nil, secmem.ErrReleased
	}
	return id.p.Sign(id.priv, signed(domain, body))
}

func Unsigned(p jcrypto.CryptoProvider, link, onion []byte) ([]byte, error) {
	return UnsignedEpoch(p, link, onion, 0)
}

func UnsignedEpoch(p jcrypto.CryptoProvider, link, onion []byte, epoch uint32) ([]byte, error) {
	size, err := wire.PublicKeySize(p)
	if err != nil {
		return nil, err
	}
	if len(link) != size || len(onion) != size {
		return nil, ErrKeySize
	}
	d := &Descriptor{Suite: p.Suite(), Epoch: epoch, LinkPub: link, OnionPub: onion}
	return Bundle{V: Version, Suite: p.Suite().String(), Descriptor: d.Marshal()}.Marshal(), nil
}
