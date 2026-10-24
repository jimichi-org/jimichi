package pki

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	// covers a verifier clock behind the signer's; applied to lower bounds only,
	// so no window is ever extended past its end
	Skew              = 2 * time.Minute
	MaxDescriptorLife = 24 * time.Hour
	// the shortest lifetime a node signs and the least a verifier with
	// Policy.MinLife accepts, so a node cannot make its peers fetch it again
	// every minute by signing short descriptors
	MinDescriptorLife = 16 * time.Minute
	// how long after its certificate request a node still accepts the
	// certificate; the node enforces it, an enrollment run keeps inside it
	InstallWindow = time.Minute
)

var (
	ErrFormat           = errors.New("pki: malformed encoding")
	ErrVersion          = errors.New("pki: unknown format version")
	ErrSuite            = errors.New("pki: suite mismatch")
	ErrUnknownCA        = errors.New("pki: certificate from an unknown CA")
	ErrCertSignature    = errors.New("pki: bad certificate signature")
	ErrCertTime         = errors.New("pki: certificate outside its validity")
	ErrWrongAddr        = errors.New("pki: certificate issued for another address")
	ErrCertMismatch     = errors.New("pki: certificate belongs to another node")
	ErrDescSignature    = errors.New("pki: bad descriptor signature")
	ErrDescTime         = errors.New("pki: descriptor outside its validity")
	ErrDescLife         = errors.New("pki: descriptor shorter than the least lifetime")
	ErrKeySize          = errors.New("pki: wrong key size")
	ErrDuplicate        = errors.New("pki: node repeated in the chain")
	ErrNoCert           = errors.New("pki: no certificate installed")
	ErrNonce            = errors.New("pki: request made for another nonce")
	ErrRoster           = errors.New("pki: name or address differs from the roster")
	ErrRequestSignature = errors.New("pki: bad request signature")
	ErrConflict         = errors.New("pki: the node signed descriptors that contradict each other")
	ErrNoConflict       = errors.New("pki: not a proof of inconsistency")
)

type Bundle struct {
	V          int    `json:"v"`
	Suite      string `json:"suite"`
	Cert       []byte `json:"cert"`
	Descriptor []byte `json:"descriptor"`
}

type envelope struct {
	V          int    `json:"v"`
	Suite      string `json:"suite"`
	Cert       string `json:"cert"`
	Descriptor string `json:"descriptor"`
}

func (b Bundle) Marshal() []byte {
	out, err := json.Marshal(envelope{
		V:          b.V,
		Suite:      b.Suite,
		Cert:       base64.StdEncoding.EncodeToString(b.Cert),
		Descriptor: base64.StdEncoding.EncodeToString(b.Descriptor),
	})
	if err != nil {
		panic("pki: encoding an int and three strings cannot fail")
	}
	return out
}

// the certificate may be empty, which is how an unsigned bundle travels; Verify
// then fails on it with ErrFormat
func ParseBundle(raw []byte) (*Bundle, error) {
	var e envelope
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&e); err != nil {
		return nil, ErrFormat
	}
	if e.V != Version {
		return nil, ErrVersion
	}
	cert, errCert := base64.StdEncoding.Strict().DecodeString(e.Cert)
	desc, errDesc := base64.StdEncoding.Strict().DecodeString(e.Descriptor)
	if errCert != nil || errDesc != nil || e.Suite == "" || len(desc) == 0 {
		return nil, ErrFormat
	}
	b := &Bundle{V: e.V, Suite: e.Suite, Cert: cert, Descriptor: desc}
	// encoding/json matches keys regardless of case, keeps the last of two equal
	// keys and reads a missing one as empty; only the spelling Marshal writes is
	// accepted, which rules all of that out along with spacing and trailing data
	if !bytes.Equal(b.Marshal(), raw) {
		return nil, ErrFormat
	}
	return b, nil
}

type Policy struct {
	Anchor Anchor
	Skew   time.Duration
	// zero means MaxDescriptorLife, and a longer value is cut down to it
	MaxLife time.Duration
	// the least lifetime a descriptor must carry; zero sets no bound, and a
	// descriptor cut by its certificate (expires equal to not_after) is exempt
	MinLife time.Duration
}

func (pol Policy) maxLife() time.Duration {
	if pol.MaxLife <= 0 || pol.MaxLife > MaxDescriptorLife {
		return MaxDescriptorLife
	}
	return pol.MaxLife
}

type Verified struct {
	Addr      string
	Name      string
	Identity  []byte
	CertHash  [HashSize]byte
	LinkPub   []byte
	OnionPub  []byte
	Epoch     uint32
	CertUntil time.Time
	DescFrom  time.Time
	DescUntil time.Time
}

// the order is part of the contract: the suite is settled before any key is
// parsed as a curve point, and every step fails with its own sentinel
func Verify(p jcrypto.CryptoProvider, pol Policy, addr string, bundle []byte, now time.Time) (*Verified, error) {
	return verifyBundle(p, pol, addr, bundle, now, true)
}

// VerifyStatement is Verify without the clock: the anchor, both signatures,
// the certificate hash, the address, the suite, the shape of both windows and
// the key sizes are checked, their position against now is not. What passes is
// something the node said, whether or not a client may still use it, so two
// statements that contradict each other prove it after both have expired
func VerifyStatement(p jcrypto.CryptoProvider, pol Policy, addr string, bundle []byte) (*Verified, error) {
	return verifyBundle(p, pol, addr, bundle, time.Time{}, false)
}

func verifyBundle(p jcrypto.CryptoProvider, pol Policy, addr string, bundle []byte, now time.Time, clock bool) (*Verified, error) {
	if pol.Anchor.Suite != p.Suite() {
		return nil, ErrSuite
	}
	b, err := ParseBundle(bundle)
	if err != nil {
		return nil, err
	}
	if b.Suite != p.Suite().String() {
		return nil, ErrSuite
	}

	c, err := ParseCert(b.Cert)
	if err != nil {
		return nil, err
	}
	if c.Suite != p.Suite() {
		return nil, ErrSuite
	}
	if c.CAID != pol.Anchor.ID(p) {
		return nil, ErrUnknownCA
	}
	if !p.Verify(pol.Anchor.Pub, signed(certDomain, c.body()), c.Sig) {
		return nil, ErrCertSignature
	}
	skew := max(pol.Skew, 0)
	if err := certWindow(c, now, skew, clock); err != nil {
		return nil, err
	}
	if c.Addr != addr {
		return nil, ErrWrongAddr
	}

	d, err := ParseDescriptor(b.Descriptor)
	if err != nil {
		return nil, err
	}
	if d.Suite != p.Suite() {
		return nil, ErrSuite
	}
	if !bytes.Equal(d.CertHash[:], p.Hash(b.Cert)) {
		return nil, ErrCertMismatch
	}
	if !p.Verify(c.Identity, signed(descriptorDomain, d.body()), d.Sig) {
		return nil, ErrDescSignature
	}
	if err := descWindow(d, c, now, skew, pol.maxLife(), pol.MinLife, clock); err != nil {
		return nil, err
	}
	if err := keySizes(p, d); err != nil {
		return nil, err
	}
	return &Verified{
		Addr:      c.Addr,
		Name:      c.Name,
		Identity:  c.Identity,
		CertHash:  d.CertHash,
		LinkPub:   d.LinkPub,
		OnionPub:  d.OnionPub,
		Epoch:     d.Epoch,
		CertUntil: time.Unix(c.NotAfter, 0),
		DescFrom:  time.Unix(d.Published, 0),
		DescUntil: time.Unix(d.Expires, 0),
	}, nil
}

// the check of an enrollment, whose operator can act on both names: a bundle
// that fails, or two nodes with one address, onion key or identity, refuse the
// list; a client verifies every bundle on its own
func VerifyChain(p jcrypto.CryptoProvider, pol Policy, addrs []string, bundles [][]byte, now time.Time) ([]Verified, error) {
	if len(addrs) != len(bundles) {
		return nil, fmt.Errorf("pki: %d addresses for %d bundles", len(addrs), len(bundles))
	}
	nodes := make([]Verified, len(addrs))
	for i, addr := range addrs {
		v, err := Verify(p, pol, addr, bundles[i], now)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", addr, err)
		}
		nodes[i] = *v
	}
	for i := range nodes {
		for j := range i {
			a, b := &nodes[j], &nodes[i]
			if a.Addr == b.Addr || bytes.Equal(a.OnionPub, b.OnionPub) ||
				len(a.Identity) > 0 && bytes.Equal(a.Identity, b.Identity) {
				return nil, fmt.Errorf("nodes %s and %s: %w", a.Addr, b.Addr, ErrDuplicate)
			}
		}
	}
	return nodes, nil
}

// the baseline for measuring what authentication is worth: the same bundle
// read with no signature, time or address checked, and with no identity
func Unverified(p jcrypto.CryptoProvider, addr string, bundle []byte) (*Verified, error) {
	b, err := ParseBundle(bundle)
	if err != nil {
		return nil, err
	}
	if b.Suite != p.Suite().String() {
		return nil, ErrSuite
	}
	d, err := ParseDescriptor(b.Descriptor)
	if err != nil {
		return nil, err
	}
	if d.Suite != p.Suite() {
		return nil, ErrSuite
	}
	if err := keySizes(p, d); err != nil {
		return nil, err
	}
	return &Verified{Addr: addr, LinkPub: d.LinkPub, OnionPub: d.OnionPub, Epoch: d.Epoch}, nil
}

// the shape of the window is checked always, its position against now only
// with clock
func certWindow(c *Cert, now time.Time, skew time.Duration, clock bool) error {
	if c.NotAfter <= c.NotBefore {
		return ErrCertTime
	}
	if clock && (now.Add(skew).Unix() < c.NotBefore || now.Unix() >= c.NotAfter) {
		return ErrCertTime
	}
	return nil
}

func descWindow(d *Descriptor, c *Cert, now time.Time, skew, maxLife, minLife time.Duration, clock bool) error {
	switch {
	case d.Expires <= d.Published, d.Expires > c.NotAfter:
		return ErrDescTime
	// the difference of two int64 can overflow, the unsigned one cannot once
	// expires is known to be the larger
	case uint64(d.Expires)-uint64(d.Published) > uint64(maxLife/time.Second):
		return ErrDescTime
	case minLife > 0 && d.Expires != c.NotAfter && uint64(d.Expires)-uint64(d.Published) < uint64(minLife/time.Second):
		return ErrDescLife
	case clock && (now.Add(skew).Unix() < d.Published || now.Unix() >= d.Expires):
		return ErrDescTime
	}
	return nil
}

func keySizes(p jcrypto.CryptoProvider, d *Descriptor) error {
	size, err := wire.PublicKeySize(p)
	if err != nil {
		return err
	}
	if len(d.LinkPub) != size || len(d.OnionPub) != size {
		return ErrKeySize
	}
	return nil
}
