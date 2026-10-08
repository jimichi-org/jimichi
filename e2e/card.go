package e2e

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

const (
	cardVersion  = 1
	exchangeCard = "e2e/card"
)

var ErrCard = errors.New("e2e: bad contact card")

// the agreement key length is a part of the card format, so a card decodes
// without a provider; a test holds it equal to wire.PublicKeySize
var staticSize = map[jcrypto.Suite]int{
	jcrypto.SuiteGOST:   64,
	jcrypto.SuiteC25519: 32,
}

type Card struct {
	Suite   jcrypto.Suite
	Mailbox string
	Queue   [QueueSize]byte
	Static  []byte
}

// u8 version | u8 suite | u8 len(mailbox) | mailbox | queue | static key
func (c Card) Bytes() []byte {
	b := make([]byte, 0, 3+len(c.Mailbox)+QueueSize+len(c.Static))
	b = append(b, cardVersion, byte(c.Suite), byte(len(c.Mailbox)))
	b = append(b, c.Mailbox...)
	b = append(b, c.Queue[:]...)
	return append(b, c.Static...)
}

func (c Card) String() string {
	return c.Suite.String() + ":" + base64.StdEncoding.EncodeToString(c.Bytes())
}

func (c Card) valid() bool {
	size, ok := staticSize[c.Suite]
	return ok && pki.ValidAddr(c.Mailbox) && c.Queue != [QueueSize]byte{} && len(c.Static) == size
}

// only the canonical encoding decodes: no trailing bytes, a known suite, a
// mailbox address as pki spells it and a queue that is not all zeroes
func DecodeCard(b []byte) (Card, error) {
	if len(b) < 3 || b[0] != cardVersion {
		return Card{}, ErrCard
	}
	suite, n := jcrypto.Suite(b[1]), int(b[2])
	size, ok := staticSize[suite]
	if !ok || len(b) != 3+n+QueueSize+size {
		return Card{}, ErrCard
	}
	c := Card{Suite: suite, Mailbox: string(b[3 : 3+n])}
	copy(c.Queue[:], b[3+n:])
	c.Static = bytes.Clone(b[3+n+QueueSize:])
	if !c.valid() {
		return Card{}, ErrCard
	}
	return c, nil
}

// "<suite>:<base64 with padding>", the suite named in the prefix and in the
// card the same
func ParseCard(s string) (Card, error) {
	name, enc, ok := strings.Cut(s, ":")
	if !ok {
		return Card{}, ErrCard
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(enc)
	if err != nil {
		return Card{}, ErrCard
	}
	c, err := DecodeCard(raw)
	if err != nil || c.Suite.String() != name {
		return Card{}, ErrCard
	}
	// the decoder skips line breaks, so only a round trip proves the one spelling
	if c.String() != s {
		return Card{}, ErrCard
	}
	return c, nil
}

// the whole transcript hash: a short fingerprint could be matched by a key
// ground out for the purpose
func CardHash(p jcrypto.CryptoProvider, c Card) ([]byte, error) {
	if p == nil || c.Suite != p.Suite() || !c.valid() {
		return nil, ErrCard
	}
	ctx, err := jcrypto.NewContext(p, exchangeCard, c.Bytes())
	if err != nil {
		return nil, err
	}
	return ctx.Sum(), nil
}

func (c Card) equal(o Card) bool { return bytes.Equal(c.Bytes(), o.Bytes()) }
