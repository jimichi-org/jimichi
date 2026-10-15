// Package profile is the -peer client in a vault volume: the volume holds the
// contact's card, and the identity its key derives gives the client's own.
package profile

import (
	"bytes"
	"errors"
	"fmt"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/vault"
)

const (
	version = 1
	// the mailbox length in a card is one byte and the longest key is GOST's
	maxContent = 1 + 3 + 255 + e2e.QueueSize + 64
)

var (
	errNoProvider = errors.New("profile: no provider or volume")
	errTaken      = errors.New("profile: the identity is taken or closed")
	errMailbox    = errors.New("profile: the volume names another mailbox")
)

// owns the pair and F
type Profile struct {
	Pair    *noise.KeyPair
	Fetch   *secmem.Buffer
	Card    e2e.Card
	Contact e2e.Card
}

// builds the own card from the volume's identity; a contact given here is
// checked as PUT /contact checks it, and without one nothing is written
func New(p jcrypto.CryptoProvider, mailboxAddr string, contact *e2e.Card) vault.Fill {
	return func(id *vault.Identity, buf []byte) (int, error) {
		if p == nil || id == nil {
			return 0, errNoProvider
		}
		own, err := ownCard(p, id.Public(), id.Fetch(), mailboxAddr)
		if err != nil {
			return 0, err
		}
		if contact == nil {
			return 0, nil
		}
		if err := checkContact(p, own, *contact); err != nil {
			return 0, err
		}
		self, err := e2e.NewIdentityFrom(p, id, own)
		if err != nil {
			return 0, err
		}
		defer self.Close()
		if err := passes(p, self, *contact); err != nil {
			return 0, err
		}
		return put(buf, *contact)
	}
}

// for Draft.Write once the identity is taken: the contact is checked against
// the own card by public values, and its key against a pair thrown away at once
func WithContact(p jcrypto.CryptoProvider, own, contact e2e.Card) vault.Fill {
	return func(_ *vault.Identity, buf []byte) (int, error) {
		if p == nil {
			return 0, errNoProvider
		}
		if _, err := e2e.DecodeCard(own.Bytes()); err != nil || own.Suite != p.Suite() {
			return 0, e2e.ErrCard
		}
		if err := checkContact(p, own, contact); err != nil {
			return 0, err
		}
		tmp, err := e2e.NewIdentity(p, own.Mailbox, own.Queue)
		if err != nil {
			return 0, err
		}
		defer tmp.Close()
		if err := passes(p, tmp, contact); err != nil {
			return 0, err
		}
		return put(buf, contact)
	}
}

// every refusal of the content is ErrCard, and on a refusal the volume keeps
// its identity
func Parse(p jcrypto.CryptoProvider, v *vault.Volume) (*Profile, error) {
	if p == nil || v == nil {
		return nil, errNoProvider
	}
	content := v.Content()
	if len(content) < 2 || len(content) > maxContent || content[0] != version {
		return nil, e2e.ErrCard
	}
	contact, err := e2e.DecodeCard(content[1:])
	if err != nil || contact.Suite != p.Suite() {
		return nil, e2e.ErrCard
	}
	id := v.Identity()
	own, err := ownCard(p, id.Public(), id.Fetch(), contact.Mailbox)
	if errors.Is(err, e2e.ErrCard) {
		return nil, e2e.ErrCard
	}
	if err != nil {
		return nil, err
	}
	if bytes.Equal(contact.Static, own.Static) || contact.Queue == own.Queue {
		return nil, e2e.ErrCard
	}
	priv, pub, fetch := id.Take()
	if priv == nil || fetch == nil {
		if priv != nil {
			priv.Release()
		}
		if fetch != nil {
			fetch.Release()
		}
		return nil, errTaken
	}
	return &Profile{Pair: noise.NewKeyPair(p, priv, pub), Fetch: fetch, Card: own, Contact: contact}, nil
}

// the own card has the contact's address by construction
func (pr *Profile) Fit(mailboxAddr string) error {
	if pr.Contact.Mailbox != mailboxAddr {
		return errMailbox
	}
	return nil
}

// the profile keeps the key: closing the identity leaves it
func (pr *Profile) Identity(p jcrypto.CryptoProvider) (*e2e.Identity, error) {
	if pr.Pair == nil {
		return nil, errTaken
	}
	return e2e.NewIdentityFrom(p, pr.Pair, pr.Card)
}

func (pr *Profile) Close() {
	if pr.Pair != nil {
		pr.Pair.Close()
	}
	if pr.Fetch != nil {
		pr.Fetch.Release()
	}
}

// the round trip refuses a queue of zeroes too, which F gives with a chance
// of about 2^-128
func ownCard(p jcrypto.CryptoProvider, pub []byte, fetch *secmem.Buffer, addr string) (e2e.Card, error) {
	if fetch == nil {
		return e2e.Card{}, errTaken
	}
	queue, err := mailbox.QueueID(p, fetch.Bytes())
	if err != nil {
		return e2e.Card{}, err
	}
	c := e2e.Card{Suite: p.Suite(), Mailbox: addr, Queue: queue, Static: pub}
	return e2e.DecodeCard(c.Bytes())
}

func checkContact(p jcrypto.CryptoProvider, own, contact e2e.Card) error {
	if _, err := e2e.DecodeCard(contact.Bytes()); err != nil {
		return err
	}
	switch {
	case contact.Suite != p.Suite() || contact.Suite != own.Suite:
		return fmt.Errorf("%w: the card is of another suite", e2e.ErrCard)
	case contact.Mailbox != own.Mailbox:
		return fmt.Errorf("%w: the card names another mailbox", e2e.ErrCard)
	case bytes.Equal(contact.Static, own.Static) || contact.Queue == own.Queue:
		return fmt.Errorf("%w: the card is this client's own", e2e.ErrSelf)
	}
	return nil
}

// a session runs the one-time agreement that refuses a key no handshake
// would take
func passes(p jcrypto.CryptoProvider, self *e2e.Identity, contact e2e.Card) error {
	s, err := e2e.NewSession(p, self, contact, e2e.Options{})
	if err != nil {
		return err
	}
	s.Close()
	return nil
}

func put(buf []byte, contact e2e.Card) (int, error) {
	b := contact.Bytes()
	n := 1 + len(b)
	if n > maxContent || n > len(buf) {
		return 0, vault.ErrTooLarge
	}
	buf[0] = version
	copy(buf[1:], b)
	return n, nil
}
