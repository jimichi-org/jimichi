package e2e

import (
	"bytes"
	"errors"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/noise"
)

// a client's identity is an agreement key and never a signing key: an identity
// signature over a message would prove to anyone who sent it
type Identity struct {
	static noise.Static
	own    *noise.KeyPair
	card   Card
}

func NewIdentity(p jcrypto.CryptoProvider, mailbox string, queue [QueueSize]byte) (*Identity, error) {
	if p == nil {
		return nil, errors.New("e2e: no provider")
	}
	card := Card{Suite: p.Suite(), Mailbox: mailbox, Queue: queue, Static: make([]byte, staticSize[p.Suite()])}
	if !card.valid() {
		return nil, ErrCard
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	kp := noise.NewKeyPair(p, priv, pub)
	card.Static = bytes.Clone(pub)
	if !card.valid() {
		kp.Close()
		return nil, ErrCard
	}
	return &Identity{static: kp, own: kp, card: card}, nil
}

// the identity uses static but does not own it: Close leaves it to the caller
func NewIdentityFrom(p jcrypto.CryptoProvider, static noise.Static, card Card) (*Identity, error) {
	if p == nil || static == nil || card.Suite != p.Suite() || !card.valid() {
		return nil, ErrCard
	}
	if !bytes.Equal(card.Static, static.Public()) {
		return nil, ErrCard
	}
	card.Static = bytes.Clone(card.Static)
	return &Identity{static: static, card: card}, nil
}

func (id *Identity) Card() Card {
	c := id.card
	c.Static = bytes.Clone(c.Static)
	return c
}

func (id *Identity) Static() noise.Static { return id.static }

func (id *Identity) Close() {
	if id.own != nil {
		id.own.Close()
	}
}
