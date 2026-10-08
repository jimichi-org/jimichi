package scenario_test

import (
	"bytes"
	"errors"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/lab/scenario"
	"github.com/jimichi-org/jimichi/noise"
)

// the sender is drawn outside the package, before any call into it, and its
// private key is wiped before the first one: no copy exists for Forge, Verify
// or Control to reach, yet the forgery verifies and the control is refused
func TestForgeryWithTheSendersKeyWiped(t *testing.T) {
	lines := []scenario.Line{
		{FromSender: true, Body: []byte("the meeting moves to thursday")},
		{Body: []byte("noted")},
		{FromSender: true, Body: []byte("bring the signed copy")},
	}
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []e2e.Role{e2e.RoleInitiator, e2e.RoleResponder} {
			t.Run(s.String()+"/recipient-"+role.String(), func(t *testing.T) {
				sender, recipient := drawPair(t, p, role)
				t.Cleanup(recipient.Close)
				card := sender.Card()
				ctx, err := jcrypto.NewContext(p, "test", []byte{1})
				if err != nil {
					t.Fatal(err)
				}
				sender.Close()
				if _, err := sender.Static().Agree(recipient.Card().Static, ctx); !errors.Is(err, noise.ErrClosed) {
					t.Fatalf("the sender's key agrees after Close: %v", err)
				}

				tr, ev, err := scenario.Forge(p, recipient, card, lines)
				if err != nil {
					t.Fatalf("Forge: %v", err)
				}
				t.Cleanup(ev.Release)
				said, err := scenario.Verify(p, recipient, ev, tr)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if len(said) != 2 || !bytes.Equal(said[0], lines[0].Body) || !bytes.Equal(said[1], lines[2].Body) {
					t.Fatalf("Verify read %q", said)
				}
				if !bytes.Equal(tr.Sender.Bytes(), card.Bytes()) || tr.Records[0].FromSender != (role == e2e.RoleResponder) {
					t.Fatal("the forgery names another sender or puts the roles otherwise")
				}
				run, err := scenario.Control(p, recipient, card, lines)
				if err != nil {
					t.Fatalf("Control: %v", err)
				}
				defer run.Close()
				if !run.Rejected() {
					t.Fatalf("the control is not refused at a record: %v", run.Refusal)
				}
			})
		}
	}
}

// the rule of e2e: the smaller identity key initiates
func drawPair(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) (sender, recipient *e2e.Identity) {
	t.Helper()
	for range 64 {
		s, err := e2e.NewIdentity(p, scenario.Mailbox, [e2e.QueueSize]byte{0x0a})
		if err != nil {
			t.Fatal(err)
		}
		r, err := e2e.NewIdentity(p, scenario.Mailbox, [e2e.QueueSize]byte{0x0b})
		if err != nil {
			t.Fatal(err)
		}
		if (bytes.Compare(r.Card().Static, s.Card().Static) < 0) == (role == e2e.RoleInitiator) {
			return s, r
		}
		s.Close()
		r.Close()
	}
	t.Fatal("no pair took the role")
	return nil, nil
}
