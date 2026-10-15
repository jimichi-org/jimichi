package profile

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/vault"
)

const otherMailbox = "relay-4.jimichi.svc.cluster.local:9000"

func TestRoundTrip(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		contact := peerCard(t, p, testMailbox)
		path := create(t, p, vault.Contents{Password: password(t, "pw"), Fill: New(p, testMailbox, &contact)})
		v := open(t, p, path, "pw")
		if got, want := v.Content(), versioned(contact); !bytes.Equal(got, want) {
			t.Fatalf("content %x, want the version and the card %x", got, want)
		}
		want := cardOf(t, p, v.Identity(), contact.Mailbox)
		pr := parse(t, p, v)
		if !bytes.Equal(pr.Card.Bytes(), want.Bytes()) {
			t.Fatalf("own card %x, want %x", pr.Card.Bytes(), want.Bytes())
		}
		if !bytes.Equal(pr.Contact.Bytes(), contact.Bytes()) {
			t.Fatalf("contact %x, want %x", pr.Contact.Bytes(), contact.Bytes())
		}
		if !bytes.Equal(pr.Pair.Public(), pr.Card.Static) {
			t.Fatal("the pair is not the key of the own card")
		}
		if q, err := mailbox.QueueID(p, pr.Fetch.Bytes()); err != nil || q != pr.Card.Queue {
			t.Fatalf("F names queue %x, the card %x: %v", q, pr.Card.Queue, err)
		}
		if _, err := v.Identity().Agree(contact.Static, jcrypto.Context{}); err == nil {
			t.Fatal("the volume still agrees after Parse took its identity")
		}

		again := parse(t, p, open(t, p, path, "pw"))
		if !bytes.Equal(again.Card.Bytes(), pr.Card.Bytes()) || !bytes.Equal(again.Fetch.Bytes(), pr.Fetch.Bytes()) {
			t.Fatal("a second open gave another own card or F")
		}
	})
}

func TestTwoVolumes(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		a, b := peerCard(t, p, testMailbox), peerCard(t, p, testMailbox)
		path := create(t, p,
			vault.Contents{Password: password(t, "a"), Fill: New(p, testMailbox, &a)},
			vault.Contents{Password: password(t, "b"), Fill: New(p, testMailbox, &b)})
		pa, pb := parse(t, p, open(t, p, path, "a")), parse(t, p, open(t, p, path, "b"))
		if !bytes.Equal(pa.Contact.Bytes(), a.Bytes()) || !bytes.Equal(pb.Contact.Bytes(), b.Bytes()) {
			t.Fatal("a password opened the other volume's contact")
		}
		if bytes.Equal(pa.Card.Static, pb.Card.Static) || pa.Card.Queue == pb.Card.Queue {
			t.Fatal("two volumes with one identity")
		}
	})
}

// the first volume may wait for its contact until Write; the identity is taken
// by then, so WithContact checks against the own card
func TestContactAtWrite(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		d, err := vault.Prepare(p, vault.Contents{Password: password(t, "pw"), Fill: New(p, testMailbox, nil)})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		path := vaultPath(t)
		wantErr(t, "Write without a contact", d.Write(path, nil), vault.ErrEmpty)
		noFile(t, path)

		own := cardOf(t, p, d.Identity(), testMailbox)
		priv, pub, fetch := d.Identity().Take()
		kp := noise.NewKeyPair(p, priv, pub)
		defer kp.Close()
		defer fetch.Release()

		contact := peerCard(t, p, testMailbox)
		if err := d.Write(path, WithContact(p, own, contact)); err != nil {
			t.Fatal(err)
		}
		pr := parse(t, p, open(t, p, path, "pw"))
		if !bytes.Equal(pr.Card.Bytes(), own.Bytes()) || !bytes.Equal(pr.Contact.Bytes(), contact.Bytes()) {
			t.Fatal("the volume does not give back the own card and the contact of the draft")
		}
		if !bytes.Equal(pr.Fetch.Bytes(), fetch.Bytes()) {
			t.Fatal("the volume gives another F than the draft")
		}
	})
}

func TestSecondVolumeNeedsContact(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		contact := peerCard(t, p, testMailbox)
		path := vaultPath(t)
		err := vault.Create(p, path,
			vault.Contents{Password: password(t, "a"), Fill: New(p, testMailbox, &contact)},
			vault.Contents{Password: password(t, "b"), Fill: New(p, testMailbox, nil)})
		wantErr(t, "a second volume without a contact", err, vault.ErrEmpty)
		noFile(t, path)
	})
}

// each rule refuses with ErrCard and leaves the identity to the volume
func TestParseRules(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		contact := peerCard(t, p, testMailbox)
		good := versioned(contact)
		// version, card version, suite, address length, then the address
		badAddr := versioned(contact)
		badAddr[4] = 'R'
		cases := []struct {
			name    string
			content func(id *vault.Identity) []byte
		}{
			{"version 0", func(*vault.Identity) []byte { return append([]byte{0}, good[1:]...) }},
			{"version 2", func(*vault.Identity) []byte { return append([]byte{2}, good[1:]...) }},
			{"only the version, L = 1", func(*vault.Identity) []byte { return []byte{version} }},
			{"a byte after the card", func(*vault.Identity) []byte { return append(bytes.Clone(good), 0) }},
			{"a card cut short", func(*vault.Identity) []byte { return good[:len(good)-1] }},
			{"a card of another suite", func(*vault.Identity) []byte {
				return versioned(peerCard(t, provider(t, otherSuite(p.Suite())), testMailbox))
			}},
			{"an address that is not canonical", func(*vault.Identity) []byte { return badAddr }},
			{"the own key", func(id *vault.Identity) []byte {
				c := contact
				c.Static = id.Public()
				return versioned(c)
			}},
			{"the own queue", func(id *vault.Identity) []byte {
				c := contact
				c.Queue = cardOf(t, p, id, testMailbox).Queue
				return versioned(c)
			}},
			{"longer than 339 bytes", func(*vault.Identity) []byte {
				return append(bytes.Clone(good), make([]byte, maxContent+1-len(good))...)
			}},
		}
		for _, c := range cases {
			path := create(t, p, vault.Contents{Password: password(t, "pw"), Fill: raw(c.content)})
			v := open(t, p, path, "pw")
			_, err := Parse(p, v)
			wantErr(t, c.name, err, e2e.ErrCard)
			if v.Identity().Fetch() == nil {
				t.Fatalf("%s: a refused volume lost its identity", c.name)
			}
		}

		path := create(t, p, vault.Contents{Password: password(t, "pw"), Fill: raw(func(*vault.Identity) []byte { return good })})
		v := open(t, p, path, "pw")
		_, err := Parse(newSpy(t, provider(t, otherSuite(p.Suite()))), v)
		wantErr(t, "a provider of another suite", err, e2e.ErrCard)
		parse(t, p, v)
	})
}

// the checks of PUT /contact, on the identity in New and on the own card in
// WithContact; the identity stays usable after a refusal
func TestRefusedContacts(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		d, err := vault.Prepare(p, vault.Contents{Password: password(t, "pw"), Fill: New(p, testMailbox, nil)})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		id := d.Identity()
		own := cardOf(t, p, id, testMailbox)
		peer := peerCard(t, p, testMailbox)
		ownKey, ownQueue, zeroKey, shortKey := peer, peer, peer, peer
		ownKey.Static = own.Static
		ownQueue.Queue = own.Queue
		zeroKey.Static = make([]byte, len(peer.Static))
		shortKey.Static = peer.Static[1:]
		cases := []struct {
			name    string
			contact e2e.Card
			want    error
			// whether the card can be refused before the identity exists
			early bool
		}{
			{"another suite", peerCard(t, provider(t, otherSuite(p.Suite())), testMailbox), e2e.ErrCard, true},
			{"another mailbox", peerCard(t, p, otherMailbox), e2e.ErrCard, true},
			{"the own key", ownKey, e2e.ErrSelf, false},
			{"the own queue", ownQueue, e2e.ErrSelf, false},
			{"a key the agreement refuses", zeroKey, e2e.ErrCard, true},
			{"a key of another size", shortKey, e2e.ErrCard, true},
		}
		buf := make([]byte, vault.MaxContent)
		for _, c := range cases {
			n, err := New(p, testMailbox, &c.contact)(id, buf)
			if n != 0 {
				t.Fatalf("New, %s: wrote %d bytes", c.name, n)
			}
			wantErr(t, "New, "+c.name, err, c.want)
			n, err = WithContact(p, own, c.contact)(nil, buf)
			if n != 0 {
				t.Fatalf("WithContact, %s: wrote %d bytes", c.name, n)
			}
			wantErr(t, "WithContact, "+c.name, err, c.want)
			if c.early {
				path := vaultPath(t)
				err := vault.Create(p, path, vault.Contents{Password: password(t, "other"), Fill: New(p, testMailbox, &c.contact)})
				wantErr(t, "Create, "+c.name, err, c.want)
				noFile(t, path)
			}
		}
		if n, err := New(p, testMailbox, &peer)(id, buf); err != nil || n != 1+len(peer.Bytes()) {
			t.Fatalf("New after the refusals: %d, %v", n, err)
		}

		path := vaultPath(t)
		err = vault.Create(p, path, vault.Contents{Password: password(t, "pw"), Fill: New(p, "relay-5", &peer)})
		wantErr(t, "an own mailbox that is not an address", err, e2e.ErrCard)
		noFile(t, path)
		foreign := own
		foreign.Suite = otherSuite(p.Suite())
		if _, err := WithContact(p, foreign, peer)(nil, buf); !errors.Is(err, e2e.ErrCard) {
			t.Fatalf("WithContact with an own card of another suite: %v, want ErrCard", err)
		}
	})
}

// a queue of zeroes comes about once in 2^128; the spy hashes the transcript
// of every queue to zeroes
func TestZeroQueue(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		contact := peerCard(t, p, testMailbox)
		zero := newSpy(t, p.CryptoProvider)
		zero.zeroQueue = true
		for _, c := range []*e2e.Card{nil, &contact} {
			path := vaultPath(t)
			err := vault.Create(zero, path, vault.Contents{Password: password(t, "pw"), Fill: New(zero, testMailbox, c)})
			wantErr(t, "Create with a queue of zeroes", err, e2e.ErrCard)
			noFile(t, path)
		}

		path := create(t, p, vault.Contents{Password: password(t, "pw"), Fill: New(p, testMailbox, &contact)})
		v := open(t, zero, path, "pw")
		_, err := Parse(zero, v)
		wantErr(t, "Parse with a queue of zeroes", err, e2e.ErrCard)
	})
}

// a mailbox length is one byte, so a card is at most 338 bytes and the
// content at most 339; the longest card an address allows is far shorter
func TestAtMost339(t *testing.T) {
	buf := make([]byte, vault.MaxContent)
	long := e2e.Card{Suite: jcrypto.SuiteGOST, Mailbox: strings.Repeat("a", 255), Static: make([]byte, 64)}
	if n, err := put(buf, long); err != nil || n != 339 || maxContent != 339 {
		t.Fatalf("put of a 338-byte card: %d, %v", n, err)
	}
	long.Mailbox += "a"
	if _, err := put(buf, long); !errors.Is(err, vault.ErrTooLarge) {
		t.Fatalf("put of a 340-byte content: %v, want ErrTooLarge", err)
	}

	eachSuite(t, func(t *testing.T, p *spy) {
		addr := strings.Repeat("a", 59) + ":9000"
		contact := peerCard(t, p, addr)
		path := create(t, p, vault.Contents{Password: password(t, "pw"), Fill: New(p, addr, &contact)})
		v := open(t, p, path, "pw")
		if n := len(v.Content()); n != 1+len(contact.Bytes()) || n > maxContent {
			t.Fatalf("content of %d bytes for a card of %d", n, len(contact.Bytes()))
		}
		parse(t, p, v)
	})
}

func TestFit(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		contact := peerCard(t, p, testMailbox)
		path := create(t, p, vault.Contents{Password: password(t, "pw"), Fill: New(p, testMailbox, &contact)})
		pr := parse(t, p, open(t, p, path, "pw"))
		if err := pr.Fit(testMailbox); err != nil {
			t.Fatalf("Fit of the contact's mailbox: %v", err)
		}
		if err := pr.Fit(otherMailbox); err == nil {
			t.Fatal("Fit of another mailbox passed")
		}
	})
}

// the e2e identity uses the profile's key and leaves it on Close; the
// profile releases it
func TestIdentity(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		contact := peerCard(t, p, testMailbox)
		path := create(t, p, vault.Contents{Password: password(t, "pw"), Fill: New(p, testMailbox, &contact)})
		pr, err := Parse(p, open(t, p, path, "pw"))
		if err != nil {
			t.Fatal(err)
		}
		id, err := pr.Identity(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(id.Card().Bytes(), pr.Card.Bytes()) {
			t.Fatal("the identity has another card than the profile")
		}
		s, err := e2e.NewSession(p, id, contact, e2e.Options{})
		if err != nil {
			t.Fatalf("a session with the contact: %v", err)
		}
		s.Close()
		id.Close()

		ctx, err := jcrypto.NewContext(p, "test/agree", contact.Static)
		if err != nil {
			t.Fatal(err)
		}
		k, err := pr.Pair.Agree(contact.Static, ctx)
		if err != nil {
			t.Fatalf("the pair after the identity closed: %v", err)
		}
		k.Release()
		pr.Close()
		if _, err := pr.Pair.Agree(contact.Static, ctx); !errors.Is(err, noise.ErrClosed) {
			t.Fatalf("the pair after Close: %v, want ErrClosed", err)
		}
		if pr.Fetch.Bytes() != nil {
			t.Fatal("F after Close")
		}
	})
}
