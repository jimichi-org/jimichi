package e2e

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/wire"
)

func TestStaticSizeIsTheSuiteKeySize(t *testing.T) {
	for s, size := range staticSize {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		if want, err := wire.PublicKeySize(p); err != nil || want != size {
			t.Fatalf("%v: card key size %d, the suite's %d (%v)", s, size, want, err)
		}
	}
}

func TestCardRoundTrip(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		c := newIdentity(t, p).Card()
		raw := c.Bytes()
		want := 3 + len(testMailbox) + QueueSize + staticSize[p.Suite()]
		if len(raw) != want || len(testMailbox) != 38 {
			t.Fatalf("card of %d bytes, want %d", len(raw), want)
		}
		got, err := DecodeCard(raw)
		if err != nil || !got.equal(c) {
			t.Fatalf("DecodeCard: %v", err)
		}
		parsed, err := ParseCard(c.String())
		if err != nil || !parsed.equal(c) {
			t.Fatalf("ParseCard(%q): %v", c.String(), err)
		}
		if !strings.HasPrefix(c.String(), p.Suite().String()+":") {
			t.Fatalf("card text %q", c.String())
		}
	})
}

func TestCardIsCanonical(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		c := newIdentity(t, p).Card()
		raw := c.Bytes()
		edit := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(raw)) }
		other := jcrypto.SuiteGOST
		if p.Suite() == jcrypto.SuiteGOST {
			other = jcrypto.SuiteC25519
		}
		for _, tc := range []struct {
			name string
			b    []byte
		}{
			{"empty", nil},
			{"a trailing byte", append(bytes.Clone(raw), 0)},
			{"one byte short", raw[:len(raw)-1]},
			{"version 0", edit(func(b []byte) []byte { b[0] = 0; return b })},
			{"version 2", edit(func(b []byte) []byte { b[0] = 2; return b })},
			{"unknown suite", edit(func(b []byte) []byte { b[1] = 9; return b })},
			{"the other suite", edit(func(b []byte) []byte { b[1] = byte(other); return b })},
			{"address length off by one", edit(func(b []byte) []byte { b[2]++; return b })},
			{"address in upper case", edit(func(b []byte) []byte { b[3] = 'R'; return b })},
			{"address without a port", edit(func(b []byte) []byte {
				return Card{Suite: c.Suite, Mailbox: "relay-5", Queue: c.Queue, Static: c.Static}.Bytes()
			})},
			{"zero queue", Card{Suite: c.Suite, Mailbox: c.Mailbox, Static: c.Static}.Bytes()},
			{"short key", Card{Suite: c.Suite, Mailbox: c.Mailbox, Queue: c.Queue, Static: c.Static[1:]}.Bytes()},
		} {
			if _, err := DecodeCard(tc.b); !errors.Is(err, ErrCard) {
				t.Fatalf("DecodeCard(%s): %v, want ErrCard", tc.name, err)
			}
		}

		text := c.String()
		enc := strings.TrimPrefix(text, p.Suite().String()+":")
		for _, tc := range []struct{ name, s string }{
			{"no prefix", enc},
			{"other prefix", other.String() + ":" + enc},
			{"unknown prefix", "x25519:" + enc},
			{"no padding", strings.TrimRight(text, "=")},
			{"url alphabet", p.Suite().String() + ":" + base64.URLEncoding.EncodeToString(raw)},
			{"a line break", text[:20] + "\n" + text[20:]},
			{"a space", text + " "},
			{"empty", ""},
		} {
			if _, err := ParseCard(tc.s); !errors.Is(err, ErrCard) {
				t.Fatalf("ParseCard(%s): %v, want ErrCard", tc.name, err)
			}
		}
	})
}

func TestCardHash(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		c := newIdentity(t, p).Card()
		h, err := CardHash(p, c)
		if err != nil || len(h) != jcrypto.ContextSize {
			t.Fatalf("CardHash: %x, %v", h, err)
		}
		ctx, err := jcrypto.NewContext(p, "e2e/card", c.Bytes())
		if err != nil || !bytes.Equal(ctx.Sum(), h) {
			t.Fatal("card hash is not the e2e/card transcript hash")
		}
		c.Queue[0] ^= 1
		if h2, _ := CardHash(p, c); bytes.Equal(h, h2) {
			t.Fatal("a changed card hashes the same")
		}
		bad := c
		bad.Queue = [QueueSize]byte{}
		if _, err := CardHash(p, bad); !errors.Is(err, ErrCard) {
			t.Fatalf("CardHash of an invalid card: %v", err)
		}
		other, _ := suite.New(otherSuiteOf(p))
		if _, err := CardHash(other, c); !errors.Is(err, ErrCard) {
			t.Fatalf("CardHash under another suite: %v", err)
		}
	})
}

func otherSuiteOf(p jcrypto.CryptoProvider) jcrypto.Suite {
	if p.Suite() == jcrypto.SuiteGOST {
		return jcrypto.SuiteC25519
	}
	return jcrypto.SuiteGOST
}

func TestIdentityRefusesBadInput(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, tc := range []struct {
			name    string
			mailbox string
			queue   [QueueSize]byte
		}{
			{"bad address", "relay-5", randomQueue(t)},
			{"empty address", "", randomQueue(t)},
			{"zero queue", testMailbox, [QueueSize]byte{}},
		} {
			if _, err := NewIdentity(p, tc.mailbox, tc.queue); !errors.Is(err, ErrCard) {
				t.Fatalf("NewIdentity(%s): %v, want ErrCard", tc.name, err)
			}
		}

		id, other := newIdentity(t, p), newIdentity(t, p)
		if _, err := NewIdentityFrom(p, id.Static(), other.Card()); !errors.Is(err, ErrCard) {
			t.Fatalf("NewIdentityFrom with another key's card: %v", err)
		}
		if _, err := NewIdentityFrom(p, nil, id.Card()); !errors.Is(err, ErrCard) {
			t.Fatalf("NewIdentityFrom without a key: %v", err)
		}
		q, _ := suite.New(otherSuiteOf(p))
		if _, err := NewIdentityFrom(q, id.Static(), id.Card()); !errors.Is(err, ErrCard) {
			t.Fatalf("NewIdentityFrom under another suite: %v", err)
		}
		same, err := NewIdentityFrom(p, id.Static(), id.Card())
		if err != nil || !same.Card().equal(id.Card()) {
			t.Fatalf("NewIdentityFrom with its own card: %v", err)
		}
		// the borrowed key stays with its owner
		same.Close()
		if _, ok := id.Static().(*noise.KeyPair); !ok {
			t.Fatal("NewIdentity holds no key pair")
		}
		other2 := newIdentity(t, p)
		if _, err := NewSession(p, id, other2.Card(), Options{}); err != nil {
			t.Fatalf("the identity lost its key to a borrower's Close: %v", err)
		}
	})
}

func FuzzParseCard(f *testing.F) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			f.Fatal(err)
		}
		id, err := NewIdentity(p, testMailbox, [QueueSize]byte{1})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(id.Card().String())
		id.Close()
	}
	f.Add("c25519:")
	f.Add("gost:AQEA")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCard(s)
		if err != nil {
			return
		}
		if c.String() != s {
			t.Fatalf("%q parsed but prints as %q", s, c.String())
		}
		again, err := DecodeCard(c.Bytes())
		if err != nil || !again.equal(c) {
			t.Fatalf("%q: the decoded card does not decode again: %v", s, err)
		}
	})
}
