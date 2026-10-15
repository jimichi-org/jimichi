package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/vault"
)

func seq(first byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// the identity vector of vault: W = 40 41 .. 5f stands for PasswordKey, salt
// = 00 01 .. 1f, the volume in area 0. The own card is that of the identity
// for s = 0 with the address relay-5.jimichi.svc.cluster.local:9000 of the
// contact, whose card is that of the identity for s = 1:
//
//	queue = H("jimichi/v2/<suite>/transcript/mailbox/queue" || 00 || 01 || 0010 || F)[:16]
//	card  = 01 || u8(suite) || u8(len(address)) || address || queue || pub
//
// The values were computed as the identity vector of vault was, the queue and
// the card with the same hash in Python. The vault function of the identity
// is not exported, so the test builds the file of the vector from the format
// of the file and lets Open and Parse derive the card
var goldenCards = map[jcrypto.Suite]struct{ pub, fetch, queue, card, contact string }{
	jcrypto.SuiteC25519: {
		pub:     "32612529fbb315e4f048d8b8825cf7f5688cc34e64951fd7660ca14e65ab0747",
		fetch:   "1e0c8b31855d0d800492e62cf4436128",
		queue:   "7e42c1e53ff00a6f5d26fe4611b991d3",
		card:    "01022672656c61792d352e6a696d696368692e7376632e636c75737465722e6c6f63616c3a393030307e42c1e53ff00a6f5d26fe4611b991d332612529fbb315e4f048d8b8825cf7f5688cc34e64951fd7660ca14e65ab0747",
		contact: "01022672656c61792d352e6a696d696368692e7376632e636c75737465722e6c6f63616c3a393030308ee8e15a075dec45fbfbfcb7fb94e12187c877264cbdb46065760940b0882567d1e4e0a8e6f03fea21ac8a79a7ffd119",
	},
	jcrypto.SuiteGOST: {
		pub: "73a3e8e487ea1aedd5ec27137ea4e3e1681c89a829d7168b2deaa8b56d4a3bb4" +
			"688965d8da92054c8ee300d602acfbda4207cbd168e588f3faca08a453b316c7",
		fetch: "a7aa56b28501971de66fa3a2017ef406",
		queue: "3a0a4f1e9ef1629af30437dafeae0141",
		card: "01012672656c61792d352e6a696d696368692e7376632e636c75737465722e6c6f63616c3a393030303a0a4f1e9ef1629af30437dafeae0141" +
			"73a3e8e487ea1aedd5ec27137ea4e3e1681c89a829d7168b2deaa8b56d4a3bb4688965d8da92054c8ee300d602acfbda4207cbd168e588f3faca08a453b316c7",
		contact: "01012672656c61792d352e6a696d696368692e7376632e636c75737465722e6c6f63616c3a39303030471d68f846a44100f7ccbfe63fde6943" +
			"532993c5843a03ab89f9b3f6aa3c97eab01c99fa1191467f222c37bca834c4878635ba4cbf2cac6a2b25af5ef24c8c1476fcf1dd8b7d0a4552492f40fb8f6550",
	},
}

func TestGoldenOwnCard(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		g, ok := goldenCards[p.Suite()]
		if !ok {
			t.Fatalf("no golden card for %v", p.Suite())
		}
		p.w = seq(0x40, 32)
		contact, err := e2e.DecodeCard(unhex(t, g.contact))
		if err != nil {
			t.Fatal(err)
		}
		path := vaultPath(t)
		if err := os.WriteFile(path, goldenFile(t, p, versioned(contact)), 0o600); err != nil {
			t.Fatal(err)
		}
		pr := parse(t, p, open(t, p, path, "any password"))
		switch {
		case hex.EncodeToString(pr.Pair.Public()) != g.pub:
			t.Fatalf("pub %x, want %s", pr.Pair.Public(), g.pub)
		case hex.EncodeToString(pr.Fetch.Bytes()) != g.fetch:
			t.Fatalf("F %x, want %s", pr.Fetch.Bytes(), g.fetch)
		case hex.EncodeToString(pr.Card.Queue[:]) != g.queue:
			t.Fatalf("queue %x, want %s", pr.Card.Queue, g.queue)
		case hex.EncodeToString(pr.Card.Bytes()) != g.card:
			t.Fatalf("own card %x\nwant %s", pr.Card.Bytes(), g.card)
		case !bytes.Equal(pr.Contact.Bytes(), contact.Bytes()):
			t.Fatalf("contact %x", pr.Contact.Bytes())
		}
	})
}

// the file of ARCHITECTURE, section "Client container", for the W of the spy,
// salt 00 .. 1f and content in area 0, with random bytes in area 1:
//
//	k_0   = DeriveKey(W, "vault/volume", NewContext(p, "vault/volume", salt, [0]), 32)
//	ctx_b = NewContext(p, "vault/block", [0], r)
//	area  = r || Seal(DeriveKey(k_0, "vault/block", ctx_b, 32), nonce 0, u16be(L) || content || zeroes, ctx_b.Sum())
func goldenFile(t *testing.T, p jcrypto.CryptoProvider, content []byte) []byte {
	t.Helper()
	salt := seq(0x00, vault.SaltSize)
	w, err := secmem.NewFrom(seq(0x40, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Release()
	ctx, err := jcrypto.NewContext(p, "vault/volume", salt, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	k, err := p.DeriveKey(w, "vault/volume", ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Release()
	r := seq(0x80, 32)
	ctxB, err := jcrypto.NewContext(p, "vault/block", []byte{0}, r)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := p.DeriveKey(k, "vault/block", ctxB, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer kb.Release()
	a, err := p.NewAEAD(kb)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Destroy()
	plain := make([]byte, vault.RegionSize-32-a.Overhead())
	plain[0], plain[1] = byte(len(content)>>8), byte(len(content))
	copy(plain[2:], content)
	file := append(bytes.Clone(salt), r...)
	file = a.Seal(file, make([]byte, a.NonceSize()), plain, ctxB.Sum())
	other := make([]byte, vault.RegionSize)
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	file = append(file, other...)
	if len(file) != vault.FileSize {
		t.Fatalf("a file of %d bytes", len(file))
	}
	return file
}
