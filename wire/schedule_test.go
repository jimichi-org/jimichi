package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/gost"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func derived(t *testing.T, p jcrypto.CryptoProvider, secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) []byte {
	t.Helper()
	b, err := p.DeriveKey(secret, purpose, ctx, size)
	if err != nil {
		t.Fatalf("DeriveKey(%s): %v", purpose, err)
	}
	defer b.Release()
	return bytes.Clone(b.Bytes())
}

// the key schedule of a hop, redone here from the bytes on the wire with the
// transcript and the purposes written out, a second record of what BuildSetup
// and OpenSetup pass to the provider:
//
//	T = "jimichi/v2/<suite>/transcript/setup" || 00 || 05 (06 with identities)
//	    || 0001 version || 0001 hop index || 0008 link id
//	    || u16be(len) onion key || u16be(len) ephemeral key
//	    [|| u16be(len) identity key, for authenticated nodes]
//	secret = Agree(onion private key, ephemeral key, Hash(T))
//	layer key "setup", hop key "cell", replay tag "setup/replay" (16 bytes),
//	offsets "counter/fwd" and "counter/bwd" (8 bytes, top two bits cleared)
//
// the link ids use all eight bytes and the chain has hops past index 0
func TestSetupKeyScheduleByHand(t *testing.T) {
	for _, p := range []jcrypto.CryptoProvider{c25519.New(), gost.New()} {
		for _, authenticated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/identities %v", p.Suite(), authenticated), func(t *testing.T) {
				setupScheduleByHand(t, p, authenticated)
			})
		}
	}
}

func setupScheduleByHand(t *testing.T, p jcrypto.CryptoProvider, authenticated bool) {
	const n = 3
	links := [n]uint64{0x0102030405060708, 0xf1e2d3c4b5a69788, 0x8000000000000001}
	privs := make([]*secmem.Buffer, n)
	chain := make([]SetupHop, n)
	for i := range chain {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer priv.Release()
		privs[i] = priv
		chain[i] = SetupHop{StaticPub: pub, Link: links[i]}
		if authenticated {
			signing, identity, err := p.GenerateSigning()
			if err != nil {
				t.Fatal(err)
			}
			signing.Release()
			chain[i].Identity = identity
		}
		if i < n-1 {
			chain[i].NextAddr, chain[i].NextCircuit = "relay-next:9000", links[i+1]
		}
	}
	setup, err := BuildSetup(p, chain)
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for _, k := range setup.CellKeys {
		defer k.Release()
	}

	cell := setup.Cell
	for i := 0; i < n; i++ {
		pub := chain[i].StaticPub
		eph := bytes.Clone(cell.Body()[:len(pub)])

		keys := [][]byte{pub, eph}
		if authenticated {
			keys = append(keys, chain[i].Identity)
		}
		transcript := []byte("jimichi/v2/" + p.Suite().String() + "/transcript/setup")
		transcript = append(transcript, 0x00, byte(3+len(keys)))
		transcript = append(transcript, 0x00, 0x01, 0x02)
		transcript = append(transcript, 0x00, 0x01, byte(i))
		transcript = append(transcript, 0x00, 0x08)
		transcript = binary.BigEndian.AppendUint64(transcript, links[i])
		for _, k := range keys {
			transcript = append(transcript, byte(len(k)>>8), byte(len(k)))
			transcript = append(transcript, k...)
		}
		id := binary.BigEndian.AppendUint64(nil, links[i])
		ctx, err := jcrypto.NewContext(p, "setup", append([][]byte{{0x02}, {byte(i)}, id}, keys...)...)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ctx.Sum(), p.Hash(transcript)) {
			t.Fatalf("hop %d: the context is not the hash of the transcript written out by hand", i)
		}

		secret, err := p.Agree(privs[i], eph, ctx)
		if err != nil {
			t.Fatalf("hop %d: Agree: %v", i, err)
		}
		setupKey, err := p.DeriveKey(secret, "setup", ctx, p.KeySize())
		if err != nil {
			t.Fatal(err)
		}
		cellKey := derived(t, p, secret, "cell", ctx, p.KeySize())
		tag := derived(t, p, secret, "setup/replay", ctx, 16)
		var offsets Offsets
		for dir, purpose := range [...]string{Forward: "counter/fwd", Backward: "counter/bwd"} {
			offsets[dir] = binary.BigEndian.Uint64(derived(t, p, secret, purpose, ctx, 8)) &^ (3 << 62)
		}
		secret.Release()

		sz, err := sizesOf(p)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := p.NewAEAD(setupKey)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := nonceFor(aead.NonceSize(), Forward, links[i], 0)
		if err != nil {
			t.Fatal(err)
		}
		sealed := cell.Body()[len(pub):setupLayerLen(i, perHopCost(sz.pub, sz.overhead))]
		_, err = aead.Open(nil, nonce, sealed, []byte{0x02, byte(KindControl), byte(i)})
		aead.Destroy()
		if err != nil {
			t.Fatalf("hop %d: the layer does not open under the key derived by hand for the purpose setup: %v", i, err)
		}
		if bytes.HasPrefix(setupKey.Bytes(), tag) || bytes.HasPrefix(cellKey, tag) {
			t.Fatalf("hop %d: the replay tag is the head of a key", i)
		}
		if bytes.Equal(setupKey.Bytes(), cellKey) {
			t.Fatalf("hop %d: the layer key and the hop key are one key", i)
		}
		setupKey.Release()

		if !bytes.Equal(setup.CellKeys[i].Bytes(), cellKey) {
			t.Fatalf("hop %d: the client's hop key is not the one derived for the purpose cell", i)
		}
		if setup.Offsets[i] != offsets {
			t.Fatalf("hop %d: the client's offsets %x, by hand %x", i, setup.Offsets[i], offsets)
		}

		layer, err := OpenSetup(p, privs[i], pub, chain[i].Identity, cell)
		if err != nil {
			t.Fatalf("hop %d: OpenSetup: %v", i, err)
		}
		same := bytes.Equal(layer.CellKey.Bytes(), cellKey)
		layer.CellKey.Release()
		if !same {
			t.Fatalf("hop %d: the node's hop key is not the one derived for the purpose cell", i)
		}
		if !bytes.Equal(layer.Tag[:], tag) {
			t.Fatalf("hop %d: replay tag %x, by hand %x", i, layer.Tag, tag)
		}
		if layer.Offsets != offsets {
			t.Fatalf("hop %d: the node's offsets %x, by hand %x", i, layer.Offsets, offsets)
		}
		if i == n-1 {
			break
		}
		if cell, err = ForwardSetup(layer, i); err != nil {
			t.Fatalf("hop %d: ForwardSetup: %v", i, err)
		}
	}
}

// the purposes of a hop pinned to fixed numbers. The layer is the one of the
// golden agreement in crypto/providertest: hop 0 on link 200, the node holds b
// and publishes B, the client's ephemeral key is A (c25519: the keys of
// RFC 7748, 6.1; gost: a = 01..20, b = 11..30), which gives the transcript
// hash th, the secret and the setup key written there. The test seals an exit
// layer under that setup key; OpenSetup has to open it and return the values
// below, computed outside this code from that secret and th, with Python hmac
// and hashlib on c25519 and a separate implementation of Streebog on gost.
// The second layer of each suite is the same one sealed for an authenticated
// node whose identity key is c0 c1 .. (32 bytes on c25519, 64 on gost): the
// transcript gets that key as a sixth part, th', the secret and every value
// below change, and on gost so does the UKM, th'[0:8].
//
//	c25519: HMAC-SHA256(secret, "jimichi/v2/c25519/<purpose>" || 00 || th || 01)
//	  th            9a368224..2456625d, PRK 3e072338..eb5637e1
//	  secret        0aad4e69..2b89f7d2
//	  cell          185b1e72..7f485f04
//	  setup/replay  f9a6c675f233690a2a9c6ec5b88b5e71 (first 16 bytes)
//	  counter/fwd   7b8425bd8a83a628 -> 3b8425bd8a83a628 (first 8, top two bits cleared)
//	  counter/bwd   63d5f5d7ba30c693 -> 23d5f5d7ba30c693
//	  with the identity: th' 8f89f964..8c4e1306, PRK 6fac34aa..a07ab60b, secret 9d6ab46b..257120ac,
//	  setup key b369d36d..8622d621, cell 10504f51..94646f95, tag 10ddc255afe3733561e3cf70edadc337,
//	  fwd 696960f67b6558da -> 296960f67b6558da, bwd 838fec0fbc5b7ec8 -> 038fec0fbc5b7ec8
//	gost: HMAC-Streebog256(secret, 01 || "jimichi/v2/gost/<purpose>" || 00 || th || 01 00)
//	  th            d45eab77..0534cfab, KEK db1d1590..7da94a5d
//	  secret        b74c9d0d..65e41735
//	  cell          0c1318cd..5223c2ae
//	  setup/replay  bc06a73c93c8216e9e23faf379f2b190
//	  counter/fwd   ab1ac796e6631e15 -> 2b1ac796e6631e15
//	  counter/bwd   ace97916a58593b2 -> 2ce97916a58593b2
//	  with the identity: th' e513cc6e..4d047875, KEK 8ef73ad1..a12eb0f7, secret a4942e51..837b3976,
//	  setup key f51a229c..99fdffef, cell d197af1e..3cce5cbc, tag a1b21587831d34bd9b32c66296c52490,
//	  fwd 490a6974aa69dfa8 -> 090a6974aa69dfa8, bwd f7e39085e5275a82 -> 37e39085e5275a82
func TestOpenSetupKnownAnswer(t *testing.T) {
	c25519A := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	c25519b := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	c25519B := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	gostA := "000ad8811b8280e56a2c9b37b7170a3de04039df9151482097e3cc0669ecb7a0" +
		"623f29508cc68b124c3d15a4e2a26e3e71dc391fb2c62d558071878e6814f9a3"
	gostb := "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
	gostB := "b6749ce1d202dd4550a1ad7a8797e16e47cfdb0a0b446465e447f56abb4dae1b" +
		"43cad001b96e51d4f10df16549327c9eea30e0a74adf0ce5a01c5934ec52edc6"
	for _, tc := range []struct {
		p                      jcrypto.CryptoProvider
		pubA, privB, pubB      string
		identity               bool
		setupKey, cellKey, tag string
		forward, backward      uint64
	}{
		{
			p:    c25519.New(),
			pubA: c25519A, privB: c25519b, pubB: c25519B,
			setupKey: "cf9dfbd0cfec9ab8a8ef01637d50d7eb8b3d927ccb2707baa589d55589f1412c",
			cellKey:  "185b1e72f40e8fb0dbe012cf0e7e9432621d43973de36d6ae1ab595f7f485f04",
			tag:      "f9a6c675f233690a2a9c6ec5b88b5e71",
			forward:  0x3b8425bd8a83a628,
			backward: 0x23d5f5d7ba30c693,
		},
		{
			p:    c25519.New(),
			pubA: c25519A, privB: c25519b, pubB: c25519B,
			identity: true,
			setupKey: "b369d36df8459c544cf9a88d4a70e7c64abe452ff540573e59f6f12c8622d621",
			cellKey:  "10504f5182b04af3691651f2d6a57354d35d2628231393e792091d4f94646f95",
			tag:      "10ddc255afe3733561e3cf70edadc337",
			forward:  0x296960f67b6558da,
			backward: 0x038fec0fbc5b7ec8,
		},
		{
			p:    gost.New(),
			pubA: gostA, privB: gostb, pubB: gostB,
			setupKey: "e862ff81e89e89d1d98c392bcfe08cdab52de9de8506d8ef01fbe2110408dfff",
			cellKey:  "0c1318cd0ac9988e18cec38b6651762a5284859a217cdfc663babd075223c2ae",
			tag:      "bc06a73c93c8216e9e23faf379f2b190",
			forward:  0x2b1ac796e6631e15,
			backward: 0x2ce97916a58593b2,
		},
		{
			p:    gost.New(),
			pubA: gostA, privB: gostb, pubB: gostB,
			identity: true,
			setupKey: "f51a229c1ff18bf96114017d35a0ffba76003e5455cfed4eba88606599fdffef",
			cellKey:  "d197af1e7292c036392b7df9ed8c8e408c484219da6b82931e3a21ba3cce5cbc",
			tag:      "a1b21587831d34bd9b32c66296c52490",
			forward:  0x090a6974aa69dfa8,
			backward: 0x37e39085e5275a82,
		},
	} {
		t.Run(fmt.Sprintf("%v/identity %v", tc.p.Suite(), tc.identity), func(t *testing.T) {
			p := tc.p
			unhex := func(s string) []byte {
				b, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			pubA, pubB := unhex(tc.pubA), unhex(tc.pubB)
			privB, err := secmem.NewFrom(unhex(tc.privB))
			if err != nil {
				t.Fatal(err)
			}
			defer privB.Release()
			setupKey, err := secmem.NewFrom(unhex(tc.setupKey))
			if err != nil {
				t.Fatal(err)
			}
			defer setupKey.Release()

			aead, err := p.NewAEAD(setupKey)
			if err != nil {
				t.Fatal(err)
			}
			defer aead.Destroy()
			nonce, err := nonceFor(aead.NonceSize(), Forward, 200, 0)
			if err != nil {
				t.Fatal(err)
			}
			// all zero: an exit layer whose first forward counter is 0
			plain := make([]byte, BodySize-len(pubA)-aead.Overhead())
			body := append(bytes.Clone(pubA), aead.Seal(nil, nonce, plain, []byte{0x02, byte(KindControl), 0x00})...)
			cell, err := NewCell(Header{Kind: KindControl, Circuit: 200, Counter: 0}, body)
			if err != nil {
				t.Fatal(err)
			}

			identity := make([]byte, len(pubB))
			for i := range identity {
				identity[i] = byte(0xc0 + i)
			}
			sealedFor, other := identity, []byte(nil)
			if !tc.identity {
				sealedFor, other = nil, identity
			}
			if _, err := OpenSetup(p, privB, pubB, other, cell); !errors.Is(err, jcrypto.ErrOpen) {
				t.Fatalf("OpenSetup with the identity part the layer was not built with: %v, want ErrOpen", err)
			}
			layer, err := OpenSetup(p, privB, pubB, sealedFor, cell)
			if err != nil {
				t.Fatalf("OpenSetup: %v", err)
			}
			defer layer.CellKey.Release()
			if got := hex.EncodeToString(layer.CellKey.Bytes()); got != tc.cellKey {
				t.Errorf("hop key %s, want %s", got, tc.cellKey)
			}
			if got := hex.EncodeToString(layer.Tag[:]); got != tc.tag {
				t.Errorf("replay tag %s, want %s", got, tc.tag)
			}
			if layer.Offsets[Forward] != tc.forward || layer.Offsets[Backward] != tc.backward {
				t.Errorf("offsets %#x %#x, want %#x %#x", layer.Offsets[Forward], layer.Offsets[Backward], tc.forward, tc.backward)
			}
			if layer.NextAddr != "" || layer.First != 0 {
				t.Errorf("exit layer: next %q, first counter %d", layer.NextAddr, layer.First)
			}
		})
	}
}
