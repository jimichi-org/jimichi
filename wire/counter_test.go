package wire

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/gost"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// shared secret 40 41 .. 5f, onion key 80 81 .., ephemeral key 00 01 .. (32
// bytes each on c25519, 64 on gost); once for hop 0 on link 200 and once for
// hop 2 on link 0102030405060708, so every byte of the index and of the
// identifier is pinned, and once more for hop 0 on link 200 of an
// authenticated node with the identity key c0 c1 .. (32 bytes on c25519, 64 on
// gost). The offset is the first 8 bytes of the KDF output, big endian, with
// the top two bits cleared. Computed outside this code, with Python hashlib
// and hmac on c25519 and a separate implementation of Streebog on gost, over
// these bytes; openssl dgst (sha256, and md_gost12_256 of gost-engine) gives
// the same:
//
//	T = "jimichi/v2/<suite>/transcript/setup" || 00 || 05 (06 with an identity)
//	    || 0001 02 || 0001 <index> || 0008 <link>
//	    || u16be(len) onion || u16be(len) ephemeral [|| u16be(len) identity]
//	  120 bytes on c25519, 182 on gost; 154 and 248 with an identity
//	c25519, th = SHA-256(T)
//	  HMAC-SHA256(secret, "jimichi/v2/c25519/counter/fwd" || 00 || th || 01)[:8]
//	  hop 0, link 200: th b14c23db..2e00928c
//	    fwd 5bdc9f320a581f9d -> 1bdc9f320a581f9d, bwd c0745a8762bbd942 -> 00745a8762bbd942
//	  hop 2, link 0102030405060708: th 068c7bd6..d787b0f9
//	    fwd 0778248061dab8ca -> 0778248061dab8ca, bwd c961738c13a9c105 -> 0961738c13a9c105
//	  hop 0, link 200, identity: th 3f1268d9..04422ecb
//	    fwd fa24c2e6990665f2 -> 3a24c2e6990665f2, bwd f6ca6ef42dae9b09 -> 36ca6ef42dae9b09
//	gost, th = Streebog-256(T), KDF_GOSTR3411_2012_256 (RFC 7836, 4.5) =
//	  HMAC-Streebog256(secret, 01 || "jimichi/v2/gost/counter/fwd" || 00 || th || 01 00)[:8]
//	  hop 0, link 200: th c4aff7e9..6cae1080
//	    fwd 95a2d1cbcee19679 -> 15a2d1cbcee19679, bwd 1235e4fa8c36603b -> 1235e4fa8c36603b
//	  hop 2, link 0102030405060708: th 57868c17..fd01fb20
//	    fwd a285f620c8a4d7ac -> 2285f620c8a4d7ac, bwd 306883539182f0a2 -> 306883539182f0a2
//	  hop 0, link 200, identity: th d7117c13..0cfdd646
//	    fwd 21e06998e88f5a34 -> 21e06998e88f5a34, bwd eeee7d74a91ab022 -> 2eee7d74a91ab022
func TestCounterOffsetKnownAnswer(t *testing.T) {
	for _, tc := range []struct {
		p        jcrypto.CryptoProvider
		pub      int
		index    int
		link     uint64
		identity bool
		th       string
		fwd, bwd uint64
	}{
		{c25519.New(), 32, 0, 200, false, "b14c23db2eb7be7e6fb80d79859e002ef40b6c2262082d633aa6d44a2e00928c",
			0x1bdc9f320a581f9d, 0x00745a8762bbd942},
		{c25519.New(), 32, 2, 0x0102030405060708, false, "068c7bd6e11a65ebc017f90c1ee536554f95a6c18dbe7528e342ee9bd787b0f9",
			0x0778248061dab8ca, 0x0961738c13a9c105},
		{c25519.New(), 32, 0, 200, true, "3f1268d9cdfeaff916445d4aa1648775fb3a3f290da1142fb0e9128c04422ecb",
			0x3a24c2e6990665f2, 0x36ca6ef42dae9b09},
		{gost.New(), 64, 0, 200, false, "c4aff7e929db19a4171ed91d841bfe6ce2658d957a5fa5dc80ef69a76cae1080",
			0x15a2d1cbcee19679, 0x1235e4fa8c36603b},
		{gost.New(), 64, 2, 0x0102030405060708, false, "57868c17ef09fd83789be00b4ce8f58eca074ab981d154bf8e20bafcfd01fb20",
			0x2285f620c8a4d7ac, 0x306883539182f0a2},
		{gost.New(), 64, 0, 200, true, "d7117c1346e610f6d636fed3a24a065a1ff72ada68631ad72a1bc2970cfdd646",
			0x21e06998e88f5a34, 0x2eee7d74a91ab022},
	} {
		t.Run(fmt.Sprintf("%v/hop %d/identity %v", tc.p.Suite(), tc.index, tc.identity), func(t *testing.T) {
			secret, err := secmem.New(32)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Release()
			for i := range secret.Bytes() {
				secret.Bytes()[i] = byte(0x40 + i)
			}
			onion, eph := make([]byte, tc.pub), make([]byte, tc.pub)
			var identity []byte
			for i := range onion {
				onion[i], eph[i] = byte(0x80+i), byte(i)
				if tc.identity {
					identity = append(identity, byte(0xc0+i))
				}
			}
			ctx, err := setupContext(tc.p, tc.index, tc.link, onion, eph, identity)
			if err != nil {
				t.Fatalf("setupContext: %v", err)
			}
			if got := hex.EncodeToString(ctx.Sum()); got != tc.th {
				t.Fatalf("setup transcript hash %s, want %s", got, tc.th)
			}
			off, err := deriveOffsets(tc.p, secret, ctx)
			if err != nil {
				t.Fatalf("deriveOffsets: %v", err)
			}
			if off[Forward] != tc.fwd || off[Backward] != tc.bwd {
				t.Fatalf("offsets %#x %#x, want %#x %#x", off[Forward], off[Backward], tc.fwd, tc.bwd)
			}
		})
	}
}

func randomOffsets(r *rand.Rand) Offsets {
	return Offsets{r.Uint64() & (counterLimit - 1), r.Uint64() & (counterLimit - 1)}
}

// three hops, the way relays compute it and the way the client does: each
// relay adds its own offset to the value it received, the client adds or takes
// away the sums of the offsets before a hop
func TestLinkValuesNeverCoincide(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for n := 0; n < 10000; n++ {
		hops := [3]Offsets{randomOffsets(r), randomOffsets(r), randomOffsets(r)}
		base := r.Uint64N(cellLimit)
		c := &Circuit{before: make([]Offsets, 3)}
		for i := 1; i < 3; i++ {
			for _, dir := range []Direction{Forward, Backward} {
				c.before[i][dir] = shift(c.before[i-1][dir], hops[i-1][dir])
			}
		}

		var fwd, bwd [3]uint64
		fwd[0] = base
		for i := 1; i < 3; i++ {
			fwd[i] = shift(fwd[i-1], hops[i-1][Forward])
		}
		bwd[2] = shift(base, hops[2][Backward])
		for i := 1; i >= 0; i-- {
			bwd[i] = shift(bwd[i+1], hops[i][Backward])
		}

		for i := 0; i < 3; i++ {
			if got := c.valueAt(i, Forward, fwd[0]); got != fwd[i] {
				t.Fatalf("circuit %d: forward value on link %d is %#x at the client, %#x at the relays", n, i, got, fwd[i])
			}
			if got := c.valueAt(i, Backward, bwd[0]); got != bwd[i] {
				t.Fatalf("circuit %d: backward value on link %d is %#x at the client, %#x at the relays", n, i, got, bwd[i])
			}
			for j := i + 1; j < 3; j++ {
				if fwd[i] == fwd[j] || bwd[i] == bwd[j] {
					t.Fatalf("circuit %d: links %d and %d carry the same value", n, i, j)
				}
			}
			if fwd[i] >= counterLimit || bwd[i] >= counterLimit {
				t.Fatalf("circuit %d: value on link %d is past the nonce limit", n, i)
			}
		}
	}
}

// the next base counter is the next value on every link, across the wrap too,
// so every link sees its values one after another
func TestLinkValuesStayConsecutive(t *testing.T) {
	for _, off := range []uint64{0, 1, counterLimit - 1, counterLimit - 2, 1 << 61} {
		for _, base := range []uint64{0, 1, cellLimit - 2} {
			a, b := shift(base, off), shift(base+1, off)
			if (b-a)&(counterLimit-1) != 1 {
				t.Fatalf("offset %#x, base %d: %#x then %#x", off, base, a, b)
			}
			if unshift(a, off) != base {
				t.Fatalf("offset %#x, base %d: unshift gives %#x", off, base, unshift(a, off))
			}
		}
	}
}

// the first value is taken as it comes, then only the next one: a copy, a gap
// or a step back is refused and leaves the sequence where it was
func TestSequenceTakesCountersInTurn(t *testing.T) {
	var s Sequence
	for _, step := range []struct {
		counter uint64
		ok      bool
	}{
		{1000, true},
		{1001, true},
		{1001, false}, // a copy
		{1003, false}, // a gap
		{1000, false}, // a step back
		{1002, true},
		{1 << 61, false},
		{1003, true},
	} {
		if got := s.Next(step.counter); got != step.ok {
			t.Fatalf("Next(%d) = %v, want %v", step.counter, got, step.ok)
		}
	}
}

// values of a link wrap at the nonce limit and stay in turn across it
func TestSequenceAcrossTheWrap(t *testing.T) {
	var s Sequence
	for _, c := range []uint64{counterLimit - 2, counterLimit - 1, 0, 1} {
		if !s.Next(c) {
			t.Fatalf("value %#x refused", c)
		}
	}
	if s.Next(counterLimit - 1) {
		t.Fatal("a value from before the wrap accepted")
	}
}

// nothing at or past the nonce limit is a counter, not even the first one, and
// a link takes no more than cellLimit values
func TestSequenceBounds(t *testing.T) {
	for _, c := range []uint64{counterLimit, counterLimit + 5, ^uint64(0)} {
		var s Sequence
		if s.Next(c) {
			t.Fatalf("value %#x past the nonce limit accepted", c)
		}
	}
	var s Sequence
	if !s.Next(5) {
		t.Fatal("first value refused")
	}
	s.taken = cellLimit - 1
	if !s.Next(6) {
		t.Fatal("the last value before cellLimit refused")
	}
	if s.Next(7) {
		t.Fatal("a value past cellLimit accepted")
	}
}

// a sequence told its first value takes nothing else first, so a lost start
// shows up as a break
func TestSequenceWithAFixedStart(t *testing.T) {
	var s Sequence
	s.Expect(counterLimit - 1)
	if s.Next(0) {
		t.Fatal("a value after the expected first one accepted")
	}
	if !s.Next(counterLimit-1) || !s.Next(0) {
		t.Fatal("the expected first value and its successor refused")
	}
}

// an exit layer sealed by hand, so its first forward counter can be any value
func exitSetup(t *testing.T, p jcrypto.CryptoProvider, nodePub []byte, link, first uint64) *Cell {
	t.Helper()
	ephPriv, ephPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := setupContext(p, 0, link, nodePub, ephPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := p.Agree(ephPriv, nodePub, ctx)
	ephPriv.Release()
	if err != nil {
		t.Fatal(err)
	}
	setupKey, err := p.DeriveKey(secret, purposeSetup, ctx, p.KeySize())
	secret.Release()
	if err != nil {
		t.Fatal(err)
	}
	defer setupKey.Release()
	sz, err := sizesOf(p)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, setupHdr+setupLayerLen(1, perHopCost(sz.pub, sz.overhead)))
	binary.BigEndian.PutUint64(plain[setupFlags+AddrSize:setupHdr], first)
	aead, err := p.NewAEAD(setupKey)
	if err != nil {
		t.Fatal(err)
	}
	defer aead.Destroy()
	nonce, err := nonceFor(aead.NonceSize(), Forward, link, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := append(append([]byte{}, ephPub...), aead.Seal(nil, nonce, plain, setupAAD(0))...)
	cell, err := NewCell(Header{Kind: KindControl, Circuit: link}, append(body, make([]byte, BodySize-len(body))...))
	if err != nil {
		t.Fatal(err)
	}
	return cell
}

// no counter of a link reaches the nonce limit, so an exit told to expect one
// that does refuses the setup
func TestOpenSetupRefusesAFirstCounterPastTheLimit(t *testing.T) {
	p := c25519.New()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()

	layer, err := OpenSetup(p, priv, pub, nil, exitSetup(t, p, pub, 77, counterLimit-1))
	if err != nil {
		t.Fatalf("OpenSetup with the last valid first counter: %v", err)
	}
	layer.CellKey.Release()
	if layer.First != counterLimit-1 || layer.NextAddr != "" || layer.NextCircuit != 0 {
		t.Fatalf("exit layer: first %#x, next %q %d", layer.First, layer.NextAddr, layer.NextCircuit)
	}
	for _, first := range []uint64{counterLimit, ^uint64(0)} {
		if _, err := OpenSetup(p, priv, pub, nil, exitSetup(t, p, pub, 78, first)); !errors.Is(err, ErrFraming) {
			t.Fatalf("first counter %#x: %v, want ErrFraming", first, err)
		}
	}
}
