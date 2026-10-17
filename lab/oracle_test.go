package lab

import (
	"encoding/binary"
	"slices"
	"sync"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/wire"
)

type sealSeen struct {
	plain, ad   int
	last, first byte
}

// records every Seal under the oracle, which is what tells the setup layers
// from the data layers without trusting the oracle itself
type spy struct {
	jcrypto.CryptoProvider
	mu       sync.Mutex
	seals    []sealSeen
	overhead int
}

func (s *spy) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	a, err := s.CryptoProvider.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.overhead = a.Overhead()
	s.mu.Unlock()
	return &spyAEAD{AEAD: a, spy: s}, nil
}

type spyAEAD struct {
	jcrypto.AEAD
	spy *spy
}

func (a *spyAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	seen := sealSeen{plain: len(plaintext), ad: len(ad)}
	if len(ad) > 0 {
		seen.last = ad[len(ad)-1]
	}
	if len(plaintext) > 0 {
		seen.first = plaintext[0]
	}
	a.spy.mu.Lock()
	a.spy.seals = append(a.spy.seals, seen)
	a.spy.mu.Unlock()
	return a.AEAD.Seal(dst, nonce, plaintext, ad)
}

func provider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// h hops linked 1, 2, ..., h, every hop but the exit naming a next one
func setupThrough(t *testing.T, p jcrypto.CryptoProvider, h int) (*wire.SetupResult, []uint64) {
	t.Helper()
	chain := make([]wire.SetupHop, h)
	links := make([]uint64, h)
	for i := range chain {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		priv.Release()
		links[i] = uint64(i + 1)
		chain[i] = wire.SetupHop{StaticPub: pub, Link: links[i]}
		if i < h-1 {
			chain[i].NextAddr = "127.0.0.1:1"
			chain[i].NextCircuit = uint64(i + 2)
		}
	}
	setup, err := wire.BuildSetup(p, chain)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	})
	return setup, links
}

func circuitThrough(t *testing.T, p jcrypto.CryptoProvider, h int) (*wire.SetupResult, *wire.Circuit) {
	t.Helper()
	setup, links := setupThrough(t, p, h)
	c, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, links)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return setup, c
}

func sealThree(t *testing.T, c *wire.Circuit) {
	t.Helper()
	if _, err := c.Seal(0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SealCover(1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(2, nil); err != nil {
		t.Fatal(err)
	}
}

// a message of zero bytes is a message: its length 0 leaves the top bit
// clear. On c25519 at three hops the entry's setup layer is 494 - 32 - 16 =
// 446 bytes, as long as the innermost data layer 494 - 3 * 16, and starts with
// the flag byte 1 of a next address: a rule by length would count it as a
// message. No other case collides
func TestOracleLabelsTheInnermostLayerOnly(t *testing.T) {
	for _, c := range []struct {
		suite jcrypto.Suite
		hops  int
	}{
		{jcrypto.SuiteC25519, 1}, {jcrypto.SuiteC25519, 2}, {jcrypto.SuiteC25519, 3}, {jcrypto.SuiteC25519, 4},
		{jcrypto.SuiteGOST, 2}, {jcrypto.SuiteGOST, 3},
	} {
		s := &spy{CryptoProvider: provider(t, c.suite)}
		labels := &Labels{}
		o := &oracle{CryptoProvider: s, labels: labels}
		_, circuit := circuitThrough(t, o, c.hops)
		sealThree(t, circuit)

		got, ok := labels.Cells()
		if !ok || !slices.Equal(got, []bool{true, false, true}) {
			t.Errorf("%s at %d hops: labels %v, ok %v; want [true false true]", c.suite, c.hops, got, ok)
		}
		setupSeals, dataSeals, byLength := 0, 0, 0
		var entrySetup sealSeen
		for _, seen := range s.seals {
			switch seen.ad {
			case 3:
				setupSeals++
				if seen.last == 0 {
					entrySetup = seen
				}
			case dataAAD:
				dataSeals++
			}
			if seen.plain == wire.BodySize-c.hops*s.overhead && seen.first&coverBit == 0 {
				byLength++
			}
		}
		if setupSeals != c.hops || dataSeals != 3*c.hops {
			t.Errorf("%s at %d hops: %d setup and %d data seals, want %d and %d",
				c.suite, c.hops, setupSeals, dataSeals, c.hops, 3*c.hops)
		}
		want := 2
		if c.suite == jcrypto.SuiteC25519 && c.hops == 3 {
			want = 3
			if entrySetup.plain != wire.BodySize-3*16 || entrySetup.first != 1 {
				t.Errorf("c25519 at 3 hops: the entry's setup layer is %d bytes starting with %d, want 446 and 1",
					entrySetup.plain, entrySetup.first)
			}
		}
		if byLength != want {
			t.Errorf("%s at %d hops: a rule by length counts %d messages, want %d", c.suite, c.hops, byLength, want)
		}
	}
}

func TestOracleMarksWhatItCannotAccountFor(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	labels := &Labels{}
	o := &oracle{CryptoProvider: p, labels: labels}
	setup, _ := circuitThrough(t, o, 3)
	second, err := o.NewAEAD(setup.CellKeys[2])
	if err != nil {
		t.Fatal(err)
	}
	second.Destroy()
	if _, ok := labels.Cells(); ok {
		t.Error("a second AEAD on the exit's key left the labels consistent")
	}

	// one AEAD on the exit's key and no circuit, whose own AEAD on that key
	// would be a second one and mark the labels by itself
	data := func(hop byte) []byte {
		ad := []byte{wire.Version, byte(wire.KindData)}
		ad = binary.BigEndian.AppendUint64(ad, 5)
		return append(ad, hop)
	}
	for _, c := range []struct {
		name  string
		seals [][]byte
		first []byte
		want  []bool
		ok    bool
	}{
		{"setup associated data", [][]byte{{wire.Version, byte(wire.KindControl), 0}}, []byte{0}, nil, false},
		{"the entry's position", [][]byte{data(0)}, []byte{0}, nil, false},
		{"the exit's position", [][]byte{data(2), data(2)}, []byte{0, coverBit}, []bool{true, false}, true},
	} {
		labels := &Labels{}
		o := &oracle{CryptoProvider: p, labels: labels}
		setup, _ := setupThrough(t, o, 3)
		a, err := o.NewAEAD(setup.CellKeys[2])
		if err != nil {
			t.Fatal(err)
		}
		for i, ad := range c.seals {
			nonce := make([]byte, a.NonceSize())
			nonce[0] = byte(i + 1)
			plain := make([]byte, wire.BodySize-3*16)
			plain[0] = c.first[i]
			a.Seal(nil, nonce, plain, ad)
		}
		a.Destroy()
		got, ok := labels.Cells()
		if ok != c.ok || !slices.Equal(got, c.want) {
			t.Errorf("%s: labels %v, ok %v; want %v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// relays get the provider of the run unwrapped: Execute wraps only the one it
// hands to client.Dial
func TestOracleLabelsPerClient(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	first, second := &Labels{}, &Labels{}
	_, a := circuitThrough(t, &oracle{CryptoProvider: p, labels: first}, 3)
	_, b := circuitThrough(t, &oracle{CryptoProvider: p, labels: second}, 3)
	if _, err := a.Seal(0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SealCover(0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		labels *Labels
		want   []bool
	}{{"first", first, []bool{true}}, {"second", second, []bool{false}}} {
		if got, ok := c.labels.Cells(); !ok || !slices.Equal(got, c.want) {
			t.Errorf("%s client: labels %v, ok %v; want %v", c.name, got, ok, c.want)
		}
	}
}
