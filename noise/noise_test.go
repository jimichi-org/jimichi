package noise_test

import (
	"bytes"
	"errors"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/noise"
)

var prologue = [][]byte{{0x01}, []byte("card of the initiator"), []byte("card of the responder")}

func TestKKRoundTrip(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ini, resp := kkPair(t, p, prologue)
		first := mustWrite(t, ini, []byte("one"))
		if got := mustRead(t, resp, first); string(got) != "one" {
			t.Fatalf("first payload %q", got)
		}
		second := mustWrite(t, resp, []byte("two"))
		if got := mustRead(t, ini, second); string(got) != "two" {
			t.Fatalf("second payload %q", got)
		}
		if !ini.Done() || !resp.Done() {
			t.Fatal("handshake not done after two messages")
		}
		a, b := mustSplit(t, ini), mustSplit(t, resp)
		if !bytes.Equal(a.i2r, b.i2r) || !bytes.Equal(a.r2i, b.r2i) || !bytes.Equal(a.sid, b.sid) {
			t.Fatal("the sides split into different keys")
		}
		if bytes.Equal(a.i2r, a.r2i) {
			t.Fatal("both directions got one key")
		}
		if _, _, _, err := ini.Split(); !errors.Is(err, noise.ErrState) {
			t.Fatalf("second Split: %v, want ErrState", err)
		}
	})
}

func TestMessagesOutOfTurn(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ini, resp := kkPair(t, p, prologue)
		if _, err := resp.WriteMessage(nil); !errors.Is(err, noise.ErrState) {
			t.Fatalf("responder writes first: %v", err)
		}
		if _, err := ini.ReadMessage(make([]byte, 128)); !errors.Is(err, noise.ErrState) {
			t.Fatalf("initiator reads first: %v", err)
		}
		if _, _, _, err := ini.Split(); !errors.Is(err, noise.ErrState) {
			t.Fatalf("Split before the end: %v", err)
		}
	})
}

// every bit of both messages matters, and a refused message leaves the state as
// it was, the MixHash made for it included: the genuine one reads afterwards
func TestEveryFlippedBitIsRefused(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ini, resp := kkPair(t, p, prologue)
		flip := func(t *testing.T, reader *noise.HandshakeState, kind byte, msg []byte) {
			t.Helper()
			for bit := 0; bit < 8*len(msg); bit++ {
				bad := bytes.Clone(msg)
				bad[bit/8] ^= 1 << (bit % 8)
				if err := reader.MixHash([]byte{kind}); err != nil {
					t.Fatal(err)
				}
				if _, err := reader.ReadMessage(bad); err == nil {
					t.Fatalf("message %d with bit %d flipped was read", kind, bit)
				}
			}
			if err := reader.MixHash([]byte{kind}); err != nil {
				t.Fatal(err)
			}
			mustRead(t, reader, msg)
		}

		if err := ini.MixHash([]byte{1}); err != nil {
			t.Fatal(err)
		}
		first := mustWrite(t, ini, []byte("payload"))
		flip(t, resp, 1, first)
		if _, err := resp.ReadMessage(first[:len(first)-1]); !errors.Is(err, noise.ErrState) {
			t.Fatalf("a message read twice: %v", err)
		}

		if err := resp.MixHash([]byte{2}); err != nil {
			t.Fatal(err)
		}
		second := mustWrite(t, resp, []byte("payload"))
		flip(t, ini, 2, second)
		a, b := mustSplit(t, ini), mustSplit(t, resp)
		if !bytes.Equal(a.sid, b.sid) || !bytes.Equal(a.i2r, b.i2r) {
			t.Fatal("the sides disagree after the refused messages")
		}
	})
}

func TestShortAndLongMessagesAreRefused(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ini, resp := kkPair(t, p, prologue)
		first := mustWrite(t, ini, make([]byte, 8))
		for _, bad := range [][]byte{nil, first[:10], first[:len(first)-1], append(bytes.Clone(first), 0)} {
			if _, err := resp.ReadMessage(bad); !errors.Is(err, noise.ErrMessage) {
				t.Fatalf("a %d-byte message: %v, want ErrMessage", len(bad), err)
			}
		}
		mustRead(t, resp, first)
	})
}

func TestWrongKeysOrPrologueAreRefused(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		si, sr, other := staticKey(t, p), staticKey(t, p), staticKey(t, p)
		otherCard := [][]byte{prologue[0], prologue[1], []byte("card of the respondeR")}
		for _, tc := range []struct {
			name                 string
			iLocal, rLocal       noise.Static
			iRemote, rRemote     []byte
			iPrologue, rPrologue [][]byte
		}{
			{"the initiator expects another responder", si, sr, other.Public(), si.Public(), prologue, prologue},
			{"the responder expects another initiator", si, sr, sr.Public(), other.Public(), prologue, prologue},
			{"another static key answers for the responder", si, other, sr.Public(), si.Public(), prologue, prologue},
			{"a card byte differs", si, sr, sr.Public(), si.Public(), prologue, otherCard},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ini, err := noise.New(noise.Config{Provider: p, Pattern: noise.KK, Name: "test", Initiator: true,
					Prologue: tc.iPrologue, Local: tc.iLocal, RemoteStatic: tc.iRemote})
				if err != nil {
					t.Fatal(err)
				}
				defer ini.Close()
				resp, err := noise.New(noise.Config{Provider: p, Pattern: noise.KK, Name: "test",
					Prologue: tc.rPrologue, Local: tc.rLocal, RemoteStatic: tc.rRemote})
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Close()
				if _, err := resp.ReadMessage(mustWrite(t, ini, nil)); !errors.Is(err, noise.ErrMessage) {
					t.Fatalf("ReadMessage: %v, want ErrMessage", err)
				}
			})
		}
	})
}

func TestAcceptPayloadLeavesTheStateOnRefusal(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		si, sr := staticKey(t, p), staticKey(t, p)
		ini, err := noise.New(noise.Config{Provider: p, Pattern: noise.KK, Name: "test", Initiator: true,
			Prologue: prologue, Local: si, RemoteStatic: sr.Public()})
		if err != nil {
			t.Fatal(err)
		}
		defer ini.Close()
		take := false
		resp, err := noise.New(noise.Config{Provider: p, Pattern: noise.KK, Name: "test",
			Prologue: prologue, Local: sr, RemoteStatic: si.Public(),
			AcceptPayload: func([]byte) bool { return take }})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Close()
		msg := mustWrite(t, ini, []byte("payload"))
		if _, err := resp.ReadMessage(msg); !errors.Is(err, noise.ErrMessage) {
			t.Fatalf("refused payload: %v, want ErrMessage", err)
		}
		take = true
		if got := mustRead(t, resp, msg); string(got) != "payload" {
			t.Fatalf("payload %q", got)
		}
		mustRead(t, ini, mustWrite(t, resp, nil))
		if a, b := mustSplit(t, ini), mustSplit(t, resp); !bytes.Equal(a.sid, b.sid) {
			t.Fatal("the sides disagree after a refused payload")
		}
	})
}

func TestPayloadNeedsAnAgreementFirst(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		si, sr := staticKey(t, p), staticKey(t, p)
		pt := noise.Pattern{
			PreInitiator: []noise.Token{noise.TokenS},
			PreResponder: []noise.Token{noise.TokenS},
			Messages:     [][]noise.Token{{noise.TokenE}, {noise.TokenE, noise.TokenEE}},
		}
		hs, err := noise.New(noise.Config{Provider: p, Pattern: pt, Name: "test", Initiator: true,
			Prologue: prologue, Local: si, RemoteStatic: sr.Public()})
		if err != nil {
			t.Fatal(err)
		}
		defer hs.Close()
		if _, err := hs.WriteMessage(nil); !errors.Is(err, noise.ErrNoKey) {
			t.Fatalf("WriteMessage before any DH: %v, want ErrNoKey", err)
		}
	})
}

func TestUnsupportedPatterns(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		si, sr := staticKey(t, p), staticKey(t, p)
		for _, tc := range []struct {
			name string
			pt   noise.Pattern
		}{
			{"a static key sent in a message", noise.Pattern{Messages: [][]noise.Token{{noise.TokenE, noise.TokenS, noise.TokenES}}}},
			{"an ephemeral key as a pre-message", noise.Pattern{PreInitiator: []noise.Token{noise.TokenE}, Messages: noise.KK.Messages}},
			{"an unknown token", noise.Pattern{Messages: [][]noise.Token{{noise.TokenE, 9}}}},
			{"no messages", noise.Pattern{PreInitiator: []noise.Token{noise.TokenS}}},
		} {
			_, err := noise.New(noise.Config{Provider: p, Pattern: tc.pt, Name: "test", Initiator: true,
				Prologue: prologue, Local: si, RemoteStatic: sr.Public()})
			if !errors.Is(err, noise.ErrPattern) {
				t.Fatalf("%s: %v, want ErrPattern", tc.name, err)
			}
		}
	})
}

func TestIncompleteConfiguration(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		si, sr := staticKey(t, p), staticKey(t, p)
		for _, tc := range []struct {
			name string
			cfg  noise.Config
		}{
			{"no provider", noise.Config{Pattern: noise.KK, Name: "test", Prologue: prologue, Local: si, RemoteStatic: sr.Public()}},
			{"no remote static", noise.Config{Provider: p, Pattern: noise.KK, Name: "test", Prologue: prologue, Local: si}},
			{"no local static", noise.Config{Provider: p, Pattern: noise.KK, Name: "test", Prologue: prologue, RemoteStatic: sr.Public()}},
			{"keys of two sizes", noise.Config{Provider: p, Pattern: noise.KK, Name: "test", Prologue: prologue, Local: si, RemoteStatic: sr.Public()[1:]}},
		} {
			if _, err := noise.New(tc.cfg); !errors.Is(err, noise.ErrConfig) {
				t.Fatalf("%s: %v, want ErrConfig", tc.name, err)
			}
		}
		if _, err := noise.New(noise.Config{Provider: p, Pattern: noise.KK, Name: "test", Local: si, RemoteStatic: sr.Public()}); err == nil {
			t.Fatal("New without a prologue succeeded")
		}
	})
}

// a relay of these handshakes would hold a locked page per leftover: after Split
// nothing the provider made is held but the two keys handed out
func TestEverySecretIsReleased(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ti, tr := &trackingProvider{CryptoProvider: p}, &trackingProvider{CryptoProvider: p}
		// the static agreements go through the key pair's provider: the tracking
		// one, while the static keys themselves are made outside it
		static := func(tp *trackingProvider) *noise.KeyPair {
			priv, pub, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			kp := noise.NewKeyPair(tp, priv, pub)
			t.Cleanup(kp.Close)
			return kp
		}
		si, sr := static(ti), static(tr)
		ini, err := noise.New(noise.Config{Provider: ti, Pattern: noise.KK, Name: "test", Initiator: true,
			Prologue: prologue, Local: si, RemoteStatic: sr.Public()})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := noise.New(noise.Config{Provider: tr, Pattern: noise.KK, Name: "test",
			Prologue: prologue, Local: sr, RemoteStatic: si.Public()})
		if err != nil {
			t.Fatal(err)
		}
		mustRead(t, resp, mustWrite(t, ini, nil))
		mustRead(t, ini, mustWrite(t, resp, nil))
		mustSplit(t, ini)
		mustSplit(t, resp)
		// per side: one ephemeral key, four agreements, three chained keys, two
		// message keys and the two direction keys
		for name, tp := range map[string]*trackingProvider{"initiator": ti, "responder": tr} {
			if made, held := tp.live(); made != 12 || held != 0 {
				t.Fatalf("%s: %d buffers made, %d held; want 12 and 0", name, made, held)
			}
		}

		// a handshake closed half way holds nothing either
		half := &trackingProvider{CryptoProvider: p}
		hs, err := noise.New(noise.Config{Provider: half, Pattern: noise.KK, Name: "test", Initiator: true,
			Prologue: prologue, Local: si, RemoteStatic: sr.Public()})
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, hs, nil)
		if _, err := hs.ReadMessage(make([]byte, 200)); err == nil {
			t.Fatal("garbage read")
		}
		hs.Close()
		if _, held := half.live(); held != 0 {
			t.Fatalf("%d buffers held after Close", held)
		}
	})
}

func TestKeyPairAfterClose(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		kp, other := staticKey(t, p), staticKey(t, p)
		kp.Close()
		ctx, err := jcrypto.NewContext(p, "test", []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kp.Agree(other.Public(), ctx); !errors.Is(err, noise.ErrClosed) {
			t.Fatalf("Agree after Close: %v, want ErrClosed", err)
		}
		kp.Close()
	})
}
