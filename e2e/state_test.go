package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

// the values the documentation states, held literally
func TestDocumentedValues(t *testing.T) {
	if MaxSkip != 64 || bitmapSize != 64 || RecordSize != 392 || InnerSize != 371 || MaxBody != 368 || QueueSize != 16 {
		t.Fatalf("window %d, bitmap %d, record %d, inner %d, body %d, queue %d",
			MaxSkip, bitmapSize, RecordSize, InnerSize, MaxBody, QueueSize)
	}
	o := Options{}.withDefaults()
	if o.HandshakeTimeout != 60*time.Second || o.StaleFetches != 450 || o.Seen != 64 || o.Now == nil {
		t.Fatalf("defaults %+v", o)
	}
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		if cap(pr.resp.seen.keys) != 64 || pr.resp.opt.StaleFetches != 450 || pr.resp.opt.HandshakeTimeout != time.Minute {
			t.Fatalf("a session made with Options{} has ring %d and %+v", cap(pr.resp.seen.keys), pr.resp.opt)
		}
	})
}

func TestRingPushesOutTheOldest(t *testing.T) {
	r := newRing(64)
	tag := func(i int) []byte { return []byte{byte(i), byte(i >> 8)} }
	for i := range 65 {
		r.add(tag(i))
	}
	if r.has(tag(0)) || !r.has(tag(1)) || !r.has(tag(64)) {
		t.Fatal("the 65th tag did not push out the first one alone")
	}
	r.add(tag(64))
	if !r.has(tag(1)) {
		t.Fatal("a tag already held pushed out another")
	}
	r.add(tag(0))
	if r.has(tag(1)) || !r.has(tag(2)) || !r.has(tag(0)) || !r.has(tag(64)) {
		t.Fatal("the second tag was not the next one out")
	}
}

type forgery struct {
	name string
	rec  []byte
	want error
}

// what a third party can put in the queue: it knows both cards and every
// record it saw on the way, and no key
func forgeries(t *testing.T, p jcrypto.CryptoProvider, s *Session, realKK1 []byte) []forgery {
	t.Helper()
	priv, stranger, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	random := func(kind byte, head ...[]byte) []byte {
		b := make([]byte, RecordSize)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		b[0] = kind
		off := 1
		for _, h := range head {
			off += copy(b[off:], h)
		}
		return b
	}
	num := func(n uint64) []byte { return binary.BigEndian.AppendUint32(nil, uint32(n)) }

	s.mu.Lock()
	next, established, accepted := s.recv.n, s.established, bytes.Clone(s.accepted)
	s.mu.Unlock()
	beyond := ErrBad
	if established {
		beyond = ErrWindow
	}
	pub := len(stranger)
	out := []forgery{
		{"a short record", random(kindData, num(next))[:RecordSize-1], ErrBad},
		{"a long record", append(random(kindData, num(next)), 0), ErrBad},
		{"kind 0", random(0), ErrBad},
		{"kind 4", random(4), ErrBad},
		{"data at the next number", random(kindData, num(next)), ErrBad},
		{"data 3 ahead", random(kindData, num(next+3)), ErrBad},
		{"data 64 ahead", random(kindData, num(next+64)), ErrBad},
		{"data 65 ahead", random(kindData, num(next+65)), beyond},
		{"kk1 under a stranger's key", random(kindKK1, stranger), ErrBad},
		{"kk2 under a stranger's key", random(kindKK2, stranger), ErrBad},
		{"kk1 with a real E_I not taken yet", random(kindKK1, realKK1[1:1+pub]), ErrBad},
	}
	switch {
	case accepted == nil:
	case s.role == RoleResponder:
		out = append(out, forgery{"kk1 with the E_I of the session", random(kindKK1, accepted[1:1+pub]), ErrReplayedHandshake})
	default:
		out = append(out, forgery{"kk2 with the E_R of the session", random(kindKK2, accepted[1:1+pub]), ErrBad})
	}
	return out
}

// whoever can write to a queue holds no key: nothing it puts there moves a
// session, resets a count, withdraws an offer or spends a ring slot
func TestForgedInputsChangeNothing(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, sc := range []struct {
			name string
			// brings the pair to the state under test, returns the side that
			// takes the forgeries and what must still work after them
			setup func(t *testing.T, pr *pair) (*Session, func())
		}{
			{"responder offering kk2", func(t *testing.T, pr *pair) (*Session, func()) {
				kk1 := mustHandshake(t, pr.ini)
				pr.ini.Stored(kk1)
				mustReceive(t, pr.resp, kk1, EventSession)
				pr.resp.Fetched()
				return pr.resp, func() {
					mustReceive(t, pr.ini, mustHandshake(t, pr.resp), EventSession)
					pr.confirm(t)
				}
			}},
			{"confirmed responder", func(t *testing.T, pr *pair) (*Session, func()) {
				pr.handshake(t)
				pr.confirm(t)
				pr.resp.Fetched()
				return pr.resp, func() {
					mustReceive(t, pr.resp, mustSeal(t, pr.ini, "still"), EventMessage)
					mustReceive(t, pr.ini, mustSeal(t, pr.resp, "here"), EventMessage)
				}
			}},
			{"stale responder", func(t *testing.T, pr *pair) (*Session, func()) {
				pr.handshake(t)
				pr.confirm(t)
				pr.resp.Fetched()
				pr.resp.Fetched()
				return pr.resp, func() {
					mustReceive(t, pr.resp, mustSeal(t, pr.ini, "back"), EventMessage)
					if pr.resp.State() != StateConfirmed {
						t.Fatalf("responder %v after an opened record", pr.resp.State())
					}
				}
			}},
			{"initiator waiting for kk2", func(t *testing.T, pr *pair) (*Session, func()) {
				kk1 := mustHandshake(t, pr.ini)
				pr.ini.Stored(kk1)
				mustReceive(t, pr.resp, kk1, EventSession)
				return pr.ini, func() {
					mustReceive(t, pr.ini, mustHandshake(t, pr.resp), EventSession)
					pr.confirm(t)
				}
			}},
			{"established initiator", func(t *testing.T, pr *pair) (*Session, func()) {
				pr.handshake(t)
				pr.ini.Fetched()
				return pr.ini, func() { pr.confirm(t) }
			}},
			{"stale initiator", func(t *testing.T, pr *pair) (*Session, func()) {
				pr.handshake(t)
				pr.confirm(t)
				pr.ini.Fetched()
				pr.ini.Fetched()
				return pr.ini, func() {
					if !pr.ini.Tick() || pr.ini.State() != StateHandshaking {
						t.Fatal("the stale initiator did not start over")
					}
				}
			}},
		} {
			t.Run(sc.name, func(t *testing.T) {
				pr := newPair(t, p, Options{StaleFetches: 2})
				s, after := sc.setup(t, pr)
				// a restart of the real initiator, not yet delivered: its E_I is
				// public as soon as it is on the way
				fresh := mustHandshake(t, newSession(t, p, pr.idI, pr.idR.Card(), Options{}))
				for _, f := range forgeries(t, p, s, fresh) {
					wantRefusedAsIs(t, f.name, s, f.rec, f.want)
				}
				after()
			})
		}
	})
}

// the ring takes E_I only after kk1 opened: a forged kk1 carrying the real E_I
// cannot get the real one refused as a replay
func TestForgedKK1DoesNotSpendTheEphemeralKey(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{StaleFetches: 2})
		for round := range 2 {
			kk1 := mustHandshake(t, pr.ini)
			pr.ini.Stored(kk1)
			for _, at := range []int{RecordSize - 1, 1 + len(pr.idI.Card().Static)} {
				forged := bytes.Clone(kk1)
				forged[at] ^= 1
				wantRefusedAsIs(t, "kk1 with the real E_I and a changed ciphertext", pr.resp, forged, ErrBad)
			}
			mustReceive(t, pr.resp, kk1, EventSession)
			mustReceive(t, pr.ini, mustHandshake(t, pr.resp), EventSession)
			pr.confirm(t)
			if round == 0 {
				// both go stale, the initiator starts over and the stale
				// responder takes the new kk1
				pr.resp.Fetched()
				pr.resp.Fetched()
				pr.ini.Fetched()
				pr.ini.Fetched()
				if !pr.ini.Tick() {
					t.Fatal("no restart")
				}
			}
		}
	})
}

// a refusal, a skip and a restart give back every key they took: the steady
// state is the identity and two chains, or the identity, e_I and ck while the
// initiator waits for kk2
func TestRefusalsAndRestartsReleaseKeys(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{StaleFetches: 2})
		wantHeld(t, "initiator waiting for kk2", pr.trackI, 3)
		wantHeld(t, "responder before kk1", pr.trackR, 1)

		first := mustHandshake(t, pr.ini)
		pr.ini.Stored(first)
		mustReceive(t, pr.resp, first, EventSession)
		pr.clock.Add(time.Minute)
		if !pr.ini.Tick() {
			t.Fatal("no restart after the kk2 timeout")
		}
		wantHeld(t, "initiator after the kk2 timeout", pr.trackI, 3)
		// the responder replaces its unconfirmed session
		pr.handshake(t)
		wantHeld(t, "responder after a replacement", pr.trackR, 3)
		wantHeld(t, "initiator with a session", pr.trackI, 3)
		pr.confirm(t)

		mustSeal(t, pr.ini, "skipped")
		mustSeal(t, pr.ini, "skipped")
		mustReceive(t, pr.resp, mustSeal(t, pr.ini, "after a skip of 2"), EventMessage)
		wantHeld(t, "responder after a skip", pr.trackR, 3)

		forged := mustSeal(t, pr.ini, "renumbered")
		binary.BigEndian.PutUint32(forged[1:], number(forged)+3)
		wantRefusedAsIs(t, "a record 3 ahead that does not open", pr.resp, forged, ErrBad)
		wantHeld(t, "responder after a forged record", pr.trackR, 3)

		bad := sealRaw(t, pr.ini, rawInner(0x02, 1, []byte("a"), 0))
		wantRefusedAsIs(t, "a record with a bad layout", pr.resp, bad, ErrBad)
		wantHeld(t, "responder after a bad layout", pr.trackR, 3)
		wantHeld(t, "initiator after sealing", pr.trackI, 3)

		pr.ini.Fetched()
		pr.ini.Fetched()
		if !pr.ini.Tick() {
			t.Fatal("no restart of the stale initiator")
		}
		wantHeld(t, "initiator after a stale restart", pr.trackI, 3)
		pr.resp.Fetched()
		pr.resp.Fetched()
		pr.handshake(t)
		wantHeld(t, "responder after replacing a stale session", pr.trackR, 3)
		wantHeld(t, "initiator with the new session", pr.trackI, 3)
	})
}

// the inner layouts the layer builds and opens are wiped once the record is
// sealed or read, a refused one included; the body Receive returns is a copy
func TestPlaintextsAreWiped(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		if ev := mustReceive(t, pr.resp, mustSeal(t, pr.ini, "a secret"), EventMessage); string(ev.Body) != "a secret" {
			t.Fatalf("body %q", ev.Body)
		}
		mustReceive(t, pr.ini, mustSeal(t, pr.resp, "another"), EventMessage)
		mustReceive(t, pr.resp, sealDummy(t, pr.ini), EventDummy)
		bad := sealRaw(t, pr.ini, rawInner(0x02, 6, []byte("hidden"), 0))
		wantRefusedAsIs(t, "a record with a bad layout", pr.resp, bad, ErrBad)
		for name, tp := range map[string]*trackingProvider{"initiator": pr.trackI, "responder": pr.trackR} {
			if n := tp.unwiped(); n != 0 || len(tp.plain) < 4 {
				t.Fatalf("%s: %d of %d plaintext buffers not wiped", name, n, len(tp.plain))
			}
		}
	})
}

// a fetch counts only under a session: fetches while the handshake runs do
// not make the new session stale
func TestFetchesBeforeTheSessionDoNotCount(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{StaleFetches: 3})
		kk1 := mustHandshake(t, pr.ini)
		pr.ini.Stored(kk1)
		for range 5 {
			pr.ini.Fetched()
			pr.resp.Fetched()
		}
		mustReceive(t, pr.resp, kk1, EventSession)
		kk2 := mustHandshake(t, pr.resp)
		for range 5 {
			pr.ini.Fetched()
		}
		mustReceive(t, pr.ini, kk2, EventSession)
		if pr.ini.State() != StateEstablished || pr.resp.State() != StateEstablished {
			t.Fatalf("states %v and %v after the handshake", pr.ini.State(), pr.resp.State())
		}
		pr.ini.Fetched()
		pr.ini.Fetched()
		if pr.ini.State() != StateEstablished || pr.ini.Tick() {
			t.Fatal("stale before the count")
		}
		pr.ini.Fetched()
		if pr.ini.State() != StateStale {
			t.Fatal("not stale at the count")
		}
		if st := pr.ini.Stats(); st.Stale != 1 {
			t.Fatalf("stale count %d", st.Stale)
		}
	})
}

// a number is spent before the cipher runs: a failed Seal never hands the
// same number, and so the same key and nonce, to the next record
func TestNumberSpentOnAFailedSeal(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		fp := &faultyProvider{CryptoProvider: p}
		pr := newPair(t, fp, Options{})
		pr.handshake(t)
		pr.confirm(t)
		fp.aead.Store(true)
		_, err := pr.ini.Seal([]byte("lost"))
		wantErr(t, "Seal with a failing cipher", err, errInjected)
		_, err = pr.ini.SealDummy()
		wantErr(t, "SealDummy with a failing cipher", err, errInjected)
		fp.aead.Store(false)
		rec := mustSeal(t, pr.ini, "next")
		if number(rec) != 3 {
			t.Fatalf("number %d after two failed seals, want 3", number(rec))
		}
		mustReceive(t, pr.resp, rec, EventMessage)
		if st := pr.resp.Stats(); st.Lost != 2 {
			t.Fatalf("lost %d", st.Lost)
		}
		wantHeld(t, "initiator after the failed seals", pr.trackI, 3)
	})
}

// a failure of the own provider is not a bad record: it is not counted as one,
// it changes nothing, and the record opens once the provider works again
func TestLocalFailureIsNotABadRecord(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		fp := &faultyProvider{CryptoProvider: p}
		pr := newPair(t, fp, Options{})
		kk1 := mustHandshake(t, pr.ini)
		pr.ini.Stored(kk1)

		before := pr.resp.view()
		fp.agree.Store(true)
		_, err := pr.resp.Receive(kk1)
		fp.agree.Store(false)
		if !errors.Is(err, errInjected) || errors.Is(err, ErrBad) {
			t.Fatalf("kk1 with a failing Agree: %v", err)
		}
		if after := pr.resp.view(); !viewsEqual(before, after) {
			t.Fatal("a local failure changed the session")
		}
		mustReceive(t, pr.resp, kk1, EventSession)
		mustReceive(t, pr.ini, mustHandshake(t, pr.resp), EventSession)
		pr.confirm(t)

		rec := mustSeal(t, pr.ini, "kept")
		fp.aead.Store(true)
		_, err = pr.resp.Receive(rec)
		fp.aead.Store(false)
		if !errors.Is(err, errInjected) || errors.Is(err, ErrBad) {
			t.Fatalf("data with a failing cipher: %v", err)
		}
		mustReceive(t, pr.resp, rec, EventMessage)
		if st := pr.resp.Stats(); st.Bad != 0 {
			t.Fatalf("local failures counted as bad records: %+v", st)
		}
		wantHeld(t, "responder after local failures", pr.trackR, 3)
	})
}
