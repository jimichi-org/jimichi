package e2e

import (
	"bytes"
	"errors"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/noise"
)

func TestRolesFollowTheKeyOrder(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		if pr.ini.Role() != RoleInitiator || pr.resp.Role() != RoleResponder {
			t.Fatalf("roles %v and %v", pr.ini.Role(), pr.resp.Role())
		}
		if _, ok := pr.resp.Handshake(); ok {
			t.Fatal("the responder offers a record before kk1")
		}
		if pr.ini.State() != StateHandshaking || pr.resp.State() != StateHandshaking {
			t.Fatal("a session before the handshake")
		}
		pr.handshake(t)
		if pr.ini.State() != StateEstablished || pr.resp.State() != StateEstablished {
			t.Fatalf("states %v and %v after the handshake", pr.ini.State(), pr.resp.State())
		}
		if pr.ini.Epoch() != 0 || pr.resp.Epoch() != 1 {
			t.Fatalf("epochs %d and %d", pr.ini.Epoch(), pr.resp.Epoch())
		}
	})
}

func TestNewSessionRefusals(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		id, peer := newIdentity(t, p), newIdentity(t, p)
		if _, err := NewSession(p, id, id.Card(), Options{}); !errors.Is(err, ErrSelf) {
			t.Fatalf("own card as the contact: %v, want ErrSelf", err)
		}
		sameQueue := peer.Card()
		sameQueue.Queue = id.Card().Queue
		if _, err := NewSession(p, id, sameQueue, Options{}); !errors.Is(err, ErrSelf) {
			t.Fatalf("contact on the own queue: %v, want ErrSelf", err)
		}
		zeroKey := peer.Card()
		zeroKey.Static = make([]byte, len(zeroKey.Static))
		if _, err := NewSession(p, id, zeroKey, Options{}); !errors.Is(err, ErrCard) {
			t.Fatalf("a key the agreement refuses: %v, want ErrCard", err)
		}
		badCard := peer.Card()
		badCard.Mailbox = "relay-5"
		if _, err := NewSession(p, id, badCard, Options{}); !errors.Is(err, ErrCard) {
			t.Fatalf("an invalid card: %v, want ErrCard", err)
		}
		foreign := peer.Card()
		foreign.Suite = otherSuiteOf(p)
		if _, err := NewSession(p, id, foreign, Options{}); !errors.Is(err, ErrCard) {
			t.Fatalf("a card of another suite: %v, want ErrCard", err)
		}
	})
}

func TestHandshakeRecordUntilStored(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		kk1 := mustHandshake(t, pr.ini)
		if len(kk1) != RecordSize || kk1[0] != kindKK1 {
			t.Fatalf("kk1 of %d bytes, kind %d", len(kk1), kk1[0])
		}
		if again := mustHandshake(t, pr.ini); !bytes.Equal(again, kk1) {
			t.Fatal("the stuck kk1 changed between two ticks")
		}
		other := bytes.Clone(kk1)
		other[100] ^= 1
		pr.ini.Stored(other)
		if _, ok := pr.ini.Handshake(); !ok {
			t.Fatal("Stored of another record took kk1 off")
		}
		pr.ini.Stored(kk1)
		if _, ok := pr.ini.Handshake(); ok {
			t.Fatal("kk1 offered after it was stored")
		}
		mustReceive(t, pr.resp, kk1, EventSession)
		kk2 := mustHandshake(t, pr.resp)
		if len(kk2) != RecordSize || kk2[0] != kindKK2 {
			t.Fatalf("kk2 of %d bytes, kind %d", len(kk2), kk2[0])
		}
		mustReceive(t, pr.ini, kk2, EventSession)
		// the responder learns that kk2 arrived from the first record under it
		pr.confirm(t)
		if _, ok := pr.resp.Handshake(); ok {
			t.Fatal("kk2 offered after the session was confirmed")
		}
	})
}

func TestCopiesOfHandshakes(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		kk1 := mustHandshake(t, pr.ini)
		pr.handshake(t)
		_, err := pr.resp.Receive(kk1)
		wantErr(t, "a copy of the taken kk1", err, ErrCopy)
		_, err = pr.ini.Receive(pr.ini.accepted)
		wantErr(t, "a copy of the taken kk2", err, ErrCopy)
		if st := pr.resp.Stats(); st.Copies != 1 || st.Handshakes != 1 {
			t.Fatalf("responder stats %+v", st)
		}
		if pr.ini.Epoch() != 0 || pr.resp.Epoch() != 1 {
			t.Fatal("a copy changed the epoch")
		}
		_, err = pr.resp.Receive(append([]byte{kindKK2}, kk1[1:]...))
		wantErr(t, "kk2 at the responder", err, ErrBad)
		_, err = pr.ini.Receive(kk1)
		wantErr(t, "kk1 at the initiator", err, ErrBad)
	})
}

// a forged kk2 opens nowhere and leaves the initiator waiting for the real one
func TestGarbageKK2LeavesTheInitiator(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		kk1 := mustHandshake(t, pr.ini)
		pr.ini.Stored(kk1)
		mustReceive(t, pr.resp, kk1, EventSession)
		kk2 := mustHandshake(t, pr.resp)
		for i := 1; i < RecordSize; i += 37 {
			bad := bytes.Clone(kk2)
			bad[i] ^= 0x80
			_, err := pr.ini.Receive(bad)
			wantErr(t, "a flipped kk2", err, ErrBad)
		}
		_, err := pr.ini.Receive(kk2[:RecordSize-1])
		wantErr(t, "a short kk2", err, ErrBad)
		mustReceive(t, pr.ini, kk2, EventSession)
		pr.confirm(t)
	})
}

// a handshake whose payload is not all zeroes opens but is refused on both
// sides, and the refusal changes nothing
func TestHandshakePayloadMustBeZero(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		payload := make([]byte, pr.ini.handshakePayload())
		payload[len(payload)-1] = 1

		forged, err := pr.ini.newHandshake()
		if err != nil {
			t.Fatal(err)
		}
		defer forged.Close()
		if err := forged.MixHash([]byte{kindKK1}); err != nil {
			t.Fatal(err)
		}
		msg, err := forged.WriteMessage(payload)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pr.resp.Receive(append([]byte{kindKK1}, msg...))
		wantErr(t, "kk1 with a payload", err, ErrBad)

		kk1 := mustHandshake(t, pr.ini)
		pr.ini.Stored(kk1)
		reader, err := pr.resp.newHandshake()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		if err := reader.MixHash([]byte{kindKK1}); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadMessage(kk1[1:]); err != nil {
			t.Fatal(err)
		}
		if err := reader.MixHash([]byte{kindKK2}); err != nil {
			t.Fatal(err)
		}
		bad, err := reader.WriteMessage(payload)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pr.ini.Receive(append([]byte{kindKK2}, bad...))
		wantErr(t, "kk2 with a payload", err, ErrBad)

		mustReceive(t, pr.resp, kk1, EventSession)
		mustReceive(t, pr.ini, mustHandshake(t, pr.resp), EventSession)
		pr.confirm(t)
	})
}

func TestResponderReplacesOnlyADeadSession(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{StaleFetches: 5})
		first := mustHandshake(t, pr.ini)
		pr.ini.Stored(first)
		mustReceive(t, pr.resp, first, EventSession)

		// unconfirmed: a fresh kk1 replaces the session
		pr.clock.Add(time.Minute)
		if !pr.ini.Tick() {
			t.Fatal("no restart after the kk2 timeout")
		}
		second := mustHandshake(t, pr.ini)
		pr.ini.Stored(second)
		mustReceive(t, pr.resp, second, EventSession)
		if pr.resp.Epoch() != 2 {
			t.Fatalf("responder epoch %d after a replacement", pr.resp.Epoch())
		}
		mustReceive(t, pr.ini, mustHandshake(t, pr.resp), EventSession)
		pr.confirm(t)

		// confirmed and live: refused, the session goes on
		stranger := newSession(t, p, pr.idI, pr.idR.Card(), Options{})
		fresh := mustHandshake(t, stranger)
		_, err := pr.resp.Receive(fresh)
		wantErr(t, "a fresh kk1 to a confirmed session", err, ErrRefusedHandshake)
		mustReceive(t, pr.resp, mustSeal(t, pr.ini, "still here"), EventMessage)

		// stale: accepted again
		for i := 0; i < 5; i++ {
			pr.resp.Fetched()
		}
		if pr.resp.State() != StateStale {
			t.Fatalf("responder %v after the stale count", pr.resp.State())
		}
		again := newSession(t, p, pr.idI, pr.idR.Card(), Options{})
		mustReceive(t, pr.resp, mustHandshake(t, again), EventSession)
		if st := pr.resp.Stats(); st.RefusedHandshakes != 1 || st.Handshakes != 3 {
			t.Fatalf("responder stats %+v", st)
		}
	})
}

// the ring holds the last Seen ephemeral keys: a replay inside it is refused,
// the oldest falls out, and a full ring does not stop new handshakes
func TestSeenRing(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		const seen = 4
		pr := newPair(t, p, Options{Seen: seen})
		var kk1s [][]byte
		for i := 0; i < seen+1; i++ {
			s := newSession(t, p, pr.idI, pr.idR.Card(), Options{})
			kk1 := mustHandshake(t, s)
			kk1s = append(kk1s, kk1)
			mustReceive(t, pr.resp, kk1, EventSession)
		}
		_, err := pr.resp.Receive(kk1s[1])
		wantErr(t, "a kk1 in the ring", err, ErrReplayedHandshake)
		_, err = pr.resp.Receive(kk1s[seen])
		wantErr(t, "the kk1 of the session", err, ErrCopy)
		// the first one was pushed out: an old kk1 outside the ring resets an
		// unconfirmed session only, the case the rules allow; taking it pushes
		// out the second
		mustReceive(t, pr.resp, kk1s[0], EventSession)
		_, err = pr.resp.Receive(kk1s[2])
		wantErr(t, "a kk1 still in the ring", err, ErrReplayedHandshake)
		if st := pr.resp.Stats(); st.ReplayedHandshakes != 2 || st.Handshakes != seen+2 {
			t.Fatalf("stats %+v", st)
		}
	})
}

// with the default ring of 64: after 65 different kk1 the first one is gone
func TestSeenRingDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("65 handshakes per suite")
	}
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		var kk1s [][]byte
		for i := 0; i < 65; i++ {
			s := newSession(t, p, pr.idI, pr.idR.Card(), Options{})
			kk1s = append(kk1s, mustHandshake(t, s))
			mustReceive(t, pr.resp, kk1s[i], EventSession)
			s.Close()
		}
		_, err := pr.resp.Receive(kk1s[1])
		wantErr(t, "the second kk1", err, ErrReplayedHandshake)
		mustReceive(t, pr.resp, kk1s[0], EventSession)
	})
}

func TestRestartAfterTheKK2Timeout(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		kk1 := mustHandshake(t, pr.ini)
		pr.clock.Add(2 * time.Minute)
		if pr.ini.Tick() {
			t.Fatal("the kk2 wait started before kk1 was stored")
		}
		pr.ini.Stored(kk1)
		pr.clock.Add(59 * time.Second)
		if pr.ini.Tick() {
			t.Fatal("restart before the timeout")
		}
		mustReceive(t, pr.resp, kk1, EventSession)
		old := mustHandshake(t, pr.resp)
		pr.clock.Add(time.Second)
		if !pr.ini.Tick() || pr.ini.Epoch() != 1 {
			t.Fatal("no restart at the timeout")
		}
		next := mustHandshake(t, pr.ini)
		if bytes.Equal(next[:1+len(pr.idI.Card().Static)], kk1[:1+len(pr.idI.Card().Static)]) {
			t.Fatal("the restart kept the ephemeral key")
		}
		_, err := pr.ini.Receive(old)
		wantErr(t, "kk2 of the dropped handshake", err, ErrBad)
		pr.ini.Stored(next)
		mustReceive(t, pr.resp, next, EventSession)
		mustReceive(t, pr.ini, mustHandshake(t, pr.resp), EventSession)
		pr.confirm(t)
	})
}

func TestStaleInitiatorStartsOver(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{StaleFetches: 3})
		pr.handshake(t)
		pr.confirm(t)
		pr.ini.Fetched()
		pr.ini.Fetched()
		mustReceive(t, pr.ini, sealDummy(t, pr.resp), EventDummy)
		pr.ini.Fetched()
		pr.ini.Fetched()
		if pr.ini.Tick() || pr.ini.State() != StateEstablished {
			t.Fatal("an opened record did not reset the count")
		}
		pr.ini.Fetched()
		if pr.ini.State() != StateStale {
			t.Fatalf("initiator %v after the stale count", pr.ini.State())
		}
		_, err := pr.ini.SealDummy()
		wantErr(t, "SealDummy while stale", err, ErrStale)
		if !pr.ini.Tick() || pr.ini.State() != StateHandshaking || pr.ini.Epoch() != 1 {
			t.Fatal("the stale initiator did not start over")
		}
		if st := pr.ini.Stats(); st.Stale != 1 {
			t.Fatalf("stale count %d", st.Stale)
		}
		_, err = pr.ini.SealDummy()
		wantErr(t, "SealDummy after the restart", err, ErrNotReady)
		mustHandshake(t, pr.ini)
	})
}

func TestStaleResponderSealsNothing(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{StaleFetches: 2})
		pr.handshake(t)
		pr.confirm(t)
		pr.resp.Fetched()
		pr.resp.Fetched()
		if pr.resp.State() != StateStale || pr.resp.CanSealReal() {
			t.Fatalf("responder %v after the stale count", pr.resp.State())
		}
		_, err := pr.resp.Seal([]byte("x"))
		wantErr(t, "Seal while stale", err, ErrStale)
		_, err = pr.resp.SealDummy()
		wantErr(t, "SealDummy while stale", err, ErrStale)
		if pr.resp.Tick() {
			t.Fatal("the responder changed its epoch on its own")
		}
		mustReceive(t, pr.resp, mustSeal(t, pr.ini, "back"), EventMessage)
		if pr.resp.State() != StateConfirmed {
			t.Fatalf("responder %v after an opened record", pr.resp.State())
		}
		mustSeal(t, pr.resp, "answer")
	})
}

func TestConfirmationRecord(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		if pr.ini.NeedsRecord() {
			t.Fatal("a record needed before the session")
		}
		_, err := pr.ini.Seal([]byte("early"))
		wantErr(t, "Seal before the session", err, ErrNotReady)
		pr.handshake(t)
		if !pr.ini.NeedsRecord() || pr.resp.NeedsRecord() {
			t.Fatal("the initiator does not ask for the confirming record")
		}
		if pr.resp.CanSealReal() {
			t.Fatal("the responder may seal before the confirmation")
		}
		_, err = pr.resp.Seal([]byte("early"))
		wantErr(t, "responder Seal before the confirmation", err, ErrNotReady)
		dummy := sealDummy(t, pr.resp)
		mustReceive(t, pr.ini, dummy, EventDummy)
		if !pr.ini.NeedsRecord() {
			t.Fatal("a received record took the need away")
		}
		rec := mustSeal(t, pr.ini, "first")
		if pr.ini.NeedsRecord() {
			t.Fatal("still needs a record after sealing one")
		}
		if ev := mustReceive(t, pr.resp, rec, EventMessage); string(ev.Body) != "first" {
			t.Fatalf("body %q", ev.Body)
		}
		if !pr.resp.CanSealReal() || pr.resp.State() != StateConfirmed {
			t.Fatal("the responder is not confirmed by the first record")
		}
		if ev := mustReceive(t, pr.ini, mustSeal(t, pr.resp, "reply"), EventMessage); string(ev.Body) != "reply" {
			t.Fatalf("body %q", ev.Body)
		}
	})
}

// the key-compromise impersonation of kk1: whoever holds s_R makes a kk1 that
// opens as the initiator's, yet without s_I no data record follows, so a
// confirmed session survives it and an unconfirmed one is all it can reset
func TestKCIResetsNoLiveSession(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		holder := kciInitiator(t, p, pr)
		kci := mustHandshake(t, holder)

		mustReceive(t, pr.resp, kci, EventSession)
		kk2 := mustHandshake(t, pr.resp)
		_, err := holder.Receive(kk2)
		wantErr(t, "kk2 at the impersonator", err, ErrBad)
		if pr.resp.State() != StateEstablished {
			t.Fatal("the impersonated session got further than unconfirmed")
		}
		for i := 0; i < 8; i++ {
			forged := make([]byte, RecordSize)
			forged[0] = kindData
			forged[4] = byte(i)
			forged[10+i] = 1
			_, err := pr.resp.Receive(forged)
			wantErr(t, "a forged data record", err, ErrBad)
		}
		if pr.resp.State() == StateConfirmed {
			t.Fatal("confirmed without the initiator")
		}

		// the real initiator replaces it, and once confirmed the impersonator
		// cannot reset the session any more
		pr.handshake(t)
		pr.confirm(t)
		again := kciInitiator(t, p, pr)
		_, err = pr.resp.Receive(mustHandshake(t, again))
		wantErr(t, "an impersonated kk1 to a confirmed session", err, ErrRefusedHandshake)
		mustReceive(t, pr.resp, mustSeal(t, pr.ini, "live"), EventMessage)
	})
}

// knows S_I and s_R only: ss comes from s_R, the rest it cannot compute
type kciStatic struct {
	p      jcrypto.CryptoProvider
	pub    []byte
	holder noise.Static
	victim []byte
}

func (k kciStatic) Public() []byte { return bytes.Clone(k.pub) }

func (k kciStatic) Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if bytes.Equal(remote, k.victim) {
		return k.holder.Agree(k.pub, ctx)
	}
	return nil, errors.New("no key for this agreement")
}

func kciInitiator(t *testing.T, p jcrypto.CryptoProvider, pr *pair) *Session {
	t.Helper()
	cardI := pr.idI.Card()
	static := kciStatic{p: p, pub: cardI.Static, holder: pr.idR.Static(), victim: pr.idR.Card().Static}
	id, err := NewIdentityFrom(p, static, cardI)
	if err != nil {
		t.Fatal(err)
	}
	return newSession(t, p, id, pr.idR.Card(), Options{})
}

func sealDummy(t testing.TB, s *Session) []byte {
	t.Helper()
	rec, err := s.SealDummy()
	if err != nil {
		t.Fatalf("SealDummy: %v", err)
	}
	return rec
}

func TestCloseReleasesEverything(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		pr.handshake(t)
		pr.confirm(t)
		mustReceive(t, pr.ini, mustSeal(t, pr.resp, "x"), EventMessage)
		pr.ini.Close()
		pr.resp.Close()
		pr.idI.Close()
		pr.idR.Close()
		for name, tp := range map[string]*trackingProvider{"initiator": pr.trackI, "responder": pr.trackR} {
			if held := tp.held(); len(held) != 0 {
				t.Fatalf("%s holds %v after Close", name, held)
			}
		}
		if _, err := pr.ini.SealDummy(); !errors.Is(err, ErrNotReady) {
			t.Fatalf("SealDummy after Close: %v", err)
		}
		if _, err := pr.resp.Receive(make([]byte, RecordSize)); !errors.Is(err, ErrBad) {
			t.Fatalf("Receive after Close: %v", err)
		}
		pr.ini.Close()
	})
}

// what a live session holds: the identity, one chain key per direction, and
// at the initiator nothing of the handshake
func TestLiveSessionHoldsTwoChainKeys(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		if held := pr.trackI.held(); held["ephemeral"] != 2 || len(held) != 2 || held["mix"] != 1 {
			t.Fatalf("initiator waiting for kk2 holds %v", held)
		}
		pr.handshake(t)
		pr.confirm(t)
		for i := 0; i < 3; i++ {
			mustReceive(t, pr.resp, mustSeal(t, pr.ini, "a"), EventMessage)
			mustReceive(t, pr.ini, mustSeal(t, pr.resp, "b"), EventMessage)
		}
		for name, tp := range map[string]*trackingProvider{"initiator": pr.trackI, "responder": pr.trackR} {
			held := tp.held()
			if held["ephemeral"] != 1 || held[purposeStepNext] != 2 || len(held) != 2 {
				t.Fatalf("%s holds %v", name, held)
			}
		}
	})
}

func TestNoSignatures(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ns := noSigning{CryptoProvider: p, t: t}
		pr := newPair(t, ns, Options{StaleFetches: 1})
		pr.handshake(t)
		pr.confirm(t)
		mustReceive(t, pr.ini, mustSeal(t, pr.resp, "x"), EventMessage)
		pr.ini.Fetched()
		pr.ini.Tick()
		mustHandshake(t, pr.ini)
		if _, err := CardHash(ns, pr.idI.Card()); err != nil {
			t.Fatal(err)
		}
	})
}
