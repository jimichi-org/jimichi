package e2e

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func livePair(t *testing.T, p jcrypto.CryptoProvider) *pair {
	t.Helper()
	pr := newPair(t, p, Options{})
	pr.handshake(t)
	pr.confirm(t)
	return pr
}

func number(rec []byte) uint32 { return binary.BigEndian.Uint32(rec[1:dataHeader]) }

func TestRatchetInOrder(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		for i := 0; i < 5; i++ {
			body := strings.Repeat("x", i*90)
			rec := mustSeal(t, pr.ini, body)
			if rec[0] != kindData || number(rec) != uint32(i+1) {
				t.Fatalf("record %d: kind %d, number %d", i, rec[0], number(rec))
			}
			if ev := mustReceive(t, pr.resp, rec, EventMessage); string(ev.Body) != body {
				t.Fatalf("body of %d bytes back as %d", len(body), len(ev.Body))
			}
			back := mustSeal(t, pr.resp, body)
			if number(back) != uint32(i) {
				t.Fatalf("reply number %d", number(back))
			}
			mustReceive(t, pr.ini, back, EventMessage)
		}
		if st := pr.resp.Stats(); st.Received != 5 || st.DummiesReceived != 1 || st.Sent != 5 || st.Lost != 0 {
			t.Fatalf("responder stats %+v", st)
		}
	})
}

func TestRatchetSkipAndWindow(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		var recs [][]byte
		for i := 0; i < 130; i++ {
			recs = append(recs, mustSeal(t, pr.ini, "r"))
		}
		// recs[i] carries number i+1; the next expected is 1
		wantRefusedAsIs(t, "65 numbers ahead", pr.resp, recs[65], ErrWindow)
		mustReceive(t, pr.resp, recs[64], EventMessage)
		if st := pr.resp.Stats(); st.Lost != 64 || st.Window != 1 {
			t.Fatalf("after a skip of 64: %+v", st)
		}

		wantRefusedAsIs(t, "the same record again", pr.resp, recs[64], ErrCopy)
		wantRefusedAsIs(t, "a skipped record arriving later", pr.resp, recs[3], ErrLate)
		mustReceive(t, pr.resp, recs[65], EventMessage)
		wantRefusedAsIs(t, "a copy one behind", pr.resp, recs[64], ErrCopy)
		if st := pr.resp.Stats(); st.Copies != 2 || st.Late != 1 || st.Lost != 64 {
			t.Fatalf("stats %+v", st)
		}
		// beyond the bitmap a copy cannot be told from a late record
		mustReceive(t, pr.resp, recs[129], EventMessage)
		wantRefusedAsIs(t, "a record past the bitmap", pr.resp, recs[64], ErrLate)
	})
}

// a forged number costs at most 64 steps and changes nothing, the count of
// fetches and the staleness included
func TestGarbageNumberChangesNothing(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{StaleFetches: 3})
		pr.handshake(t)
		pr.confirm(t)
		rec := mustSeal(t, pr.ini, "real")
		forge := func(n uint32) []byte {
			bad := bytes.Clone(rec)
			binary.BigEndian.PutUint32(bad[1:], n)
			if n == 1 {
				bad[RecordSize-1] ^= 1
			}
			return bad
		}
		pr.resp.Fetched()
		pr.resp.Fetched()
		for _, n := range []uint32{1, 2, 64, 65} {
			wantRefusedAsIs(t, "a forged record", pr.resp, forge(n), ErrBad)
		}
		pr.resp.Fetched()
		if pr.resp.State() != StateStale {
			t.Fatal("a forged record reset the count of fetches")
		}
		for _, n := range []uint32{1, 3} {
			wantRefusedAsIs(t, "a forged record to a stale session", pr.resp, forge(n), ErrBad)
		}
		mustReceive(t, pr.resp, rec, EventMessage)
		if st := pr.resp.Stats(); st.Lost != 0 || st.Bad != 6 || pr.resp.State() != StateConfirmed {
			t.Fatalf("stats %+v, state %v", st, pr.resp.State())
		}
	})
}

func TestDirectionsAreIndependent(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		// numbers the other direction expects next, so the records are tried
		mine := mustSeal(t, pr.ini, "to the responder")
		_, err := pr.ini.Receive(mine)
		wantErr(t, "own record back", err, ErrBad)
		sealDummy(t, pr.resp)
		theirs := mustSeal(t, pr.resp, "to the initiator")
		_, err = pr.resp.Receive(theirs)
		wantErr(t, "own record back", err, ErrBad)
		mustReceive(t, pr.resp, mine, EventMessage)
		mustReceive(t, pr.ini, theirs, EventMessage)
		for i := 0; i < 3; i++ {
			mustSeal(t, pr.ini, "unread")
		}
		mustReceive(t, pr.ini, mustSeal(t, pr.resp, "independent"), EventMessage)
	})
}

func TestBodyLimits(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		full := strings.Repeat("m", MaxBody)
		if ev := mustReceive(t, pr.resp, mustSeal(t, pr.ini, full), EventMessage); string(ev.Body) != full {
			t.Fatal("a full body changed")
		}
		if ev := mustReceive(t, pr.resp, mustSeal(t, pr.ini, ""), EventMessage); len(ev.Body) != 0 {
			t.Fatal("an empty body is not empty")
		}
		_, err := pr.ini.Seal(make([]byte, MaxBody+1))
		wantErr(t, "a body of 369 bytes", err, ErrTooLong)
		d := sealDummy(t, pr.ini)
		if len(d) != RecordSize {
			t.Fatalf("dummy of %d bytes", len(d))
		}
		mustReceive(t, pr.resp, d, EventDummy)
	})
}

// records that open but break the inner layout are refused: only the peer can
// make them, and a refusal still leaves the state as it was
func TestInnerLayoutRules(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		for _, tc := range []struct {
			name  string
			inner []byte
		}{
			{"an unknown flag", rawInner(0x02, 1, []byte("a"), 0)},
			{"a dummy with a body", rawInner(flagDummy, 1, []byte("a"), 0)},
			{"a length past the body", rawInner(0, MaxBody+1, nil, 0)},
			{"padding not zero", rawInner(0, 1, []byte("a"), 7)},
			{"a dummy with padding", rawInner(flagDummy, 0, nil, 7)},
		} {
			wantRefusedAsIs(t, tc.name, pr.resp, sealRaw(t, pr.ini, tc.inner), ErrBad)
		}
		// the refused numbers count as lost once a good record opens
		mustReceive(t, pr.resp, mustSeal(t, pr.ini, "good"), EventMessage)
		if st := pr.resp.Stats(); st.Lost != 5 {
			t.Fatalf("lost %d", st.Lost)
		}
	})
}

func rawInner(flags byte, n int, body []byte, tail byte) []byte {
	b := make([]byte, InnerSize)
	b[0] = flags
	binary.BigEndian.PutUint16(b[1:], uint16(n))
	copy(b[innerHeader:], body)
	if tail != 0 {
		b[InnerSize-1] = tail
	}
	return b
}

// seals an inner the layer would never build: a record only the peer can make
func sealRaw(t testing.TB, s *Session, inner []byte) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.sealInner(inner)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// a dummy costs what a message costs, call for call
func TestDummyAndMessageCostTheSame(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		cost := func(tp *trackingProvider, f func()) map[string]int {
			before := tp.snapshot()
			f()
			after := tp.snapshot()
			for k, v := range before {
				after[k] -= v
			}
			return after
		}
		var real, dummy []byte
		sealReal := cost(pr.trackI, func() { real = mustSeal(t, pr.ini, "same work") })
		sealFake := cost(pr.trackI, func() { dummy = sealDummy(t, pr.ini) })
		if !sameCalls(sealReal, sealFake) {
			t.Fatalf("Seal %v, SealDummy %v", sealReal, sealFake)
		}
		openReal := cost(pr.trackR, func() { mustReceive(t, pr.resp, real, EventMessage) })
		openFake := cost(pr.trackR, func() { mustReceive(t, pr.resp, dummy, EventDummy) })
		if !sameCalls(openReal, openFake) {
			t.Fatalf("Receive of a message %v, of a dummy %v", openReal, openFake)
		}
		if sealReal["seal"] != 1 || openReal["open"] != 1 || sealReal[purposeStepKey] != 1 {
			t.Fatalf("one record took %v", sealReal)
		}
	})
}

func sameCalls(a, b map[string]int) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}

func TestNumbersRunOut(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := livePair(t, p)
		pr.ini.mu.Lock()
		pr.ini.send.n = lastNumber - 1
		pr.ini.mu.Unlock()
		rec := mustSeal(t, pr.ini, "last")
		if number(rec) != lastNumber-1 {
			t.Fatalf("number %d", number(rec))
		}
		_, err := pr.ini.Seal([]byte("one more"))
		wantErr(t, "Seal past the last number", err, ErrExhausted)
		_, err = pr.ini.SealDummy()
		wantErr(t, "SealDummy past the last number", err, ErrExhausted)
		if !pr.ini.Tick() || pr.ini.State() != StateHandshaking {
			t.Fatal("the initiator did not start over")
		}
		pr.resp.mu.Lock()
		pr.resp.send.n = lastNumber
		pr.resp.mu.Unlock()
		_, err = pr.resp.SealDummy()
		wantErr(t, "responder past the last number", err, ErrExhausted)
	})
}

func TestRecordSizes(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		pr := newPair(t, p, Options{})
		size := staticSize[p.Suite()]
		want := map[jcrypto.Suite]int{jcrypto.SuiteC25519: 343, jcrypto.SuiteGOST: 311}[p.Suite()]
		if got := pr.ini.handshakePayload(); got != want || 1+size+got+16 != RecordSize {
			t.Fatalf("handshake payload %d, want %d", got, want)
		}
		if InnerSize != MaxBody+innerHeader || dataHeader+InnerSize+16 != RecordSize {
			t.Fatal("the data record layout does not add up")
		}
	})
}
