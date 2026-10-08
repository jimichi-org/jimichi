package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

const testMailbox = "relay-5.jimichi.svc.cluster.local:9000"

// every test runs on a provider that fails it on a signing call, so no path
// of the layer, refused and forged inputs included, can sign or verify
func eachSuite(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider)) {
	t.Helper()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(s.String(), func(t *testing.T) { run(t, noSigning{CryptoProvider: p, t: t}) })
	}
}

type tracked struct {
	b    *secmem.Buffer
	what string
}

// keeps every secret the provider hands out with what made it, counts the
// calls and records the public outputs and the plaintexts, so a test can see
// what a session did
type trackingProvider struct {
	jcrypto.CryptoProvider
	mu     sync.Mutex
	bufs   []tracked
	calls  map[string]int
	hashes map[string]bool
	keys   map[string]bool
	plain  [][]byte
}

func track(p jcrypto.CryptoProvider) *trackingProvider {
	return &trackingProvider{CryptoProvider: p, calls: map[string]int{}, hashes: map[string]bool{}, keys: map[string]bool{}}
}

func (p *trackingProvider) keep(b *secmem.Buffer, what string) *secmem.Buffer {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[what]++
	if b != nil {
		p.bufs = append(p.bufs, tracked{b, what})
		p.keys[hex.EncodeToString(b.Bytes())] = true
	}
	return b
}

func (p *trackingProvider) count(what string) {
	p.mu.Lock()
	p.calls[what]++
	p.mu.Unlock()
}

func (p *trackingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateEphemeral()
	return p.keep(priv, "ephemeral"), pub, err
}

func (p *trackingProvider) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.Agree(priv, pub, ctx)
	return p.keep(b, "agree"), err
}

func (p *trackingProvider) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.MixKey(chain, secret, ctx)
	return p.keep(b, "mix"), err
}

func (p *trackingProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	return p.keep(b, purpose), err
}

func (p *trackingProvider) Hash(data ...[]byte) []byte {
	out := p.CryptoProvider.Hash(data...)
	p.mu.Lock()
	p.calls["hash"]++
	p.hashes[hex.EncodeToString(out)] = true
	p.mu.Unlock()
	return out
}

func (p *trackingProvider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	a, err := p.CryptoProvider.NewAEAD(key)
	p.count("aead")
	if err != nil {
		return nil, err
	}
	return &countingAEAD{AEAD: a, p: p}, nil
}

type countingAEAD struct {
	jcrypto.AEAD
	p *trackingProvider
}

func (a *countingAEAD) Seal(dst, nonce, pt, ad []byte) []byte {
	a.p.count("seal")
	a.p.keepPlain(pt)
	return a.AEAD.Seal(dst, nonce, pt, ad)
}

func (a *countingAEAD) Open(dst, nonce, ct, ad []byte) ([]byte, error) {
	a.p.count("open")
	pt, err := a.AEAD.Open(dst, nonce, ct, ad)
	if err == nil {
		a.p.keepPlain(pt)
	}
	return pt, err
}

func (p *trackingProvider) keepPlain(b []byte) {
	p.mu.Lock()
	p.plain = append(p.plain, b)
	p.mu.Unlock()
}

// the plaintext buffers the layer handed to Seal or got from Open that still
// hold a non-zero byte
func (p *trackingProvider) unwiped() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, b := range p.plain {
		if !allZero(b) {
			n++
		}
	}
	return n
}

func (a *countingAEAD) Destroy() {
	a.p.count("destroy")
	a.AEAD.Destroy()
}

// the secrets still held, by what made them
func (p *trackingProvider) held() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]int{}
	for _, t := range p.bufs {
		if t.b.Bytes() != nil {
			out[t.what]++
		}
	}
	return out
}

func (p *trackingProvider) heldCount() int {
	n := 0
	for _, c := range p.held() {
		n += c
	}
	return n
}

func wantHeld(t testing.TB, what string, p *trackingProvider, want int) {
	t.Helper()
	if held := p.held(); p.heldCount() != want {
		t.Fatalf("%s holds %v, want %d buffers", what, held, want)
	}
}

func (p *trackingProvider) snapshot() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]int, len(p.calls))
	for k, v := range p.calls {
		out[k] = v
	}
	return out
}

// client identities are agreement keys only: any signing call fails the test
type noSigning struct {
	jcrypto.CryptoProvider
	t testing.TB
}

func (p noSigning) GenerateSigning() (*secmem.Buffer, []byte, error) {
	p.t.Error("GenerateSigning called")
	return p.CryptoProvider.GenerateSigning()
}

func (p noSigning) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	p.t.Error("Sign called")
	return p.CryptoProvider.Sign(priv, msg)
}

func (p noSigning) Verify(pub, msg, sig []byte) bool {
	p.t.Error("Verify called")
	return p.CryptoProvider.Verify(pub, msg, sig)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func randomQueue(t testing.TB) [QueueSize]byte {
	var q [QueueSize]byte
	if _, err := rand.Read(q[:]); err != nil {
		t.Fatal(err)
	}
	q[0] |= 1
	return q
}

func newIdentity(t testing.TB, p jcrypto.CryptoProvider) *Identity {
	t.Helper()
	id, err := NewIdentity(p, testMailbox, randomQueue(t))
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	t.Cleanup(id.Close)
	return id
}

// two identities, the initiator's key the smaller one
func identities(t testing.TB, pi, pr jcrypto.CryptoProvider) (*Identity, *Identity) {
	t.Helper()
	for {
		a, b := newIdentity(t, pi), newIdentity(t, pr)
		if bytes.Compare(a.Card().Static, b.Card().Static) < 0 {
			return a, b
		}
		a.Close()
		b.Close()
	}
}

func newSession(t testing.TB, p jcrypto.CryptoProvider, self *Identity, peer Card, opt Options) *Session {
	t.Helper()
	s, err := NewSession(p, self, peer, opt)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

type pair struct {
	ini, resp      *Session
	idI, idR       *Identity
	clock          *clock
	trackI, trackR *trackingProvider
}

func newPair(t testing.TB, p jcrypto.CryptoProvider, opt Options) *pair {
	t.Helper()
	c := newClock()
	if opt.Now == nil {
		opt.Now = c.Now
	}
	ti, tr := track(p), track(p)
	idI, idR := identities(t, ti, tr)
	pr := &pair{idI: idI, idR: idR, clock: c, trackI: ti, trackR: tr}
	pr.ini = newSession(t, ti, idI, idR.Card(), opt)
	pr.resp = newSession(t, tr, idR, idI.Card(), opt)
	return pr
}

func mustHandshake(t testing.TB, s *Session) []byte {
	t.Helper()
	rec, ok := s.Handshake()
	if !ok {
		t.Fatal("no handshake record offered")
	}
	return rec
}

func mustReceive(t testing.TB, s *Session, rec []byte, want EventKind) Event {
	t.Helper()
	ev, err := s.Receive(rec)
	if err != nil {
		t.Fatalf("Receive(kind %d): %v", rec[0], err)
	}
	if ev.Kind != want {
		t.Fatalf("Receive(kind %d) gave event %d, want %d", rec[0], ev.Kind, want)
	}
	return ev
}

func wantErr(t testing.TB, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

// kk1 stored and taken, kk2 stored and taken: both sides hold the session
func (pr *pair) handshake(t testing.TB) {
	t.Helper()
	kk1 := mustHandshake(t, pr.ini)
	pr.ini.Stored(kk1)
	mustReceive(t, pr.resp, kk1, EventSession)
	kk2 := mustHandshake(t, pr.resp)
	pr.resp.Stored(kk2)
	mustReceive(t, pr.ini, kk2, EventSession)
}

// the initiator's first record confirms the session at the responder
func (pr *pair) confirm(t testing.TB) {
	t.Helper()
	rec, err := pr.ini.SealDummy()
	if err != nil {
		t.Fatalf("SealDummy: %v", err)
	}
	mustReceive(t, pr.resp, rec, EventDummy)
	if st := pr.resp.State(); st != StateConfirmed {
		t.Fatalf("responder in %v after the first record", st)
	}
}

var errInjected = errors.New("injected failure")

// fails Agree or NewAEAD while a test asks it to, as a full key memory or a
// broken provider would
type faultyProvider struct {
	jcrypto.CryptoProvider
	agree, aead atomic.Bool
}

func (p *faultyProvider) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if p.agree.Load() {
		return nil, errInjected
	}
	return p.CryptoProvider.Agree(priv, pub, ctx)
}

func (p *faultyProvider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	if p.aead.Load() {
		return nil, errInjected
	}
	return p.CryptoProvider.NewAEAD(key)
}

// everything a refused input must leave as it was, the counters apart
type view struct {
	State                          State
	Epoch                          uint64
	Established, Confirmed, Stale  bool
	NeedsRecord, HSStored, Pending bool
	StoredAt                       time.Time
	Fetches                        int
	Offer, Accepted, SID           []byte
	SendCK, RecvCK                 []byte
	SendN, RecvN, RecvOpened       uint64
	Seen                           []string
	SeenNext                       int
}

func (s *Session) view() view {
	v := view{State: s.State(), Epoch: s.Epoch()}
	v.Offer, _ = s.Handshake()
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Established, v.Confirmed, v.Stale = s.established, s.confirmed, s.stale
	v.NeedsRecord, v.HSStored, v.Pending = s.needsRecord, s.hsStored, s.hs != nil
	v.StoredAt, v.Fetches = s.storedAt, s.fetches
	v.Accepted, v.SID = bytes.Clone(s.accepted), bytes.Clone(s.sid)
	if s.send.ck != nil {
		v.SendCK = bytes.Clone(s.send.ck.Bytes())
	}
	if s.recv.ck != nil {
		v.RecvCK = bytes.Clone(s.recv.ck.Bytes())
	}
	v.SendN, v.RecvN, v.RecvOpened = s.send.n, s.recv.n, s.recv.opened
	v.Seen, v.SeenNext = slices.Clone(s.seen.keys), s.seen.next
	return v
}

func viewsEqual(a, b view) bool { return reflect.DeepEqual(a, b) }

// feeds rec to s and requires the refusal want, one more on its counter and
// nothing else changed
func wantRefusedAsIs(t testing.TB, what string, s *Session, rec []byte, want error) {
	t.Helper()
	before, stats := s.view(), s.Stats()
	_, err := s.Receive(rec)
	wantErr(t, what, err, want)
	if after := s.view(); !viewsEqual(after, before) {
		t.Fatalf("%s changed the session:\n before %+v\n after  %+v", what, before, after)
	}
	switch want {
	case ErrBad:
		stats.Bad++
	case ErrCopy:
		stats.Copies++
	case ErrLate:
		stats.Late++
	case ErrWindow:
		stats.Window++
	case ErrReplayedHandshake:
		stats.ReplayedHandshakes++
	}
	if got := s.Stats(); got != stats {
		t.Fatalf("%s: stats %+v, want %+v", what, got, stats)
	}
}

func mustSeal(t testing.TB, s *Session, body string) []byte {
	t.Helper()
	rec, err := s.Seal([]byte(body))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(rec) != RecordSize {
		t.Fatalf("record of %d bytes", len(rec))
	}
	return rec
}
