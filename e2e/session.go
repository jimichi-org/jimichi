// Package e2e is the end-to-end layer between two clients: contact cards, the
// KK handshake over package noise, a hash ratchet per direction and the rules
// that let a session recover without an operator.
package e2e

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	RecordSize = 392
	InnerSize  = 371
	MaxBody    = 368
	QueueSize  = 16
	MaxSkip    = 64
)

const (
	kindKK1  byte = 0x01
	kindKK2  byte = 0x02
	kindData byte = 0x03

	dirI2R byte = 0x01
	dirR2I byte = 0x02

	flagDummy   byte = 0x01
	dataHeader       = 5
	innerHeader      = 3
	// the receiver remembers which of the numbers below the next one opened
	bitmapSize = 64
	// the last number a sender seals is one below; no record takes it
	lastNumber = math.MaxUint32

	handshakeName   = "e2e/kk"
	prologueVersion = 0x01
	exchangeCheck   = "e2e/check"
	exchangeStep    = "e2e/step"
	purposeStepKey  = "e2e/step/key"
	purposeStepNext = "e2e/step/next"
)

var (
	ErrSelf      = errors.New("e2e: the contact is this identity")
	ErrTooLong   = errors.New("e2e: body too long")
	ErrNotReady  = errors.New("e2e: no session to seal under")
	ErrStale     = errors.New("e2e: session stale")
	ErrExhausted = errors.New("e2e: record numbers exhausted")

	// Receive leaves the session as it was on any of these; a refused kk1 that
	// opened enters the ring of seen handshakes all the same
	ErrCopy              = errors.New("e2e: copy of a record already taken")
	ErrLate              = errors.New("e2e: record behind one taken later")
	ErrWindow            = errors.New("e2e: record too far ahead")
	ErrBad               = errors.New("e2e: record does not open")
	ErrRefusedHandshake  = errors.New("e2e: fresh handshake while a confirmed session is live")
	ErrReplayedHandshake = errors.New("e2e: handshake seen before")
)

type Role uint8

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

func (r Role) String() string {
	switch r {
	case RoleInitiator:
		return "initiator"
	case RoleResponder:
		return "responder"
	default:
		return "unknown"
	}
}

type State uint8

const (
	StateHandshaking State = iota + 1
	StateEstablished
	StateConfirmed
	StateStale
)

func (s State) String() string {
	switch s {
	case StateHandshaking:
		return "handshaking"
	case StateEstablished:
		return "established"
	case StateConfirmed:
		return "confirmed"
	case StateStale:
		return "stale"
	default:
		return "unknown"
	}
}

type EventKind uint8

const (
	EventNone EventKind = iota
	EventMessage
	EventDummy
	EventSession
)

type Event struct {
	Kind EventKind
	Body []byte
}

type Options struct {
	HandshakeTimeout time.Duration
	StaleFetches     int
	Seen             int
	Now              func() time.Time
}

func (o Options) withDefaults() Options {
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 60 * time.Second
	}
	if o.StaleFetches <= 0 {
		o.StaleFetches = 450
	}
	if o.Seen <= 0 {
		o.Seen = 64
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

type Stats struct {
	Sent, Received               uint64
	DummiesSent, DummiesReceived uint64
	Copies, Late, Lost           uint64
	Window, Bad                  uint64
	Handshakes                   uint64
	RefusedHandshakes            uint64
	ReplayedHandshakes           uint64
	Stale                        uint64
}

type chain struct {
	dir byte
	ck  *secmem.Buffer
	// the next number to seal, or the next one expected
	n uint64
	// bit i: number n-1-i opened
	opened uint64
}

func (c *chain) release() {
	if c.ck != nil {
		c.ck.Release()
	}
	*c = chain{}
}

type Session struct {
	mu sync.Mutex

	p        jcrypto.CryptoProvider
	self     *Identity
	peer     Card
	opt      Options
	role     Role
	pubSize  int
	nonce    []byte
	prologue [][]byte

	closed bool
	epoch  uint64

	// the initiator's handshake while it waits for kk2
	hs *noise.HandshakeState
	// the handshake record of this epoch, offered until the mailbox stores it
	hsRec    []byte
	hsStored bool
	storedAt time.Time
	// the handshake record the session came from, to tell its copies
	accepted []byte

	established bool
	confirmed   bool
	stale       bool
	needsRecord bool
	sid         []byte
	send, recv  chain
	fetches     int

	seen ring

	stats Stats
}

func NewSession(p jcrypto.CryptoProvider, self *Identity, peer Card, opt Options) (*Session, error) {
	if p == nil || self == nil {
		return nil, errors.New("e2e: no provider or identity")
	}
	opt = opt.withDefaults()
	own := self.Card()
	if own.Suite != p.Suite() || peer.Suite != p.Suite() || !peer.valid() {
		return nil, ErrCard
	}
	pubSize, err := wire.PublicKeySize(p)
	if err != nil {
		return nil, err
	}
	if len(peer.Static) != pubSize || len(own.Static) != pubSize {
		return nil, ErrCard
	}
	order := bytes.Compare(own.Static, peer.Static)
	if order == 0 || own.Queue == peer.Queue {
		return nil, ErrSelf
	}
	nonce, err := recordNonce(p, pubSize)
	if err != nil {
		return nil, err
	}
	if err := checkPeerKey(p, peer.Static); err != nil {
		return nil, err
	}

	s := &Session{
		p:       p,
		self:    self,
		peer:    peer,
		opt:     opt,
		role:    RoleResponder,
		pubSize: pubSize,
		nonce:   nonce,
		seen:    newRing(opt.Seen),
	}
	cardI, cardR := peer, own
	if order < 0 {
		s.role = RoleInitiator
		cardI, cardR = own, peer
	}
	s.prologue = [][]byte{{prologueVersion}, cardI.Bytes(), cardR.Bytes()}
	s.peer.Static = bytes.Clone(peer.Static)
	if s.role == RoleInitiator {
		if err := s.startHandshake(); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// both suites have a 16-byte tag; a suite with another one would not fit the
// record, and the zero nonce is the only nonce the layer uses
func recordNonce(p jcrypto.CryptoProvider, pubSize int) ([]byte, error) {
	probe, err := secmem.New(p.KeySize())
	if err != nil {
		return nil, err
	}
	defer probe.Release()
	a, err := p.NewAEAD(probe)
	if err != nil {
		return nil, err
	}
	defer a.Destroy()
	if dataHeader+InnerSize+a.Overhead() != RecordSize || 1+pubSize+a.Overhead() >= RecordSize {
		return nil, fmt.Errorf("e2e: suite %v does not fit a %d-byte record", p.Suite(), RecordSize)
	}
	return make([]byte, a.NonceSize()), nil
}

// a one-time pair, so the identity key takes no part; a key the agreement
// refuses would fail every handshake later
func checkPeerKey(p jcrypto.CryptoProvider, pub []byte) error {
	priv, tmp, err := p.GenerateEphemeral()
	if err != nil {
		return err
	}
	defer priv.Release()
	ctx, err := jcrypto.NewContext(p, exchangeCheck, tmp, pub)
	if err != nil {
		return err
	}
	out, err := p.Agree(priv, pub, ctx)
	if err != nil {
		if errors.Is(err, jcrypto.ErrBadPublicKey) {
			return fmt.Errorf("%w: %v", ErrCard, err)
		}
		return err
	}
	out.Release()
	return nil
}

func (s *Session) handshakePayload() int {
	return RecordSize - 1 - s.pubSize - (RecordSize - dataHeader - InnerSize)
}

func (s *Session) newHandshake() (*noise.HandshakeState, error) {
	size := s.handshakePayload()
	return noise.New(noise.Config{
		Provider:     s.p,
		Pattern:      noise.KK,
		Name:         handshakeName,
		Initiator:    s.role == RoleInitiator,
		Prologue:     s.prologue,
		Local:        s.self.Static(),
		RemoteStatic: s.peer.Static,
		AcceptPayload: func(pt []byte) bool {
			return len(pt) == size && allZero(pt)
		},
	})
}

func (s *Session) startHandshake() error {
	hs, err := s.newHandshake()
	if err != nil {
		return err
	}
	rec, err := s.writeHandshake(hs, kindKK1)
	if err != nil {
		hs.Close()
		return err
	}
	s.hs, s.hsRec, s.hsStored = hs, rec, false
	return nil
}

func (s *Session) writeHandshake(hs *noise.HandshakeState, kind byte) ([]byte, error) {
	if err := hs.MixHash([]byte{kind}); err != nil {
		return nil, err
	}
	msg, err := hs.WriteMessage(make([]byte, s.handshakePayload()))
	if err != nil {
		return nil, err
	}
	rec := append([]byte{kind}, msg...)
	if len(rec) != RecordSize {
		return nil, fmt.Errorf("e2e: handshake record of %d bytes", len(rec))
	}
	return rec, nil
}

// drops the session and the pending handshake; the ring of seen handshakes
// outlives sessions
func (s *Session) drop() {
	if s.hs != nil {
		s.hs.Close()
		s.hs = nil
	}
	s.send.release()
	s.recv.release()
	s.hsRec, s.hsStored, s.accepted, s.sid = nil, false, nil, nil
	s.established, s.confirmed, s.stale, s.needsRecord = false, false, false, false
	s.fetches = 0
}

func (s *Session) restart() {
	s.drop()
	s.epoch++
	// on a failure Tick tries again
	_ = s.startHandshake()
}

func (s *Session) Role() Role { return s.role }

func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.established:
		return StateHandshaking
	case s.stale:
		return StateStale
	case s.role == RoleResponder && s.confirmed:
		return StateConfirmed
	default:
		return StateEstablished
	}
}

func (s *Session) Epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

func (s *Session) Handshake() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.hsRec == nil || s.hsStored {
		return nil, false
	}
	return bytes.Clone(s.hsRec), true
}

// the kk2 wait starts here: until the mailbox holds kk1 the responder cannot
// have answered
func (s *Session) Stored(rec []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.hsRec == nil || s.hsStored || !bytes.Equal(rec, s.hsRec) {
		return
	}
	s.hsStored, s.storedAt = true, s.opt.Now()
}

func (s *Session) NeedsRecord() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.established && s.needsRecord
}

func (s *Session) CanSealReal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.canSeal(true) == nil
}

func (s *Session) canSeal(real bool) error {
	switch {
	case s.closed || !s.established:
		return ErrNotReady
	case s.stale:
		return ErrStale
	case real && s.role == RoleResponder && !s.confirmed:
		return ErrNotReady
	case s.send.n >= lastNumber:
		return ErrExhausted
	}
	return nil
}

func (s *Session) Seal(body []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(body) > MaxBody {
		return nil, ErrTooLong
	}
	if err := s.canSeal(true); err != nil {
		return nil, err
	}
	inner := make([]byte, InnerSize)
	binary.BigEndian.PutUint16(inner[1:innerHeader], uint16(len(body)))
	copy(inner[innerHeader:], body)
	return s.sealInner(inner)
}

// the same work as Seal, so the cost of a record does not tell a dummy
func (s *Session) SealDummy() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.canSeal(false); err != nil {
		return nil, err
	}
	inner := make([]byte, InnerSize)
	inner[0] = flagDummy
	return s.sealInner(inner)
}

// the number is spent before the cipher runs, so no failure can bring it back
func (s *Session) sealInner(inner []byte) ([]byte, error) {
	defer secmem.Zero(inner)
	c := &s.send
	n := c.n
	mk, next, err := s.step(c.ck, c.dir, n, true)
	if err != nil {
		return nil, err
	}
	c.ck.Release()
	c.ck, c.n = next, n+1
	defer mk.Release()
	a, err := s.p.NewAEAD(mk)
	if err != nil {
		return nil, err
	}
	defer a.Destroy()
	ad := dataAD(n)
	rec := make([]byte, dataHeader, RecordSize)
	copy(rec, ad)
	rec = a.Seal(rec, s.nonce, inner, ad)
	s.needsRecord = false
	if inner[0]&flagDummy != 0 {
		s.stats.DummiesSent++
	} else {
		s.stats.Sent++
	}
	return rec, nil
}

func dataAD(n uint64) []byte {
	ad := make([]byte, dataHeader)
	ad[0] = kindData
	binary.BigEndian.PutUint32(ad[1:], uint32(n))
	return ad
}

// ctx_n = (SID, direction, n); the next chain key replaces ck at once, the
// record key serves one Seal or Open
func (s *Session) step(ck *secmem.Buffer, dir byte, n uint64, withKey bool) (mk, next *secmem.Buffer, err error) {
	var num [4]byte
	binary.BigEndian.PutUint32(num[:], uint32(n))
	ctx, err := jcrypto.NewContext(s.p, exchangeStep, s.sid, []byte{dir}, num[:])
	if err != nil {
		return nil, nil, err
	}
	if withKey {
		if mk, err = s.p.DeriveKey(ck, purposeStepKey, ctx, s.p.KeySize()); err != nil {
			return nil, nil, err
		}
	}
	if next, err = s.p.DeriveKey(ck, purposeStepNext, ctx, s.p.KeySize()); err != nil {
		if mk != nil {
			mk.Release()
		}
		return nil, nil, err
	}
	return mk, next, nil
}

func (s *Session) Receive(rec []byte) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Event{}, ErrBad
	}
	ev, err := s.receive(rec)
	s.count(err)
	return ev, err
}

func (s *Session) receive(rec []byte) (Event, error) {
	if len(rec) != RecordSize {
		return Event{}, ErrBad
	}
	switch {
	case rec[0] == kindKK1 && s.role == RoleResponder:
		return s.receiveKK1(rec)
	case rec[0] == kindKK2 && s.role == RoleInitiator:
		return s.receiveKK2(rec)
	case rec[0] == kindData:
		return s.receiveData(rec)
	}
	return Event{}, ErrBad
}

func (s *Session) count(err error) {
	switch {
	case err == nil:
	case errors.Is(err, ErrCopy):
		s.stats.Copies++
	case errors.Is(err, ErrLate):
		s.stats.Late++
	case errors.Is(err, ErrWindow):
		s.stats.Window++
	case errors.Is(err, ErrBad):
		s.stats.Bad++
	case errors.Is(err, ErrRefusedHandshake):
		s.stats.RefusedHandshakes++
	case errors.Is(err, ErrReplayedHandshake):
		s.stats.ReplayedHandshakes++
	}
}

// a failure of the own provider or of key memory is not the record's fault and
// is not counted as one
func notOpened(err error) error {
	if errors.Is(err, noise.ErrMessage) || errors.Is(err, noise.ErrState) {
		return ErrBad
	}
	return err
}

// a fresh kk1 replaces a session only while that one is absent, unconfirmed or
// stale: a key-compromise impersonation or an old kk1 the ring forgot resets no
// live session, since without se nobody but the initiator confirms
func (s *Session) receiveKK1(rec []byte) (Event, error) {
	if s.accepted != nil && bytes.Equal(rec, s.accepted) {
		return Event{}, ErrCopy
	}
	tag := s.p.Hash(rec[1 : 1+s.pubSize])
	if s.seen.has(tag) {
		return Event{}, ErrReplayedHandshake
	}
	hs, err := s.newHandshake()
	if err != nil {
		return Event{}, err
	}
	defer hs.Close()
	if err := hs.MixHash([]byte{kindKK1}); err != nil {
		return Event{}, err
	}
	if _, err := hs.ReadMessage(rec[1:]); err != nil {
		return Event{}, notOpened(err)
	}
	s.seen.add(tag)
	if s.established && s.confirmed && !s.stale {
		return Event{}, ErrRefusedHandshake
	}

	reply, err := s.writeHandshake(hs, kindKK2)
	if err != nil {
		return Event{}, err
	}
	i2r, r2i, sid, err := hs.Split()
	if err != nil {
		return Event{}, err
	}
	s.drop()
	s.epoch++
	s.establish(sid, r2i, i2r, rec)
	s.hsRec = reply
	return Event{Kind: EventSession}, nil
}

func (s *Session) receiveKK2(rec []byte) (Event, error) {
	if s.established {
		if bytes.Equal(rec, s.accepted) {
			return Event{}, ErrCopy
		}
		return Event{}, ErrBad
	}
	if s.hs == nil {
		return Event{}, ErrBad
	}
	if err := s.hs.MixHash([]byte{kindKK2}); err != nil {
		return Event{}, err
	}
	if _, err := s.hs.ReadMessage(rec[1:]); err != nil {
		return Event{}, notOpened(err)
	}
	i2r, r2i, sid, err := s.hs.Split()
	if err != nil {
		s.restart()
		return Event{}, err
	}
	s.hs.Close()
	s.hs = nil
	s.establish(sid, i2r, r2i, rec)
	s.hsRec = nil
	s.needsRecord = true
	return Event{Kind: EventSession}, nil
}

func (s *Session) establish(sid []byte, send, recv *secmem.Buffer, from []byte) {
	sendDir, recvDir := dirI2R, dirR2I
	if s.role == RoleResponder {
		sendDir, recvDir = dirR2I, dirI2R
	}
	s.sid = sid
	s.send = chain{dir: sendDir, ck: send}
	s.recv = chain{dir: recvDir, ck: recv}
	s.accepted = bytes.Clone(from)
	s.established = true
	s.fetches = 0
	s.stats.Handshakes++
}

// a copy and a late record are told apart by the bitmap only, before anything
// is opened; past the bitmap nothing tells them apart
func (s *Session) receiveData(rec []byte) (Event, error) {
	if !s.established {
		return Event{}, ErrBad
	}
	c := &s.recv
	n := uint64(binary.BigEndian.Uint32(rec[1:dataHeader]))
	if n < c.n {
		back := c.n - 1 - n
		if back < bitmapSize && c.opened&(1<<back) != 0 {
			return Event{}, ErrCopy
		}
		return Event{}, ErrLate
	}
	if n-c.n > MaxSkip {
		return Event{}, ErrWindow
	}

	ck, owned := c.ck, false
	for i := c.n; i < n; i++ {
		_, next, err := s.step(ck, c.dir, i, false)
		if owned {
			ck.Release()
		}
		if err != nil {
			return Event{}, err
		}
		ck, owned = next, true
	}
	mk, next, err := s.step(ck, c.dir, n, true)
	if owned {
		ck.Release()
	}
	if err != nil {
		return Event{}, err
	}
	inner, err := s.open(mk, rec)
	if err != nil {
		next.Release()
		return Event{}, err
	}
	defer secmem.Zero(inner)
	body, dummy, ok := parseInner(inner)
	if !ok {
		next.Release()
		return Event{}, ErrBad
	}

	c.ck.Release()
	c.ck = next
	s.stats.Lost += n - c.n
	if shift := n + 1 - c.n; shift >= bitmapSize {
		c.opened = 0
	} else {
		c.opened <<= shift
	}
	c.opened |= 1
	c.n = n + 1
	s.fetches, s.stale = 0, false
	if s.role == RoleResponder {
		s.confirmed = true
		// the initiator holds kk2 if it sealed under the session
		s.hsStored = true
	}
	if dummy {
		s.stats.DummiesReceived++
		return Event{Kind: EventDummy}, nil
	}
	s.stats.Received++
	return Event{Kind: EventMessage, Body: body}, nil
}

func (s *Session) open(mk *secmem.Buffer, rec []byte) ([]byte, error) {
	defer mk.Release()
	a, err := s.p.NewAEAD(mk)
	if err != nil {
		return nil, err
	}
	defer a.Destroy()
	inner, err := a.Open(nil, s.nonce, rec[dataHeader:], rec[:dataHeader])
	if err != nil {
		return nil, ErrBad
	}
	return inner, nil
}

// flags with bit 0 for a dummy and nothing else, the length, the body and
// zeroes; a dummy is empty
func parseInner(inner []byte) (body []byte, dummy bool, ok bool) {
	if len(inner) != InnerSize || inner[0]&^flagDummy != 0 {
		return nil, false, false
	}
	dummy = inner[0] == flagDummy
	n := int(binary.BigEndian.Uint16(inner[1:innerHeader]))
	if n > MaxBody || (dummy && n != 0) || !allZero(inner[innerHeader+n:]) {
		return nil, false, false
	}
	return bytes.Clone(inner[innerHeader : innerHeader+n]), dummy, true
}

func (s *Session) Fetched() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.established {
		return
	}
	s.fetches++
	if s.fetches >= s.opt.StaleFetches && !s.stale {
		s.stale = true
		s.stats.Stale++
	}
}

// the initiator starts over when kk2 does not come, when the session went
// stale and when its numbers ran out; the responder waits for a fresh kk1
func (s *Session) Tick() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.role != RoleInitiator {
		return false
	}
	switch {
	case !s.established && s.hs == nil:
		_ = s.startHandshake()
	case !s.established && s.hsStored && s.opt.Now().Sub(s.storedAt) >= s.opt.HandshakeTimeout:
		s.restart()
		return true
	case s.established && (s.stale || s.send.n >= lastNumber):
		s.restart()
		return true
	}
	return false
}

func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// releases every key of the session; the identity stays with its owner
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.drop()
	s.closed = true
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// the hashes of the kk1 ephemeral keys seen lately, the oldest pushed out
type ring struct {
	keys []string
	next int
	set  map[string]struct{}
}

func newRing(size int) ring {
	return ring{keys: make([]string, 0, size), set: make(map[string]struct{}, size)}
}

func (r *ring) has(tag []byte) bool {
	_, ok := r.set[string(tag)]
	return ok
}

func (r *ring) add(tag []byte) {
	k := string(tag)
	if _, ok := r.set[k]; ok {
		return
	}
	if len(r.keys) < cap(r.keys) {
		r.keys = append(r.keys, k)
	} else {
		delete(r.set, r.keys[r.next])
		r.keys[r.next] = k
		r.next = (r.next + 1) % len(r.keys)
	}
	r.set[k] = struct{}{}
}
