package scenario

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/noise"
)

const (
	KindKK1  byte = 0x01
	KindKK2  byte = 0x02
	KindData byte = 0x03
)

// the mailbox of the testbed; the cards name it and the transcripts bind it
const Mailbox = "relay-5.jimichi.svc.cluster.local:9000"

var (
	ErrScript   = errors.New("scenario: the sessions cannot play the script")
	ErrMismatch = errors.New("scenario: the transcript does not verify")
	errNoKey    = errors.New("scenario: no key to answer this agreement with")
)

// a refusal of Verify: Record is the index of the record that does not verify,
// -1 when the transcript is refused as a whole
type Mismatch struct {
	Record int
	Reason string
}

func (m *Mismatch) Error() string {
	if m.Record < 0 {
		return fmt.Sprintf("%v: %s", ErrMismatch, m.Reason)
	}
	return fmt.Sprintf("%v: record %d: %s", ErrMismatch, m.Record, m.Reason)
}

func (m *Mismatch) Is(target error) bool { return target == ErrMismatch }

// the index of the record a Verify error refuses, -1 for any other error
func RefusedAt(err error) int {
	var m *Mismatch
	if errors.As(err, &m) {
		return m.Record
	}
	return -1
}

var (
	senderQueue    = [e2e.QueueSize]byte{0x01}
	recipientQueue = [e2e.QueueSize]byte{0x02}
)

// one data record of a conversation; a dummy carries no body
type Line struct {
	FromSender, Dummy bool
	Body              []byte
}

type Record struct {
	FromSender, Dummy bool
	Kind              byte
	Bytes             []byte
	// the plaintext the transcript claims for a data record
	Body []byte
}

type Transcript struct {
	Sender, Recipient e2e.Card
	Records           []Record
}

// the ephemeral key the recipient drew for its handshake record; the
// provider derives no public key from a private one, so both halves travel
type Evidence struct {
	Ephemeral *secmem.Buffer
	Public    []byte
}

func (ev *Evidence) Release() {
	if ev != nil && ev.Ephemeral != nil {
		ev.Ephemeral.Release()
	}
}

// a sender and a recipient on one mailbox, drawn again until the recipient
// takes role
func Identities(p jcrypto.CryptoProvider, role e2e.Role) (sender, recipient *e2e.Identity, err error) {
	if p == nil {
		return nil, nil, errors.New("scenario: no provider")
	}
	for range 64 {
		s, err := e2e.NewIdentity(p, Mailbox, senderQueue)
		if err != nil {
			return nil, nil, err
		}
		r, err := e2e.NewIdentity(p, Mailbox, recipientQueue)
		if err != nil {
			s.Close()
			return nil, nil, err
		}
		if initiates(r.Card(), s.Card()) == (role == e2e.RoleInitiator) {
			return s, r, nil
		}
		s.Close()
		r.Close()
	}
	return nil, nil, fmt.Errorf("scenario: no pair of keys gave the recipient the role %v", role)
}

// the rule of e2e: the smaller identity key initiates
func initiates(own, peer e2e.Card) bool { return bytes.Compare(own.Static, peer.Static) < 0 }

func Genuine(p jcrypto.CryptoProvider, sender, recipient *e2e.Identity, script []Line) (*Transcript, *Evidence, error) {
	if p == nil || sender == nil || recipient == nil {
		return nil, nil, errors.New("scenario: no provider or identity")
	}
	rec := &recorder{CryptoProvider: p}
	defer rec.release()
	return converse(p, rec, sender, recipient, script)
}

// the sender's side runs on a stand-in for its identity key that holds the
// public half only: no argument carries the sender's private key
func Forge(p jcrypto.CryptoProvider, recipient *e2e.Identity, sender e2e.Card, script []Line) (*Transcript, *Evidence, error) {
	if p == nil || recipient == nil {
		return nil, nil, errors.New("scenario: no provider or identity")
	}
	rec := &recorder{CryptoProvider: p}
	defer rec.release()
	stand := &forgedStatic{pub: bytes.Clone(sender.Static), recipient: recipient.Static(), drawn: rec}
	id, err := e2e.NewIdentityFrom(p, stand, sender)
	if err != nil {
		return nil, nil, err
	}
	defer id.Close()
	return converse(p, rec, id, recipient, script)
}

// both sides are production sessions; the recipient's draws its ephemeral
// keys through rec, which keeps them for the stand-in and for the evidence
func converse(p jcrypto.CryptoProvider, rec *recorder, sender, recipient *e2e.Identity, script []Line) (*Transcript, *Evidence, error) {
	for _, l := range script {
		if l.Dummy && len(l.Body) != 0 {
			return nil, nil, fmt.Errorf("%w: a dummy with a body", ErrScript)
		}
	}
	t := &Transcript{Sender: sender.Card(), Recipient: recipient.Card()}
	ss, err := e2e.NewSession(p, sender, t.Recipient, e2e.Options{})
	if err != nil {
		return nil, nil, err
	}
	defer ss.Close()
	rs, err := e2e.NewSession(rec, recipient, t.Sender, e2e.Options{})
	if err != nil {
		return nil, nil, err
	}
	defer rs.Close()
	if t.Records, err = play(ss, rs, script); err != nil {
		return nil, nil, err
	}
	ev, err := rec.evidence(handshakeKey(t, rs.Role()))
	if err != nil {
		return nil, nil, err
	}
	return t, ev, nil
}

func play(sender, recipient *e2e.Session, script []Line) ([]Record, error) {
	byInitiator := sender.Role() == e2e.RoleInitiator
	ini, resp := sender, recipient
	if !byInitiator {
		ini, resp = recipient, sender
	}
	kk1, ok := ini.Handshake()
	if !ok {
		return nil, errors.New("scenario: the initiator offers no kk1")
	}
	ini.Stored(kk1)
	if err := expect(resp, kk1, e2e.EventSession, nil); err != nil {
		return nil, err
	}
	kk2, ok := resp.Handshake()
	if !ok {
		return nil, errors.New("scenario: the responder offers no kk2")
	}
	resp.Stored(kk2)
	if err := expect(ini, kk2, e2e.EventSession, nil); err != nil {
		return nil, err
	}
	out := []Record{
		{FromSender: byInitiator, Kind: KindKK1, Bytes: kk1},
		{FromSender: !byInitiator, Kind: KindKK2, Bytes: kk2},
	}

	// the responder seals a message only after the first record of the
	// initiator; the conversation driver sends one at once, a dummy if nothing
	// else is waiting
	if len(script) == 0 || script[0].FromSender != byInitiator {
		script = append([]Line{{FromSender: byInitiator, Dummy: true}}, script...)
	}
	for _, l := range script {
		from, to := sender, recipient
		if !l.FromSender {
			from, to = recipient, sender
		}
		rec, err := seal(from, l)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrScript, err)
		}
		if err := expect(to, rec, dataEvent(l.Dummy), l.Body); err != nil {
			return nil, err
		}
		out = append(out, Record{FromSender: l.FromSender, Dummy: l.Dummy, Kind: KindData, Bytes: rec, Body: bytes.Clone(l.Body)})
	}
	return out, nil
}

func seal(s *e2e.Session, l Line) ([]byte, error) {
	if l.Dummy {
		return s.SealDummy()
	}
	return s.Seal(l.Body)
}

func dataEvent(dummy bool) e2e.EventKind {
	if dummy {
		return e2e.EventDummy
	}
	return e2e.EventMessage
}

func expect(s *e2e.Session, rec []byte, want e2e.EventKind, body []byte) error {
	ev, err := s.Receive(rec)
	if err != nil {
		return err
	}
	if ev.Kind != want || !bytes.Equal(ev.Body, body) {
		return fmt.Errorf("scenario: a record of kind %d gave the event %d with %d bytes, want the event %d with %d", rec[0], ev.Kind, len(ev.Body), want, len(body))
	}
	return nil
}

// the ephemeral key in the recipient's handshake record: kk1 when it
// initiates, kk2 when it responds
func handshakeKey(t *Transcript, role e2e.Role) []byte {
	kind := KindKK2
	if role == e2e.RoleInitiator {
		kind = KindKK1
	}
	size := len(t.Recipient.Static)
	for _, r := range t.Records {
		if !r.FromSender && r.Kind == kind && len(r.Bytes) > size {
			return r.Bytes[1 : 1+size]
		}
	}
	return nil
}

// plays the transcript to a fresh session of the recipient that draws the
// evidence key: every record of the sender must open to the body it claims,
// every record of the recipient must come out again byte for byte. Returns
// the sender's messages
func Verify(p jcrypto.CryptoProvider, recipient *e2e.Identity, ev *Evidence, t *Transcript) ([][]byte, error) {
	if p == nil || recipient == nil || ev == nil || ev.Ephemeral == nil || t == nil {
		return nil, errors.New("scenario: nothing to verify")
	}
	if !bytes.Equal(t.Recipient.Bytes(), recipient.Card().Bytes()) {
		return nil, &Mismatch{Record: -1, Reason: "the transcript names another recipient"}
	}
	s, err := e2e.NewSession(&injector{CryptoProvider: p, ev: ev}, recipient, t.Sender, e2e.Options{})
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var said [][]byte
	for i, r := range t.Records {
		if err := r.check(); err != nil {
			return nil, &Mismatch{Record: i, Reason: err.Error()}
		}
		if r.FromSender {
			want := e2e.EventSession
			if r.Kind == KindData {
				want = dataEvent(r.Dummy)
			}
			if err := expect(s, r.Bytes, want, r.Body); err != nil {
				return nil, &Mismatch{Record: i, Reason: "the sender's record: " + err.Error()}
			}
			if want == e2e.EventMessage {
				said = append(said, bytes.Clone(r.Body))
			}
			continue
		}
		made, err := remake(s, r)
		if err != nil {
			return nil, &Mismatch{Record: i, Reason: "the recipient's record: " + err.Error()}
		}
		if !bytes.Equal(made, r.Bytes) {
			return nil, &Mismatch{Record: i, Reason: "the recipient's record comes out otherwise"}
		}
	}
	if _, pending := s.Handshake(); pending || s.State() == e2e.StateHandshaking {
		return nil, &Mismatch{Record: -1, Reason: "no whole handshake"}
	}
	return said, nil
}

func remake(s *e2e.Session, r Record) ([]byte, error) {
	if r.Kind == KindData {
		return seal(s, Line{Dummy: r.Dummy, Body: r.Body})
	}
	rec, ok := s.Handshake()
	if !ok {
		return nil, errors.New("no handshake record to make")
	}
	s.Stored(rec)
	return rec, nil
}

func (r Record) check() error {
	switch {
	case len(r.Bytes) != e2e.RecordSize:
		return fmt.Errorf("%d bytes", len(r.Bytes))
	case r.Kind < KindKK1 || r.Kind > KindData || r.Bytes[0] != r.Kind:
		return fmt.Errorf("kind %d, first byte %d", r.Kind, r.Bytes[0])
	case r.Dummy && r.Kind != KindData:
		return errors.New("a dummy handshake record")
	case (r.Dummy || r.Kind != KindData) && len(r.Body) != 0:
		return errors.New("a body on a record that carries none")
	}
	return nil
}

// a forgery made with a fresh key in place of the recipient's, of the
// recipient's mailbox and queue and in its role, so that the key is the one
// difference
type ControlRun struct {
	Stand *e2e.Identity
	// names the stand as the recipient and verifies under its key
	Transcript *Transcript
	Evidence   *Evidence
	// what Verify says of the same records named to the recipient, under the
	// recipient's key
	Refusal error
}

func (c *ControlRun) Close() {
	if c == nil {
		return
	}
	c.Evidence.Release()
	if c.Stand != nil {
		c.Stand.Close()
	}
}

// the record at which the recipient's key refuses the control, -1 when it does
// not or when it refuses the transcript as a whole, as for a name
func (c *ControlRun) RefusedAt() int { return RefusedAt(c.Refusal) }

func (c *ControlRun) Rejected() bool { return c.RefusedAt() >= 0 }

// the forgery must verify under the key it was made with, or the control
// shows nothing
func Control(p jcrypto.CryptoProvider, recipient *e2e.Identity, sender e2e.Card, script []Line) (*ControlRun, error) {
	if p == nil || recipient == nil {
		return nil, errors.New("scenario: no provider or identity")
	}
	own := recipient.Card()
	run := &ControlRun{}
	for range 64 {
		id, err := e2e.NewIdentity(p, own.Mailbox, own.Queue)
		if err != nil {
			return nil, err
		}
		if initiates(id.Card(), sender) == initiates(own, sender) {
			run.Stand = id
			break
		}
		id.Close()
	}
	if run.Stand == nil {
		return nil, errors.New("scenario: no fresh key took the recipient's role")
	}
	var err error
	if run.Transcript, run.Evidence, err = Forge(p, run.Stand, sender, script); err != nil {
		run.Close()
		return nil, err
	}
	if _, err := Verify(p, run.Stand, run.Evidence, run.Transcript); err != nil {
		run.Close()
		return nil, fmt.Errorf("scenario: the control does not verify under the key it was made with: %w", err)
	}
	named := *run.Transcript
	named.Recipient = own
	if _, run.Refusal = Verify(p, recipient, run.Evidence, &named); run.Refusal != nil && !errors.Is(run.Refusal, ErrMismatch) {
		err := run.Refusal
		run.Close()
		return nil, err
	}
	return run, nil
}

// the clear part of a record, the one part that is not pseudorandom: the kind,
// and in a data record the ratchet number after it (e2e, the data header)
func clearHeader(r Record) []byte {
	n := 1
	if r.Kind == KindData {
		n = 5
	}
	return r.Bytes[:min(n, len(r.Bytes))]
}

// two transcripts of the same cards with the same records in the same order by
// author, kind, length and clear header, claiming the same bodies
func SameShape(a, b *Transcript) bool {
	if a == nil || b == nil || len(a.Records) != len(b.Records) ||
		!bytes.Equal(a.Sender.Bytes(), b.Sender.Bytes()) || !bytes.Equal(a.Recipient.Bytes(), b.Recipient.Bytes()) {
		return false
	}
	for i, x := range a.Records {
		y := b.Records[i]
		if x.FromSender != y.FromSender || x.Dummy != y.Dummy || x.Kind != y.Kind ||
			len(x.Bytes) != len(y.Bytes) || !bytes.Equal(clearHeader(x), clearHeader(y)) || !bytes.Equal(x.Body, y.Body) {
			return false
		}
	}
	return true
}

// passes every draw on and keeps a copy of its private half
type recorder struct {
	jcrypto.CryptoProvider
	mu    sync.Mutex
	drawn []drawnKey
}

type drawnKey struct {
	priv *secmem.Buffer
	pub  []byte
}

func (r *recorder) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := r.CryptoProvider.GenerateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	kept, err := priv.Clone()
	if err != nil {
		priv.Release()
		return nil, nil, err
	}
	r.mu.Lock()
	r.drawn = append(r.drawn, drawnKey{priv: kept, pub: bytes.Clone(pub)})
	r.mu.Unlock()
	return priv, pub, nil
}

// the agreement of the drawn key whose public half is pub with remote
func (r *recorder) agree(pub, remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.drawn {
		if bytes.Equal(d.pub, pub) {
			return r.CryptoProvider.Agree(d.priv, remote, ctx)
		}
	}
	return nil, errNoKey
}

func (r *recorder) evidence(pub []byte) (*Evidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.drawn {
		if len(pub) != 0 && bytes.Equal(d.pub, pub) {
			priv, err := d.priv.Clone()
			if err != nil {
				return nil, err
			}
			return &Evidence{Ephemeral: priv, Public: bytes.Clone(pub)}, nil
		}
	}
	return nil, errors.New("scenario: the recipient drew no key for its handshake record")
}

func (r *recorder) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.drawn {
		d.priv.Release()
	}
	r.drawn = nil
}

// stands in for the sender's identity key with its public half. Agree is
// symmetric under one context on both suites, so the agreement of the
// sender's key with the recipient's identity key, or with an ephemeral key
// the recipient drew, is that key's own agreement with the sender's public key
type forgedStatic struct {
	pub       []byte
	recipient noise.Static
	drawn     *recorder
}

func (f *forgedStatic) Public() []byte { return bytes.Clone(f.pub) }

func (f *forgedStatic) Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if bytes.Equal(remote, f.recipient.Public()) {
		return f.recipient.Agree(f.pub, ctx)
	}
	return f.drawn.agree(remote, f.pub, ctx)
}

// hands the evidence key to every draw of the recipient's session; the draw
// for the card check gets it too, and that agreement is released at once and
// enters no record
type injector struct {
	jcrypto.CryptoProvider
	ev *Evidence
}

func (i *injector) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, err := i.ev.Ephemeral.Clone()
	if err != nil {
		return nil, nil, err
	}
	return priv, bytes.Clone(i.ev.Public), nil
}

// Spy passes every call on and keeps hashes, never keys: of each key pair it
// draws and of each private key that reaches Agree, so a run can tell whether
// a key took part in it
type Spy struct {
	jcrypto.CryptoProvider
	mu     sync.Mutex
	drawn  map[string]string
	agreed map[string]bool
}

func NewSpy(p jcrypto.CryptoProvider) *Spy {
	return &Spy{CryptoProvider: p, drawn: map[string]string{}, agreed: map[string]bool{}}
}

func (s *Spy) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := s.CryptoProvider.GenerateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	pubHash, privHash := s.Hash(pub), s.Hash(priv.Bytes())
	s.mu.Lock()
	s.drawn[string(pubHash)] = string(privHash)
	s.mu.Unlock()
	return priv, pub, nil
}

func (s *Spy) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if priv != nil {
		if b := priv.Bytes(); b != nil {
			h := s.Hash(b)
			s.mu.Lock()
			s.agreed[string(h)] = true
			s.mu.Unlock()
		}
	}
	return s.CryptoProvider.Agree(priv, pub, ctx)
}

// whether the private key drawn with pub reached Agree since the last Forget
func (s *Spy) Used(pub []byte) bool {
	h := s.Hash(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	priv, ok := s.drawn[string(h)]
	return ok && s.agreed[priv]
}

// whether the spy drew the key pair with the public half pub
func (s *Spy) Drew(pub []byte) bool {
	h := s.Hash(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.drawn[string(h)]
	return ok
}

func (s *Spy) Forget() {
	s.mu.Lock()
	s.agreed = map[string]bool{}
	s.mu.Unlock()
}
