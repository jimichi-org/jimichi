// Package noise runs Noise-shaped handshakes over a CryptoProvider. It is not
// a Noise instance: Agree returns a KDF output rather than a raw DH value, the
// hash and the chaining key go through transcript contexts, and no chaining key
// comes from the protocol name.
package noise

import (
	"bytes"
	"errors"
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type Token uint8

const (
	TokenE Token = iota + 1
	TokenS
	TokenEE
	TokenES
	TokenSE
	TokenSS
)

type Pattern struct {
	PreInitiator, PreResponder []Token
	Messages                   [][]Token
}

var KK = Pattern{
	PreInitiator: []Token{TokenS},
	PreResponder: []Token{TokenS},
	Messages:     [][]Token{{TokenE, TokenES, TokenSS}, {TokenE, TokenEE, TokenSE}},
}

const (
	exchangeHash  = "noise/hash"
	exchangeDH    = "noise/dh"
	exchangeKey   = "noise/key"
	exchangeSplit = "noise/split"

	purposeKey = "noise/key"
	purposeI2R = "noise/split/i2r"
	purposeR2I = "noise/split/r2i"
)

var (
	ErrPattern = errors.New("noise: unsupported pattern or token")
	ErrConfig  = errors.New("noise: incomplete configuration")
	ErrState   = errors.New("noise: message out of turn or handshake over")
	ErrNoKey   = errors.New("noise: payload before any agreement")
	ErrMessage = errors.New("noise: message does not open")
	ErrClosed  = errors.New("noise: key released")
)

// the local static key; the handshake reaches it only through Agree, so a key
// held elsewhere, or a simulated one, can stand in for it
type Static interface {
	Public() []byte
	Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error)
}

// a Static over a key the pair owns and releases on Close
type KeyPair struct {
	p   jcrypto.CryptoProvider
	pub []byte

	mu   sync.RWMutex
	priv *secmem.Buffer
}

func NewKeyPair(p jcrypto.CryptoProvider, priv *secmem.Buffer, pub []byte) *KeyPair {
	return &KeyPair{p: p, pub: bytes.Clone(pub), priv: priv}
}

func (k *KeyPair) Public() []byte { return bytes.Clone(k.pub) }

func (k *KeyPair) Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.priv == nil {
		return nil, ErrClosed
	}
	return k.p.Agree(k.priv, remote, ctx)
}

func (k *KeyPair) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.priv != nil {
		k.priv.Release()
		k.priv = nil
	}
}

type Config struct {
	Provider jcrypto.CryptoProvider
	Pattern  Pattern
	// the handshake transcript starts as the exchange "noise/"+Name
	Name         string
	Initiator    bool
	Prologue     [][]byte
	Local        Static
	RemoteStatic []byte
	// a payload it refuses fails the read like one that does not open, and
	// leaves the state as it was; nil takes any payload
	AcceptPayload func(payload []byte) bool
}

type HandshakeState struct {
	p         jcrypto.CryptoProvider
	pattern   Pattern
	initiator bool
	accept    func([]byte) bool
	local     Static
	rs        []byte
	pubSize   int

	h []byte
	// h at the end of the last message: a failed message rolls back to it,
	// with the MixHash calls made for that message
	mark []byte
	ck   *secmem.Buffer
	e    *secmem.Buffer
	re   []byte
	msg  int

	split  bool
	closed bool
}

func New(cfg Config) (*HandshakeState, error) {
	p := cfg.Provider
	if p == nil {
		return nil, ErrConfig
	}
	if err := checkPattern(cfg.Pattern); err != nil {
		return nil, err
	}
	hs := &HandshakeState{
		p:         p,
		pattern:   cfg.Pattern,
		initiator: cfg.Initiator,
		accept:    cfg.AcceptPayload,
		local:     cfg.Local,
		rs:        bytes.Clone(cfg.RemoteStatic),
	}
	// the provider has no size query: the static keys give the size of the
	// ephemeral ones, so every pattern here holds at least one
	switch {
	case cfg.Local != nil:
		hs.pubSize = len(cfg.Local.Public())
		if len(hs.rs) != 0 && len(hs.rs) != hs.pubSize {
			return nil, ErrConfig
		}
	case len(hs.rs) != 0:
		hs.pubSize = len(hs.rs)
	default:
		return nil, ErrConfig
	}
	if hs.pubSize == 0 {
		return nil, ErrConfig
	}

	ctx, err := jcrypto.NewContext(p, "noise/"+cfg.Name, cfg.Prologue...)
	if err != nil {
		return nil, err
	}
	hs.h = ctx.Sum()
	for _, pre := range []struct {
		tokens    []Token
		initiator bool
	}{{cfg.Pattern.PreInitiator, true}, {cfg.Pattern.PreResponder, false}} {
		for range pre.tokens {
			key := hs.rs
			if pre.initiator == hs.initiator {
				if hs.local == nil {
					return nil, ErrConfig
				}
				key = hs.local.Public()
			}
			if len(key) == 0 {
				return nil, ErrConfig
			}
			if hs.h, err = mixHash(p, hs.h, key); err != nil {
				return nil, err
			}
		}
	}
	hs.mark = bytes.Clone(hs.h)
	return hs, nil
}

// pre-messages carry static keys only; a static key sent inside a message is
// not supported yet
func checkPattern(pt Pattern) error {
	if len(pt.Messages) == 0 {
		return ErrPattern
	}
	for _, pre := range [][]Token{pt.PreInitiator, pt.PreResponder} {
		if len(pre) > 1 || (len(pre) == 1 && pre[0] != TokenS) {
			return ErrPattern
		}
	}
	for _, m := range pt.Messages {
		for _, t := range m {
			if t != TokenE && (t < TokenEE || t > TokenSS) {
				return ErrPattern
			}
		}
	}
	return nil
}

func mixHash(p jcrypto.CryptoProvider, h, d []byte) ([]byte, error) {
	ctx, err := jcrypto.NewContext(p, exchangeHash, h, d)
	if err != nil {
		return nil, err
	}
	return ctx.Sum(), nil
}

func (hs *HandshakeState) MixHash(d []byte) error {
	if hs.closed || hs.split {
		return ErrState
	}
	h, err := mixHash(hs.p, hs.h, d)
	if err != nil {
		return err
	}
	hs.h = h
	return nil
}

func (hs *HandshakeState) Done() bool { return hs.msg == len(hs.pattern.Messages) }

func (hs *HandshakeState) myTurn() bool {
	return !hs.closed && !hs.Done() && (hs.msg%2 == 0) == hs.initiator
}

func (hs *HandshakeState) WriteMessage(payload []byte) ([]byte, error) {
	if !hs.myTurn() {
		return nil, ErrState
	}
	st := hs.begin()
	out, err := hs.write(st, payload)
	if err != nil {
		hs.abort(st)
		return nil, err
	}
	hs.commit(st)
	return out, nil
}

func (hs *HandshakeState) write(st *step, payload []byte) ([]byte, error) {
	var out []byte
	for _, t := range hs.pattern.Messages[hs.msg] {
		if t == TokenE {
			if hs.e != nil || st.e != nil {
				return nil, ErrPattern
			}
			priv, pub, err := hs.p.GenerateEphemeral()
			if err != nil {
				return nil, err
			}
			st.e = priv
			out = append(out, pub...)
			if st.h, err = mixHash(hs.p, st.h, pub); err != nil {
				return nil, err
			}
			continue
		}
		if err := st.dh(t); err != nil {
			return nil, err
		}
	}
	c, err := st.encrypt(payload)
	if err != nil {
		return nil, err
	}
	return append(out, c...), nil
}

// nothing changes until the message opened and its payload was accepted, so
// a forged message cannot break a handshake that waits for the real one
func (hs *HandshakeState) ReadMessage(msg []byte) ([]byte, error) {
	if hs.closed || hs.Done() || (hs.msg%2 == 0) == hs.initiator {
		return nil, ErrState
	}
	st := hs.begin()
	pt, err := hs.read(st, msg)
	if err != nil {
		hs.abort(st)
		return nil, err
	}
	hs.commit(st)
	return pt, nil
}

func (hs *HandshakeState) read(st *step, msg []byte) ([]byte, error) {
	rest := msg
	for _, t := range hs.pattern.Messages[hs.msg] {
		if t == TokenE {
			if hs.re != nil || st.re != nil || len(rest) < hs.pubSize {
				return nil, ErrMessage
			}
			st.re = bytes.Clone(rest[:hs.pubSize])
			rest = rest[hs.pubSize:]
			var err error
			if st.h, err = mixHash(hs.p, st.h, st.re); err != nil {
				return nil, err
			}
			continue
		}
		if err := st.dh(t); err != nil {
			if errors.Is(err, jcrypto.ErrBadPublicKey) {
				return nil, ErrMessage
			}
			return nil, err
		}
	}
	pt, err := st.decrypt(rest)
	if err != nil {
		return nil, err
	}
	if hs.accept != nil && !hs.accept(pt) {
		return nil, ErrMessage
	}
	return pt, nil
}

// Split hands the two direction keys to the caller and keeps nothing secret;
// sid is the final transcript hash
func (hs *HandshakeState) Split() (i2r, r2i *secmem.Buffer, sid []byte, err error) {
	if hs.closed || hs.split || !hs.Done() {
		return nil, nil, nil, ErrState
	}
	if hs.ck == nil {
		return nil, nil, nil, ErrNoKey
	}
	ctx, err := jcrypto.NewContext(hs.p, exchangeSplit, hs.h)
	if err != nil {
		return nil, nil, nil, err
	}
	i2r, err = hs.p.DeriveKey(hs.ck, purposeI2R, ctx, hs.p.KeySize())
	if err != nil {
		return nil, nil, nil, err
	}
	r2i, err = hs.p.DeriveKey(hs.ck, purposeR2I, ctx, hs.p.KeySize())
	if err != nil {
		i2r.Release()
		return nil, nil, nil, err
	}
	hs.release()
	hs.split = true
	return i2r, r2i, bytes.Clone(hs.h), nil
}

func (hs *HandshakeState) Close() {
	hs.release()
	hs.closed = true
}

func (hs *HandshakeState) release() {
	if hs.ck != nil {
		hs.ck.Release()
		hs.ck = nil
	}
	if hs.e != nil {
		hs.e.Release()
		hs.e = nil
	}
}

// the values one message changes, held apart until it succeeds
type step struct {
	hs    *HandshakeState
	h     []byte
	ck    *secmem.Buffer
	ownCK bool
	e     *secmem.Buffer
	re    []byte
}

func (hs *HandshakeState) begin() *step {
	return &step{hs: hs, h: hs.h, ck: hs.ck}
}

func (hs *HandshakeState) abort(st *step) {
	if st.ownCK {
		st.ck.Release()
	}
	if st.e != nil {
		st.e.Release()
	}
	hs.h = bytes.Clone(hs.mark)
}

func (hs *HandshakeState) commit(st *step) {
	if st.ownCK {
		if hs.ck != nil {
			hs.ck.Release()
		}
		hs.ck = st.ck
	}
	if st.e != nil {
		hs.e = st.e
	}
	if st.re != nil {
		hs.re = st.re
	}
	hs.h = st.h
	hs.mark = bytes.Clone(st.h)
	hs.msg++
	if hs.Done() && hs.e != nil {
		hs.e.Release()
		hs.e = nil
	}
}

// every DH token of a message sees the same h; the token byte in the context
// tells them apart
func (st *step) dh(t Token) error {
	p := st.hs.p
	ctx, err := jcrypto.NewContext(p, exchangeDH, st.h, []byte{byte(t)})
	if err != nil {
		return err
	}
	sec, err := st.agree(t, ctx)
	if err != nil {
		return err
	}
	if st.ck == nil {
		st.ck, st.ownCK = sec, true
		return nil
	}
	next, err := p.MixKey(st.ck, sec, ctx)
	sec.Release()
	if err != nil {
		return err
	}
	if st.ownCK {
		st.ck.Release()
	}
	st.ck, st.ownCK = next, true
	return nil
}

// the first letter of a token names the initiator's key, the second the
// responder's
func (st *step) agree(t Token, ctx jcrypto.Context) (*secmem.Buffer, error) {
	var mine, theirs byte
	switch t {
	case TokenEE:
		mine, theirs = 'e', 'e'
	case TokenSS:
		mine, theirs = 's', 's'
	case TokenES:
		mine, theirs = 'e', 's'
	case TokenSE:
		mine, theirs = 's', 'e'
	default:
		return nil, ErrPattern
	}
	if !st.hs.initiator {
		mine, theirs = theirs, mine
	}

	remote := st.hs.rs
	if theirs == 'e' {
		remote = st.re
		if remote == nil {
			remote = st.hs.re
		}
	}
	if len(remote) == 0 {
		return nil, ErrPattern
	}
	if mine == 's' {
		if st.hs.local == nil {
			return nil, ErrPattern
		}
		return st.hs.local.Agree(remote, ctx)
	}
	e := st.e
	if e == nil {
		e = st.hs.e
	}
	if e == nil {
		return nil, ErrPattern
	}
	return st.hs.p.Agree(e, remote, ctx)
}

// one key per message and h as the associated data, so the zero nonce never
// repeats under a key
func (st *step) aead() (jcrypto.AEAD, error) {
	if st.ck == nil {
		return nil, ErrNoKey
	}
	p := st.hs.p
	ctx, err := jcrypto.NewContext(p, exchangeKey, st.h)
	if err != nil {
		return nil, err
	}
	k, err := p.DeriveKey(st.ck, purposeKey, ctx, p.KeySize())
	if err != nil {
		return nil, err
	}
	defer k.Release()
	return p.NewAEAD(k)
}

func (st *step) encrypt(pt []byte) ([]byte, error) {
	a, err := st.aead()
	if err != nil {
		return nil, err
	}
	c := a.Seal(nil, make([]byte, a.NonceSize()), pt, st.h)
	a.Destroy()
	if st.h, err = mixHash(st.hs.p, st.h, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (st *step) decrypt(c []byte) ([]byte, error) {
	a, err := st.aead()
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, make([]byte, a.NonceSize()), c, st.h)
	a.Destroy()
	if err != nil {
		return nil, ErrMessage
	}
	if st.h, err = mixHash(st.hs.p, st.h, c); err != nil {
		return nil, err
	}
	return pt, nil
}
