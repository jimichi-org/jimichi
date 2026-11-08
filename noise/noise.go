// Package noise shares transactional NN, NK and KK token processing between link and E2E profiles.
package noise

import (
	"bytes"
	"errors"
	"slices"
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

var canonicalNN = Pattern{
	Messages: [][]Token{{TokenE}, {TokenE, TokenEE}},
}

var canonicalNK = Pattern{
	PreResponder: []Token{TokenS},
	Messages:     [][]Token{{TokenE, TokenES}, {TokenE, TokenEE}},
}

var canonicalKK = Pattern{
	PreInitiator: []Token{TokenS},
	PreResponder: []Token{TokenS},
	Messages:     [][]Token{{TokenE, TokenES, TokenSS}, {TokenE, TokenEE, TokenSE}},
}

var NN = clonePattern(canonicalNN)
var NK = clonePattern(canonicalNK)
var KK = clonePattern(canonicalKK)

func clonePattern(p Pattern) Pattern {
	out := Pattern{PreInitiator: append([]Token(nil), p.PreInitiator...), PreResponder: append([]Token(nil), p.PreResponder...)}
	for _, m := range p.Messages {
		out.Messages = append(out.Messages, append([]Token(nil), m...))
	}
	return out
}

func samePattern(a, b Pattern) bool {
	if !slices.Equal(a.PreInitiator, b.PreInitiator) || !slices.Equal(a.PreResponder, b.PreResponder) || len(a.Messages) != len(b.Messages) {
		return false
	}
	for i := range a.Messages {
		if !slices.Equal(a.Messages[i], b.Messages[i]) {
			return false
		}
	}
	return true
}

func canonicalPattern(p Pattern) (Pattern, string, error) {
	for _, c := range []struct {
		p    Pattern
		name string
	}{{canonicalNN, "NN"}, {canonicalNK, "NK"}, {canonicalKK, "KK"}} {
		if samePattern(p, c.p) {
			return clonePattern(c.p), c.name, nil
		}
	}
	return Pattern{}, "", ErrPattern
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
	ErrPattern         = errors.New("noise: unsupported pattern or token")
	ErrConfig          = errors.New("noise: incomplete configuration")
	ErrState           = errors.New("noise: message out of turn or handshake over")
	ErrNoKey           = errors.New("noise: payload before any agreement")
	ErrMessage         = errors.New("noise: message does not open")
	ErrClosed          = errors.New("noise: key released")
	ErrMessageTooLarge = errors.New("noise: message exceeds 65535 bytes")
)

// the local static key; the handshake reaches it only through Agree, so a key
// held elsewhere, or a simulated one, can stand in for it
type DHStatic interface {
	Public() []byte
	NoiseDH(remote []byte) (*secmem.Buffer, error)
}

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

func (k *KeyPair) NoiseDH(remote []byte) (*secmem.Buffer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.priv == nil {
		return nil, ErrClosed
	}
	return k.p.NoiseDH(k.priv, remote)
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

type NoiseConfig struct {
	Provider      jcrypto.CryptoProvider
	Pattern       Pattern
	Initiator     bool
	Prologue      []byte
	Local         DHStatic
	RemoteStatic  []byte
	AcceptPayload func([]byte) bool
}

type staticSnapshot struct {
	Static
	raw DHStatic
	pub []byte
}

func (s staticSnapshot) Public() []byte { return bytes.Clone(s.pub) }
func (s staticSnapshot) NoiseDH(remote []byte) (*secmem.Buffer, error) {
	if s.raw == nil {
		return nil, ErrConfig
	}
	return s.raw.NoiseDH(remote)
}

func NewNoise(cfg NoiseConfig) (*HandshakeState, error) {
	return newNoise(cfg, secmem.New)
}

func newNoise(cfg NoiseConfig, allocate func(int) (*secmem.Buffer, error)) (*HandshakeState, error) {
	if cfg.Provider == nil {
		return nil, ErrConfig
	}
	info := cfg.Provider.HandshakeInfo()
	if !info.Valid() || info.KeySize != cfg.Provider.KeySize() {
		return nil, ErrConfig
	}
	pattern, name, err := canonicalPattern(cfg.Pattern)
	if err != nil {
		return nil, err
	}
	if len(cfg.RemoteStatic) != 0 && len(cfg.RemoteStatic) != info.PublicKeySize {
		return nil, ErrConfig
	}
	var local Static
	if cfg.Local != nil {
		pub := cfg.Local.Public()
		if len(pub) != info.PublicKeySize {
			return nil, ErrConfig
		}
		local = staticSnapshot{raw: cfg.Local, pub: bytes.Clone(pub)}
	}
	if name == "KK" && (local == nil || len(cfg.RemoteStatic) == 0) || name == "NK" && (cfg.Initiator && len(cfg.RemoteStatic) == 0 || !cfg.Initiator && local == nil) {
		return nil, ErrConfig
	}
	return newHandshake(Config{Provider: cfg.Provider, Pattern: pattern,
		Name:      "Noise_" + name + "_" + info.DHName + "_" + info.CipherName + "_" + info.HashName,
		Initiator: cfg.Initiator, Prologue: [][]byte{bytes.Clone(cfg.Prologue)}, Local: local,
		RemoteStatic: bytes.Clone(cfg.RemoteStatic), AcceptPayload: cfg.AcceptPayload}, noiseBackend{allocate: allocate, info: info}, info.PublicKeySize)
}

type HandshakeState struct {
	p         jcrypto.CryptoProvider
	pattern   Pattern
	initiator bool
	accept    func([]byte) bool
	local     Static
	rs        []byte
	pubSize   int

	symmetricState
	backend    symmetricBackend
	production bool
	info       jcrypto.HandshakeInfo
	e          *secmem.Buffer
	re         []byte
	msg        int

	split  bool
	closed bool
}

func New(cfg Config) (*HandshakeState, error) {
	return newHandshake(cfg, legacyBackend{}, 0)
}

func newHandshake(cfg Config, backend symmetricBackend, size int) (*HandshakeState, error) {
	p := cfg.Provider
	if p == nil {
		return nil, ErrConfig
	}
	pattern, _, err := canonicalPattern(cfg.Pattern)
	if err != nil {
		return nil, err
	}
	cfg.Pattern = pattern
	if cfg.Local != nil {
		raw, _ := cfg.Local.(DHStatic)
		cfg.Local = staticSnapshot{Static: cfg.Local, raw: raw, pub: bytes.Clone(cfg.Local.Public())}
	}
	hs := &HandshakeState{
		p: p, backend: backend, pattern: cfg.Pattern,
		initiator: cfg.Initiator, accept: cfg.AcceptPayload,
		local: cfg.Local, rs: bytes.Clone(cfg.RemoteStatic),
	}
	if b, ok := backend.(noiseBackend); ok {
		hs.production = true
		hs.info = b.info
	}
	switch {
	case cfg.Local != nil:
		hs.pubSize = len(cfg.Local.Public())
		if len(hs.rs) != 0 && len(hs.rs) != hs.pubSize {
			return nil, ErrConfig
		}
	case len(hs.rs) != 0:
		hs.pubSize = len(hs.rs)
	case isNN(cfg.Pattern):
		hs.pubSize = size
		if hs.pubSize == 0 {
			priv, pub, err := p.GenerateEphemeral()
			if err != nil {
				return nil, err
			}
			priv.Release()
			hs.pubSize = len(pub)
		}
	default:
		return nil, ErrConfig
	}
	if hs.pubSize == 0 {
		return nil, ErrConfig
	}

	hs.symmetricState, err = backend.initialize(cfg)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			hs.release()
		}
	}()
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
			if hs.h, err = backend.mixHash(p, hs.h, key); err != nil {
				return nil, err
			}
		}
	}
	ok = true
	return hs, nil
}

func isNN(pt Pattern) bool {
	return len(pt.PreInitiator) == 0 && len(pt.PreResponder) == 0 &&
		len(pt.Messages) == 2 && len(pt.Messages[0]) == 1 && pt.Messages[0][0] == TokenE &&
		len(pt.Messages[1]) == 2 && pt.Messages[1][0] == TokenE && pt.Messages[1][1] == TokenEE
}

func (hs *HandshakeState) MixHash(d []byte) error {
	if hs.closed || hs.split || hs.production {
		return ErrState
	}
	h, err := hs.backend.mixHash(hs.p, hs.h, d)
	if err != nil {
		return err
	}
	hs.h = h
	return nil
}

func (hs *HandshakeState) Done() bool { return hs.msg == len(hs.pattern.Messages) }

func (hs *HandshakeState) myTurn() bool {
	return !hs.closed && !hs.split && !hs.Done() && (hs.msg%2 == 0) == hs.initiator
}

func (hs *HandshakeState) WriteMessage(payload []byte) ([]byte, error) {
	return hs.writeMessage(nil, payload, false)
}
func (hs *HandshakeState) WriteMessageBound(prefix, payload []byte) ([]byte, error) {
	return hs.writeMessage(prefix, payload, true)
}
func (hs *HandshakeState) writeMessage(prefix, payload []byte, bound bool) ([]byte, error) {
	if !hs.myTurn() || bound && hs.production {
		return nil, ErrState
	}
	if hs.production {
		overhead := 0
		keyed := hs.key != nil
		for _, t := range hs.pattern.Messages[hs.msg] {
			if t == TokenE {
				overhead += hs.pubSize
			} else {
				keyed = true
			}
		}
		if keyed {
			overhead += hs.info.TagSize
		}
		if len(payload) > 65535-overhead {
			return nil, ErrMessageTooLarge
		}
	}
	st := hs.begin()
	if bound {
		h, err := hs.backend.mixHash(hs.p, st.h, prefix)
		if err != nil {
			hs.abort(st)
			return nil, err
		}
		st.h = h
	}
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
			if priv == nil || len(priv.Bytes()) != 32 || len(pub) != hs.pubSize {
				if priv != nil {
					priv.Release()
				}
				return nil, ErrConfig
			}
			st.e = priv
			out = append(out, pub...)
			if st.h, err = hs.backend.mixHash(hs.p, st.h, pub); err != nil {
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
	return hs.readMessage(nil, msg, false)
}
func (hs *HandshakeState) ReadMessageBound(prefix, msg []byte) ([]byte, error) {
	return hs.readMessage(prefix, msg, true)
}
func (hs *HandshakeState) readMessage(prefix, msg []byte, bound bool) ([]byte, error) {
	if hs.closed || hs.split || hs.Done() || (hs.msg%2 == 0) == hs.initiator || bound && hs.production {
		return nil, ErrState
	}
	if hs.production && len(msg) > 65535 {
		return nil, ErrMessageTooLarge
	}
	st := hs.begin()
	if bound {
		h, err := hs.backend.mixHash(hs.p, st.h, prefix)
		if err != nil {
			hs.abort(st)
			return nil, err
		}
		st.h = h
	}
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
			if st.h, err = hs.backend.mixHash(hs.p, st.h, st.re); err != nil {
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
		secmem.Zero(pt)
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
	i2r, r2i, err = hs.backend.split(hs.p, hs.symmetricState)
	if err != nil {
		return nil, nil, nil, err
	}
	hs.release()
	hs.split = true
	return i2r, r2i, bytes.Clone(hs.h), nil
}

func (hs *HandshakeState) SplitTransport() (i2r, r2i *CipherState, sid []byte, err error) {
	if !hs.production || hs.closed || hs.split || !hs.Done() {
		return nil, nil, nil, ErrState
	}
	first, second, err := hs.backend.split(hs.p, hs.symmetricState)
	if err != nil {
		return nil, nil, nil, err
	}
	defer first.Release()
	defer second.Release()
	i2r, err = newCipherState(hs.p, first, 0, hs.info)
	if err != nil {
		return nil, nil, nil, err
	}
	r2i, err = newCipherState(hs.p, second, 0, hs.info)
	if err != nil {
		i2r.Destroy()
		return nil, nil, nil, err
	}
	sid = bytes.Clone(hs.h)
	hs.release()
	hs.split = true
	return i2r, r2i, sid, nil
}

func (hs *HandshakeState) Close() {
	hs.release()
	hs.closed = true
}

func (hs *HandshakeState) release() {
	if hs.key != nil {
		hs.key.Release()
		hs.key = nil
	}
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
	hs *HandshakeState
	symmetricState
	ownCK      bool
	ownKey     bool
	keyChanged bool
	e          *secmem.Buffer
	re         []byte
}

func (hs *HandshakeState) begin() *step {
	return &step{hs: hs, symmetricState: hs.symmetricState}
}

func (hs *HandshakeState) abort(st *step) {
	if st.ownKey {
		st.key.Release()
	}
	if st.ownCK {
		st.ck.Release()
	}
	if st.e != nil {
		st.e.Release()
	}
}

func (hs *HandshakeState) commit(st *step) {
	if st.keyChanged {
		if hs.key != nil {
			hs.key.Release()
		}
		hs.key = st.key
	}
	hs.nonce = st.nonce
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
	hs.msg++
	if hs.Done() && hs.e != nil {
		hs.e.Release()
		hs.e = nil
	}
}

// legacy contexts distinguish DH tokens without changing the transcript hash
func (st *step) dh(t Token) error {
	p := st.hs.p
	var ctx jcrypto.Context
	var err error
	if !st.hs.production {
		ctx, err = jcrypto.NewContext(p, exchangeDH, st.h, []byte{byte(t)})
		if err != nil {
			return err
		}
	}
	sec, err := st.agree(t, ctx)
	if err != nil {
		return err
	}
	next, key, err := st.hs.backend.mixKey(p, st.ck, sec, ctx)
	if next != sec {
		sec.Release()
	}
	if err != nil {
		return err
	}
	if st.ownCK {
		st.ck.Release()
	}
	if st.ownKey {
		st.key.Release()
	}
	st.ck, st.ownCK = next, true
	st.key, st.ownKey, st.keyChanged = key, key != nil, true
	st.nonce = 0
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
		if st.hs.production {
			raw, ok := st.hs.local.(DHStatic)
			if !ok {
				return nil, ErrConfig
			}
			return raw.NoiseDH(remote)
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
	if st.hs.production {
		return st.hs.p.NoiseDH(e, remote)
	}
	return st.hs.p.Agree(e, remote, ctx)
}

func (st *step) plaintext() bool {
	return st.hs.msg == 0 && isNN(st.hs.pattern)
}

func (st *step) encrypt(pt []byte) ([]byte, error) {
	var c []byte
	var err error
	if !st.hs.backend.keyed(st.symmetricState) {
		if !st.plaintext() {
			return nil, ErrNoKey
		}
		c = bytes.Clone(pt)
	} else {
		c, st.nonce, err = st.hs.backend.encrypt(st.hs.p, st.symmetricState, pt)
		if err != nil {
			return nil, err
		}
	}
	if st.h, err = st.hs.backend.mixHash(st.hs.p, st.h, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (st *step) decrypt(c []byte) ([]byte, error) {
	var pt []byte
	var err error
	if !st.hs.backend.keyed(st.symmetricState) {
		if !st.plaintext() {
			return nil, ErrNoKey
		}
		pt = bytes.Clone(c)
	} else {
		pt, st.nonce, err = st.hs.backend.decrypt(st.hs.p, st.symmetricState, c)
		if err != nil {
			return nil, err
		}
	}
	if st.h, err = st.hs.backend.mixHash(st.hs.p, st.h, c); err != nil {
		secmem.Zero(pt)
		return nil, err
	}
	return pt, nil
}
