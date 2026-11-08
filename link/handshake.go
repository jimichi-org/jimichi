package link

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	handshakeVersion = 4
	handshakeSize    = 528
	modeAnonymous    = 0
	modeClient       = 1
	modePeer         = 2
)

var (
	ErrHandshake = errors.New("link: handshake failed")
	ErrFrame     = errors.New("link: frame did not open")

	errIdentityWithoutKey = errors.New("link: an identity needs the link key it goes with")
)

type Peer struct {
	LinkPub  []byte
	Identity []byte
}

type Local struct {
	StaticPriv *secmem.Buffer
	StaticPub  []byte
	Identity   []byte
	Addr       string
}

type AcceptConfig struct {
	Local          Local
	Peers          func(string) (Peer, bool)
	AllowAnonymous bool
}

type borrowedStatic struct {
	p    jcrypto.CryptoProvider
	priv *secmem.Buffer
	pub  []byte
}

func (k borrowedStatic) Public() []byte { return bytes.Clone(k.pub) }

func (k borrowedStatic) Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	return k.p.Agree(k.priv, remote, ctx)
}

func (k borrowedStatic) NoiseDH(remote []byte) (*secmem.Buffer, error) {
	return k.p.NoiseDH(k.priv, remote)
}

func Dial(raw net.Conn, p jcrypto.CryptoProvider, peerStatic, peerIdentity []byte) (*Conn, error) {
	if peerStatic == nil && len(peerIdentity) > 0 {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, handshakeError(errIdentityWithoutKey)
	}
	mode := byte(modeAnonymous)
	if peerStatic != nil {
		mode = modeClient
	}
	return dial(raw, p, mode, Local{}, Peer{LinkPub: peerStatic, Identity: peerIdentity})
}

func DialPeer(raw net.Conn, p jcrypto.CryptoProvider, local Local, peer Peer) (*Conn, error) {
	return dial(raw, p, modePeer, local, peer)
}

func dial(raw net.Conn, p jcrypto.CryptoProvider, mode byte, local Local, peer Peer) (result *Conn, resultErr error) {
	defer func() {
		if result == nil && raw != nil {
			_ = raw.Close()
		}
	}()
	if raw == nil {
		return nil, ErrHandshake
	}
	local, peer = snapshotLocal(local), snapshotPeer(peer)
	n, tag, err := handshakeSizes(p)
	if err != nil {
		return nil, handshakeError(err)
	}
	if mode != modeAnonymous && !validPeer(peer, n) {
		return nil, handshakeError(jcrypto.ErrBadPublicKey)
	}
	selector := ""
	if mode == modePeer {
		if !validLocal(local, n) || !pki.ValidAddr(local.Addr) {
			return nil, ErrHandshake
		}
		selector = local.Addr
	}
	header := append([]byte{handshakeVersion, mode, byte(len(selector))}, selector...)
	firstTag := tag
	if mode == modeAnonymous {
		firstTag = 0
	}
	hs, err := newHandshake(p, mode, true, local, peer, header, handshakeSize-n-tag)
	if err != nil {
		return nil, handshakeError(err)
	}
	defer hs.Close()
	message, err := hs.WriteMessage(make([]byte, handshakeSize-len(header)-n-firstTag))
	if err != nil {
		return nil, handshakeError(err)
	}
	flight := append(header, message...)
	if len(flight) != handshakeSize {
		return nil, ErrHandshake
	}
	if err := writeFull(raw, flight); err != nil {
		return nil, handshakeError(err)
	}
	answer, err := readFlight(raw)
	if err != nil {
		return nil, handshakeError(err)
	}
	if _, err := hs.ReadMessage(answer); err != nil {
		return nil, handshakeError(err)
	}
	return finish(raw, p, hs, true)
}

func Accept(raw net.Conn, p jcrypto.CryptoProvider, staticPriv *secmem.Buffer, staticPub, identity []byte) (*Conn, error) {
	return AcceptWithConfig(raw, p, AcceptConfig{
		Local: Local{StaticPriv: staticPriv, StaticPub: staticPub, Identity: identity}, AllowAnonymous: false,
	})
}

func AcceptWithConfig(raw net.Conn, p jcrypto.CryptoProvider, cfg AcceptConfig) (result *Conn, resultErr error) {
	defer func() {
		if result == nil && raw != nil {
			_ = raw.Close()
		}
	}()
	if raw == nil {
		return nil, ErrHandshake
	}
	cfg.Local = snapshotLocal(cfg.Local)
	n, tag, err := handshakeSizes(p)
	if err != nil {
		return nil, handshakeError(err)
	}
	flight, err := readFirstFlight(raw)
	if err != nil {
		return nil, handshakeError(err)
	}
	mode, selectorSize := flight[1], int(flight[2])
	local := cfg.Local
	switch mode {
	case modeAnonymous:
		if !cfg.AllowAnonymous {
			return nil, ErrHandshake
		}
		local = Local{}
	case modeClient:
		if !validLocal(local, n) {
			return nil, ErrHandshake
		}
	case modePeer:
		if !validLocal(local, n) || cfg.Peers == nil || selectorSize == 0 {
			return nil, ErrHandshake
		}
	default:
		return nil, ErrHandshake
	}
	header := flight[:3+selectorSize]
	var peer Peer
	if mode == modePeer {
		selector := string(header[3:])
		if !pki.ValidAddr(selector) {
			return nil, ErrHandshake
		}
		var ok bool
		peer, ok = cfg.Peers(selector)
		peer = snapshotPeer(peer)
		if !ok || !validPeer(peer, n) {
			return nil, ErrHandshake
		}
	}
	firstTag := tag
	if mode == modeAnonymous {
		firstTag = 0
	}
	hs, err := newHandshake(p, mode, false, local, peer, header, handshakeSize-len(header)-n-firstTag)
	if err != nil {
		return nil, handshakeError(err)
	}
	defer hs.Close()
	if _, err := hs.ReadMessage(flight[len(header):]); err != nil {
		return nil, handshakeError(err)
	}
	answer, err := hs.WriteMessage(make([]byte, handshakeSize-n-tag))
	if err != nil {
		return nil, handshakeError(err)
	}
	if len(answer) != handshakeSize {
		return nil, ErrHandshake
	}
	if err := writeFull(raw, answer); err != nil {
		return nil, handshakeError(err)
	}
	return finish(raw, p, hs, false)
}

func handshakeSizes(p jcrypto.CryptoProvider) (int, int, error) {
	info, err := handshakeInfo(p)
	if err != nil {
		return 0, 0, err
	}
	if 3+wire.AddrSize+info.PublicKeySize+info.TagSize >= handshakeSize {
		return 0, 0, ErrHandshake
	}
	return info.PublicKeySize, info.TagSize, nil
}

func snapshotPeer(peer Peer) Peer {
	return Peer{LinkPub: bytes.Clone(peer.LinkPub), Identity: bytes.Clone(peer.Identity)}
}
func snapshotLocal(local Local) Local {
	local.StaticPub = bytes.Clone(local.StaticPub)
	local.Identity = bytes.Clone(local.Identity)
	return local
}

func readFlight(r io.Reader) ([]byte, error) {
	flight := make([]byte, handshakeSize)
	if _, err := io.ReadFull(r, flight); err != nil {
		return nil, err
	}
	return flight, nil
}
func readFirstFlight(r io.Reader) ([]byte, error) {
	flight := make([]byte, handshakeSize)
	if _, err := io.ReadFull(r, flight[:3]); err != nil {
		return nil, err
	}
	mode, n := flight[1], int(flight[2])
	if flight[0] != handshakeVersion || mode > modePeer || n > wire.AddrSize || mode != modePeer && n != 0 || mode == modePeer && n == 0 {
		return nil, ErrHandshake
	}
	if _, err := io.ReadFull(r, flight[3:]); err != nil {
		return nil, err
	}
	if mode == modePeer && !pki.ValidAddr(string(flight[3:3+n])) {
		return nil, ErrHandshake
	}
	return flight, nil
}

func validPeer(peer Peer, n int) bool {
	return len(peer.LinkPub) == n && (len(peer.Identity) == 0 || len(peer.Identity) == n)
}

func validLocal(local Local, n int) bool {
	return local.StaticPriv != nil && local.StaticPriv.Bytes() != nil && validPeer(Peer{local.StaticPub, local.Identity}, n)
}

func handshakePrologue(p jcrypto.CryptoProvider, mode byte, header, initiator, responder []byte) []byte {
	out := []byte("jimichi/link/v1/" + p.Suite().String() + "/" + []string{"nn", "nk", "kk"}[mode])
	out = append(out, 0, wire.Version)
	out = binary.BigEndian.AppendUint16(out, uint16(len(header)))
	out = append(out, header...)
	for i, id := range [][]byte{initiator, responder} {
		out = append(out, byte(i+1))
		out = binary.BigEndian.AppendUint16(out, uint16(len(id)))
		out = append(out, id...)
	}
	return out
}

func newHandshake(p jcrypto.CryptoProvider, mode byte, initiator bool, local Local, peer Peer, header []byte, payloadSize int) (*noise.HandshakeState, error) {
	patterns := []noise.Pattern{noise.NN, noise.NK, noise.KK}
	var localStatic noise.DHStatic
	var remote, initiatorIdentity, responderIdentity []byte
	if mode != modeAnonymous {
		if !initiator || mode == modePeer {
			localStatic = borrowedStatic{p, local.StaticPriv, local.StaticPub}
		}
		if initiator || mode == modePeer {
			remote = peer.LinkPub
		}
		responderIdentity = local.Identity
		if initiator {
			responderIdentity = peer.Identity
		}
		if mode == modePeer {
			initiatorIdentity = peer.Identity
			if initiator {
				initiatorIdentity = local.Identity
			}
		}
	}
	return noise.NewNoise(noise.NoiseConfig{
		Provider: p, Pattern: patterns[mode],
		Initiator: initiator, Local: localStatic, RemoteStatic: remote,
		Prologue: handshakePrologue(p, mode, header, initiatorIdentity, responderIdentity),
		AcceptPayload: func(payload []byte) bool {
			if len(payload) != payloadSize {
				return false
			}
			for _, b := range payload {
				if b != 0 {
					return false
				}
			}
			return true
		},
	})
}

func finish(raw net.Conn, p jcrypto.CryptoProvider, hs *noise.HandshakeState, initiator bool) (*Conn, error) {
	i2r, r2i, _, err := hs.SplitTransport()
	if err != nil {
		return nil, handshakeError(err)
	}
	send, recv := i2r, r2i
	if !initiator {
		send, recv = r2i, i2r
	}
	return &Conn{raw: raw, send: send, recv: recv, frame: handshakeSize, buf: make([]byte, handshakeSize), confirmed: initiator}, nil
}

func writeFull(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func handshakeError(err error) error { return fmt.Errorf("%w: %w", ErrHandshake, err) }
