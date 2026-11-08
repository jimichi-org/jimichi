package link

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

type flightFixture struct {
	p             jcrypto.CryptoProvider
	mode          byte
	local, peer   Local
	first, second []byte
}

func flights(t *testing.T, kind jcrypto.Suite, mode byte) flightFixture {
	t.Helper()
	p, err := suite.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	makeLocal := func(addr string) Local {
		b, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Release)
		return Local{StaticPriv: b, StaticPub: pub, Addr: addr}
	}
	i, r := makeLocal("i.test:9000"), makeLocal("r.test:9000")
	selector := ""
	if mode == modePeer {
		selector = i.Addr
	}
	header := append([]byte{4, mode, byte(len(selector))}, selector...)
	n, tag, err := handshakeSizes(p)
	if err != nil {
		t.Fatal(err)
	}
	firstTag := tag
	if mode == modeAnonymous {
		firstTag = 0
	}
	ini, err := newHandshake(p, mode, true, i, Peer{LinkPub: r.StaticPub}, header, handshakeSize-n-tag)
	if err != nil {
		t.Fatal(err)
	}
	defer ini.Close()
	resp, err := newHandshake(p, mode, false, r, Peer{LinkPub: i.StaticPub}, header, handshakeSize-len(header)-n-firstTag)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()
	first, err := ini.WriteMessage(make([]byte, handshakeSize-len(header)-n-firstTag))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.ReadMessage(first); err != nil {
		t.Fatal(err)
	}
	second, err := resp.WriteMessage(make([]byte, handshakeSize-n-tag))
	if err != nil {
		t.Fatal(err)
	}
	return flightFixture{p, mode, i, r, append(header, first...), second}
}
func TestEveryFlightPrefixAndFragmentBoundary(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for mode := byte(0); mode <= 2; mode++ {
			f := flights(t, kind, mode)
			for _, tc := range []struct {
				raw  []byte
				read func(io.Reader) ([]byte, error)
			}{{f.first, readFirstFlight}, {f.first, readFlight}, {f.second, readFlight}} {
				for n := 0; n < handshakeSize; n++ {
					if out, err := tc.read(bytes.NewReader(tc.raw[:n])); out != nil || err == nil {
						t.Fatalf("%s mode %d accepted prefix %d", kind, mode, n)
					}
				}
				for n := 1; n < handshakeSize; n++ {
					out, err := tc.read(io.MultiReader(bytes.NewReader(tc.raw[:n]), bytes.NewReader(tc.raw[n:])))
					if err != nil || !bytes.Equal(out, tc.raw) {
						t.Fatalf("%s mode %d fragment %d: %v", kind, mode, n, err)
					}
				}
			}
		}
	}
}

type scriptedSocket struct {
	input             []byte
	readErr, writeErr error
	short             bool
	closed            bool
	writes            int
}

func (s *scriptedSocket) Read(b []byte) (int, error) {
	if len(s.input) == 0 {
		if s.readErr != nil {
			return 0, s.readErr
		}
		return 0, io.EOF
	}
	n := copy(b, s.input)
	s.input = s.input[n:]
	return n, nil
}
func (s *scriptedSocket) Write(b []byte) (int, error) {
	s.writes++
	if s.short || s.writeErr != nil {
		return len(b) / 2, s.writeErr
	}
	return len(b), nil
}
func (s *scriptedSocket) Close() error                     { s.closed = true; return nil }
func (s *scriptedSocket) LocalAddr() net.Addr              { return dummyAddr("local") }
func (s *scriptedSocket) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (s *scriptedSocket) SetDeadline(time.Time) error      { return nil }
func (s *scriptedSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *scriptedSocket) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "test" }
func (d dummyAddr) String() string  { return string(d) }

type timeoutFault struct{}

func (timeoutFault) Error() string   { return "scripted timeout" }
func (timeoutFault) Timeout() bool   { return true }
func (timeoutFault) Temporary() bool { return true }
func assertBorrowed(t *testing.T, p jcrypto.CryptoProvider, local Local, before []byte) {
	t.Helper()
	if !bytes.Equal(local.StaticPriv.Bytes(), before) {
		t.Fatal("I/O failure changed borrowed static")
	}
	b, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	out, err := p.NoiseDH(local.StaticPriv, pub)
	if err != nil {
		t.Fatal("borrowed static unusable after I/O failure")
	}
	out.Release()
}
func publicFlight(t *testing.T, f flightFixture, s *scriptedSocket, dial bool) (*Conn, error) {
	t.Helper()
	if dial {
		if f.mode == modePeer {
			return DialPeer(s, f.p, f.local, Peer{LinkPub: f.peer.StaticPub})
		}
		var key []byte
		if f.mode == modeClient {
			key = f.peer.StaticPub
		}
		return Dial(s, f.p, key, nil)
	}
	return AcceptWithConfig(s, f.p, AcceptConfig{Local: f.peer, AllowAnonymous: f.mode == modeAnonymous, Peers: func(addr string) (Peer, bool) { return Peer{LinkPub: f.local.StaticPub}, addr == f.local.Addr }})
}
func TestPublicFlightIOFailuresCloseSocket(t *testing.T) {
	sentinel := errors.New("scripted I/O failure")
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for mode := byte(0); mode <= 2; mode++ {
			f := flights(t, kind, mode)
			beforeI, beforeR := bytes.Clone(f.local.StaticPriv.Bytes()), bytes.Clone(f.peer.StaticPriv.Bytes())
			for _, dial := range []bool{true, false} {
				inbound := f.first
				if dial {
					inbound = f.second
				}
				cuts := []int{0, 1, 2, 3, 3 + len(f.local.Addr), 3 + f.p.HandshakeInfo().PublicKeySize, handshakeSize - 17, handshakeSize - 1}
				for _, cut := range cuts {
					for _, cause := range []error{io.EOF, sentinel, timeoutFault{}} {
						s := &scriptedSocket{input: bytes.Clone(inbound[:cut]), readErr: cause}
						c, err := publicFlight(t, f, s, dial)
						if c != nil || !errors.Is(err, ErrHandshake) || !s.closed {
							t.Fatalf("%s mode %d dial %v read cutoff %d: %v", kind, mode, dial, cut, err)
						}
						if !errors.Is(err, cause) && !errors.Is(cause, io.EOF) {
							t.Fatal("underlying read error identity lost")
						}
					}
				}
				for _, fault := range []struct {
					short bool
					err   error
					want  error
				}{{true, nil, io.ErrShortWrite}, {false, sentinel, sentinel}, {false, timeoutFault{}, timeoutFault{}}} {
					s := &scriptedSocket{input: bytes.Clone(inbound), short: fault.short, writeErr: fault.err}
					c, err := publicFlight(t, f, s, dial)
					if c != nil || !errors.Is(err, ErrHandshake) || !errors.Is(err, fault.want) || !s.closed || s.writes != 1 {
						t.Fatalf("%s mode %d dial %v write failure: %v", kind, mode, dial, err)
					}
				}
			}
			assertBorrowed(t, f.p, f.local, beforeI)
			assertBorrowed(t, f.p, f.peer, beforeR)
		}
	}
}
func TestHandshakeMetadataDoesNotProbeCryptography(t *testing.T) {
	p := metadataOnly{}
	if n, err := FrameSize(p); err != nil || n != 528 {
		t.Fatal("metadata frame size mismatch")
	}
	if n, err := InitiatorHandshakeSize(p); err != nil || n != 528 {
		t.Fatal("metadata flight size mismatch")
	}
	if n, err := ResponderHandshakeSize(p); err != nil || n != 528 {
		t.Fatal("metadata response size mismatch")
	}
}

type metadataOnly struct{ jcrypto.CryptoProvider }

func (metadataOnly) HandshakeInfo() jcrypto.HandshakeInfo {
	return jcrypto.HandshakeInfo{DHName: "25519", CipherName: "JimichiXChaChaPoly", HashName: "SHA256", PublicKeySize: 32, DHSize: 32, HashSize: 32, KeySize: 32, NonceSize: 24, TagSize: 16}
}
func (metadataOnly) KeySize() int { return 32 }
