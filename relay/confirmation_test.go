package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/wire"
)

type compromisedResponder struct {
	p                  jcrypto.CryptoProvider
	priv               *secmem.Buffer
	claimed, responder []byte
}

func (k compromisedResponder) Public() []byte { return bytes.Clone(k.claimed) }
func (k compromisedResponder) NoiseDH(remote []byte) (*secmem.Buffer, error) {
	if bytes.Equal(remote, k.responder) {
		return k.p.NoiseDH(k.priv, k.claimed)
	}
	return k.p.NoiseDH(k.priv, remote)
}
func linkPrologue(p jcrypto.CryptoProvider, pattern string, header []byte) []byte {
	out := append([]byte("jimichi/link/v1/"+p.Suite().String()+"/"+pattern), 0, wire.Version)
	out = binary.BigEndian.AppendUint16(out, uint16(len(header)))
	out = append(out, header...)
	return append(out, 1, 0, 0, 2, 0, 0)
}

type handlerListener struct {
	net.Listener
	relay    *Relay
	accepted chan *handlerConnection
}

func (l *handlerListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := &handlerConnection{Conn: raw, relay: l.relay, done: make(chan struct{})}
	l.accepted <- conn
	return conn, nil
}

type handlerConnection struct {
	net.Conn
	relay *Relay
	done  chan struct{}
	once  sync.Once
}

func (c *handlerConnection) Close() error {
	err := c.Conn.Close()
	c.relay.mu.Lock()
	_, held := c.relay.conns[c]
	c.relay.mu.Unlock()
	// leave runs after transport cleanup and circuit teardown, before the final raw close
	if !held {
		c.once.Do(func() { close(c.done) })
	}
	return err
}
func finishHandler(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler retained failed or closed transport")
	}
}
func assertNoCircuit(t *testing.T, r *Relay, delivered, dials *atomic.Int64) {
	t.Helper()
	r.mu.Lock()
	n := len(r.circuits)
	r.mu.Unlock()
	st := r.Stats().Snapshot()
	if n != 0 || st.Accepted != 0 || st.Delivered != 0 || st.Forwarded != 0 || delivered.Load() != 0 || dials.Load() != 0 {
		t.Fatal("handshake or padding reached setup, circuit or application processing")
	}
}
func TestPeerFirstFlightAndPaddingCreateNoCircuit(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, attack := range []string{"padding", "replay", "kci"} {
			t.Run(kind.String()+"/"+attack, func(t *testing.T) {
				p, err := suite.New(kind)
				if err != nil {
					t.Fatal(err)
				}
				ipriv, ipub, err := p.GenerateEphemeral()
				if err != nil {
					t.Fatal(err)
				}
				defer ipriv.Release()
				var delivered, dials atomic.Int64
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				selected := "initiator.test:9000"
				tracked := &handlerListener{Listener: ln, accepted: make(chan *handlerConnection, 1)}
				s := serveOn(t, p, Config{Peers: func(addr string) (Peer, bool) { return Peer{LinkPub: bytes.Clone(ipub)}, addr == selected }, Deliver: func(uint64, []byte) []byte { delivered.Add(1); return nil }, Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("unexpected extension")
				}}, tracked, func(r *Relay) { tracked.relay = r })
				var local noise.DHStatic = noise.NewKeyPair(p, ipriv, ipub)
				if attack == "kci" {
					ipriv.Release()
					local = compromisedResponder{p, s.r.cfg.StaticPriv, ipub, s.pub}
				}
				header := append([]byte{4, 2, byte(len(selected))}, []byte(selected)...)
				hs, err := noise.NewNoise(noise.NoiseConfig{Provider: p, Pattern: noise.KK, Initiator: true, Prologue: linkPrologue(p, "kk", header), Local: local, RemoteStatic: s.pub})
				if err != nil {
					t.Fatal(err)
				}
				defer hs.Close()
				first, err := hs.WriteMessage(make([]byte, 528-len(header)-len(ipub)-16))
				if err != nil {
					t.Fatal(err)
				}
				flight := append(header, first...)
				var handled <-chan struct{}
				connect := func() net.Conn {
					raw, err := net.DialTimeout("tcp", s.addr, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					select {
					case conn := <-tracked.accepted:
						handled = conn.done
					case <-time.After(3 * time.Second):
						t.Fatal("relay did not accept test connection")
					}
					t.Cleanup(func() { _ = raw.Close() })
					_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
					return raw
				}
				raw := connect()
				if _, err := raw.Write(flight); err != nil {
					t.Fatal(err)
				}
				answer := make([]byte, 528)
				if _, err := io.ReadFull(raw, answer); err != nil {
					t.Fatal(err)
				}
				assertNoCircuit(t, s.r, &delivered, &dials)
				if attack == "kci" {
					if _, err := hs.ReadMessage(answer); !errors.Is(err, noise.ErrMessage) {
						t.Fatalf("KCI unexpectedly confirmed initiator: %v", err)
					}
					_, _ = raw.Write(make([]byte, 528))
					_ = raw.Close()
					finishHandler(t, handled)
					assertNoCircuit(t, s.r, &delivered, &dials)
					return
				}
				if _, err := hs.ReadMessage(answer); err != nil {
					t.Fatal(err)
				}
				send, recv, _, err := hs.SplitTransport()
				if err != nil {
					t.Fatal(err)
				}
				defer send.Destroy()
				defer recv.Destroy()
				padding := wire.NewPadding()
				old, err := send.Encrypt(nil, padding[:])
				if err != nil {
					t.Fatal(err)
				}
				if attack == "padding" {
					if _, err := raw.Write(old); err != nil {
						t.Fatal(err)
					}
					_ = raw.Close()
					finishHandler(t, handled)
					assertNoCircuit(t, s.r, &delivered, &dials)
					return
				}
				_ = raw.Close()
				finishHandler(t, handled)
				raw = connect()
				if _, err := raw.Write(flight); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(raw, answer); err != nil {
					t.Fatal(err)
				}
				assertNoCircuit(t, s.r, &delivered, &dials)
				if _, err := raw.Write(old); err != nil {
					t.Fatal(err)
				}
				_ = raw.Close()
				finishHandler(t, handled)
				assertNoCircuit(t, s.r, &delivered, &dials)
			})
		}
	}
}
