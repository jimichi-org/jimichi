package link

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/wire"
)

func TestOptionalIdentityPresenceMustMatch(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, mode := range []byte{modeClient, modePeer} {
			for _, presence := range []string{"empty", "present", "responder mismatch", "initiator mismatch"} {
				if mode == modeClient && presence == "initiator mismatch" {
					continue
				}
				t.Run(kind.String()+"/"+[]string{"nn", "nk", "kk"}[mode]+"/"+presence, func(t *testing.T) {
					f := flights(t, kind, mode)
					i, r := f.local, f.peer
					pi, pr := Peer{LinkPub: i.StaticPub}, Peer{LinkPub: r.StaticPub}
					if presence != "empty" {
						idI, idR := make([]byte, len(i.StaticPub)), make([]byte, len(r.StaticPub))
						idI[0] = 1
						idR[0] = 2
						i.Identity = idI
						r.Identity = idR
						pi.Identity = bytes.Clone(idI)
						pr.Identity = bytes.Clone(idR)
					}
					if presence == "responder mismatch" {
						pr.Identity = nil
					}
					if presence == "initiator mismatch" {
						pi.Identity = nil
					}
					a, b := net.Pipe()
					_ = a.SetDeadline(time.Now().Add(3 * time.Second))
					_ = b.SetDeadline(time.Now().Add(3 * time.Second))
					defer a.Close()
					defer b.Close()
					done := make(chan error, 1)
					go func() {
						c, err := AcceptWithConfig(b, f.p, AcceptConfig{Local: r, Peers: func(string) (Peer, bool) { return pi, true }})
						if c != nil {
							_ = c.Close()
						}
						done <- err
					}()
					var c *Conn
					var err error
					if mode == modePeer {
						c, err = DialPeer(a, f.p, i, pr)
					} else {
						c, err = Dial(a, f.p, pr.LinkPub, pr.Identity)
					}
					if c != nil {
						_ = c.Close()
					}
					serverErr := <-done
					match := presence == "empty" || presence == "present"
					if match && (err != nil || serverErr != nil) {
						t.Fatalf("matching identity configuration: %v / %v", err, serverErr)
					}
					if !match && (c != nil || !errors.Is(err, ErrHandshake) || !errors.Is(serverErr, ErrHandshake)) {
						t.Fatal("mismatched identity presence accepted")
					}
				})
			}
		}
	}
}

type readSignal struct {
	net.Conn
	mu                 sync.Mutex
	readBytes, written int
	waiting            chan struct{}
	once               sync.Once
}

func (s *readSignal) Read(b []byte) (int, error) {
	s.mu.Lock()
	ready := s.readBytes >= 1056
	s.mu.Unlock()
	if ready {
		s.once.Do(func() { close(s.waiting) })
	}
	n, err := s.Conn.Read(b)
	s.mu.Lock()
	s.readBytes += n
	s.mu.Unlock()
	return n, err
}
func (s *readSignal) Write(b []byte) (int, error) {
	n, err := s.Conn.Write(b)
	s.mu.Lock()
	s.written += n
	s.mu.Unlock()
	return n, err
}
func (s *readSignal) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readBytes, s.written
}
func TestPaddingConfirmsWithoutReturningACell(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for mode := byte(0); mode <= 2; mode++ {
			f := flights(t, kind, mode)
			a, b := net.Pipe()
			raw := &readSignal{Conn: b, waiting: make(chan struct{})}
			_ = a.SetDeadline(time.Now().Add(3 * time.Second))
			_ = b.SetDeadline(time.Now().Add(3 * time.Second))
			accepted := make(chan *Conn, 1)
			errs := make(chan error, 1)
			go func() {
				c, err := AcceptWithConfig(raw, f.p, AcceptConfig{Local: f.peer, AllowAnonymous: mode == modeAnonymous, Peers: func(string) (Peer, bool) { return Peer{LinkPub: f.local.StaticPub}, true }})
				accepted <- c
				errs <- err
			}()
			var c *Conn
			var err error
			if mode == modePeer {
				c, err = DialPeer(a, f.p, f.local, Peer{LinkPub: f.peer.StaticPub})
			} else {
				var key []byte
				if mode == modeClient {
					key = f.peer.StaticPub
				}
				c, err = Dial(a, f.p, key, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			s := <-accepted
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
			beforeR, beforeW := raw.counts()
			if err := s.WriteCell(wire.NewPadding()); !errors.Is(err, ErrUnconfirmed) {
				t.Fatal("pending responder sent")
			}
			afterR, afterW := raw.counts()
			if beforeR != afterR || beforeW != afterW {
				t.Fatal("pending write performed socket I/O")
			}
			readDone := make(chan error, 1)
			var got wire.Cell
			go func() { readDone <- s.ReadCell(&got) }()
			if err := c.WriteCell(wire.NewPadding()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-raw.waiting:
			case <-time.After(3 * time.Second):
				t.Fatal("padding did not advance to the next frame read")
			}
			select {
			case <-readDone:
				t.Fatal("padding reached caller")
			default:
			}
			cell, _ := wire.NewCell(wire.Header{Kind: wire.KindData, Counter: 9}, make([]byte, wire.BodySize))
			sent := make(chan error, 1)
			go func() { sent <- s.WriteCell(cell) }()
			var reply wire.Cell
			if err := c.ReadCell(&reply); err != nil {
				t.Fatal(err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if err := c.WriteCell(cell); err != nil {
				t.Fatal(err)
			}
			if err := <-readDone; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[:], cell[:]) {
				t.Fatal("padding replaced following data")
			}
			_ = c.Close()
			_ = s.Close()
			_ = c.Close()
			_ = s.Close()
		}
	}
}
func TestDefaultAcceptRefusesAnonymous(t *testing.T) {
	p, _ := suite.New(jcrypto.SuiteC25519)
	f := flights(t, jcrypto.SuiteC25519, modeAnonymous)
	s := &scriptedSocket{input: f.first}
	if c, err := Accept(s, p, nil, nil, nil); c != nil || !errors.Is(err, ErrHandshake) || !s.closed {
		t.Fatal("default listener admitted anonymous mode")
	}
}
