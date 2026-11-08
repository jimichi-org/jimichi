package link_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/wire"
)

func peerProvider(t *testing.T) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func peerLocals(t *testing.T, p jcrypto.CryptoProvider) (link.Local, link.Local) {
	t.Helper()
	i, ip := keyPair(t, p)
	r, rp := keyPair(t, p)
	return link.Local{StaticPriv: i, StaticPub: ip, Identity: identityKey(t, p), Addr: "sender.test:9000"},
		link.Local{StaticPriv: r, StaticPub: rp, Identity: identityKey(t, p), Addr: "receiver.test:9000"}
}

func TestPeersProveBothKeysAndKeepBorrowedStatics(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, long := range []bool{false, true} {
			i, r := peerLocals(t, p)
			tracked := &trackingProvider{CryptoProvider: p}
			if long {
				i.Addr = strings.Repeat("a", wire.AddrSize-len(":9000")) + ":9000"
			}
			a, b := net.Pipe()
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			rec := &recorder{Conn: a}
			accepted := make(chan *link.Conn, 1)
			go func() {
				srv, err := link.AcceptWithConfig(b, tracked, link.AcceptConfig{Local: r, Peers: func(addr string) (link.Peer, bool) {
					return link.Peer{LinkPub: i.StaticPub, Identity: i.Identity}, addr == i.Addr
				}})
				if err != nil {
					t.Errorf("AcceptWithConfig: %v", err)
					_ = b.Close()
				}
				accepted <- srv
			}()
			cli, err := link.DialPeer(rec, tracked, i, link.Peer{LinkPub: r.StaticPub, Identity: r.Identity})
			if err != nil {
				t.Fatal(err)
			}
			srv := <-accepted
			if srv == nil {
				t.Fatal("no accepted peer")
			}
			if rec.seen.Len() != 528 || !bytes.Equal(rec.seen.Bytes()[:3], []byte{4, 2, byte(len(i.Addr))}) || string(rec.seen.Bytes()[3:3+len(i.Addr)]) != i.Addr {
				t.Fatal("KK flight lost its fixed size or roster selector")
			}
			go func() { _ = cli.WriteCell(sample(19)) }()
			var got wire.Cell
			if err := srv.ReadCell(&got); err != nil || !bytes.Equal(got[:], sample(19)[:]) {
				t.Fatalf("the first peer frame: %v", err)
			}
			_ = cli.Close()
			_ = srv.Close()
			if made, live := tracked.counts(); made == 0 || live != 0 {
				t.Fatalf("peer handshakes made %d secret buffers and kept %d", made, live)
			}
			if i.StaticPriv.Bytes() == nil || r.StaticPriv.Bytes() == nil {
				t.Fatal("handshake or connection released a borrowed static key")
			}
		}
	})
}

func TestPeerRefusesUntrustedKeysIdentitiesAndSelectors(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, name := range []string{"unknown", "expired", "wrong initiator key", "wrong initiator identity", "wrong responder identity", "changed selector"} {
			t.Run(name, func(t *testing.T) {
				i, r := peerLocals(t, p)
				trusted := link.Peer{LinkPub: i.StaticPub, Identity: i.Identity}
				expected := link.Peer{LinkPub: r.StaticPub, Identity: r.Identity}
				known := true
				switch name {
				case "unknown", "expired":
					known = false
				case "wrong initiator key":
					_, trusted.LinkPub = keyPair(t, p)
				case "wrong initiator identity":
					trusted.Identity = identityKey(t, p)
				case "wrong responder identity":
					expected.Identity = identityKey(t, p)
				}
				a, b := net.Pipe()
				_ = a.SetDeadline(time.Now().Add(3 * time.Second))
				_ = b.SetDeadline(time.Now().Add(3 * time.Second))
				m := &meter{Conn: a}
				if name == "changed selector" {
					m.flipWritten = map[int]byte{3: 's' ^ 't'}
				}
				done := make(chan error, 1)
				go func() {
					defer b.Close()
					c, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: r, Peers: func(string) (link.Peer, bool) { return trusted, known }})
					if c != nil {
						_ = c.Close()
					}
					done <- err
				}()
				c, err := link.DialPeer(m, p, i, expected)
				if c != nil || !errors.Is(err, link.ErrHandshake) {
					t.Fatalf("DialPeer: %v, want refusal", err)
				}
				if err := <-done; !errors.Is(err, link.ErrHandshake) {
					t.Fatalf("AcceptWithConfig: %v, want refusal", err)
				}
				if _, sent := m.totals(); sent != 528 {
					t.Fatalf("refused initiator wrote %d bytes, want one flight", sent)
				}
				_ = a.Close()
			})
		}
	})
}

func TestAnonymousBaselineMustBeAllowed(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		_, r := peerLocals(t, p)
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() {
			defer b.Close()
			_, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: r})
			done <- err
		}()
		_ = a.SetDeadline(time.Now().Add(3 * time.Second))
		if c, err := link.Dial(a, p, nil, nil); c != nil || !errors.Is(err, link.ErrHandshake) {
			t.Fatalf("anonymous dial to protected listener: %v", err)
		}
		if err := <-done; !errors.Is(err, link.ErrHandshake) {
			t.Fatalf("protected listener accepted NN: %v", err)
		}
		_ = a.Close()
	})
}

func TestPeerNeedsTrustedResolverAndLocalConfiguration(t *testing.T) {
	p := &trackingProvider{CryptoProvider: peerProvider(t)}
	i, r := peerLocals(t, p.CryptoProvider)
	for _, name := range []string{"no address", "invalid address", "no private", "no public", "no peer key"} {
		t.Run(name, func(t *testing.T) {
			local, peer := i, link.Peer{LinkPub: r.StaticPub, Identity: r.Identity}
			switch name {
			case "no address":
				local.Addr = ""
			case "invalid address":
				local.Addr = "UPPER.test:9000"
			case "no private":
				local.StaticPriv = nil
			case "no public":
				local.StaticPub = nil
			case "no peer key":
				peer.LinkPub = nil
			}
			a, b := net.Pipe()
			m := &meter{Conn: a}
			if c, err := link.DialPeer(m, p, local, peer); c != nil || !errors.Is(err, link.ErrHandshake) {
				t.Fatalf("incomplete peer dial: %v", err)
			}
			if _, n := m.totals(); n != 0 {
				t.Fatal("incomplete peer dial wrote a downgraded flight")
			}
			_ = a.Close()
			_ = b.Close()
		})
	}
	if _, live := p.counts(); live != 0 {
		t.Fatalf("incomplete peer dial retained %d secrets", live)
	}
}

type shortConn struct {
	net.Conn
	short bool
	calls int
}

func (c *shortConn) Write(b []byte) (int, error) {
	if c.short {
		c.calls++
		return len(b) - 1, nil
	}
	return c.Conn.Write(b)
}

func TestShortWriteFailsAndReleasesTheHandshake(t *testing.T) {
	eachSuite(t, func(t *testing.T, base jcrypto.CryptoProvider) {
		p := &trackingProvider{CryptoProvider: base}
		_, pub := keyPair(t, base)
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		m := &shortConn{Conn: a, short: true}
		if c, err := link.Dial(m, p, pub, nil); c != nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short first flight: %v", err)
		}
		if _, live := p.counts(); live != 0 {
			t.Fatalf("short flight retained %d secrets", live)
		}
	})
}

func TestProtectedListenerNeedsAPeerResolver(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		i, r := peerLocals(t, p)
		a, b := net.Pipe()
		defer a.Close()
		done := make(chan error, 1)
		go func() {
			defer b.Close()
			_, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: r})
			done <- err
		}()
		if c, err := link.DialPeer(a, p, i, link.Peer{LinkPub: r.StaticPub, Identity: r.Identity}); c != nil || !errors.Is(err, link.ErrHandshake) {
			t.Fatalf("peer without resolver: %v", err)
		}
		if err := <-done; !errors.Is(err, link.ErrHandshake) {
			t.Fatalf("untrusted peer accepted: %v", err)
		}
	})
}

func TestListenerRefusesLegacyAndMalformedHeaders(t *testing.T) {
	p := peerProvider(t)
	_, r := peerLocals(t, p)
	for _, header := range [][]byte{{0, 0, 0}, {1, 1, 0}, {2, 1, 0}, {3, 3, 0}, {3, 1, 1}, {3, 0, 1}, {3, 2, wire.AddrSize + 1}} {
		a, b := net.Pipe()
		go func() { _, _ = a.Write(header); _ = a.Close() }()
		m := &meter{Conn: b}
		_, err := link.AcceptWithConfig(m, p, link.AcceptConfig{Local: r, AllowAnonymous: true, Peers: func(string) (link.Peer, bool) {
			t.Error("malformed header reached peer lookup")
			return link.Peer{}, false
		}})
		if !errors.Is(err, link.ErrHandshake) {
			t.Fatalf("header %x: %v", header, err)
		}
		if _, sent := m.totals(); sent != 0 {
			t.Fatalf("header %x got %d answer bytes", header, sent)
		}
		_ = b.Close()
	}
}

func TestTransportShortWriteStaysFailed(t *testing.T) {
	p := peerProvider(t)
	priv, pub := keyPair(t, p)
	a, b := net.Pipe()
	m := &shortConn{Conn: a}
	accepted := make(chan *link.Conn, 1)
	go func() {
		c, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: link.Local{StaticPriv: priv, StaticPub: pub, Identity: nil}, AllowAnonymous: true})
		if err != nil {
			t.Errorf("Accept: %v", err)
		}
		accepted <- c
	}()
	c, err := link.Dial(m, p, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	defer c.Close()
	if s == nil {
		t.Fatal("no accepted link")
	}
	defer s.Close()
	m.short = true
	for range 2 {
		if err := c.WriteCell(sample(1)); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short transport frame: %v", err)
		}
	}
	if m.calls != 1 {
		t.Fatalf("%d writes after a short frame, want one", m.calls)
	}
}

func TestReplayedPeerFlightCannotOpenItsOldTransport(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		i, r := peerLocals(t, p)
		cfg := link.AcceptConfig{Local: r, Peers: func(addr string) (link.Peer, bool) {
			return link.Peer{LinkPub: i.StaticPub, Identity: i.Identity}, addr == i.Addr
		}}
		a, b := net.Pipe()
		rec := &recorder{Conn: a}
		accepted := make(chan *link.Conn, 1)
		go func() {
			c, err := link.AcceptWithConfig(b, p, cfg)
			if err != nil {
				t.Errorf("AcceptWithConfig: %v", err)
			}
			accepted <- c
		}()
		c, err := link.DialPeer(rec, p, i, link.Peer{LinkPub: r.StaticPub, Identity: r.Identity})
		if err != nil {
			t.Fatal(err)
		}
		s := <-accepted
		if s == nil {
			t.Fatal("no accepted peer")
		}
		go func() { _ = c.WriteCell(sample(1)) }()
		var got wire.Cell
		if err := s.ReadCell(&got); err != nil {
			t.Fatal(err)
		}
		captured := bytes.Clone(rec.seen.Bytes())
		_ = c.Close()
		_ = s.Close()
		if len(captured) != 1056 {
			t.Fatalf("captured %d bytes, want one flight and one frame", len(captured))
		}
		a, b = net.Pipe()
		defer a.Close()
		defer b.Close()
		_ = a.SetDeadline(time.Now().Add(5 * time.Second))
		_ = b.SetDeadline(time.Now().Add(5 * time.Second))
		done := make(chan error, 1)
		go func() {
			c, err := link.AcceptWithConfig(b, p, cfg)
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			var got wire.Cell
			done <- c.ReadCell(&got)
		}()
		if _, err := a.Write(captured[:528]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(a, make([]byte, 528)); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Write(captured[528:]); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, link.ErrFrame) {
			t.Fatalf("old frame under a replayed first flight: %v", err)
		}
	})
}
