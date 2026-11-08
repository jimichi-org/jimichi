package link_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/wire"
)

type recorder struct {
	net.Conn
	seen bytes.Buffer
	// set after the handshake: what goes onto the wire in place of a frame
	rewrite func(frame []byte) []byte
}

func (r *recorder) Write(b []byte) (int, error) {
	r.seen.Write(b)
	if r.rewrite == nil {
		return r.Conn.Write(b)
	}
	if _, err := r.Conn.Write(r.rewrite(b)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func eachSuite(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider)) {
	t.Helper()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			run(t, p)
		})
	}
}

func modeName(auth bool) string {
	if auth {
		return "authenticated"
	}
	return "anonymous"
}

func eachMode(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider, auth bool)) {
	t.Helper()
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, auth := range []bool{false, true} {
			t.Run(modeName(auth), func(t *testing.T) { run(t, p, auth) })
		}
	})
}

func keyPair(t *testing.T, p jcrypto.CryptoProvider) (*secmem.Buffer, []byte) {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	return priv, pub
}

func pairOn(t *testing.T, p jcrypto.CryptoProvider, authenticate bool) (*link.Conn, *link.Conn, *recorder) {
	t.Helper()
	priv, pub := keyPair(t, p)

	a, b := net.Pipe()
	rec := &recorder{Conn: a}

	type res struct {
		c   *link.Conn
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: link.Local{StaticPriv: priv, StaticPub: pub, Identity: nil}, AllowAnonymous: true})
		done <- res{c, err}
	}()

	var static []byte
	if authenticate {
		static = pub
	}
	client, err := link.Dial(rec, p, static, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("Accept: %v", r.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = r.c.Close() })
	return client, r.c, rec
}

func pair(t *testing.T, authenticate bool) (*link.Conn, *link.Conn, *recorder) {
	t.Helper()
	return pairOn(t, c25519.New(), authenticate)
}

func sample(counter uint64) *wire.Cell {
	body := bytes.Repeat([]byte{0x5A}, wire.BodySize)
	c, _ := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: 0xCAFE, Counter: counter}, body)
	return c
}

func TestCellsCrossTheLink(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		client, server, _ := pairOn(t, p, auth)
		for _, dir := range []struct {
			name     string
			from, to *link.Conn
		}{{"initiator to responder", client, server}, {"responder to initiator", server, client}} {
			go func() {
				for i := uint64(0); i < 3; i++ {
					_ = dir.from.WriteCell(sample(i))
				}
			}()
			for i := uint64(0); i < 3; i++ {
				var got wire.Cell
				if err := dir.to.ReadCell(&got); err != nil {
					t.Fatalf("%s: ReadCell: %v", dir.name, err)
				}
				h, err := got.Header()
				if err != nil || h.Counter != i {
					t.Fatalf("%s: cell %d: header %+v, err %v", dir.name, i, h, err)
				}
			}
		}
	})
}

// the whole point of the layer: nothing of the cell header is visible on the
// wire, so counters cannot be matched across links
func TestHeaderIsHidden(t *testing.T) {
	client, server, rec := pair(t, true)
	go func() { _ = client.WriteCell(sample(0x0102030405060708)) }()
	var got wire.Cell
	if err := server.ReadCell(&got); err != nil {
		t.Fatalf("ReadCell: %v", err)
	}

	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, 0x0102030405060708)
	circuit := make([]byte, 8)
	binary.BigEndian.PutUint64(circuit, 0xCAFE)
	wire := rec.seen.Bytes()
	if bytes.Contains(wire, counter) || bytes.Contains(wire, circuit) {
		t.Fatal("cell header leaked onto the wire")
	}
	if bytes.Contains(wire, bytes.Repeat([]byte{0x5A}, 32)) {
		t.Fatal("cell body leaked onto the wire")
	}
}

func TestFramesHaveOneSize(t *testing.T) {
	client, server, rec := pair(t, false)
	p := c25519.New()
	hs, _ := link.InitiatorHandshakeSize(p)
	frame, _ := link.FrameSize(p)

	go func() {
		for i := uint64(0); i < 4; i++ {
			_ = client.WriteCell(sample(i))
		}
	}()
	for i := 0; i < 4; i++ {
		var got wire.Cell
		if err := server.ReadCell(&got); err != nil {
			t.Fatal(err)
		}
	}
	if n := rec.seen.Len() - hs; n != 4*frame {
		t.Fatalf("wire carried %d bytes after the handshake, want %d", n, 4*frame)
	}
}

// padding costs a frame of the same size on the wire and never reaches the reader
func TestPaddingIsDroppedByTheReceiver(t *testing.T) {
	client, server, rec := pair(t, false)
	p := c25519.New()
	hs, _ := link.InitiatorHandshakeSize(p)
	frame, _ := link.FrameSize(p)

	go func() {
		_ = client.WriteCell(wire.NewPadding())
		_ = client.WriteCell(sample(7))
		_ = client.WriteCell(wire.NewPadding())
		_ = client.WriteCell(wire.NewPadding())
		_ = client.WriteCell(sample(8))
	}()
	for _, want := range []uint64{7, 8} {
		var got wire.Cell
		if err := server.ReadCell(&got); err != nil {
			t.Fatalf("ReadCell: %v", err)
		}
		h, err := got.Header()
		if err != nil || h.Counter != want || h.Kind != wire.KindData {
			t.Fatalf("got %+v, err %v, want payload %d", h, err, want)
		}
	}
	if n := rec.seen.Len() - hs; n != 5*frame {
		t.Fatalf("wire carried %d bytes after the handshake, want %d", n, 5*frame)
	}
}

// the frame number is the nonce, so a frame put on the wire a second time and a
// frame with one byte changed both fail to open at the receiver
func TestCopiedOrAlteredFrameDoesNotOpen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rewrite func(frame []byte) []byte
		// frames that open before the one that must not
		opens int
	}{
		{"copy", func(frame []byte) []byte { return append(bytes.Clone(frame), frame...) }, 1},
		{"altered byte", func(frame []byte) []byte {
			out := bytes.Clone(frame)
			out[len(out)/2] ^= 0x01
			return out
		}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, rec := pair(t, true)
			rec.rewrite = tc.rewrite
			go func() { _ = client.WriteCell(sample(7)) }()

			var got wire.Cell
			read := func() error {
				done := make(chan error, 1)
				go func() { done <- server.ReadCell(&got) }()
				select {
				case err := <-done:
					return err
				case <-time.After(3 * time.Second):
					t.Fatal("no frame reached the receiver")
					return nil
				}
			}
			for i := 0; i < tc.opens; i++ {
				if err := read(); err != nil || got != *sample(7) {
					t.Fatalf("the genuine frame did not open as sent: %v", err)
				}
			}
			if err := read(); !errors.Is(err, link.ErrFrame) {
				t.Fatalf("the frame read as %v, want %v", err, link.ErrFrame)
			}
		})
	}
}

// a frame put on the wire ahead of a genuine one takes no frame number, so the
// genuine frame would still open under its own: after the first frame that
// does not open the link takes nothing more
func TestNothingOpensAfterAFrameThatDidNot(t *testing.T) {
	client, server, rec := pair(t, true)
	junk := bytes.Repeat([]byte{0xA5}, client.FrameSize())
	rec.rewrite = func(frame []byte) []byte { return append(bytes.Clone(junk), frame...) }
	go func() { _ = client.WriteCell(sample(7)) }()

	var got wire.Cell
	if err := server.ReadCell(&got); !errors.Is(err, link.ErrFrame) {
		t.Fatalf("the frame put ahead read as %v, want %v", err, link.ErrFrame)
	}
	for i := 0; i < 2; i++ {
		if err := server.ReadCell(&got); !errors.Is(err, link.ErrFrame) {
			t.Fatalf("read %d after it: %v, cell %x, want %v", i, err, got[:8], link.ErrFrame)
		}
	}
}

// a read cut short mid-frame leaves the stream out of step, so the link reads
// nothing more, even once the socket would give it a whole genuine frame
func TestNothingIsReadAfterAReadCutShort(t *testing.T) {
	p := c25519.New()
	priv, pub := keyPair(t, p)
	a, b := net.Pipe()
	m := &meter{Conn: a}
	accepted := make(chan *link.Conn, 1)
	go func() {
		srv, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: link.Local{StaticPriv: priv, StaticPub: pub, Identity: nil}, AllowAnonymous: true})
		if err != nil {
			t.Errorf("Accept: %v", err)
		}
		accepted <- srv
	}()
	client, err := link.Dial(m, p, pub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	server := <-accepted
	if server == nil {
		t.FailNow()
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	half := bytes.Repeat([]byte{0xA5}, client.FrameSize()/2)
	go func() { _, _ = b.Write(half) }()
	_ = a.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var got wire.Cell
	if err := client.ReadCell(&got); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the read cut short returned %v, want a deadline error", err)
	}
	_ = a.SetReadDeadline(time.Time{})
	before, _ := m.totals()

	go func() { _ = server.WriteCell(sample(7)) }()
	if err := client.ReadCell(&got); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the read after it returned %v, cell %x, want the same deadline error", err, got[:8])
	}
	if after, _ := m.totals(); after != before {
		t.Fatalf("the link read %d more bytes after a read cut short", after-before)
	}
}

// a peer that stops reading must not hold the writer, and once a frame has
// failed the link sends nothing more: the peer's frame numbers are out of step
func TestWriteGivesUpOnAPeerThatStopsReading(t *testing.T) {
	client, server, _ := pair(t, false)
	client.SetWriteTimeout(50 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- client.WriteCell(sample(1)) }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write returned %v, want a deadline error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write still blocked on a peer that does not read")
	}

	go func() {
		var cell wire.Cell
		_ = server.ReadCell(&cell)
	}()
	if err := client.WriteCell(sample(2)); err == nil {
		t.Fatal("the link sent a frame after a failed one")
	}
}

// counts both directions of the initiator's side of a link, and stands in for
// whoever sits on the wire: flipWritten and flipRead name a byte of the stream
// in that direction and the bits to change in it
type meter struct {
	net.Conn
	mu            sync.Mutex
	read, written int

	flipWritten, flipRead map[int]byte
}

func flipped(b []byte, at int, flips map[int]byte) []byte {
	if len(flips) == 0 {
		return b
	}
	out := bytes.Clone(b)
	for i := range out {
		out[i] ^= flips[at+i]
	}
	return out
}

func (m *meter) Read(b []byte) (int, error) {
	n, err := m.Conn.Read(b)
	m.mu.Lock()
	copy(b[:n], flipped(b[:n], m.read, m.flipRead))
	m.read += n
	m.mu.Unlock()
	return n, err
}

func (m *meter) Write(b []byte) (int, error) {
	m.mu.Lock()
	out := flipped(b, m.written, m.flipWritten)
	m.mu.Unlock()
	n, err := m.Conn.Write(out)
	m.mu.Lock()
	m.written += n
	m.mu.Unlock()
	return n, err
}

func (m *meter) totals() (read, written int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.read, m.written
}

// each direction carries one authenticated handshake flight before frame 0
func TestResponderConfirmsTheKeys(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		hello, _ := link.InitiatorHandshakeSize(p)
		answer, _ := link.ResponderHandshakeSize(p)
		frame, _ := link.FrameSize(p)
		if hello != 528 || answer != 528 || frame != 528 {
			t.Fatalf("handshake/frame sizes = %d/%d/%d, want 528 each", hello, answer, frame)
		}
		priv, pub := keyPair(t, p)
		a, b := net.Pipe()
		m := &meter{Conn: a}
		accepted := make(chan *link.Conn, 1)
		go func() {
			srv, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: link.Local{StaticPriv: priv, StaticPub: pub, Identity: nil}, AllowAnonymous: true})
			if err != nil {
				t.Errorf("Accept: %v", err)
			}
			accepted <- srv
		}()
		var static []byte
		if auth {
			static = pub
		}
		client, err := link.Dial(m, p, static, nil)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		server := <-accepted
		if server == nil {
			t.FailNow()
		}
		if read, written := m.totals(); read != answer || written != hello {
			t.Fatalf("the initiator read %d and wrote %d bytes in the handshake, want %d and %d", read, written, answer, hello)
		}

		if err := server.WriteCell(sample(0)); !errors.Is(err, link.ErrUnconfirmed) {
			t.Fatalf("pending write: %v", err)
		}
		go func() { _ = client.WriteCell(sample(0)) }()
		var confirm wire.Cell
		if err := server.ReadCell(&confirm); err != nil {
			t.Fatal(err)
		}
		go func() {
			_ = server.WriteCell(sample(41))
			_ = server.WriteCell(sample(42))
		}()
		for _, want := range []uint64{41, 42} {
			var got wire.Cell
			if err := client.ReadCell(&got); err != nil {
				t.Fatalf("ReadCell: %v", err)
			}
			if h, err := got.Header(); err != nil || h.Counter != want {
				t.Fatalf("got %+v, %v, want cell %d", h, err, want)
			}
		}
		if read, _ := m.totals(); read != answer+2*frame {
			t.Fatalf("%d bytes came back for two cells after the handshake, want %d", read-answer, 2*frame)
		}
		_ = client.Close()
		_ = server.Close()
	})
}

// a handshake between Dial and Accept that must fail at the initiator, which
// has then written its hello and nothing else
func refused(t *testing.T, p jcrypto.CryptoProvider, m *meter, b net.Conn, dialStatic []byte, acceptPriv *secmem.Buffer, acceptPub []byte) {
	t.Helper()
	refusedAs(t, p, m, b, dialStatic, nil, acceptPriv, acceptPub, nil)
}

// the same with the identity the initiator expects and the one the responder
// binds
func refusedAs(t *testing.T, p jcrypto.CryptoProvider, m *meter, b net.Conn, dialStatic, dialIdentity []byte, acceptPriv *secmem.Buffer, acceptPub, acceptIdentity []byte) {
	t.Helper()
	hello, _ := link.InitiatorHandshakeSize(p)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		if srv, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: link.Local{StaticPriv: acceptPriv, StaticPub: acceptPub, Identity: acceptIdentity}, AllowAnonymous: true}); err == nil {
			defer srv.Close()
			var c wire.Cell
			_ = srv.ReadCell(&c)
		}
	}()

	client, err := link.Dial(m, p, dialStatic, dialIdentity)
	if !errors.Is(err, link.ErrHandshake) || client != nil {
		t.Fatalf("Dial = %v, want %v", err, link.ErrHandshake)
	}
	if _, written := m.totals(); written != hello {
		t.Fatalf("the initiator wrote %d bytes, want its hello of %d and nothing after it", written, hello)
	}
	_ = m.Close()
	_ = b.Close()
	<-done
}

func TestWrongStaticKeyFailsTheHandshake(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		_, otherPub := keyPair(t, p)
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a}, b, otherPub, priv, pub)
	})
}

// the responder holds the right private key and names other bytes as its
// published key: the initiator put the descriptor's bytes into the transcript
func TestResponderNamingAnotherKeyIsNotConfirmed(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		_, otherPub := keyPair(t, p)
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a}, b, pub, priv, otherPub)
	})

	// X25519 drops the top bit, so this is the same point written another way
	t.Run("another encoding of the same key", func(t *testing.T) {
		p := c25519.New()
		priv, pub := keyPair(t, p)
		other := bytes.Clone(pub)
		other[len(other)-1] ^= 0x80
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a}, b, pub, priv, other)
	})
}

func identityKey(t *testing.T, p jcrypto.CryptoProvider) []byte {
	t.Helper()
	priv, pub, err := p.GenerateSigning()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	return pub
}

// node a holds its link key and binds its identity; the descriptor of node c
// names the link key of a under the identity of c. A handshake meant for c
// that reaches a is not confirmed, and neither is one where only one side
// binds an identity. The handshake meant for a is
func TestHandshakeIsBoundToTheIdentity(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		idA, idC := identityKey(t, p), identityKey(t, p)
		for _, tc := range []struct {
			name         string
			dial, accept []byte
		}{
			{"meant for c, reaching a", idC, idA},
			{"no identity expected, a binds its own", nil, idA},
			{"the identity of a expected, a binds none", idA, nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				a, b := net.Pipe()
				refusedAs(t, p, &meter{Conn: a}, b, pub, tc.dial, priv, pub, tc.accept)
			})
		}

		a, b := net.Pipe()
		accepted := make(chan *link.Conn, 1)
		go func() {
			srv, err := link.AcceptWithConfig(b, p, link.AcceptConfig{Local: link.Local{StaticPriv: priv, StaticPub: pub, Identity: idA}, AllowAnonymous: true})
			if err != nil {
				t.Errorf("Accept: %v", err)
			}
			accepted <- srv
		}()
		client, err := link.Dial(a, p, pub, idA)
		if err != nil {
			t.Fatalf("Dial meant for a: %v", err)
		}
		if server := <-accepted; server != nil {
			_ = server.Close()
		}
		_ = client.Close()
	})
}

// an identity binds only together with the link key it goes with, so an
// anonymous dial that names one is refused before the hello
func TestDialRefusesAnIdentityWithoutALinkKey(t *testing.T) {
	p := c25519.New()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// a dial that went ahead would write its hello into the drain and then
	// wait for an answer that never comes until the deadline
	go func() { _, _ = io.Copy(io.Discard, b) }()
	_ = a.SetDeadline(time.Now().Add(time.Second))
	m := &meter{Conn: a}
	conn, err := link.Dial(m, p, nil, identityKey(t, p))
	if read, written := m.totals(); read != 0 || written != 0 {
		t.Fatalf("the dial read %d and wrote %d bytes, want a refusal before the hello", read, written)
	}
	if err == nil || conn != nil {
		t.Fatalf("Dial = %v, want a refusal", err)
	}
}

// a changed mode also changes the transcript and the pattern
func TestFlippedModeByteFailsTheHandshake(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		priv, pub := keyPair(t, p)
		var static []byte
		if auth {
			static = pub
		}
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a, flipWritten: map[int]byte{1: 0x01}}, b, static, priv, pub)
	})
}

// X25519 ignores the top bit of a public key, so a key re-encoded on the way
// gives both sides the same raw agreement; the transcripts differ
func TestReencodedEphemeralKeyFailsTheHandshake(t *testing.T) {
	p := c25519.New()
	_, pub := keyPair(t, p)
	for _, auth := range []bool{false, true} {
		for _, tc := range []struct {
			name          string
			written, read map[int]byte
		}{
			{"the initiator's key", map[int]byte{3 + len(pub) - 1: 0x80}, nil},
			{"the responder's key", nil, map[int]byte{len(pub) - 1: 0x80}},
		} {
			t.Run(modeName(auth)+"/"+tc.name, func(t *testing.T) {
				priv, pub := keyPair(t, p)
				var static []byte
				if auth {
					static = pub
				}
				a, b := net.Pipe()
				m := &meter{Conn: a, flipWritten: tc.written, flipRead: tc.read}
				refused(t, p, m, b, static, priv, pub)
			})
		}
	}
}

// an authenticated hello to a responder that holds no link key is refused
// before the responder generates or agrees anything
func TestAuthenticatedHelloNeedsALinkKey(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		for _, tc := range []struct {
			name string
			priv *secmem.Buffer
			pub  []byte
		}{
			{"no key", nil, nil},
			{"no public key", priv, nil},
			{"no private key", nil, pub},
			{"a short public key", priv, pub[:len(pub)-1]},
		} {
			a, b := net.Pipe()
			m := &meter{Conn: b}
			go func() { _, _ = a.Write(append([]byte{4, 1, 0}, make([]byte, 525)...)) }()
			_ = b.SetDeadline(time.Now().Add(2 * time.Second))
			conn, err := link.AcceptWithConfig(m, p, link.AcceptConfig{Local: link.Local{StaticPriv: tc.priv, StaticPub: tc.pub, Identity: nil}, AllowAnonymous: true})
			if !errors.Is(err, link.ErrHandshake) || conn != nil {
				t.Fatalf("%s: Accept = %v, want %v", tc.name, err, link.ErrHandshake)
			}
			if _, written := m.totals(); written != 0 {
				t.Fatalf("%s: the responder wrote %d bytes", tc.name, written)
			}
			_ = a.Close()
			_ = b.Close()
		}
	})
}

// a hello whose first byte names no mode is refused the same way, although the
// key after it is a valid one
func TestHelloOfAnUnknownModeIsRefused(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		_, eph := keyPair(t, p)
		for _, mode := range []byte{0x03, 0x80, 0xff} {
			a, b := net.Pipe()
			m := &meter{Conn: b}
			go func() {
				_, _ = a.Write(append([]byte{4, mode, 0}, eph...))
				_, _ = io.Copy(io.Discard, a)
			}()
			_ = b.SetDeadline(time.Now().Add(2 * time.Second))
			conn, err := link.AcceptWithConfig(m, p, link.AcceptConfig{Local: link.Local{StaticPriv: priv, StaticPub: pub, Identity: nil}, AllowAnonymous: true})
			if !errors.Is(err, link.ErrHandshake) || conn != nil {
				t.Fatalf("mode %#02x: Accept = %v, want %v", mode, err, link.ErrHandshake)
			}
			if _, written := m.totals(); written != 0 {
				t.Fatalf("mode %#02x: the responder wrote %d bytes", mode, written)
			}
			_ = a.Close()
			_ = b.Close()
		}
	})
}

func TestDialRefusesALinkKeyOfAnotherLength(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		_, pub := keyPair(t, p)
		for _, static := range [][]byte{{}, pub[:len(pub)-1], append(bytes.Clone(pub), 0)} {
			a, b := net.Pipe()
			m := &meter{Conn: a}
			_ = a.SetDeadline(time.Now().Add(2 * time.Second))
			conn, err := link.Dial(m, p, static, nil)
			if !errors.Is(err, link.ErrHandshake) || conn != nil {
				t.Fatalf("link key of %d bytes: Dial = %v, want %v", len(static), err, link.ErrHandshake)
			}
			if _, written := m.totals(); written != 0 {
				t.Fatalf("link key of %d bytes: the initiator wrote %d bytes", len(static), written)
			}
			_ = a.Close()
			_ = b.Close()
		}
	})
}

// which agreements a hand-made responder puts into the frame keys
type keying int

const (
	keyedInFull keying = iota
	keyedByStaticOnly
	keyedByEphemeralOnly
)

type testStatic struct {
	p    jcrypto.CryptoProvider
	priv *secmem.Buffer
	pub  []byte
}

func (k testStatic) Public() []byte { return bytes.Clone(k.pub) }

func (k testStatic) NoiseDH(remote []byte) (*secmem.Buffer, error) {
	return k.p.NoiseDH(k.priv, remote)
}

func (k testStatic) Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	return k.p.Agree(k.priv, remote, ctx)
}

type keyingProvider struct {
	jcrypto.CryptoProvider
	how   keying
	calls int
}

func (p *keyingProvider) NoiseKDF2(chain, secret *secmem.Buffer) (*secmem.Buffer, *secmem.Buffer, error) {
	p.calls++
	if p.calls > 1 && secret != nil {
		if p.how == keyedByStaticOnly {
			return p.CryptoProvider.NoiseKDF2(chain, nil)
		}
		if p.how == keyedByEphemeralOnly {
			zero, err := secmem.New(32)
			if err != nil {
				return nil, nil, err
			}
			defer zero.Release()
			return p.CryptoProvider.NoiseKDF2(zero, secret)
		}
	}
	return p.CryptoProvider.NoiseKDF2(chain, secret)
}

// the literal prologue fixes the wrapper's domain, header and identity order;
// independent production vectors in noise pin its cryptographic operations
func handResponder(t *testing.T, p jcrypto.CryptoProvider, conn net.Conn, staticPriv *secmem.Buffer, staticPub, identity []byte, how keying, prefix []byte) (answer []byte, send, recv jcrypto.AEAD, ok bool) {
	t.Helper()
	flight := make([]byte, 528)
	if _, err := io.ReadFull(conn, flight); err != nil {
		t.Errorf("hello: %v", err)
		return
	}
	mode := flight[1]
	if flight[0] != 4 || flight[2] != 0 || mode > 1 {
		t.Error("unexpected handshake header")
		return
	}
	profile := &keyingProvider{CryptoProvider: p, how: how}
	pattern, name := noise.NN, "nn"
	var local noise.DHStatic
	if mode == 1 {
		pattern, name = noise.NK, "nk"
		local = testStatic{profile, staticPriv, staticPub}
	} else {
		identity = nil
	}
	prologue := append([]byte("jimichi/link/v1/"+p.Suite().String()+"/"+name), 0, wire.Version, 0, 3, 4, mode, 0, 1, 0, 0, 2)
	prologue = binary.BigEndian.AppendUint16(prologue, uint16(len(identity)))
	prologue = append(prologue, identity...)
	hs, err := noise.NewNoise(noise.NoiseConfig{Provider: profile, Pattern: pattern, Prologue: prologue, Local: local})
	if err != nil {
		t.Error(err)
		return
	}
	defer hs.Close()
	if _, err := hs.ReadMessage(flight[3:]); err != nil {
		t.Error(err)
		return
	}
	payload := make([]byte, 528-len(staticPub)-16)
	copy(payload, prefix)
	answer, err = hs.WriteMessage(payload)
	if err != nil {
		t.Error(err)
		return
	}
	i2r, r2i, _, err := hs.Split()
	if err != nil {
		t.Error(err)
		return
	}
	defer i2r.Release()
	defer r2i.Release()
	send, err = p.NewAEAD(r2i)
	if err != nil {
		t.Error(err)
		return
	}
	recv, err = p.NewAEAD(i2r)
	if err != nil {
		send.Destroy()
		t.Error(err)
		return
	}
	return answer, send, recv, true
}

func answerWith(t *testing.T, p jcrypto.CryptoProvider, conn net.Conn, staticPriv *secmem.Buffer, staticPub []byte, how keying, first *wire.Cell) {
	t.Helper()
	var prefix []byte
	if !first.IsPadding() {
		prefix = []byte{1}
	}
	answer, send, recv, ok := handResponder(t, p, conn, staticPriv, staticPub, nil, how, prefix)
	if !ok {
		return
	}
	defer send.Destroy()
	defer recv.Destroy()
	_, _ = conn.Write(answer)
}

// the first frame opens only under the opposite Split key, in sequence zero
func TestDirectionsHaveSeparateKeys(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		directionsHaveSeparateKeys(t, p, auth, nil)
		if auth {
			t.Run("with an identity", func(t *testing.T) { directionsHaveSeparateKeys(t, p, auth, identityKey(t, p)) })
		}
	})
}

func directionsHaveSeparateKeys(t *testing.T, p jcrypto.CryptoProvider, auth bool, identity []byte) {
	frameSize, _ := link.FrameSize(p)
	priv, pub := keyPair(t, p)
	var static []byte
	if auth {
		static = pub
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		eph, send, recv, ok := handResponder(t, p, b, priv, pub, identity, keyedInFull, nil)
		if !ok {
			return
		}
		defer send.Destroy()
		defer recv.Destroy()
		zero := make([]byte, send.NonceSize())
		if _, err := b.Write(eph); err != nil {
			t.Errorf("answer: %v", err)
			return
		}
		frame := make([]byte, frameSize)
		if _, err := io.ReadFull(b, frame); err != nil {
			t.Errorf("the initiator's first frame: %v", err)
			return
		}
		if _, err := send.Open(nil, zero, frame, nil); err == nil {
			t.Error("the initiator's frame opens under the responder's sending key")
		}
		plain, err := recv.Open(nil, zero, frame, nil)
		if err != nil {
			t.Errorf("the initiator's frame under the i2r Split key: %v", err)
			return
		}
		if !bytes.Equal(plain, sample(7)[:]) {
			t.Error("the initiator's frame carries another cell")
		}
		if bytes.Equal(frame, send.Seal(nil, zero, sample(7)[:], nil)) {
			t.Error("frame 0 of both directions is sealed under one key")
		}
	}()
	// the responder reports through t, so a failing test waits for it
	defer func() {
		_ = a.Close()
		_ = b.Close()
		<-done
	}()

	client, err := link.Dial(a, p, static, identity)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if err := client.WriteCell(sample(7)); err != nil {
		t.Fatalf("WriteCell: %v", err)
	}
	<-done
}

func TestHandshakeNeedsTheConfirmation(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		hello, _ := link.InitiatorHandshakeSize(p)
		frame, _ := link.FrameSize(p)
		priv, pub := keyPair(t, p)
		_, eph := keyPair(t, p)
		var static []byte
		if auth {
			static = pub
		}
		answer := func(how keying, first *wire.Cell) func(net.Conn) {
			return func(conn net.Conn) { answerWith(t, p, conn, priv, pub, how, first) }
		}

		type respond struct {
			name    string
			respond func(conn net.Conn)
			ok      bool
			timeout bool
		}
		cases := []respond{
			{"a zero payload under the right keys", answer(keyedInFull, wire.NewPadding()), true, false},
			{"a nonzero payload under the right keys", answer(keyedInFull, sample(0)), false, false},
			{"a frame of noise", func(conn net.Conn) {
				_, _ = io.ReadFull(conn, make([]byte, hello))
				_, _ = conn.Write(append(bytes.Clone(eph), bytes.Repeat([]byte{0xA5}, frame-len(eph))...))
			}, false, false},
			{"the key and then silence", func(conn net.Conn) {
				_, _ = io.ReadFull(conn, make([]byte, hello))
				_, _ = conn.Write(eph)
			}, false, true},
			{"the key and then a closed connection", func(conn net.Conn) {
				_, _ = io.ReadFull(conn, make([]byte, hello))
				_, _ = conn.Write(eph)
				_ = conn.Close()
			}, false, false},
		}
		if auth {
			// the frame keys depend on both agreements
			cases = append(cases,
				respond{"keys from the static agreement alone", answer(keyedByStaticOnly, wire.NewPadding()), false, false},
				respond{"keys from the ephemeral agreement alone", answer(keyedByEphemeralOnly, wire.NewPadding()), false, false},
			)
		}
		for _, tc := range cases {
			a, b := net.Pipe()
			m := &meter{Conn: a}
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.respond(b)
			}()
			_ = a.SetDeadline(time.Now().Add(time.Second))
			client, err := link.Dial(m, p, static, nil)
			switch {
			case tc.ok && err != nil:
				t.Errorf("%s: Dial = %v, want a link", tc.name, err)
			case !tc.ok && !errors.Is(err, link.ErrHandshake):
				t.Errorf("%s: Dial = %v, want %v", tc.name, err, link.ErrHandshake)
			case tc.timeout && !errors.Is(err, os.ErrDeadlineExceeded):
				t.Errorf("%s: Dial = %v, want the caller's deadline to end the wait", tc.name, err)
			}
			if _, written := m.totals(); written != hello {
				t.Errorf("%s: the initiator wrote %d bytes, want only its hello of %d", tc.name, written, hello)
			}
			if client != nil {
				_ = client.Close()
			}
			_ = a.Close()
			_ = b.Close()
			<-done
		}
	})
}
