package link

import (
	"errors"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/wire"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type operationGate struct {
	net.Conn
	enabled                        atomic.Bool
	readOnce, writeOnce            sync.Once
	readStarted, writeStarted      chan struct{}
	reads, writes, closes          atomic.Int32
	readErr, writeErr, deadlineErr error
}

func (g *operationGate) Read(b []byte) (int, error) {
	g.reads.Add(1)
	if g.enabled.Load() {
		g.readOnce.Do(func() { close(g.readStarted) })
		if g.readErr != nil {
			return 0, g.readErr
		}
	}
	return g.Conn.Read(b)
}
func (g *operationGate) Write(b []byte) (int, error) {
	g.writes.Add(1)
	if g.enabled.Load() {
		g.writeOnce.Do(func() { close(g.writeStarted) })
		if g.writeErr != nil {
			return len(b) / 2, g.writeErr
		}
	}
	return g.Conn.Write(b)
}
func (g *operationGate) Close() error { g.closes.Add(1); return g.Conn.Close() }
func (g *operationGate) SetWriteDeadline(d time.Time) error {
	if g.enabled.Load() && g.deadlineErr != nil {
		return g.deadlineErr
	}
	return g.Conn.SetWriteDeadline(d)
}
func livePair(t *testing.T, kind jcrypto.Suite) (*Conn, *Conn, *operationGate, *operationGate) {
	t.Helper()
	p, err := suite.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	wrap := func(c net.Conn) *operationGate {
		return &operationGate{Conn: c, readStarted: make(chan struct{}), writeStarted: make(chan struct{})}
	}
	ga, gb := wrap(a), wrap(b)
	done := make(chan *Conn, 1)
	errs := make(chan error, 1)
	go func() { c, err := AcceptWithConfig(gb, p, AcceptConfig{AllowAnonymous: true}); done <- c; errs <- err }()
	i, err := Dial(ga, p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := <-done
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	cell, _ := wire.NewCell(wire.Header{Kind: wire.KindData}, make([]byte, wire.BodySize))
	sent := make(chan error, 1)
	go func() { sent <- i.WriteCell(cell) }()
	var got wire.Cell
	if err := r.ReadCell(&got); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = i.Close(); _ = r.Close() })
	return i, r, ga, gb
}
func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("I/O did not reach synchronized boundary")
	}
}
func awaitOperation(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("close did not unblock I/O")
		return nil
	}
}
func assertTerminalNoIO(t *testing.T, c *Conn, g *operationGate, want error) {
	t.Helper()
	r, w := g.reads.Load(), g.writes.Load()
	cell := wire.NewPadding()
	if err := c.WriteCell(cell); !errors.Is(err, want) {
		t.Fatal("write lost first terminal error")
	}
	if err := c.ReadCell(cell); !errors.Is(err, want) {
		t.Fatal("read lost first terminal error")
	}
	_ = c.Close()
	_ = c.Close()
	if g.reads.Load() != r || g.writes.Load() != w || g.closes.Load() != 1 {
		t.Fatal("terminal or repeated-close operation performed socket I/O")
	}
	if _, err := c.send.Encrypt(nil, nil); !errors.Is(err, noise.ErrClosed) {
		t.Fatal("send cipher survived terminal cleanup")
	}
	if _, err := c.recv.Decrypt(nil, nil); !errors.Is(err, noise.ErrClosed) {
		t.Fatal("receive cipher survived terminal cleanup")
	}
}
func TestConcurrentCloseUnblocksBothDirections(t *testing.T) {
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, responder := range []bool{false, true} {
			for _, writing := range []bool{false, true} {
				i, r, ga, gb := livePair(t, kind)
				c, g := i, ga
				if responder {
					c, g = r, gb
				}
				g.enabled.Store(true)
				done := make(chan error, 1)
				if writing {
					go func() { done <- c.WriteCell(wire.NewPadding()) }()
					awaitSignal(t, g.writeStarted)
				} else {
					go func() { var cell wire.Cell; done <- c.ReadCell(&cell) }()
					awaitSignal(t, g.readStarted)
				}
				closed := make(chan error, 1)
				go func() { closed <- c.Close() }()
				if err := awaitOperation(t, done); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("concurrent close result: %v", err)
				}
				if err := awaitOperation(t, closed); err != nil {
					t.Fatal(err)
				}
				assertTerminalNoIO(t, c, g, net.ErrClosed)
			}
		}
	}
}
func TestFatalTransportErrorsPoisonBothDirections(t *testing.T) {
	sentinel := errors.New("scripted transport failure")
	for _, kind := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, responder := range []bool{false, true} {
			for _, failure := range []string{"read", "write", "deadline", "authentication"} {
				i, r, ga, gb := livePair(t, kind)
				c, g, other := i, ga, gb
				if responder {
					c, g, other = r, gb, ga
				}
				var err error
				want := sentinel
				switch failure {
				case "read":
					g.readErr = sentinel
					g.enabled.Store(true)
					var cell wire.Cell
					err = c.ReadCell(&cell)
				case "write":
					g.writeErr = io.ErrShortWrite
					g.enabled.Store(true)
					want = io.ErrShortWrite
					err = c.WriteCell(wire.NewPadding())
				case "deadline":
					g.deadlineErr = sentinel
					g.enabled.Store(true)
					c.SetWriteTimeout(time.Second)
					err = c.WriteCell(wire.NewPadding())
				case "authentication":
					want = ErrFrame
					sent := make(chan error, 1)
					go func() { _, err := other.Conn.Write(make([]byte, 528)); sent <- err }()
					var cell wire.Cell
					err = c.ReadCell(&cell)
					_ = awaitOperation(t, sent)
				}
				if !errors.Is(err, want) {
					t.Fatalf("terminal %s result: %v", failure, err)
				}
				assertTerminalNoIO(t, c, g, want)
			}
		}
	}
}
