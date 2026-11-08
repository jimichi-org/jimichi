package lab

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type testMarkClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*testMarkTimer
	created chan struct{}
}
type testMarkTimer struct {
	clock   *testMarkClock
	at      time.Time
	ch      chan time.Time
	stopped bool
}

func newTestMarkClock() *testMarkClock {
	return &testMarkClock{now: time.Unix(1000, 0), created: make(chan struct{}, 100)}
}
func (c *testMarkClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testMarkClock) Timer(d time.Duration) markTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &testMarkTimer{clock: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	c.created <- struct{}{}
	return t
}
func (t *testMarkTimer) C() <-chan time.Time { return t.ch }
func (t *testMarkTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := !t.stopped
	t.stopped = true
	return active
}
func (c *testMarkClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if !t.stopped && !c.now.Before(t.at) {
			t.stopped = true
			t.ch <- c.now
		}
	}
}
func (c *testMarkClock) wait(t *testing.T) {
	t.Helper()
	select {
	case <-c.created:
	case <-time.After(time.Second):
		t.Fatal("no private timer")
	}
}

type testMarkConn struct {
	mu     sync.Mutex
	b      bytes.Buffer
	limit  int
	err    error
	closed bool
}

func (c *testMarkConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *testMarkConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	n := len(b)
	if c.limit > 0 {
		n = min(n, c.limit)
	}
	_, _ = c.b.Write(b[:n])
	return n, c.err
}
func (c *testMarkConn) Close() error                     { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *testMarkConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *testMarkConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *testMarkConn) SetDeadline(time.Time) error      { return nil }
func (c *testMarkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testMarkConn) SetWriteDeadline(time.Time) error { return nil }
func (c *testMarkConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.b.Bytes()...)
}
func testMarked(clock *testMarkClock) (*markConn, *testMarkConn) {
	raw := &testMarkConn{}
	c := newMarkConn(raw, MarkConfig{Enabled: true, Code: []int8{1, -1}, Slot: time.Second}, 3, 4, clock)
	return c, raw
}

type writeAnswer struct {
	n   int
	err error
}

func asyncMarkWrite(c *markConn, b []byte) <-chan writeAnswer {
	ch := make(chan writeAnswer, 1)
	go func() { n, e := c.Write(b); ch <- writeAnswer{n, e} }()
	return ch
}
func receiveMark(t *testing.T, ch <-chan writeAnswer) writeAnswer {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(time.Second):
		t.Fatal("write did not unblock")
		return writeAnswer{}
	}
}

func TestMarkFramingFIFO(t *testing.T) {
	clock := newTestMarkClock()
	c, raw := testMarked(clock)
	for _, b := range [][]byte{{1}, {2, 3, 4, 5}, {6}, {7, 8, 9, 10, 11}} {
		if n, e := c.Write(b); n != len(b) || e != nil {
			t.Fatal(n, e)
		}
	}
	if !bytes.Equal(raw.bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
		t.Fatal(raw.bytes())
	}
	if s := c.snapshot(); s.ForwardedFrames != 2 || s.WaitStarted != 0 {
		t.Fatal(s)
	}
}

func TestMarkCoalescedHandshakeInterrupted(t *testing.T) {
	clock := newTestMarkClock()
	c, raw := testMarked(clock)
	c.arm(clock.Now())
	ch := asyncMarkWrite(c, []byte{1, 2, 3, 4, 5, 6, 7})
	clock.wait(t)
	if !bytes.Equal(raw.bytes(), []byte{1, 2, 3}) {
		t.Fatal(raw.bytes())
	}
	_ = c.Close()
	a := receiveMark(t, ch)
	if a.n != 3 || !errors.Is(a.err, net.ErrClosed) {
		t.Fatal(a)
	}
	if s := c.snapshot(); s.ForwardedFrames != 0 || s.WaitAborted != 1 {
		t.Fatal(s)
	}
}

func TestMarkCloseUnblocksUnderlyingWrite(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	clock := newTestMarkClock()
	c := newMarkConn(a, MarkConfig{}, 0, 4, clock)
	ch := asyncMarkWrite(c, []byte{1, 2, 3, 4})
	_ = c.Close()
	if a := receiveMark(t, ch); a.err == nil {
		t.Fatal(a)
	}
}
func TestMarkGateFrameCompletion(t *testing.T) {
	clock := newTestMarkClock()
	c, raw := testMarked(clock)
	c.arm(clock.Now())
	if n, e := c.Write([]byte{1, 2, 3}); n != 3 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := c.Write(nil); n != 0 || e != nil || c.snapshot().WaitStarted != 0 {
		t.Fatal(n, e)
	}
	answer := asyncMarkWrite(c, []byte{4, 5})
	clock.wait(t)
	if len(raw.bytes()) != 3 {
		t.Fatal("gated bytes accepted")
	}
	clock.advance(time.Second)
	if a := receiveMark(t, answer); a.n != 2 || a.err != nil {
		t.Fatal(a)
	}
	if c.snapshot().RealizedFrames[0] != 0 {
		t.Fatal("partial frame realized")
	}
	clock.advance(2 * time.Second)
	if n, e := c.Write([]byte{6, 7}); n != 2 || e != nil {
		t.Fatal(n, e)
	}
	s := c.snapshot()
	if s.RealizedFrames[0] != 1 || s.WaitStarted != 1 || s.ForwardedFrames != 1 || s.GateWaitTotal != time.Second {
		t.Fatal(s)
	}
	if n, e := c.Write([]byte{8, 9, 10, 11}); n != 4 || e != nil {
		t.Fatal(n, e)
	}
	if c.snapshot().WaitStarted != 1 {
		t.Fatal("open boundary gated")
	}
}
func TestMarkGateBoundaries(t *testing.T) {
	for _, test := range []struct {
		at     time.Duration
		gate   bool
		symbol int
	}{{0, true, 0}, {time.Second, false, 0}, {2 * time.Second, false, 0}, {4 * time.Second, false, 0}, {6 * time.Second, true, 1}, {7 * time.Second, false, 0}, {8 * time.Second, false, 0}} {
		t.Run(test.at.String(), func(t *testing.T) {
			clock := newTestMarkClock()
			c, _ := testMarked(clock)
			c.skip = 0
			c.arm(clock.Now())
			clock.advance(test.at)
			answer := asyncMarkWrite(c, []byte{1, 2, 3, 4})
			if test.gate {
				clock.wait(t)
				clock.advance(time.Second)
			}
			a := receiveMark(t, answer)
			if a.err != nil {
				t.Fatal(a)
			}
			s := c.snapshot()
			if (s.WaitStarted > 0) != test.gate {
				t.Fatal(s)
			}
			if test.gate && s.RealizedFrames[test.symbol] != 1 {
				t.Fatal(s)
			}
		})
	}
}
func TestMarkPartialWriteErrors(t *testing.T) {
	for _, e := range []error{nil, io.ErrUnexpectedEOF} {
		clock := newTestMarkClock()
		c, raw := testMarked(clock)
		raw.limit = 2
		raw.err = e
		n, err := c.Write([]byte{1, 2, 3, 4})
		want := e
		if e == nil {
			want = io.ErrShortWrite
		}
		if n != 2 || !errors.Is(err, want) || c.skip != 1 {
			t.Fatal(n, err, c.skip)
		}
	}
	clock := newTestMarkClock()
	c, raw := testMarked(clock)
	c.skip = 0
	c.arm(clock.Now())
	raw.limit = 2
	raw.err = io.ErrUnexpectedEOF
	ch := asyncMarkWrite(c, []byte{1, 2, 3, 4})
	clock.wait(t)
	clock.advance(time.Second)
	if a := receiveMark(t, ch); a.n != 2 || !errors.Is(a.err, io.ErrUnexpectedEOF) {
		t.Fatal(a)
	}
	if c.snapshot().RealizedFrames[0] != 0 {
		t.Fatal("failed partial realized")
	}
	raw.limit = 0
	raw.err = nil
	if _, e := c.Write([]byte{3, 4}); e != nil {
		t.Fatal(e)
	}
	if c.snapshot().RealizedFrames[0] != 1 {
		t.Fatal(c.snapshot())
	}
}
func TestMarkDeadlineChangesAndClose(t *testing.T) {
	for _, action := range []string{"expire", "shorten", "extend", "clear", "close"} {
		t.Run(action, func(t *testing.T) {
			clock := newTestMarkClock()
			c, _ := testMarked(clock)
			c.skip = 0
			c.arm(clock.Now())
			if action == "extend" || action == "clear" {
				_ = c.SetWriteDeadline(clock.Now().Add(time.Second / 4))
			}
			ch := asyncMarkWrite(c, []byte{1, 2, 3, 4})
			clock.wait(t)
			want := error(nil)
			switch action {
			case "expire":
				_ = c.SetWriteDeadline(clock.Now())
				want = os.ErrDeadlineExceeded
			case "shorten":
				_ = c.SetDeadline(clock.Now().Add(time.Second / 8))
				clock.wait(t)
				clock.advance(time.Second / 8)
				want = os.ErrDeadlineExceeded
			case "extend":
				_ = c.SetWriteDeadline(clock.Now().Add(2 * time.Second))
				clock.wait(t)
				clock.advance(time.Second)
			case "clear":
				_ = c.SetWriteDeadline(time.Time{})
				clock.wait(t)
				clock.advance(time.Second)
			case "close":
				_ = c.Close()
				want = net.ErrClosed
			}
			a := receiveMark(t, ch)
			if !errors.Is(a.err, want) {
				t.Fatal(a, want)
			}
			s := c.snapshot()
			if want != nil && (s.WaitAborted != 1 || s.RealizedFrames[0] != 0) {
				t.Fatal(s)
			}
			if want == nil && s.RealizedFrames[0] != 1 {
				t.Fatal(s)
			}
		})
	}
}
func TestMarkShamDoesNotConsultCode(t *testing.T) {
	clock := newTestMarkClock()
	raw := &testMarkConn{}
	c := newMarkConn(raw, MarkConfig{Slot: time.Second}, 0, 4, clock)
	c.arm(clock.Now())
	if n, e := c.Write([]byte{1, 2, 3, 4}); n != 4 || e != nil || c.snapshot().WaitStarted != 0 {
		t.Fatal(n, e)
	}
}
func TestMarkConcurrentCloseDeadline(t *testing.T) {
	clock := newTestMarkClock()
	c, _ := testMarked(clock)
	c.skip = 0
	c.arm(clock.Now())
	ch := asyncMarkWrite(c, []byte{1})
	clock.wait(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.SetDeadline(time.Time{})
			_ = c.SetReadDeadline(time.Time{})
			_ = c.Close()
		}()
	}
	wg.Wait()
	if a := receiveMark(t, ch); !errors.Is(a.err, net.ErrClosed) {
		t.Fatal(a)
	}
}
func TestValidateMarkCopiesAndRejects(t *testing.T) {
	base := Config{Flows: 6, Hops: 3, Duration: 16 * time.Second, SendEvery: time.Second, Mark: &MarkConfig{Flow: 1, Code: []int8{1, -1}, Slot: time.Second}}
	got, e := validateMark(base)
	if e != nil {
		t.Fatal(e)
	}
	base.Mark.Code[0] = -1
	if got.Mark.Code[0] != 1 {
		t.Fatal("code aliased")
	}
	for _, m := range []MarkConfig{{Flow: 6, Code: []int8{1, -1}, Slot: time.Second}, {Code: []int8{1, 1}, Slot: time.Second}, {Code: []int8{1, -1}, Slot: time.Duration(1 << 62)}, {Code: []int8{1, -1}, Slot: time.Second, Offset: 15 * time.Second}} {
		base.Mark = &m
		if _, e := validateMark(base); e == nil {
			t.Fatal(m)
		}
	}
}
