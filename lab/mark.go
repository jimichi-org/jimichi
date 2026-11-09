package lab

import (
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

type MarkConfig struct {
	Enabled bool          `json:"enabled"`
	Flow    int           `json:"flow"`
	Code    []int8        `json:"code"`
	Slot    time.Duration `json:"slot"`
	Offset  time.Duration `json:"offset"`
}

type MarkCounters struct {
	WaitStarted     int           `json:"wait_started"`
	WaitAborted     int           `json:"wait_aborted"`
	PlannedWait     time.Duration `json:"planned_wait"`
	GateWaitTotal   time.Duration `json:"gate_wait_total"`
	GateWaitMax     time.Duration `json:"gate_wait_max"`
	RealizedFrames  []int         `json:"realized_frames_per_symbol"`
	ForwardedFrames int           `json:"forwarded_frames"`
	Realization     string        `json:"realization"`
}

func validateMark(c Config) (Config, error) {
	if c.Mark == nil {
		return c, nil
	}
	m := *c.Mark
	m.Code = append([]int8(nil), m.Code...)
	if c.Flows < 1 || m.Flow < 0 || m.Flow >= c.Flows || c.Hops < 2 || c.Duration <= 0 || c.SendEvery <= 0 || m.Slot <= 0 || m.Offset < 0 || len(m.Code) < 2 || len(m.Code) > 12 || len(m.Code)%2 != 0 {
		return c, errors.New("mark: invalid configuration")
	}
	if c.Duration > time.Duration(math.MaxInt64)/2 {
		return c, errors.New("mark: unsafe capture duration")
	}
	sum := 0
	for _, s := range m.Code {
		if s != 1 && s != -1 {
			return c, errors.New("mark: invalid symbol")
		}
		sum += int(s)
	}
	if sum != 0 || m.Slot > time.Duration(math.MaxInt64)/(4*time.Duration(len(m.Code))) {
		return c, errors.New("mark: invalid code or duration")
	}
	span := 4 * time.Duration(len(m.Code)) * m.Slot
	if m.Offset > time.Duration(math.MaxInt64)-span || m.Offset+span > c.Duration {
		return c, errors.New("mark: mark outside capture")
	}
	c.Mark = &m
	return c, nil
}

type markTimer interface {
	C() <-chan time.Time
	Stop() bool
}
type markClock interface {
	Now() time.Time
	Timer(time.Duration) markTimer
}
type realMarkClock struct{}
type realMarkTimer struct{ *time.Timer }

func (realMarkClock) Now() time.Time                  { return time.Now() }
func (realMarkClock) Timer(d time.Duration) markTimer { return realMarkTimer{time.NewTimer(d)} }
func (t realMarkTimer) C() <-chan time.Time           { return t.Timer.C }

type markConn struct {
	net.Conn
	writeMu             sync.Mutex
	deadlineMu          sync.Mutex
	mu                  sync.Mutex
	clock               markClock
	cfg                 MarkConfig
	skip, frame, offset int
	prepared, delayed   bool
	symbol              int
	armed               bool
	epoch               time.Time
	deadline            time.Time
	done                chan struct{}
	changed             chan struct{}
	closed              bool
	stats               MarkCounters
}

func newMarkConn(conn net.Conn, cfg MarkConfig, handshake, frame int, clock markClock) *markConn {
	return &markConn{Conn: conn, cfg: cfg, skip: handshake, frame: frame, clock: clock, done: make(chan struct{}), changed: make(chan struct{}), stats: MarkCounters{RealizedFrames: make([]int, len(cfg.Code))}}
}

func (c *markConn) arm(origin time.Time) {
	c.mu.Lock()
	c.epoch = origin.Add(c.cfg.Offset)
	c.armed = true
	c.wake()
	c.mu.Unlock()
}
func (c *markConn) wake() { close(c.changed); c.changed = make(chan struct{}) }

func (c *markConn) gate() (bool, int, error) {
	c.mu.Lock()
	now := c.clock.Now()
	if c.closed {
		c.mu.Unlock()
		return false, 0, net.ErrClosed
	}
	if !c.deadline.IsZero() && !now.Before(c.deadline) {
		c.mu.Unlock()
		return false, 0, os.ErrDeadlineExceeded
	}
	if !c.armed || !c.cfg.Enabled || now.Before(c.epoch) {
		c.mu.Unlock()
		return false, 0, nil
	}
	d := now.Sub(c.epoch)
	span := 4 * time.Duration(len(c.cfg.Code)) * c.cfg.Slot
	if d >= span {
		c.mu.Unlock()
		return false, 0, nil
	}
	k := int(d / (4 * c.cfg.Slot))
	slot := int(d/c.cfg.Slot) % 4
	if !(c.cfg.Code[k] == 1 && slot == 0 || c.cfg.Code[k] == -1 && slot == 2) {
		c.mu.Unlock()
		return false, 0, nil
	}
	release := c.epoch.Add((d/c.cfg.Slot + 1) * c.cfg.Slot)
	c.stats.WaitStarted++
	c.stats.PlannedWait += release.Sub(now)
	start := now
	c.mu.Unlock()
	var err error
	for {
		c.mu.Lock()
		now = c.clock.Now()
		switch {
		case c.closed:
			err = net.ErrClosed
		case !c.deadline.IsZero() && !now.Before(c.deadline):
			err = os.ErrDeadlineExceeded
		case !now.Before(release):
			elapsed := max(now.Sub(start), 0)
			c.stats.GateWaitTotal += elapsed
			c.stats.GateWaitMax = max(c.stats.GateWaitMax, elapsed)
			c.mu.Unlock()
			return true, k, nil
		}
		if err != nil {
			elapsed := max(now.Sub(start), 0)
			c.stats.GateWaitTotal += elapsed
			c.stats.GateWaitMax = max(c.stats.GateWaitMax, elapsed)
			c.stats.WaitAborted++
			c.mu.Unlock()
			return false, k, err
		}
		until := release
		if !c.deadline.IsZero() && c.deadline.Before(until) {
			until = c.deadline
		}
		changed := c.changed
		timer := c.clock.Timer(until.Sub(now))
		c.mu.Unlock()
		select {
		case <-timer.C():
		case <-changed:
		case <-c.done:
		}
		if !timer.Stop() {
			select {
			case <-timer.C():
			default:
			}
		}
	}
}

func (c *markConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	total := 0
	for len(b) > 0 {
		limit := c.skip
		if c.skip == 0 {
			if c.offset == 0 && !c.prepared {
				delayed, k, err := c.gate()
				if err != nil {
					return total, err
				}
				c.delayed, c.symbol, c.prepared = delayed, k, true
			}
			limit = c.frame - c.offset
		}
		part := b[:min(len(b), limit)]
		n, err := c.Conn.Write(part)
		if n < 0 || n > len(part) {
			return total, io.ErrShortWrite
		}
		total += n
		b = b[n:]
		if c.skip > 0 {
			c.skip -= n
		} else {
			c.offset += n
			if c.offset == c.frame {
				c.mu.Lock()
				c.stats.ForwardedFrames++
				if c.delayed {
					c.stats.RealizedFrames[c.symbol]++
				}
				c.mu.Unlock()
				c.offset = 0
				c.prepared = false
				c.delayed = false
			}
		}
		if err != nil {
			return total, err
		}
		if n < len(part) {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (c *markConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.done)
		c.wake()
	}
	c.mu.Unlock()
	return c.Conn.Close()
}
func (c *markConn) SetDeadline(t time.Time) error      { return c.setDeadline(t, true) }
func (c *markConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false) }
func (c *markConn) setDeadline(t time.Time, both bool) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	var err error
	if both {
		err = c.Conn.SetDeadline(t)
	} else {
		err = c.Conn.SetWriteDeadline(t)
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.deadline = t
	c.wake()
	c.mu.Unlock()
	return nil
}
func (c *markConn) snapshot() MarkCounters {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.RealizedFrames = append([]int(nil), s.RealizedFrames...)
	n := 0
	for _, v := range s.RealizedFrames {
		if v > 0 {
			n++
		}
	}
	s.Realization = "none"
	if n > 0 {
		s.Realization = "partial"
	}
	if n == len(s.RealizedFrames) {
		s.Realization = "complete"
	}
	return s
}
