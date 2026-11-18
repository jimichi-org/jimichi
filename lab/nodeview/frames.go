package nodeview

import (
	"context"
	"net"
	"strconv"
	"sync"
)

func addressPort(b []byte) uint16 {
	h, p, e := net.SplitHostPort(string(b))
	if e != nil || h != "127.0.0.1" {
		return 0
	}
	n, e := strconv.ParseUint(p, 10, 16)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != p {
		return 0
	}
	return uint16(n)
}
func loopback(port uint16) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))) }

type reassembler struct {
	first               bool
	flight              []byte
	have                int
	frame               []byte
	used                int
	flightRef, frameRef arenaRef
}

func newReassembler(c *collector) reassembler {
	zero := [528]byte{}
	flight, frame := c.copy(zero[:]), c.copy(zero[:])
	return reassembler{flight: c.arena.bytes(flight), frame: c.arena.bytes(frame), flightRef: flight, frameRef: frame}
}

func (r *reassembler) add(b []byte, flight func([]byte), frame func([]byte)) {
	if len(r.flight) != 528 || len(r.frame) != 528 {
		return
	}
	if !r.first {
		n := copy(r.flight[r.have:], b)
		r.have += n
		b = b[n:]
		if r.have == len(r.flight) {
			r.first = true
			flight(r.flight[:])
			clear(r.flight[:])
		}
	}
	for len(b) > 0 {
		n := copy(r.frame[r.used:], b)
		r.used += n
		b = b[n:]
		if r.used == len(r.frame) {
			frame(r.frame[:])
			clear(r.frame[:])
			r.used = 0
		}
	}
}

type observedConn struct {
	rawDenied
	net.Conn
	c               *collector
	generation      uint32
	readMu, writeMu sync.Mutex
	read, write     reassembler
	once            sync.Once
}

func observeConn(raw net.Conn, c *collector, initiator bool) (*observedConn, error) {
	start := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.recordLocked(start, true)
	if len(c.view.connections) >= maxConnections {
		c.fail(ReasonLimit)
		return nil, fail(ReasonLimit)
	}
	g := c.generation()
	local, remote := addressPort([]byte(raw.LocalAddr().String())), addressPort([]byte(raw.RemoteAddr().String()))
	for _, v := range c.view.connections {
		if v.localPort == local && v.remotePort == remote {
			c.fail(ReasonContract)
			return nil, fail(ReasonContract)
		}
	}
	c.view.connections = append(c.view.connections, connectionView{generation: g, localPort: local, remotePort: remote, peer: 255, initiator: initiator})
	c.inventory()
	read, write := newReassembler(c), newReassembler(c)
	if c.err != ReasonNone {
		return nil, fail(c.err)
	}
	return &observedConn{Conn: raw, c: c, generation: g, read: read, write: write}, nil
}
func (o *observedConn) flight(b []byte, in bool) {
	o.c.mu.Lock()
	defer o.c.mu.Unlock()
	for i := range o.c.view.connections {
		v := &o.c.view.connections[i]
		if v.generation != o.generation {
			continue
		}
		if in && !v.initiator || !in && v.initiator {
			if len(b) >= 3 && b[0] == 4 && b[1] == 2 && int(b[2]) <= len(b)-3 {
				v.selectorPort = addressPort(b[3 : 3+int(b[2])])
			}
		}
	}
}
func (o *observedConn) frame(b []byte, dir uint8, t int64) {
	c := o.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending() >= maxPendingFrames {
		c.fail(ReasonLimit)
		return
	}
	if len(c.view.frames) >= maxLifecycles*2 {
		c.fail(ReasonLimit)
		return
	}
	c.view.frames = append(c.view.frames, frameView{connection: o.generation, direction: dir, time: t, data: c.copy(b)})
	c.pendingFrames = append(c.pendingFrames, len(c.view.frames)-1)
	c.inventory()
	c.associate()
}
func (o *observedConn) Read(b []byte) (int, error) {
	pre := o.c.now()
	o.readMu.Lock()
	defer o.readMu.Unlock()
	o.c.record(pre, false)
	n, e := o.Conn.Read(b)
	post := o.c.now()
	defer o.c.record(post, true)
	if n < 0 || n > len(b) {
		o.c.mu.Lock()
		o.c.fail(ReasonContract)
		o.c.mu.Unlock()
		return n, e
	}
	if n > 0 {
		t := post
		o.read.add(b[:n], func(v []byte) { o.flight(v, true) }, func(v []byte) { o.frame(v, 0, t) })
	}
	return n, e
}
func (o *observedConn) Write(b []byte) (int, error) {
	pre := o.c.now()
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	argument := -1
	if o.write.first {
		argument = o.c.writeArgument(o.generation, o.write.used, b)
	}
	o.c.record(pre, false)
	n, e := o.Conn.Write(b)
	post := o.c.now()
	defer o.c.record(post, true)
	if n < 0 || n > len(b) {
		o.c.mu.Lock()
		o.c.fail(ReasonContract)
		o.c.mu.Unlock()
		return n, e
	}
	o.c.writeResult(argument, n, len(b), e != nil)
	if n > 0 {
		t := post
		o.write.add(b[:n], func(v []byte) { o.flight(v, false) }, func(v []byte) { o.frame(v, 1, t) })
	}
	return n, e
}

func (c *collector) writeArgument(connection uint32, offset int, b []byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if offset < 0 || offset > 528 || len(b) > 528-offset {
		return -1
	}
	match := -1
	for _, i := range c.pendingTransports {
		t := &c.transports[i]
		if t.direction != 1 || t.frame.size != 528 {
			continue
		}
		frame := c.arena.bytes(t.frame)
		if equalBytes(frame[offset:offset+len(b)], b) {
			if match >= 0 {
				c.fail(ReasonContract)
				return -1
			}
			match = i
		}
	}
	if match >= 0 {
		t := &c.transports[match]
		if t.connection != 0 && t.connection != connection {
			c.fail(ReasonContract)
			return -1
		}
		t.connection = connection
		t.attempted = true
		c.associate()
	}
	return match
}

func (c *collector) writeResult(index, n, total int, failed bool) {
	if index < 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if index >= len(c.transports) {
		c.fail(ReasonContract)
		return
	}
	t := &c.transports[index]
	t.partial = t.partial || n > 0 && n < total
	t.failed = t.failed || failed || n == 0 && total > 0
	c.associate()
}
func (o *observedConn) Close() error {
	e := o.Conn.Close()
	post := o.c.now()
	defer o.c.record(post, true)
	o.once.Do(func() {
		o.readMu.Lock()
		defer o.readMu.Unlock()
		o.writeMu.Lock()
		defer o.writeMu.Unlock()
		t := post
		o.c.mu.Lock()
		defer o.c.mu.Unlock()
		for _, r := range []*reassembler{&o.read, &o.write} {
			o.c.arena.erase(&r.flightRef)
			o.c.arena.erase(&r.frameRef)
			r.flight, r.frame = nil, nil
			r.have, r.used = 0, 0
		}
		for i := range o.c.view.connections {
			if o.c.view.connections[i].generation == o.generation {
				o.c.view.connections[i].closed = t
			}
		}
		o.c.view.releases = append(o.c.view.releases, releaseView{connection: o.generation, time: t, kind: 2, late: o.c.cutoff != 0 && t > o.c.cutoff, cleanup: o.c.cleanup})
	})
	return e
}

type observedListener struct {
	net.Listener
	c *collector
}

func (l observedListener) Accept() (net.Conn, error) {
	raw, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	v, e := observeConn(raw, l.c, false)
	if e != nil {
		raw.Close()
		return nil, e
	}
	return v, nil
}

func ownedDial(ports map[uint16]bool, c *collector) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		p := addressPort([]byte(addr))
		if network != "tcp" || p == 0 || !ports[p] {
			return nil, fail(ReasonEnrollment)
		}
		var d net.Dialer
		raw, e := d.DialContext(ctx, network, addr)
		if e != nil {
			return nil, e
		}
		if c == nil {
			return raw, nil
		}
		out, e := observeConn(raw, c, true)
		if e != nil {
			raw.Close()
			return nil, e
		}
		return out, e
	}
}
