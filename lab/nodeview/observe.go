package nodeview

import (
	"bytes"
	"encoding/binary"
	"slices"
	"sync"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

type connectionView struct {
	generation            uint32
	localPort, remotePort uint16
	peer                  uint8
	selectorPort          uint16
	initiator             bool
	authenticated         bool
	closed                int64
}
type setupView struct {
	generation, hop, connection uint32
	outConnection               uint32
	context                     [32]byte
	index                       uint8
	circuit, nextCircuit, first uint64
	nextPort                    uint16
	opened, released            int64
	stages                      uint16
	input                       arenaRef
	inner                       arenaRef
}
type cellView struct {
	generation, connection, hop               uint32
	kind, dir, index                          uint8
	circuit, counter                          uint64
	outputCircuit, outputCounter              uint64
	inputTime, localTime, sealTime, writeTime int64
	stages                                    uint16
	terminal                                  uint8
	cover, noDeliver, nilReply                bool
	delivered, paired                         bool
	reply                                     arenaRef
	input, inner, output                      arenaRef
	outTransport                              int
}
type transportView struct {
	generation                 uint32
	aead, connection           uint32
	direction                  uint8
	time                       int64
	header                     wire.Header
	frame, cell                arenaRef
	matched                    bool
	frameIndex                 int
	attempted, partial, failed bool
}
type frameView struct {
	connection uint32
	direction  uint8
	time       int64
	data       arenaRef
	matched    bool
}
type transportKey struct {
	circuit         uint64
	direction, kind uint8
}
type contentFragment struct {
	hop  uint32
	kind uint8
	data arenaRef
}
type releaseView struct {
	hop, connection uint32
	time            int64
	kind            uint8
	late, cleanup   bool
}
type nodeView struct {
	budget *memoryBudget
	rawDenied
	position         uint8
	arena            *lockedArena
	scorerProjection bool
	samples          []cellSample
	connections      []connectionView
	setups           []setupView
	cells            []cellView
	frames           []frameView
	mailbox          []mailboxObservation
	releases         []releaseView
}
type cellSample struct {
	connection, hop uint32
	time            int64
	sealTime        int64
	kind, dir       byte
	stages          uint16
}

const (
	stageInput uint16 = 1 << iota
	stageLocal
	stageSealed
	stagePartial
	stageWritten
)
const (
	terminalForwarded uint8 = iota
	terminalNoWrite
	terminalWriteFailed
	terminalCutoff
	terminalProvenance
	terminalAmbiguous
)

type collector struct {
	rawDenied
	mu                    sync.Mutex
	arena                 *lockedArena
	view                  nodeView
	transports            []transportView
	pendingCells          []int
	pendingTransports     []int
	pendingFrames         []int
	transportIndex        map[transportKey][]int
	fragments             []contentFragment
	keys                  map[*secmem.Buffer]keyTag
	contexts              map[[32]byte]*setupView
	bindings              map[uint64]uint32
	next                  uint32
	err                   Reason
	start, cutoff         int64
	frozen, cleanup, peer bool
	summary               CaptureSummary
	publicKeySize         int
	mailboxOrder          uint32
	observerValid         bool
	now                   func() int64
}

func newCollector(now func() int64, peer bool, pubSize int) (*collector, error) {
	a, err := newArena(relayArenaBytes)
	if err != nil {
		return nil, err
	}
	c := &collector{arena: a, keys: make(map[*secmem.Buffer]keyTag), contexts: make(map[[32]byte]*setupView), bindings: make(map[uint64]uint32), transportIndex: make(map[transportKey][]int), now: now, peer: peer, publicKeySize: pubSize}
	c.view.connections = make([]connectionView, 0, maxConnections)
	c.observerValid = true
	c.view.setups = make([]setupView, 0, maxContexts)
	c.view.cells = make([]cellView, 0, maxLifecycles)
	c.transports = make([]transportView, 0, maxPendingFrames)
	c.view.frames = make([]frameView, 0, maxPendingFrames)
	return c, nil
}
func (c *collector) fail(r Reason) {
	if c.err == ReasonNone {
		c.err = r
	}
}
func (c *collector) generation() uint32 {
	c.next++
	if c.next == 0 {
		c.fail(ReasonLimit)
	}
	return c.next
}
func (c *collector) copy(b []byte) arenaRef {
	r, ok := c.arena.copy(b)
	if !ok {
		c.fail(ReasonLimit)
	}
	return r
}
func (c *collector) begin(start, cutoff int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.start, c.cutoff = start, cutoff
}
func (c *collector) measured(t int64) bool { return c.start != 0 && t >= c.start && t < c.cutoff }
func (c *collector) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.keys)
	clear(c.contexts)
	clear(c.bindings)
	c.arena.close()
	c.view.wipe()
	clear(c.transports)
	clear(c.fragments)
	clear(c.pendingCells)
	clear(c.pendingTransports)
	clear(c.pendingFrames)
	clear(c.transportIndex)
	c.transports = nil
	c.fragments = nil
	c.pendingCells = nil
	c.pendingTransports = nil
	c.pendingFrames = nil
	c.transportIndex = nil
}

func decodeNonce(n []byte) (uint64, uint64, uint8, bool) {
	var circuit, counter uint64
	var dir uint8
	switch {
	case len(n) >= 17:
		dir = n[0]
		circuit = binary.BigEndian.Uint64(n[1:9])
		counter = binary.BigEndian.Uint64(n[9:17])
		for _, b := range n[17:] {
			if b != 0 {
				return 0, 0, 0, false
			}
		}
	case len(n) == 16:
		v := binary.BigEndian.Uint64(n[:8])
		if v>>63 != 0 {
			return 0, 0, 0, false
		}
		dir = uint8(v >> 62)
		counter = v & ((1 << 62) - 1)
		circuit = binary.BigEndian.Uint64(n[8:16])
	default:
		return 0, 0, 0, false
	}
	return circuit, counter, dir, dir <= 1 && counter < 1<<62
}

func (c *collector) findSetup(context [32]byte) *setupView {
	for i := range c.view.setups {
		if c.view.setups[i].context == context {
			return &c.view.setups[i]
		}
	}
	return nil
}
func (c *collector) setupOpened(g uint32, tag keyTag, nonce, input, plain, ad []byte, t int64) {
	if len(ad) != 3 || ad[0] != wire.Version || ad[1] != byte(wire.KindControl) || ad[2] >= wire.MaxHops || len(plain) < 73 {
		c.fail(ReasonContract)
		return
	}
	id, count, dir, ok := decodeNonce(nonce)
	if !ok || count != 0 || dir != 0 {
		c.fail(ReasonContract)
		return
	}
	if c.findSetup(tag.context) != nil || len(c.view.setups) >= maxContexts {
		c.fail(ReasonContract)
		return
	}
	s := setupView{generation: g, context: tag.context, index: ad[2], circuit: id, opened: t, stages: stageInput, input: c.copy(input), inner: c.copy(plain[73:])}
	next := binary.BigEndian.Uint64(plain[65:73])
	if plain[0] == 1 {
		s.nextPort = addressPort(bytes.TrimRight(plain[1:65], "\x00"))
		if s.nextPort == 0 {
			c.fail(ReasonContract)
			return
		}
		s.nextCircuit = next
	} else if plain[0] == 0 {
		s.first = next
		if next >= 1<<62 {
			c.fail(ReasonContract)
			return
		}
	} else {
		c.fail(ReasonContract)
		return
	}
	c.view.setups = append(c.view.setups, s)
	c.inventory()
	c.associate()
}

func (c *collector) hopCreated(g uint32, tag keyTag) {
	s := c.findSetup(tag.context)
	if s == nil || s.hop != 0 {
		c.fail(ReasonContract)
		return
	}
	s.hop = g
	s.stages |= stageLocal
}
func (c *collector) hopOperation(g uint32, open bool, nonce, input, output, ad []byte, t int64) {
	id, counter, dir, ok := decodeNonce(nonce)
	if !ok || len(ad) != 11 || ad[0] != wire.Version || ad[1] != byte(wire.KindData) || ad[10] >= wire.MaxHops || binary.BigEndian.Uint64(ad[2:10]) != counter || open != (dir == 0) {
		c.fail(ReasonContract)
		return
	}
	var setup *setupView
	for i := range c.view.setups {
		if c.view.setups[i].hop == g {
			if setup != nil {
				c.fail(ReasonContract)
				return
			}
			setup = &c.view.setups[i]
		}
	}
	if setup == nil || setup.circuit != id || setup.index != ad[10] {
		c.fail(ReasonContract)
		return
	}
	cipher, plain := wire.BodySize-int(setup.index)*16, wire.BodySize-(int(setup.index)+1)*16
	if open && (len(input) != cipher || len(output) != plain) || !open && (len(input) != plain || len(output) != cipher) {
		c.fail(ReasonContract)
		return
	}
	if len(c.view.cells) >= maxLifecycles {
		c.fail(ReasonLimit)
		return
	}
	v := cellView{generation: c.generation(), hop: g, kind: byte(wire.KindData), dir: dir, index: ad[10], circuit: id, counter: counter, localTime: t, stages: stageLocal, input: c.copy(input), inner: c.copy(output), outTransport: -1}
	if dir == 1 {
		v.output = v.inner
		v.inner = arenaRef{}
	}
	if setup.nextPort == 0 && dir == 0 && len(output) >= 2 {
		length := binary.BigEndian.Uint16(output[:2])
		v.cover = length&0x8000 != 0
		v.noDeliver = v.cover
	}
	if setup.nextPort == 0 && dir == 1 {
		payload, cover, valid := framedPayload(input)
		if !valid {
			c.fail(ReasonContract)
			return
		}
		match := -1
		for i := range c.view.cells {
			f := &c.view.cells[i]
			if f.hop != g || f.dir != 0 || f.paired {
				continue
			}
			if f.cover && !cover || !f.cover && !f.delivered {
				continue
			}
			if !f.cover && (f.nilReply != cover || !cover && !bytes.Equal(payload, c.arena.bytes(f.reply))) {
				continue
			}
			if match != -1 {
				c.fail(ReasonContract)
				return
			}
			match = i
			break
		}
		if match < 0 {
			c.fail(ReasonContract)
			return
		}
		f := &c.view.cells[match]
		f.paired = true
		v.stages |= stageInput
		v.connection = setup.connection
		v.inputTime = f.inputTime
		v.outputCircuit = id
		v.outputCounter = counter
		c.arena.erase(&f.reply)
		c.arena.erase(&v.input)
	}
	c.view.cells = append(c.view.cells, v)
	setup.stages |= stageSealed
	c.pendingCells = append(c.pendingCells, len(c.view.cells)-1)
	c.inventory()
	if dir == 0 && c.measured(t) {
		fragment := output
		if c.peer && setup.nextPort == 0 {
			if len(output) >= 2+35+392 {
				fragment = output[2+35 : 2+35+392]
			} else {
				fragment = nil
			}
		}
		if len(fragment) > 0 {
			c.fragments = append(c.fragments, contentFragment{g, 1, c.copy(fragment)})
		}
	}
	c.associate()
}

func (c *collector) transport(g uint32, open bool, frame, plain []byte, t int64) {
	if c.pending() >= maxPendingFrames {
		c.fail(ReasonLimit)
		return
	}
	if len(plain) != wire.CellSize {
		c.fail(ReasonContract)
		return
	}
	var cell wire.Cell
	copy(cell[:], plain)
	h, e := cell.Header()
	if e != nil {
		c.fail(ReasonContract)
		return
	}
	if len(c.transports) >= maxLifecycles*2 {
		c.fail(ReasonLimit)
		return
	}
	dir := uint8(1)
	if open {
		dir = 0
	}
	c.transports = append(c.transports, transportView{generation: c.generation(), aead: g, direction: dir, time: t, header: h, frame: c.copy(frame), cell: c.copy(plain)})
	if dir == 1 {
		c.transports[len(c.transports)-1].connection = c.bindings[uint64(g)<<1|1]
	}
	c.pendingTransports = append(c.pendingTransports, len(c.transports)-1)
	c.inventory()
	key := transportKey{h.Circuit, dir, uint8(h.Kind)}
	c.transportIndex[key] = append(c.transportIndex[key], len(c.transports)-1)
	c.associate()
}

func (c *collector) associate() {
	for _, ti := range c.pendingTransports {
		t := &c.transports[ti]
		if t.matched {
			continue
		}
		match := -1
		for _, fi := range c.pendingFrames {
			f := &c.view.frames[fi]
			if f.matched || f.direction != t.direction {
				continue
			}
			if bytes.Equal(c.arena.bytes(f.data), c.arena.bytes(t.frame)) {
				if match != -1 {
					c.fail(ReasonContract)
					return
				}
				match = fi
			}
		}
		if match < 0 {
			continue
		}
		f := &c.view.frames[match]
		binding := uint64(t.aead)<<1 | uint64(t.direction)
		if conn, ok := c.bindings[binding]; ok && conn != f.connection {
			c.fail(ReasonContract)
			return
		}
		c.bindings[binding] = f.connection
		t.connection = f.connection
		t.matched = true
		t.frameIndex = match
		f.matched = true
		for i := range c.view.connections {
			if c.view.connections[i].generation == f.connection {
				c.view.connections[i].authenticated = true
			}
		}
		c.arena.erase(&t.frame)
		c.arena.erase(&f.data)
		if t.header.Kind == wire.KindPadding {
			c.arena.erase(&t.cell)
		}
	}
	for si := range c.view.setups {
		s := &c.view.setups[si]
		if s.connection != 0 {
			continue
		}
		match := -1
		for _, ti := range c.transportIndex[transportKey{s.circuit, 0, byte(wire.KindControl)}] {
			t := &c.transports[ti]
			if !t.matched || t.header.Counter != uint64(s.index) {
				continue
			}
			b := c.arena.bytes(t.cell)
			prefix := c.publicKeySize
			if len(b) >= 18+prefix+s.input.size && bytes.Equal(b[18+prefix:18+prefix+s.input.size], c.arena.bytes(s.input)) {
				if match != -1 {
					c.fail(ReasonContract)
					return
				}
				match = ti
			}
		}
		if match >= 0 {
			s.connection = c.transports[match].connection
			c.arena.erase(&s.input)
			c.arena.erase(&c.transports[match].cell)
		}
	}
	for si := range c.view.setups {
		s := &c.view.setups[si]
		if s.connection == 0 || s.nextPort == 0 || s.outConnection != 0 {
			continue
		}
		match := -1
		for ti := range c.transports {
			t := &c.transports[ti]
			if !t.matched || t.direction != 1 || t.header.Kind != wire.KindControl || t.header.Circuit != s.nextCircuit || t.header.Counter != uint64(s.index)+1 || !c.connectionPort(t.connection, s.nextPort) {
				continue
			}
			b := c.arena.bytes(t.cell)
			inner := c.arena.bytes(s.inner)
			if len(b) >= 18+len(inner) && bytes.Equal(inner, b[18:18+len(inner)]) {
				if match != -1 {
					c.fail(ReasonContract)
					return
				}
				match = ti
			}
		}
		if match >= 0 {
			s.outConnection = c.transports[match].connection
			c.arena.erase(&s.inner)
		}
	}
	for _, vi := range c.pendingCells {
		v := &c.view.cells[vi]
		var s *setupView
		for si := range c.view.setups {
			if c.view.setups[si].hop == v.hop {
				s = &c.view.setups[si]
				break
			}
		}
		if s == nil || s.connection == 0 {
			continue
		}
		if v.stages&stageInput == 0 {
			match := -1
			inCircuit := v.circuit
			if v.dir == 1 {
				inCircuit = s.nextCircuit
			}
			for _, ti := range c.transportIndex[transportKey{inCircuit, 0, byte(wire.KindData)}] {
				t := &c.transports[ti]
				if !t.matched {
					continue
				}
				b := c.arena.bytes(t.cell)
				if len(b) < 18 {
					continue
				}
				if v.dir == 0 {
					if t.connection != s.connection || t.header.Circuit != v.circuit || t.header.Counter != v.counter {
						continue
					}
				} else {
					if s.nextPort == 0 {
						continue
					}
					if t.header.Circuit != s.nextCircuit || !c.connectionPort(t.connection, s.nextPort) {
						continue
					}
				}
				input := c.arena.bytes(v.input)
				if len(input) <= len(b)-18 && bytes.Equal(input, b[18:18+len(input)]) {
					if match != -1 {
						c.fail(ReasonContract)
						return
					}
					match = ti
				}
			}
			if match >= 0 {
				t := &c.transports[match]
				v.connection = t.connection
				v.inputTime = t.time
				v.stages |= stageInput
				if v.dir == 1 {
					v.outputCircuit = v.circuit
					v.outputCounter = v.counter
					v.circuit = t.header.Circuit
					v.counter = t.header.Counter
				}
				c.arena.erase(&v.input)
				c.arena.erase(&t.cell)
			} else if v.dir == 1 && s.nextPort == 0 {
				v.stages |= stageInput
				v.connection = s.connection
			}
		}
		if v.stages&stageInput != 0 && v.stages&stageSealed == 0 {
			match := -1
			outCircuit := s.nextCircuit
			if v.dir == 1 {
				outCircuit = v.outputCircuit
			}
			for _, ti := range c.transportIndex[transportKey{outCircuit, 1, byte(wire.KindData)}] {
				t := &c.transports[ti]
				if t.connection == 0 {
					continue
				}
				b := c.arena.bytes(t.cell)
				if len(b) < 18 {
					continue
				}
				var p []byte
				if v.dir == 0 {
					if s.nextPort == 0 {
						continue
					}
					if t.header.Circuit != s.nextCircuit || !c.connectionPort(t.connection, s.nextPort) {
						continue
					}
					p = c.arena.bytes(v.inner)
				} else {
					if t.connection != s.connection || t.header.Circuit != v.outputCircuit || t.header.Counter != v.outputCounter {
						continue
					}
					p = c.arena.bytes(v.output)
				}
				if len(p) > 0 && len(p) <= len(b)-18 && bytes.Equal(p, b[18:18+len(p)]) {
					if match != -1 {
						c.fail(ReasonContract)
						return
					}
					match = ti
				}
			}
			if match >= 0 {
				t := &c.transports[match]
				v.stages |= stageSealed
				v.outTransport = match
				v.sealTime = t.time
				v.outputCircuit = t.header.Circuit
				v.outputCounter = t.header.Counter
				c.arena.erase(&v.inner)
				c.arena.erase(&v.output)
				c.arena.erase(&t.cell)
			}
		}
		if v.outTransport >= 0 && v.stages&stageSealed != 0 {
			t := &c.transports[v.outTransport]
			if t.partial {
				v.stages |= stagePartial
			}
			if t.failed {
				v.terminal = terminalWriteFailed
			}
			if t.matched {
				v.stages |= stageWritten
				v.writeTime = c.view.frames[t.frameIndex].time
			}
		}
	}
	kept := c.pendingCells[:0]
	for _, i := range c.pendingCells {
		v := c.view.cells[i]
		complete := v.stages&stageWritten != 0
		for _, s := range c.view.setups {
			if s.hop == v.hop && s.nextPort == 0 && v.dir == 0 && v.stages&stageInput != 0 {
				complete = true
			}
		}
		if !complete {
			kept = append(kept, i)
		}
	}
	c.pendingCells = kept
	active := c.pendingTransports[:0]
	for _, i := range c.pendingTransports {
		if !c.transports[i].matched {
			active = append(active, i)
		}
	}
	c.pendingTransports = active
	frames := c.pendingFrames[:0]
	for _, i := range c.pendingFrames {
		if !c.view.frames[i].matched {
			frames = append(frames, i)
		}
	}
	c.pendingFrames = frames
	c.summary.PendingHighWater = max(c.summary.PendingHighWater, uint64(c.pending()))
	if c.pending() > maxPendingFrames {
		c.fail(ReasonLimit)
	}
}

func (c *collector) pending() int { return len(c.pendingFrames) + len(c.pendingTransports) }
func (c *collector) connectionPort(g uint32, port uint16) bool {
	for _, v := range c.view.connections {
		if v.generation == g {
			return v.remotePort == port && v.initiator && v.authenticated
		}
	}
	return false
}

func (c *collector) released(g uint32, tag keyTag, t int64) {
	if tag.purpose != "cell" {
		return
	}
	for i := range c.view.setups {
		s := &c.view.setups[i]
		if s.hop == g {
			s.released = t
			s.stages |= stageWritten
			c.view.releases = append(c.view.releases, releaseView{hop: g, connection: s.connection, time: t, kind: 1, late: c.cutoff != 0 && t > c.cutoff, cleanup: c.cleanup})
			return
		}
	}
}

func (c *collector) freeze() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frozen = true
	c.associate()
	for _, t := range c.transports {
		if !t.matched && t.direction == 0 {
			c.fail(ReasonContract)
		}
	}
	for _, f := range c.view.frames {
		if !f.matched && (f.direction == 1 || c.measured(f.time)) {
			c.fail(ReasonContract)
		}
	}
	for i := range c.view.cells {
		v := &c.view.cells[i]
		switch {
		case v.terminal == terminalWriteFailed:
		case v.stages&stageWritten != 0:
			v.terminal = terminalForwarded
		case v.stages&stageInput == 0:
			v.terminal = terminalProvenance
		case v.localTime >= c.cutoff && c.cutoff != 0:
			v.terminal = terminalCutoff
		default:
			v.terminal = terminalNoWrite
		}
		c.summary.Lifecycle[v.terminal]++
	}
	c.inventory()
	if e := c.checkCounters(); e != nil {
		if c.err != ReasonNone {
			return mergeRuntimeFailure(fail(c.err), e)
		}
		return e
	}
	if c.err != ReasonNone {
		return fail(c.err)
	}
	return nil
}

func (c *collector) checkCounters() error {
	scratch, release, e := makeCounterScratch(c.view.cells, c.view.budget)
	if e != nil {
		return e
	}
	defer release()
	for _, v := range c.view.cells {
		if v.hop == 0 || v.kind != 1 {
			continue
		}
		key := uint64(v.hop)<<1 | uint64(v.dir)
		at, _ := slices.BinarySearch(scratch.keys, key)
		if v.dir == 0 && !scratch.states[at].firstSeen && v.stages&stageInput != 0 {
			scratch.states[at].firstSeen = true
			for _, setup := range c.view.setups {
				if setup.hop == v.hop && setup.nextPort == 0 {
					c.summary.Counters.FirstChecked++
					if v.counter == setup.first {
						c.summary.Counters.FirstOK++
					} else {
						c.summary.Counters.FirstFailed++
					}
				}
			}
		}
		if !c.measured(v.localTime) {
			continue
		}
		p := scratch.states[at]
		x := &c.summary.Counters
		x.Samples++
		if v.counter >= 1<<62 {
			x.Invalid++
			continue
		}
		x.DirectionOK++
		x.IndexOK++
		exit := false
		for _, setup := range c.view.setups {
			if setup.hop == v.hop && setup.nextPort == 0 {
				exit = true
			}
		}
		if exit && v.dir == 1 {
			if p.hasOutput {
				x.Transitions++
				if (p.output+1)&((1<<62)-1) == v.outputCounter {
					x.Advanced++
				} else if p.output == v.outputCounter {
					x.Repeats++
				} else {
					x.Gaps++
				}
			}
			p.output, p.hasOutput = v.outputCounter, true
			x.Missing++
			scratch.states[at] = p
			continue
		}
		if p.hasInput {
			x.Transitions++
			if (p.input+1)&((1<<62)-1) == v.counter {
				x.Advanced++
			} else if p.input == v.counter {
				x.Repeats++
			} else {
				x.Gaps++
			}
		}
		p.input, p.hasInput = v.counter, true
		outputTime := v.sealTime
		hasOutput := v.stages&stageSealed != 0
		if v.dir == 1 {
			outputTime = v.localTime
			hasOutput = v.stages&(stageInput|stageLocal) == stageInput|stageLocal
		}
		if hasOutput && c.measured(outputTime) {
			x.Matched++
			shift := (v.outputCounter - v.counter) & ((1 << 62) - 1)
			if p.hasOutput {
				x.Transitions++
				if (p.output+1)&((1<<62)-1) == v.outputCounter {
					x.Advanced++
				} else if p.output == v.outputCounter {
					x.Repeats++
				} else {
					x.Gaps++
				}
			}
			if p.hasShift {
				x.ShiftChecks++
				if p.shift == shift {
					x.ShiftOK++
				}
			}
			p.output, p.hasOutput, p.shift, p.hasShift = v.outputCounter, true, shift, true
		} else {
			x.Missing++
		}
		scratch.states[at] = p
	}
	return nil
}

func framedPayload(b []byte) ([]byte, bool, bool) {
	if len(b) < 2 {
		return nil, false, false
	}
	v := binary.BigEndian.Uint16(b[:2])
	n := int(v & 0x7fff)
	cover := v&0x8000 != 0
	if n > len(b)-2 || cover && n != 0 {
		return nil, false, false
	}
	return b[2 : 2+n], cover, true
}
