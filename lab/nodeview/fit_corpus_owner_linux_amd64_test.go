//go:build linux && amd64

package nodeview

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"unsafe"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type fitCorpusWire struct {
	b    []byte
	used int
}

func (w *fitCorpusWire) Write(b []byte) (int, error) {
	if len(b) > len(w.b)-w.used {
		return 0, io.ErrShortBuffer
	}
	copy(w.b[w.used:], b)
	w.used += len(b)
	return len(b), nil
}

type fitCorpusOwner struct {
	capture                    *privateCapture
	wire                       fitCorpusWire
	input                      bytes.Reader
	reader                     *protocolReader
	writer                     protocolWriter
	budget                     *memoryBudget
	borrowed, complete, closed bool
}

func fitCorpusAggregateHistory() (uint64, uint64, error) {
	a := &outputArithmetic{}
	var logical, physical uint64
	for _, row := range [][2]uint64{{128, 32}, {48, 24}, {240, 32}, {256, 40}, {256, 72}, {32, 24}, {16, 144}, {48, 32}, {256, 36}, {16, 112}} {
		n := a.mul(row[0], row[1])
		logical = a.add(logical, n)
		physical = a.add(physical, outputRoundObject(n, a))
	}
	if a.err != nil {
		return 0, 0, a.err
	}
	return logical, physical, nil
}

func allocateFitCorpusSlice[T any](n int) []T { return make([]T, 0, n) }

func preallocateFitCorpusSlice[T any](n int, b *memoryBudget) ([]T, error) {
	return preallocateFitCorpusWithAllocator(n, b, allocateFitCorpusSlice[T])
}

func preallocateFitCorpusWithAllocator[T any](n int, b *memoryBudget, allocate func(int) []T) ([]T, error) {
	if n < 1 || n > 256 || b == nil || b.beforeAllocation == nil || allocate == nil {
		return nil, fail(ReasonContract)
	}
	a := &outputArithmetic{}
	var zero T
	logical := a.mul(uint64(n), uint64(unsafe.Sizeof(zero)))
	physical := outputRoundObject(logical, a)
	if a.err != nil {
		return nil, a.err
	}
	if err := b.reserve(logical); err != nil {
		return nil, err
	}
	if err := b.checkAllocation(physical); err != nil {
		b.release(logical)
		return nil, err
	}
	return allocate(n), nil
}

func preallocateFitCorpusAggregate(in *evaluationInput) error {
	if in == nil || len(in.views.nodes) != 1 {
		return fail(ReasonContract)
	}
	var err error
	in.truth.messages, err = preallocateFitCorpusSlice[actualMessage](128, in.budget)
	if err != nil {
		return err
	}
	in.truth.setups, err = preallocateFitCorpusSlice[actualSetup](48, in.budget)
	if err != nil {
		return err
	}
	in.truth.seals, err = preallocateFitCorpusSlice[actualSeal](240, in.budget)
	if err != nil {
		return err
	}
	in.truth.requests, err = preallocateFitCorpusSlice[actualRequest](256, in.budget)
	if err != nil {
		return err
	}
	n := &in.views.nodes[0]
	n.mailbox, err = preallocateFitCorpusSlice[mailboxObservation](256, in.budget)
	if err != nil {
		return err
	}
	n.connections, err = preallocateFitCorpusSlice[connectionView](32, in.budget)
	if err != nil {
		return err
	}
	n.setups, err = preallocateFitCorpusSlice[setupView](16, in.budget)
	if err != nil {
		return err
	}
	in.plans, err = preallocateFitCorpusSlice[workloadPlan](16, in.budget)
	return err
}

func fitCorpusAggregatePointers(in *evaluationInput) [8]unsafe.Pointer {
	n := &in.views.nodes[0]
	return [8]unsafe.Pointer{unsafe.Pointer(unsafe.SliceData(in.truth.messages)), unsafe.Pointer(unsafe.SliceData(in.truth.setups)), unsafe.Pointer(unsafe.SliceData(in.truth.seals)), unsafe.Pointer(unsafe.SliceData(in.truth.requests)), unsafe.Pointer(unsafe.SliceData(n.mailbox)), unsafe.Pointer(unsafe.SliceData(n.connections)), unsafe.Pointer(unsafe.SliceData(n.setups)), unsafe.Pointer(unsafe.SliceData(in.plans))}
}

func validFitCorpusAggregateCaps(in *evaluationInput) bool {
	n := &in.views.nodes[0]
	return cap(in.truth.messages) == 128 && cap(in.truth.setups) == 48 && cap(in.truth.seals) == 240 && cap(in.truth.requests) == 256 && cap(n.mailbox) == 256 && cap(n.connections) == 32 && cap(n.setups) == 16 && cap(in.plans) == 16
}

func receiveFitCorpusTruth(r *decoder, t *privateTruth) error {
	if len(r.b) < 3 {
		return fail(ReasonIPC)
	}
	n := int(binary.BigEndian.Uint16(r.b[1:3]))
	available := 0
	switch r.b[0] {
	case 1:
		available = cap(t.messages) - len(t.messages)
	case 2:
		available = cap(t.setups) - len(t.setups)
	case 3:
		available = cap(t.seals) - len(t.seals)
	case 4:
		available = cap(t.requests) - len(t.requests)
	default:
		return fail(ReasonIPC)
	}
	if n > available {
		return fail(ReasonLimit)
	}
	return receiveTruth(r, t)
}

func fitCorpusBytes() (uint64, error) {
	startup, err := clientTruthStartupBytes()
	if err != nil {
		return 0, err
	}
	if startup != 2965504 || unsafe.Sizeof(actualMessage{}) != 32 || unsafe.Sizeof(actualSetup{}) != 24 || unsafe.Sizeof(actualSeal{}) != 32 || unsafe.Sizeof(actualRequest{}) != 40 || unsafe.Sizeof(mailboxObservation{}) != 72 || unsafe.Sizeof(connectionView{}) != 24 || unsafe.Sizeof(setupView{}) != 144 || unsafe.Sizeof(setupOwnerEntry{}) != 32 || unsafe.Sizeof(encodedMailboxRow{}) != 36 || unsafe.Sizeof(workloadPlan{}) != 112 || unsafe.Sizeof(decoder{}) != 40 || unsafe.Sizeof(protocolReader{}) != 72 || unsafe.Sizeof(protocolWriter{}) != 96 || unsafe.Sizeof(encoder{}) != 56 || unsafe.Sizeof(bytes.Reader{}) != 40 || unsafe.Sizeof(childIO{}) != 88 || unsafe.Sizeof(fitCorpusWire{}) > 48 || unsafe.Sizeof(fitCorpusOwner{}) > 256 {
		return 0, fail(ReasonUnsupported)
	}
	a := &outputArithmetic{}
	logical, physical, err := fitCorpusAggregateHistory()
	if err != nil || logical != 57216 || physical > 716800 {
		return 0, fail(ReasonUnsupported)
	}
	decoderControls := uint64(208)*(48+32+24) + uint64(224)*(8+8+16)
	controls := uint64(8176 + 57520 + 256 + 2480 + 69960 + 9760 + 3456 + 2376 + 17104 + 39936 + 6656 + 12960)
	if decoderControls != 28800 || decoderControls > 32768 || controls != 230640 || controls > 262144 || a.err != nil || a.add(startup, 65536, 65536, 716800, 32768, 262144) != 4108288 {
		return 0, fail(ReasonUnsupported)
	}
	return 8 << 20, nil
}

func allocateFitCorpusWire(n int) ([]byte, error) { return make([]byte, n), nil }

func newFitCorpusOwner(b *memoryBudget, probe func() (uint64, error), allocate func(uint16) (*privateCapture, error)) (*fitCorpusOwner, error) {
	return newFitCorpusOwnerWithConstructors(b, probe, allocate, allocateFitCorpusWire, newProtocolReader)
}

func newFitCorpusOwnerWithConstructors(b *memoryBudget, probe func() (uint64, error), allocate func(uint16) (*privateCapture, error), wire func(int) ([]byte, error), reader func(io.Reader, [16]byte, uint64) (*protocolReader, error)) (*fitCorpusOwner, error) {
	if b == nil || b.beforeAllocation == nil || probe == nil || allocate == nil || wire == nil || reader == nil {
		return nil, fail(ReasonContract)
	}
	charge, err := fitCorpusBytes()
	if err != nil {
		return nil, err
	}
	if err = b.reserve(charge); err != nil {
		return nil, err
	}
	if err = b.checkAllocation(charge); err != nil {
		b.release(charge)
		return nil, err
	}
	available, err := probe()
	if err != nil {
		b.release(charge)
		return nil, err
	}
	if available < charge {
		b.release(charge)
		return nil, fail(ReasonLimit)
	}
	ok := false
	o := &fitCorpusOwner{budget: b, complete: true}
	defer func() {
		if !ok {
			o.close()
		}
	}()
	if err = b.checkAllocation(2965504); err != nil {
		return nil, err
	}
	o.capture, err = newPrivateCaptureWithResources(0, probe, allocate)
	if err != nil {
		return nil, err
	}
	if err = b.checkAllocation(65536); err != nil {
		return nil, err
	}
	o.wire.b, err = wire(65536)
	if err != nil {
		return nil, err
	}
	o.writer = protocolWriter{w: &o.wire, limit: clientArenaBytes}
	if err = b.checkAllocation(65536); err != nil {
		return nil, err
	}
	o.reader, err = reader(&o.input, [16]byte{}, clientArenaBytes)
	if err != nil {
		return nil, err
	}
	ok = true
	return o, nil
}

func TestFitCorpusAdmissionReuseAndErasure(t *testing.T) {
	allocations := 0
	allocate := func(side uint16) (*privateCapture, error) { allocations++; return allocatePrivateCapture(side) }
	b := &memoryBudget{limit: (8 << 20) - 1, beforeAllocation: func(uint64) error { return nil }}
	if o, err := newFitCorpusOwner(b, availableHostMemory, allocate); o != nil || reasonOf(err) != ReasonLimit || allocations != 0 || b.used != 0 {
		t.Fatal("one-byte corpus deficit reached allocation")
	}
	b.limit = controllerArenaBytes
	if o, err := newFitCorpusOwner(b, func() (uint64, error) { return 0, fail(ReasonUnsupported) }, allocate); o != nil || reasonOf(err) != ReasonUnsupported || allocations != 0 || b.used != 0 {
		t.Fatal("unsupported corpus host reached allocation")
	}
	if o, err := newFitCorpusOwner(b, func() (uint64, error) { return (8 << 20) - 1, nil }, allocate); o != nil || reasonOf(err) != ReasonLimit || allocations != 0 || b.used != 0 {
		t.Fatal("one-byte physical deficit reached allocation")
	}
	b.beforeAllocation = (&hostCapacity{}).checkGrowth
	o, err := newFitCorpusOwner(b, availableHostMemory, allocate)
	if err != nil {
		t.Fatal("admitted reusable corpus unavailable")
	}
	defer o.close()
	p := o.capture
	messages, setups, seals, requests, packet := p.truth.messages[:cap(p.truth.messages)], p.truth.setups[:cap(p.truth.setups)], p.truth.seals[:cap(p.truth.seals)], p.truth.requests[:cap(p.truth.requests)], p.truth.clientPacket
	protected, wire, decoder := p.truth.arena.buffer.Bytes(), o.wire.b, o.reader.scratch.Bytes()
	for side := range 16 {
		messages[len(messages)-1].sent = true
		setups[len(setups)-1].side = 99
		seals[len(seals)-1].real = true
		requests[len(requests)-1].success = true
		packet[len(packet)-1] = 1
		protected[len(protected)-1] = 1
		wire[len(wire)-1] = 1
		decoder[len(decoder)-1] = 1
		if o.reset(uint16(side), [3]uint8{0, 1, 4}) != nil || o.capture != p || &p.truth.messages[:cap(p.truth.messages)][0] != &messages[0] || &o.wire.b[0] != &wire[0] || allocations != 1 {
			t.Fatal("corpus reset allocated or changed prepaid backing")
		}
		if messages[len(messages)-1] != (actualMessage{}) || setups[len(setups)-1] != (actualSetup{}) || seals[len(seals)-1] != (actualSeal{}) || requests[len(requests)-1] != (actualRequest{}) || packet[len(packet)-1] != 0 || protected[len(protected)-1] != 0 || wire[len(wire)-1] != 0 || decoder[len(decoder)-1] != 0 {
			t.Fatal("corpus reset retained an unused backing tail")
		}
	}
	o.borrowed = true
	if o.reset(0, [3]uint8{}) == nil {
		t.Fatal("borrowed corpus reset succeeded")
	}
	o.borrowed = false
	o.complete = false
	if o.reset(0, [3]uint8{}) == nil {
		t.Fatal("incomplete corpus reset succeeded")
	}
	o.complete = true
	p.dummy[[32]byte{1}] = true
	if o.reset(0, [3]uint8{}) == nil {
		t.Fatal("pending dummy callback reset succeeded")
	}
	clear(p.dummy)
	retained := retainFitCorpusBackings(o)
	retained.poisonUnused()
	retained.endProtectedBorrows()
	o.close()
	retained.assertClosed(t)
	if !o.closed || o.capture != nil || o.reader != nil || o.wire.b != nil || o.budget != nil || o.input.Len() != 0 {
		t.Fatal("final corpus close retained owned controls")
	}
	for _, x := range wire {
		if x != 0 {
			t.Fatal("corpus close retained wire bytes")
		}
	}
	if b.used != 0 || o.reset(0, [3]uint8{}) == nil {
		t.Fatal("closed corpus retained a lease or resumed")
	}
}

func (o *fitCorpusOwner) reset(side uint16, route [3]uint8) error {
	if o == nil || o.closed || o.borrowed || !o.complete || o.capture == nil {
		return fail(ReasonContract)
	}
	p := o.capture
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) != 0 || len(p.dummy) != 0 {
		return fail(ReasonContract)
	}
	clear(p.keys)
	clear(p.dummy)
	clear(p.truth.messages[:cap(p.truth.messages)])
	clear(p.truth.setups[:cap(p.truth.setups)])
	clear(p.truth.seals[:cap(p.truth.seals)])
	clear(p.truth.requests[:cap(p.truth.requests)])
	clear(p.truth.clientPacket[:cap(p.truth.clientPacket)])
	p.truth.messages = p.truth.messages[:0]
	p.truth.setups = p.truth.setups[:0]
	p.truth.seals = p.truth.seals[:0]
	p.truth.requests = p.truth.requests[:0]
	p.truth.capacity = clientTruthCapacity{}
	a := p.truth.arena
	if a == nil || a.buffer == nil || !p.truth.client {
		return fail(ReasonContract)
	}
	clear(a.buffer.Bytes())
	clear(a.free[:cap(a.free)])
	a.free = a.free[:0]
	a.used, a.live, a.high = 0, 0, 0
	p.side, p.route, p.generation, p.completeGeneration, p.nextSetupHop, p.err, p.frozen = side, route, 0, 0, 255, ReasonNone, false
	clear(o.wire.b)
	o.wire.used = 0
	o.input.Reset(nil)
	clear(o.reader.scratch.Bytes())
	o.reader.sequence, o.reader.frames, o.reader.bytes = 0, 0, 0
	o.writer.sequence, o.writer.frames, o.writer.bytes = 0, 0, 0
	return nil
}

func (o *fitCorpusOwner) transfer(t *privateTruth) error {
	if o == nil || o.closed || o.borrowed || !o.complete {
		return fail(ReasonContract)
	}
	size, err := truthStreamSize(o.capture.truth)
	if err != nil || size.bytes > 13970 || size.frames > 13 {
		return fail(ReasonLimit)
	}
	o.borrowed, o.complete = true, false
	defer func() { o.borrowed = false }()
	o.capture.frozen = true
	if err = sendTruth(&childIO{truth: &o.writer}, &o.capture.truth); err != nil {
		return err
	}
	if uint64(o.wire.used) != size.bytes || o.writer.frames != size.frames {
		return fail(ReasonContract)
	}
	o.input.Reset(o.wire.b[:o.wire.used])
	for {
		op, r, e := o.reader.next()
		if e == io.EOF {
			break
		}
		if e != nil || op != opTruth {
			return fail(ReasonIPC)
		}
		if e = receiveFitCorpusTruth(r, t); e != nil {
			return e
		}
	}
	if o.reader.frames != size.frames || o.reader.bytes != size.bytes {
		return fail(ReasonContract)
	}
	o.complete = true
	return nil
}

func (o *fitCorpusOwner) close() {
	if o == nil || o.closed {
		return
	}
	o.closed = true
	if o.capture != nil {
		o.capture.close()
		o.capture = nil
	}
	if o.reader != nil {
		o.reader.close()
		o.reader = nil
	}
	clear(o.wire.b[:cap(o.wire.b)])
	o.wire.b = nil
	o.wire.used = 0
	o.input.Reset(nil)
	if o.budget != nil {
		o.budget.release(8 << 20)
		o.budget = nil
	}
}

type fitCorpusBackings struct {
	capture                                *privateCapture
	messages                               []actualMessage
	setups                                 []actualSetup
	seals                                  []actualSeal
	requests                               []actualRequest
	packet, wire, arenaBytes, decoderBytes []byte
	free                                   []freeSpan
	arenaBuffer, decoderBuffer             *secmem.Buffer
	reader                                 *protocolReader
}

func retainFitCorpusBackings(o *fitCorpusOwner) fitCorpusBackings {
	s := fitCorpusBackings{capture: o.capture, wire: o.wire.b[:cap(o.wire.b)], reader: o.reader}
	if o.capture != nil {
		s.retainCapture(o.capture)
	}
	if o.reader != nil {
		s.decoderBuffer = o.reader.scratch
		s.decoderBytes = s.decoderBuffer.Bytes()
	}
	return s
}

func (s *fitCorpusBackings) retainCapture(p *privateCapture) {
	s.capture = p
	s.messages = p.truth.messages[:cap(p.truth.messages)]
	s.setups = p.truth.setups[:cap(p.truth.setups)]
	s.seals = p.truth.seals[:cap(p.truth.seals)]
	s.requests = p.truth.requests[:cap(p.truth.requests)]
	s.packet = p.truth.clientPacket[:cap(p.truth.clientPacket)]
	s.arenaBuffer = p.truth.arena.buffer
	s.arenaBytes = s.arenaBuffer.Bytes()
	s.free = p.truth.arena.free[:cap(p.truth.arena.free)]
}

func (s *fitCorpusBackings) poisonUnused() {
	if len(s.messages) > 0 {
		s.messages[len(s.messages)-1] = actualMessage{side: 99, body: arenaRef{7, 11}, sent: true, replied: true}
	}
	if len(s.setups) > 0 {
		s.setups[len(s.setups)-1] = actualSetup{side: 99, hop: 2, circuit: 77, roster: 4}
	}
	if len(s.seals) > 0 {
		s.seals[len(s.seals)-1] = actualSeal{side: 99, generation: 77, record: arenaRef{7, 11}, real: true}
	}
	if len(s.requests) > 0 {
		s.requests[len(s.requests)-1] = actualRequest{side: 99, generation: 77, tag: 13, record: arenaRef{7, 11}, eligibility: 2, success: true}
	}
	for _, b := range [][]byte{s.packet, s.wire, s.arenaBytes, s.decoderBytes} {
		if len(b) > 0 {
			b[len(b)-1] = 0xa5
		}
	}
	if len(s.free) > 0 {
		s.free[len(s.free)-1] = freeSpan{17, 19}
	}
}

func (s *fitCorpusBackings) endProtectedBorrows() { s.arenaBytes, s.decoderBytes = nil, nil }

func (s *fitCorpusBackings) assertClosed(t *testing.T) {
	t.Helper()
	for _, v := range s.messages {
		if v != (actualMessage{}) {
			t.Fatal("corpus close retained message capacity")
		}
	}
	for _, v := range s.setups {
		if v != (actualSetup{}) {
			t.Fatal("corpus close retained setup capacity")
		}
	}
	for _, v := range s.seals {
		if v != (actualSeal{}) {
			t.Fatal("corpus close retained seal capacity")
		}
	}
	for _, v := range s.requests {
		if v != (actualRequest{}) {
			t.Fatal("corpus close retained request capacity")
		}
	}
	for _, b := range [][]byte{s.packet, s.wire} {
		for _, v := range b {
			if v != 0 {
				t.Fatal("corpus close retained packet or wire capacity")
			}
		}
	}
	for _, v := range s.free {
		if v != (freeSpan{}) {
			t.Fatal("corpus close retained free-span capacity")
		}
	}
	// released mappings are inaccessible; zero-before-unmap is the real secmem.Release contract
	for _, buffer := range []*secmem.Buffer{s.arenaBuffer, s.decoderBuffer} {
		if buffer != nil && (buffer.Len() != 0 || buffer.Bytes() != nil || buffer.Locked()) {
			t.Fatal("corpus close retained a protected mapping")
		}
	}
	if s.reader != nil && s.reader.scratch != nil {
		t.Fatal("corpus close retained decoder control ownership")
	}
	if s.capture != nil {
		p := s.capture
		if p.truth.arena != nil || p.truth.messages != nil || p.truth.setups != nil || p.truth.seals != nil || p.truth.requests != nil || p.truth.clientPacket != nil || p.truth.client {
			t.Fatal("corpus close retained capture control ownership")
		}
	}
}

func TestFitCorpusConstructorAndTransferErrorClose(t *testing.T) {
	for _, stage := range []string{"capture", "wire", "reader", "transfer"} {
		t.Run(stage, func(t *testing.T) {
			b := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: (&hostCapacity{}).checkGrowth}
			retained := fitCorpusBackings{}
			allocate := func(side uint16) (*privateCapture, error) {
				p, e := allocatePrivateCapture(side)
				if e != nil {
					return p, e
				}
				retained.retainCapture(p)
				retained.poisonUnused()
				if stage == "capture" {
					retained.endProtectedBorrows()
					return p, fail(ReasonLimit)
				}
				return p, nil
			}
			wire := func(n int) ([]byte, error) {
				v, e := allocateFitCorpusWire(n)
				if e != nil {
					return v, e
				}
				retained.wire = v[:cap(v)]
				retained.poisonUnused()
				if stage == "wire" {
					retained.endProtectedBorrows()
					return v, fail(ReasonLimit)
				}
				return v, nil
			}
			reader := func(input io.Reader, token [16]byte, limit uint64) (*protocolReader, error) {
				r, e := newProtocolReader(input, token, limit)
				if e != nil {
					return r, e
				}
				retained.reader = r
				retained.decoderBuffer = r.scratch
				retained.decoderBytes = r.scratch.Bytes()
				retained.poisonUnused()
				if stage == "reader" {
					retained.endProtectedBorrows()
					return r, fail(ReasonLimit)
				}
				return r, nil
			}
			o, err := newFitCorpusOwnerWithConstructors(b, availableHostMemory, allocate, wire, reader)
			if stage != "transfer" {
				retained.endProtectedBorrows()
				if o != nil || reasonOf(err) != ReasonLimit || b.used != 0 {
					t.Fatal("post-allocation constructor failure did not close its real owners")
				}
				retained.assertClosed(t)
				return
			}
			if err != nil {
				t.Fatal("real transfer-error corpus construction failed")
			}
			defer o.close()
			if o.reset(0, [3]uint8{0, 1, 4}) != nil {
				t.Fatal("real transfer-error corpus reset failed")
			}
			p := o.capture
			for _, hop := range []uint8{2, 1, 0} {
				replaySetup(t, p, true, hop, 100+uint64(hop))
			}
			body := fitCertificateBody(1, 0, 0)
			replaySource(t, p, true, body[:], true)
			clear(body[:])
			record := fitCertificateRecord(1, 0, 0)
			replaySeal(t, p, true, record[:], true, 0)
			replayTypedRequest(t, p, true, 1, 0, record[:], 2, true)
			clear(record[:])
			retained = retainFitCorpusBackings(o)
			retained.poisonUnused()
			retained.endProtectedBorrows()
			o.writer.limit = 0
			if reasonOf(o.transfer(&privateTruth{})) != ReasonLimit || o.complete || o.borrowed || o.reset(1, [3]uint8{0, 1, 4}) == nil {
				t.Fatal("real failed transfer admitted a reset or lost its error state")
			}
			o.close()
			retained.assertClosed(t)
			if b.used != 0 {
				t.Fatal("failed transfer retained or double-released its corpus lease")
			}
		})
	}
}

func TestFitCorpusPreallocatedAggregateAdmission(t *testing.T) {
	logical, physical, err := fitCorpusAggregateHistory()
	if err != nil || logical != 57216 || physical > 716800 {
		t.Fatal("single-allocation aggregate physical history exceeds its retained allowance")
	}
	calls := 0
	allocate := func(n int) []mailboxObservation { calls++; return allocateFitCorpusSlice[mailboxObservation](n) }
	bytes := uint64(256) * uint64(unsafe.Sizeof(mailboxObservation{}))
	b := &memoryBudget{limit: bytes - 1, beforeAllocation: func(uint64) error { return nil }}
	if v, e := preallocateFitCorpusWithAllocator(256, b, allocate); v != nil || reasonOf(e) != ReasonLimit || calls != 0 || b.used != 0 {
		t.Fatal("aggregate one-byte managed deficit reached make")
	}
	b.limit = controllerArenaBytes
	b.beforeAllocation = func(uint64) error { return fail(ReasonUnsupported) }
	if v, e := preallocateFitCorpusWithAllocator(256, b, allocate); v != nil || reasonOf(e) != ReasonUnsupported || calls != 0 || b.used != 0 {
		t.Fatal("aggregate current host refusal reached make")
	}
	b.beforeAllocation = (&hostCapacity{}).checkGrowth
	v, err := preallocateFitCorpusWithAllocator(256, b, allocate)
	if err != nil || len(v) != 0 || cap(v) != 256 || calls != 1 || b.used != bytes {
		t.Fatal("aggregate exact prepayment did not make one bounded empty slice")
	}
	clear(v[:cap(v)])
	releaseCapacity(v, b)
	if b.used != 0 {
		t.Fatal("aggregate prepayment did not end once")
	}
	for _, coordinate := range canonicalCoordinates(Mailbox) {
		if coordinate.Population != "classifier" {
			continue
		}
		request, record, closeCorpus := fitCertificateCorpus(t, coordinate, false, b, frozenTraining{})
		if len(request) != 256 || len(record) != 208 {
			t.Fatal("preallocated real16-side corpus changed complete populations")
		}
		closeCorpus()
		if b.used != 0 {
			t.Fatal("real preallocated corpus retained a paid backing")
		}
		return
	}
	t.Fatal("canonical preallocation regression coordinate is absent")
}
