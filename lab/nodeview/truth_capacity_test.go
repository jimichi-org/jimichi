package nodeview

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/mailbox"
)

func capacityTestCapture(t *testing.T) *privateCapture {
	t.Helper()
	b, e := secmem.New(clientArenaBytes)
	if e != nil {
		t.Fatal(e)
	}
	caps := clientTruthArrayCaps()
	p := &privateCapture{nextSetupHop: 255, keys: make(map[*secmem.Buffer]keyTag), dummy: make(map[[32]byte]bool), truth: privateTruth{arena: &lockedArena{buffer: b}, client: true, messages: make([]actualMessage, 0, caps[0]), setups: make([]actualSetup, 0, caps[1]), seals: make([]actualSeal, 0, caps[2]), requests: make([]actualRequest, 0, caps[3]), clientPacket: make([]byte, clientPacketBytes)}}
	t.Cleanup(p.close)
	return p
}

func TestClientTruthHostDenialPrecedesAllCaptureAllocation(t *testing.T) {
	startup, e := clientTruthStartupBytes()
	if e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name      string
		available uint64
		failure   error
		reason    Reason
	}{
		{"insufficient", startup - 1, nil, ReasonLimit},
		{"unsupported", 0, ErrUnsupported, ReasonUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			probes, allocations := 0, 0
			p, e := newPrivateCaptureWithResources(3, func() (uint64, error) {
				probes++
				return test.available, test.failure
			}, func(side uint16) (*privateCapture, error) {
				allocations++
				return allocatePrivateCapture(side)
			})
			if p != nil {
				defer p.close()
			}
			if probes != 1 || allocations != 0 || p != nil || reasonOf(e) != test.reason || test.failure != nil && e != test.failure {
				t.Fatal("host denial entered newArena/scalar/packet allocation or published capture ownership")
			}
		})
	}
}

func TestClientTruthCapacityManualCompositeAnswers(t *testing.T) {
	for _, answer := range []struct{ messages, setups, pairs, bytes, frames uint64 }{
		{6355, 0, 0, 1048575, 6355}, {260, 3, 882, 751743, 277}, {260, 3, 1251, 1048248, 283}, {260, 3, 1252, 1049051, 283},
		{4, 189, 1241, 1006348, 213}, {130, 189, 1241, 1027138, 339}, {259, 189, 1241, 1048423, 468}, {260, 189, 1241, 1048588, 469}, {2, 3, 129, 104184, 9},
	} {
		c := clientTruthCapacity{messages: answer.messages, setups: answer.setups, seals: answer.pairs, requests: answer.pairs, recordBytes: 392 * answer.pairs}
		s, e := clientTruthSize(c)
		if e != nil || s.bytes != answer.bytes || s.frames != answer.frames {
			t.Fatal("manual complete-stream answer changed")
		}
	}
	for _, answer := range []struct{ count, seals, requests uint64 }{{127, 50706, 51341}, {128, 51105, 51745}, {129, 51537, 52182}} {
		s, e := clientTruthSize(clientTruthCapacity{seals: answer.count})
		q, qe := clientTruthSize(clientTruthCapacity{requests: answer.count, recordBytes: 392 * answer.count})
		if e != nil || qe != nil || s.bytes != answer.seals || q.bytes != answer.requests {
			t.Fatal("independent final batch rounding changed")
		}
	}
}

func TestClientTruthCapacityTransactionalLimitsAndWidths(t *testing.T) {
	c := clientTruthCapacity{}
	for range 6355 {
		var e error
		c, e = nextClientTruth(c, 1, 0)
		if e != nil {
			t.Fatal("valid message prefix refused")
		}
	}
	before := c
	if next, e := nextClientTruth(c, 1, 0); reasonOf(e) != ReasonLimit || next != before {
		t.Fatal("stream refusal changed its prior ledger")
	}
	c = clientTruthCapacity{}
	for range 8192 {
		var e error
		c, e = nextClientTruth(c, 2, 0)
		if e != nil {
			t.Fatal("valid 8192-frame prefix refused")
		}
	}
	if next, e := nextClientTruth(c, 2, 0); reasonOf(e) != ReasonLimit || next != c {
		t.Fatal("8193rd physical packet admitted")
	}
	for _, row := range [][2]int{{0, 0}, {5, 0}, {1, 392}, {4, 1}, {4, 391}, {4, 393}, {4, -1}} {
		if _, e := nextClientTruth(clientTruthCapacity{}, uint8(row[0]), row[1]); reasonOf(e) != ReasonContract {
			t.Fatal("malformed width admitted")
		}
	}
	for _, c := range []clientTruthCapacity{{messages: math.MaxUint64}, {setups: math.MaxUint64}, {seals: math.MaxUint64}, {requests: math.MaxUint64}, {recordBytes: math.MaxUint64}, {requests: 1, recordBytes: 1}} {
		if _, e := nextClientTruth(c, 1, 0); reasonOf(e) != ReasonContract {
			t.Fatal("invalid prior counter wrapped")
		}
	}
	if _, e := roundClientBacking(math.MaxUint64); reasonOf(e) != ReasonLimit {
		t.Fatal("page rounding wrapped")
	}
}

func TestClientTruthPinnedOffsetsAndPhysicalBacking(t *testing.T) {
	if caps := clientTruthArrayCaps(); caps != [4]int{6355, 8192, 2628, 32768} {
		t.Fatal("safe independent maxima changed")
	}
	if n, e := clientTruthBackingBytes(); e != nil || n != 1875968 || 16*n != 30015488 || 32*n != 60030976 {
		t.Fatal("participant physical envelope changed")
	}
	var truth privateTruth
	var capture privateCapture
	var plan workloadPlan
	for _, pair := range [][2]uintptr{
		{unsafe.Offsetof(truth.budget), 0}, {unsafe.Offsetof(truth.arena), 8}, {unsafe.Offsetof(truth.setups), 16}, {unsafe.Offsetof(truth.messages), 40}, {unsafe.Offsetof(truth.seals), 64}, {unsafe.Offsetof(truth.requests), 88}, {unsafe.Offsetof(truth.fragments), 112}, {unsafe.Offsetof(truth.ownership), 136}, {unsafe.Offsetof(truth.capacity), 160}, {unsafe.Offsetof(truth.client), 216}, {unsafe.Offsetof(truth.clientPacket), 224},
		{unsafe.Offsetof(capture.mu), 0}, {unsafe.Offsetof(capture.truth), 8}, {unsafe.Offsetof(capture.keys), 256}, {unsafe.Offsetof(capture.dummy), 264}, {unsafe.Offsetof(capture.side), 272}, {unsafe.Offsetof(capture.generation), 280}, {unsafe.Offsetof(capture.completeGeneration), 284}, {unsafe.Offsetof(capture.nextSetupHop), 288}, {unsafe.Offsetof(capture.err), 296}, {unsafe.Offsetof(capture.frozen), 312}, {unsafe.Offsetof(plan.bodies), 80}, {unsafe.Offsetof(plan.sourceLimit), 104},
	} {
		if pair[0] != pair[1] {
			t.Fatal("pinned field layout changed")
		}
	}
	if unsafe.Sizeof(truth) != 248 || unsafe.Sizeof(capture) != 320 || unsafe.Sizeof(plan) != 112 || unsafe.Sizeof(ReasonNone) != 16 {
		t.Fatal("capture/control size drift")
	}
	widths := [4]uint64{32, 24, 32, 40}
	physical := [4]uint64{204800, 196608, 90112, 1310720}
	for i, n := range clientTruthArrayCaps() {
		if got, e := roundClientBacking(uint64(n) * widths[i]); e != nil || got != physical[i] {
			t.Fatal("noscan backing was not independently page rounded")
		}
	}
}

type refusedEntropy struct{ calls int }

func (r *refusedEntropy) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("unexpected entropy")
}

func TestClientTruthRefusalPrecedesEntropyCopyAndGrammarCommit(t *testing.T) {
	p := capacityTestCapture(t)
	p.truth.messages = p.truth.messages[:cap(p.truth.messages)]
	p.truth.capacity = clientTruthCapacity{messages: 6355, wireBytes: 1048575, frames: 6355}
	before := p.truth.capacity
	reader := &refusedEntropy{}
	previous := rand.Reader
	rand.Reader = reader
	defer func() { rand.Reader = previous }()
	if _, e := randomMessage(&p.truth, 0); reasonOf(e) != ReasonLimit || reader.calls != 0 || p.truth.capacity != before || p.truth.arena.used != 0 {
		t.Fatal("refused random body read entropy or changed its prefix")
	}
	p.truth.messages = p.truth.messages[:0]
	p.truth.capacity = clientTruthCapacity{setups: 8192, wireBytes: 368640, frames: 8192}
	p.truth.setups = p.truth.setups[:cap(p.truth.setups)]
	appendSetupSeal(p, 2, 42)
	if p.err != ReasonLimit || p.generation != 0 || p.nextSetupHop != 255 || p.completeGeneration != 0 || len(p.truth.setups) != 8192 {
		t.Fatal("refused setup advanced grammar or a scalar length")
	}
	// a later callback consumes pending bookkeeping while preserving the first failed prefix
	tag := keyTag{purpose: "e2e/step/key", context: [32]byte{9}}
	p.dummy[tag.context] = true
	p.afterSeal(tag, nil, nil, nil)
	if len(p.dummy) != 0 || p.err != ReasonLimit {
		t.Fatal("sticky failure leaked pending purpose metadata or changed priority")
	}
}

func TestClientTruthFixedAliasAndFullOwnerWipe(t *testing.T) {
	p := capacityTestCapture(t)
	ref, ok := p.truth.arena.copy(bytes.Repeat([]byte{7}, 128))
	if !ok {
		t.Fatal("declared source setup")
	}
	used := p.truth.arena.used
	i, e := p.sourceMessage(ref)
	if e != nil || i != 0 || p.truth.arena.used != used || p.truth.capacity.messages != 1 || p.truth.capacity.wireBytes != 165 {
		t.Fatal("fixed source copied its declared body twice")
	}
	messages := p.truth.messages[:cap(p.truth.messages)]
	setups := p.truth.setups[:cap(p.truth.setups)]
	seals := p.truth.seals[:cap(p.truth.seals)]
	requests := p.truth.requests[:cap(p.truth.requests)]
	packet := p.truth.clientPacket[:cap(p.truth.clientPacket)]
	messages[len(messages)-1].sent = true
	setups[len(setups)-1].circuit = 7
	seals[len(seals)-1].real = true
	requests[len(requests)-1].tag = 9
	packet[len(packet)-1] = 8
	budget := &memoryBudget{used: 123, limit: 123}
	p.truth.budget = budget
	p.close()
	if budget.used != 123 || p.truth.client || p.truth.capacity != (clientTruthCapacity{}) || p.truth.clientPacket != nil || !reflect.DeepEqual(messages, make([]actualMessage, len(messages))) || !reflect.DeepEqual(setups, make([]actualSetup, len(setups))) || !reflect.DeepEqual(seals, make([]actualSeal, len(seals))) || !reflect.DeepEqual(requests, make([]actualRequest, len(requests))) || !bytes.Equal(packet, make([]byte, len(packet))) {
		t.Fatal("full prepaid owner wipe released a parent loan or retained scalar capacity")
	}
}

type capturePrefixSnapshot struct {
	capacity             clientTruthCapacity
	messages             []actualMessage
	setups               []actualSetup
	arena                []byte
	lengths, capacities  [4]int
	used, live, high     int
	generation, complete uint32
	nextHop              uint8
}

func capturePrefix(p *privateCapture) capturePrefixSnapshot {
	return capturePrefixSnapshot{
		capacity:   p.truth.capacity,
		messages:   append([]actualMessage(nil), p.truth.messages[:cap(p.truth.messages)]...),
		setups:     append([]actualSetup(nil), p.truth.setups[:cap(p.truth.setups)]...),
		arena:      bytes.Clone(p.truth.arena.buffer.Bytes()),
		lengths:    [4]int{len(p.truth.messages), len(p.truth.setups), len(p.truth.seals), len(p.truth.requests)},
		capacities: [4]int{cap(p.truth.messages), cap(p.truth.setups), cap(p.truth.seals), cap(p.truth.requests)},
		used:       p.truth.arena.used, live: p.truth.arena.live, high: p.truth.arena.high,
		generation: p.generation, complete: p.completeGeneration, nextHop: p.nextSetupHop,
	}
}

func assertCapturePrefix(t *testing.T, p *privateCapture, before capturePrefixSnapshot) {
	t.Helper()
	if p.truth.capacity != before.capacity || before.lengths != ([4]int{len(p.truth.messages), len(p.truth.setups), len(p.truth.seals), len(p.truth.requests)}) || before.capacities != ([4]int{cap(p.truth.messages), cap(p.truth.setups), cap(p.truth.seals), cap(p.truth.requests)}) || p.truth.arena.used != before.used || p.truth.arena.live != before.live || p.truth.arena.high != before.high || p.generation != before.generation || p.completeGeneration != before.complete || p.nextSetupHop != before.nextHop || !bytes.Equal(p.truth.arena.buffer.Bytes(), before.arena) || !slices.Equal(p.truth.messages[:cap(p.truth.messages)], before.messages) || !slices.Equal(p.truth.setups[:cap(p.truth.setups)], before.setups) {
		t.Fatal("refused producer changed its body, extent, scalar capacity, retained prefix or grammar")
	}
}

func blockMessageResource(p *privateCapture, resource string) {
	switch resource {
	case "stream":
		p.truth.messages = p.truth.messages[:6354]
		p.truth.setups = p.truth.setups[:3]
		p.truth.capacity = clientTruthCapacity{messages: 6354, setups: 3, wireBytes: 1048545, frames: 6357}
	case "frames":
		p.truth.setups = p.truth.setups[:8192]
		p.truth.capacity = clientTruthCapacity{setups: 8192, wireBytes: 368640, frames: 8192}
	case "scalar":
		p.truth.messages = p.truth.messages[:0:0]
	case "arena":
		p.truth.arena.used = clientArenaBytes - 127
	}
}

func TestClientTruthFixedSourceOwnResourceRefusal(t *testing.T) {
	for _, resource := range []string{"stream", "frames", "scalar"} {
		t.Run(resource, func(t *testing.T) {
			p := capacityTestCapture(t)
			storage := p.truth.messages
			defer func() { p.truth.messages = storage[:len(p.truth.messages)] }()
			ref, ok := p.truth.arena.copy(bytes.Repeat([]byte{7}, 128))
			if !ok {
				t.Fatal("declared fixed body setup")
			}
			blockMessageResource(p, resource)
			before := capturePrefix(p)
			if i, e := p.sourceMessage(ref); i != -1 || reasonOf(e) != ReasonLimit || p.err != ReasonLimit {
				t.Fatal("fixed source did not refuse its own first unavailable resource")
			}
			assertCapturePrefix(t, p, before)
			p.truth.messages = storage[:0]
			p.truth.setups = p.truth.setups[:0]
			p.truth.capacity = clientTruthCapacity{}
			after := capturePrefix(p)
			if i, e := p.sourceMessage(ref); i != -1 || reasonOf(e) != ReasonLimit || p.err != ReasonLimit {
				t.Fatal("fixed source lost its sticky resource failure")
			}
			assertCapturePrefix(t, p, after)
		})
	}
}

func TestClientTruthFixedSourceUsesDeclaredAliasAtFullArena(t *testing.T) {
	p := capacityTestCapture(t)
	ref, ok := p.truth.arena.copy(bytes.Repeat([]byte{7}, 128))
	if !ok {
		t.Fatal("declared fixed body setup")
	}
	p.truth.arena.used = clientArenaBytes
	before := bytes.Clone(p.truth.arena.buffer.Bytes())
	if i, e := p.sourceMessage(ref); e != nil || i != 0 || p.truth.arena.used != clientArenaBytes || p.truth.capacity.messages != 1 || p.truth.capacity.wireBytes != 165 || !bytes.Equal(before, p.truth.arena.buffer.Bytes()) {
		t.Fatal("fixed alias required a nonexistent second protected copy")
	}
}

type capacityCircuit struct {
	conversation.Circuit
	calls int
	err   error
	body  []byte
}

func (c *capacityCircuit) Send(body []byte) error { c.calls++; c.body = body; return c.err }

func TestClientTruthRequestDuplicateAndCapacityPrecedeCopy(t *testing.T) {
	for _, mode := range []string{"duplicate", "scalar", "arena", "sticky", "valid"} {
		t.Run(mode, func(t *testing.T) {
			p := capacityTestCapture(t)
			request := mailbox.Request{Tag: 9, Put: [16]byte{1}, Record: [392]byte{3}}
			body := request.Bytes()
			defer clear(body)
			delegate := &capacityCircuit{}
			conv := &conversation.Conversation{}
			gate := make(chan struct{})
			close(gate)
			observed := observedCircuit{Circuit: delegate, private: p, gate: gate, conversation: &conv, generation: 1}
			want := ReasonLimit
			switch mode {
			case "duplicate":
				p.truth.requests = append(p.truth.requests, actualRequest{generation: 1, tag: 9})
				p.truth.capacity = clientTruthCapacity{requests: 1, wireBytes: 45, frames: 1}
				want = ReasonLabel
			case "scalar":
				p.truth.requests = p.truth.requests[:0:0]
			case "arena":
				p.truth.arena.used = clientArenaBytes - 391
			case "sticky":
				p.err = ReasonContract
				want = ReasonContract
			case "valid":
				want = ReasonNone
			}
			before, count, ledger := p.truth.arena.used, len(p.truth.requests), p.truth.capacity
			if e := observed.Send(body); e != nil || delegate.calls != 1 || &delegate.body[0] != &body[0] {
				t.Fatal("observer changed delegated Send return or borrowed argument")
			}
			if p.err != want {
				t.Fatal("observer refusal lost its precise first cause")
			}
			if mode != "valid" {
				if p.truth.arena.used != before || len(p.truth.requests) != count || p.truth.capacity != ledger {
					t.Fatal("refused request copied payload or advanced scalar prefix")
				}
			} else if p.truth.arena.used != before+392 || len(p.truth.requests) != count+1 || p.truth.capacity.wireBytes != 437 || !bytes.Equal(p.truth.arena.bytes(p.truth.requests[0].record), request.Record[:]) {
				t.Fatal("valid request lost its separate sticky record copy")
			}
		})
	}
}

func TestClientTruthSealRefusalPreservesDelegatedAliasing(t *testing.T) {
	p := capacityTestCapture(t)
	p.truth.seals = p.truth.seals[:0:0]
	tag := keyTag{purpose: "e2e/step/key", context: [32]byte{4}}
	base := &delegationAEAD{}
	observed := &observedAEAD{AEAD: base, p: &observedProvider{private: p}, tag: tag}
	backing := make([]byte, 21, 392)
	backing[0] = 3
	plain := make([]byte, 371)
	out := observed.Seal(backing, nil, plain, []byte{3, 0, 0, 0, 0})
	if len(out) != 392 || &out[0] != &backing[0] || base.seal != 1 || p.err != ReasonLimit || len(p.truth.seals) != 0 || p.truth.arena.used != 0 || len(p.dummy) != 0 {
		t.Fatal("capacity refusal changed successful Seal or retained a partial observation")
	}
	if _, e := p.sourceMessage(arenaRef{}); reasonOf(e) != ReasonLimit {
		t.Fatal("next source work did not return the sticky observer failure")
	}
}
