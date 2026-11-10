package nodeview

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"

	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/wire"
)

type actualSetup struct {
	side    uint16
	hop     uint8
	circuit uint64
	roster  uint8
}
type actualMessage struct {
	side          uint16
	body          arenaRef
	sent, replied bool
}
type actualSeal struct {
	side       uint16
	generation uint32
	record     arenaRef
	real       bool
}
type actualRequest struct {
	side        uint16
	generation  uint32
	tag         uint16
	record      arenaRef
	eligibility uint8
	success     bool
}
type privateTruth struct {
	budget *memoryBudget
	rawDenied
	arena        *lockedArena
	setups       []actualSetup
	messages     []actualMessage
	seals        []actualSeal
	requests     []actualRequest
	fragments    []contentFragment
	ownership    setupOwnershipIndex
	capacity     clientTruthCapacity
	client       bool
	clientPacket []byte
}

func (t *privateTruth) close() {
	if t.arena != nil {
		t.arena.close()
		t.arena = nil
	}
	t.wipeMetadata()
}

func (t *privateTruth) resolveMessageReceipts() uint64 {
	var unanswered uint64
	for i := range t.messages {
		message := &t.messages[i]
		if !message.sent {
			continue
		}
		for _, receipt := range t.messages {
			if receipt.replied && equalBytes(t.arena.bytes(message.body), t.arena.bytes(receipt.body)) {
				message.replied = true
			}
		}
		if !message.replied {
			unanswered++
		}
	}
	return unanswered
}

type privateCapture struct {
	rawDenied
	mu                 sync.Mutex
	truth              privateTruth
	keys               map[*secmem.Buffer]keyTag
	dummy              map[[32]byte]bool
	side               uint16
	route              [3]uint8
	generation         uint32
	completeGeneration uint32
	nextSetupHop       uint8
	err                Reason
	frozen             bool
}

func newPrivateCapture(side uint16) (*privateCapture, error) {
	return newPrivateCaptureWithResources(side, availableHostMemory, allocatePrivateCapture)
}

func newPrivateCaptureWithResources(side uint16, probe func() (uint64, error), allocate func(uint16) (*privateCapture, error)) (*privateCapture, error) {
	if probe == nil || allocate == nil {
		return nil, fail(ReasonContract)
	}
	startup, e := clientTruthStartupBytes()
	if e != nil {
		return nil, e
	}
	available, e := probe()
	if e != nil {
		return nil, e
	}
	if startup > available {
		return nil, fail(ReasonLimit)
	}
	return allocate(side)
}

func allocatePrivateCapture(side uint16) (*privateCapture, error) {
	a, e := newArena(clientArenaBytes)
	if e != nil {
		return nil, e
	}
	caps := clientTruthArrayCaps()
	return &privateCapture{truth: privateTruth{arena: a, client: true, messages: make([]actualMessage, 0, caps[0]), setups: make([]actualSetup, 0, caps[1]), seals: make([]actualSeal, 0, caps[2]), requests: make([]actualRequest, 0, caps[3]), clientPacket: make([]byte, clientPacketBytes)}, keys: make(map[*secmem.Buffer]keyTag), dummy: make(map[[32]byte]bool), side: side, nextSetupHop: 255}, nil
}
func (p *privateCapture) derived(k *secmem.Buffer, tag keyTag) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != ReasonNone || p.frozen {
		return
	}
	if _, ok := p.keys[k]; ok {
		p.latch(ReasonContract)
		return
	}
	if len(p.keys) >= maxContexts {
		p.latch(ReasonLimit)
		return
	}
	p.keys[k] = tag
}
func (p *privateCapture) consumed(k *secmem.Buffer, tag keyTag) keyTag {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.keys[k]; ok {
		tag = t
		delete(p.keys, k)
	}
	return tag
}
func (p *privateCapture) beforeSeal(tag keyTag, nonce, plain, ad []byte) {
	if tag.purpose != "e2e/step/key" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(plain) != 371 || len(ad) != 5 || ad[0] != 3 || plain[0] > 1 {
		p.latch(ReasonLabel)
		return
	}
	if p.err != ReasonNone || p.frozen {
		return
	}
	if len(p.dummy) >= maxContexts {
		p.latch(ReasonLimit)
		return
	}
	if _, exists := p.dummy[tag.context]; exists {
		p.latch(ReasonContract)
		return
	}
	p.dummy[tag.context] = plain[0] == 1
}
func (p *privateCapture) afterSeal(tag keyTag, nonce, out, ad []byte) {
	if tag.purpose != "setup" && tag.purpose != "e2e/step/key" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if tag.purpose == "e2e/step/key" && (p.frozen || p.err != ReasonNone) {
		delete(p.dummy, tag.context)
	}
	if p.frozen || p.err != ReasonNone {
		return
	}
	switch tag.purpose {
	case "setup":
		id, count, dir, ok := decodeNonce(nonce)
		if !ok || count != 0 || dir != 0 || len(ad) != 3 || ad[0] != wire.Version || ad[1] != byte(wire.KindControl) || ad[2] >= 3 {
			p.latch(ReasonContract)
			return
		}
		hop := ad[2]
		generation, complete, nextHop := p.generation, p.completeGeneration, p.nextSetupHop
		if hop == 2 {
			if generation == ^uint32(0) {
				p.latch(ReasonLimit)
				return
			}
			generation++
			nextHop = 1
		} else {
			if generation == 0 || hop != nextHop {
				p.latch(ReasonContract)
				return
			}
			if hop == 1 {
				nextHop = 0
			} else {
				nextHop = 255
				complete = generation
			}
		}
		for _, s := range p.truth.setups {
			if s.circuit == id {
				p.latch(ReasonContract)
				return
			}
		}
		next, e := p.truth.nextClient(2, 0, 0)
		if e != nil {
			p.latch(reasonOf(e))
			return
		}
		p.truth.setups = append(p.truth.setups, actualSetup{p.side, hop, id, p.route[hop]})
		p.truth.capacity = next
		p.generation, p.completeGeneration, p.nextSetupHop = generation, complete, nextHop
	case "e2e/step/key":
		dummy, ok := p.dummy[tag.context]
		delete(p.dummy, tag.context)
		if !ok || len(out) != 392 || out[0] != 3 {
			p.latch(ReasonLabel)
			return
		}
		for _, s := range p.truth.seals {
			if bytes.Equal(p.truth.arena.bytes(s.record), out) {
				p.latch(ReasonLabel)
				return
			}
		}
		if len(p.truth.seals) >= maxTruthRecords {
			p.latch(ReasonLimit)
			return
		}
		next, e := p.truth.nextClient(3, 0, len(out))
		if e != nil {
			p.latch(reasonOf(e))
			return
		}
		r, ok := p.truth.arena.copy(out)
		if !ok {
			p.latch(ReasonLimit)
			return
		}
		p.truth.seals = append(p.truth.seals, actualSeal{p.side, p.generation, r, !dummy})
		p.truth.capacity = next
	}
}

func randomMessage(t *privateTruth, side uint16) (int, error) {
	var b [128]byte
	defer clear(b[:])
	next, e := t.nextClient(1, 0, len(b))
	if e != nil {
		return -1, e
	}
	if len(t.messages) >= maxMessages {
		return -1, fail(ReasonLimit)
	}
	for range 32 {
		if _, e := io.ReadFull(rand.Reader, b[:]); e != nil {
			return -1, fail(ReasonChild)
		}
		equal := true
		for _, v := range b[1:] {
			if v != b[0] {
				equal = false
				break
			}
		}
		if equal {
			continue
		}
		duplicate := false
		for _, m := range t.messages {
			if bytes.Equal(t.arena.bytes(m.body), b[:]) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(t.messages) >= maxMessages {
			return -1, fail(ReasonLimit)
		}
		r, ok := t.arena.copy(b[:])
		if !ok {
			return -1, fail(ReasonLimit)
		}
		t.messages = append(t.messages, actualMessage{side: side, body: r})
		t.capacity = next
		return len(t.messages) - 1, nil
	}
	return -1, fail(ReasonLabel)
}

type observedCircuit struct {
	conversation.Circuit
	private      *privateCapture
	gate         <-chan struct{}
	conversation **conversation.Conversation
	generation   uint32
}

func (o *observedCircuit) Send(payload []byte) error {
	select {
	case <-o.gate:
	}
	req, e := mailbox.ParseRequest(payload)
	if e != nil {
		return o.Circuit.Send(payload)
	}
	defer clear(req.Fetch[:])
	defer clear(req.Put[:])
	defer clear(req.Record[:])
	err := o.Circuit.Send(payload)
	st := (*o.conversation).Stats()
	elig := uint8(1)
	if st.State == e2e.StateEstablished || st.State == e2e.StateConfirmed {
		elig = 2
	} else if st.State == e2e.StateStale {
		elig = 3
	}
	p := o.private
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.frozen || p.err != ReasonNone {
		return err
	}
	for _, prior := range p.truth.requests {
		if prior.generation == o.generation && prior.tag == req.Tag {
			p.latch(ReasonLabel)
			return err
		}
	}
	if len(p.truth.requests) >= maxTruthRecords {
		p.latch(ReasonLimit)
		return err
	}
	bytes := 0
	if req.Puts() {
		bytes = len(req.Record)
	}
	next, e := p.truth.nextClient(4, bytes, bytes)
	if e != nil {
		p.latch(reasonOf(e))
		return err
	}
	var r arenaRef
	if req.Puts() {
		var ok bool
		r, ok = p.truth.arena.copy(req.Record[:])
		if !ok {
			p.latch(ReasonLimit)
			return err
		}
	}
	p.truth.requests = append(p.truth.requests, actualRequest{p.side, o.generation, req.Tag, r, elig, err == nil})
	p.truth.capacity = next
	return err
}

func matchRecordLabel(t *privateTruth, record []byte) (bool, bool) {
	count := 0
	real := false
	for _, s := range t.seals {
		if bytes.Equal(t.arena.bytes(s.record), record) {
			count++
			real = s.real
		}
	}
	return real, count == 1
}
