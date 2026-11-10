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
	arena     *lockedArena
	setups    []actualSetup
	messages  []actualMessage
	seals     []actualSeal
	requests  []actualRequest
	fragments []contentFragment
	ownership setupOwnershipIndex
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
	a, e := newArena(clientArenaBytes)
	if e != nil {
		return nil, e
	}
	return &privateCapture{truth: privateTruth{arena: a}, keys: make(map[*secmem.Buffer]keyTag), dummy: make(map[[32]byte]bool), side: side, nextSetupHop: 255}, nil
}
func (p *privateCapture) derived(k *secmem.Buffer, tag keyTag) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) >= maxContexts {
		p.err = ReasonLimit
		return
	}
	if _, ok := p.keys[k]; ok {
		p.err = ReasonContract
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
		p.err = ReasonLabel
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
	if p.frozen {
		return
	}
	switch tag.purpose {
	case "setup":
		id, count, dir, ok := decodeNonce(nonce)
		if !ok || count != 0 || dir != 0 || len(ad) != 3 || ad[0] != wire.Version || ad[1] != byte(wire.KindControl) || ad[2] >= 3 {
			p.err = ReasonContract
			return
		}
		hop := ad[2]
		if hop == 2 {
			p.generation++
			p.nextSetupHop = 1
			if p.generation == 0 {
				p.err = ReasonLimit
				return
			}
		} else {
			if p.generation == 0 || hop != p.nextSetupHop {
				p.err = ReasonContract
				return
			}
			if hop == 1 {
				p.nextSetupHop = 0
			} else {
				p.nextSetupHop = 255
				p.completeGeneration = p.generation
			}
		}
		for _, s := range p.truth.setups {
			if s.circuit == id {
				p.err = ReasonContract
				return
			}
		}
		p.truth.setups = append(p.truth.setups, actualSetup{p.side, hop, id, p.route[hop]})
	case "e2e/step/key":
		dummy, ok := p.dummy[tag.context]
		delete(p.dummy, tag.context)
		if !ok || len(out) != 392 || out[0] != 3 {
			p.err = ReasonLabel
			return
		}
		for _, s := range p.truth.seals {
			if bytes.Equal(p.truth.arena.bytes(s.record), out) {
				p.err = ReasonLabel
				return
			}
		}
		if len(p.truth.seals) >= maxTruthRecords {
			p.err = ReasonLimit
			return
		}
		r, ok := p.truth.arena.copy(out)
		if !ok {
			p.err = ReasonLimit
			return
		}
		p.truth.seals = append(p.truth.seals, actualSeal{p.side, p.generation, r, !dummy})
	}
}

func randomMessage(t *privateTruth, side uint16) (int, error) {
	var b [128]byte
	defer clear(b[:])
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
	if p.frozen {
		return err
	}
	if len(p.truth.requests) >= maxTruthRecords {
		p.err = ReasonLimit
		return err
	}
	var r arenaRef
	if req.Puts() {
		var ok bool
		r, ok = p.truth.arena.copy(req.Record[:])
		if !ok {
			p.err = ReasonLimit
			return err
		}
	}
	for _, prior := range p.truth.requests {
		if prior.generation == o.generation && prior.tag == req.Tag {
			p.err = ReasonLabel
			return err
		}
	}
	p.truth.requests = append(p.truth.requests, actualRequest{p.side, o.generation, req.Tag, r, elig, err == nil})
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
