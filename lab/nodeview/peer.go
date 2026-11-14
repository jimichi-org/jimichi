package nodeview

import (
	"bytes"
	"encoding/binary"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/relay"
)

type equalityEntry struct {
	alias uint32
	data  arenaRef
}
type mailboxCapture struct {
	queues, records []equalityEntry
	next            uint32
}

func (m *mailboxCapture) alias(c *collector, b []byte, record bool) uint32 {
	entries := &m.queues
	if record {
		entries = &m.records
	}
	for _, v := range *entries {
		if bytes.Equal(c.arena.bytes(v.data), b) {
			return v.alias
		}
	}
	if len(*entries) >= maxTruthRecords {
		c.fail(ReasonLimit)
		return 0
	}
	m.next++
	if m.next == 0 {
		c.fail(ReasonLimit)
		return 0
	}
	*entries = append(*entries, equalityEntry{m.next, c.copy(b)})
	return m.next
}

func observeDeliver(c *collector, p jcrypto.CryptoProvider, delegate relay.Deliver) relay.Deliver {
	registry := &mailboxCapture{}
	return func(circuit uint64, payload []byte) []byte {
		call := c.now()
		c.mu.Lock()
		var hop uint32
		var cellIndex = -1
		for i := range c.view.cells {
			v := &c.view.cells[i]
			if v.dir == 0 && v.circuit == circuit && v.stages&stageLocal != 0 && !v.cover && !v.delivered && v.localTime <= call {
				actual, cover, ok := framedPayload(c.arena.bytes(v.inner))
				if ok && !cover && bytes.Equal(actual, payload) {
					if cellIndex >= 0 {
						c.fail(ReasonContract)
						break
					}
					cellIndex = i
					hop = v.hop
				}
			}
		}
		if cellIndex < 0 {
			c.fail(ReasonContract)
		}
		var observed mailboxObservation
		var recordRef arenaRef
		if c.peer {
			req, e := mailbox.ParseRequest(payload)
			if e != nil {
				c.fail(ReasonContract)
			} else {
				c.mailboxOrder++
				if c.mailboxOrder == 0 || c.mailboxOrder > maxTruthRecords {
					c.fail(ReasonLimit)
				}
				observed = mailboxObservation{Circuit: hop, Order: c.mailboxOrder, CallNS: call, Tag: req.Tag, HasPut: req.Puts()}
				if req.Fetches() {
					id, e := mailbox.QueueID(p, req.Fetch[:])
					if e != nil {
						c.fail(ReasonContract)
					} else {
						observed.FetchQueue = registry.alias(c, id[:], false)
					}
					clear(id[:])
				}
				if req.Puts() {
					observed.PutQueue = registry.alias(c, req.Put[:], false)
					observed.RecordAlias = registry.alias(c, req.Record[:], true)
					observed.RecordKind, observed.RecordNumber, e = mailboxRecordHeader(req.Record[:])
					if e != nil {
						c.fail(ReasonContract)
					}
					recordRef = c.copy(req.Record[:])
				}
				clear(req.Fetch[:])
				clear(req.Put[:])
				clear(req.Record[:])
			}
		} else if c.measured(call) {
			c.fragments = append(c.fragments, contentFragment{hop, 2, c.copy(payload)})
		}
		c.recordLocked(call, false)
		c.mu.Unlock()
		out := delegate(circuit, payload)
		returned := c.now()
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.recordLocked(returned, true)
		if returned < call {
			c.fail(ReasonClock)
		}
		if cellIndex >= 0 {
			c.view.cells[cellIndex].noDeliver = false
			c.view.cells[cellIndex].nilReply = out == nil
			c.view.cells[cellIndex].delivered = true
			c.view.cells[cellIndex].reply = c.copy(out)
			c.arena.erase(&c.view.cells[cellIndex].inner)
		}
		if c.peer {
			reply, e := mailbox.ParseReply(out)
			if e != nil {
				c.fail(ReasonContract)
			} else {
				observed.ReturnNS, observed.Complete, observed.ReplyStatus = returned, true, reply.Status
				clear(reply.Record[:])
			}
			observed.record = recordRef
			if len(c.view.mailbox) >= maxTruthRecords {
				c.fail(ReasonLimit)
			} else {
				c.view.mailbox = append(c.view.mailbox, observed)
			}
			if recordRef.size > 0 && c.measured(call) {
				c.fragments = append(c.fragments, contentFragment{hop, 3, recordRef})
			}
		}
		return out
	}
}

func exitPayload(inner []byte) ([]byte, bool) {
	if len(inner) < 2 {
		return nil, false
	}
	n := binary.BigEndian.Uint16(inner[:2])
	if n&0x8000 != 0 || int(n) > len(inner)-2 {
		return nil, false
	}
	return inner[2 : 2+int(n)], true
}
