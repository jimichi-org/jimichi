package conversation

import (
	"bytes"
	"time"

	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

func (c *Conversation) onTick() {
	if c.finished {
		return
	}
	now := c.now()
	if c.circ == nil {
		c.redial(now)
		return
	}
	if len(c.pending) > 0 && now.Sub(c.pending[0].sentAt) >= c.cfg.ReplyTimeout {
		c.endCircuit(now, ErrReplyTimeout)
		return
	}
	var p *put
	if c.session != nil {
		c.session.Tick()
		c.syncEpoch(now)
		p = c.choosePut(now)
	}
	c.send(p, now)
}

func (c *Conversation) choosePut(now time.Time) *put {
	if c.inflight >= c.cfg.Window {
		c.n.windowFull.Add(1)
		return nil
	}
	// the session stops offering kk2 once the initiator's first record opened:
	// the initiator holds it, whatever the mailbox said
	if c.sticky != nil && c.sticky.handshake {
		if rec, ok := c.session.Handshake(); !ok || !bytes.Equal(rec, c.sticky.rec) {
			c.sticky = nil
		}
	}
	if c.sticky == nil {
		if rec, ok := c.session.Handshake(); ok {
			c.sticky = &sticky{rec: rec, handshake: true}
		}
	}
	if c.sticky == nil {
		p := c.fresh(now)
		if p == nil || !c.stall {
			return p
		}
		c.sticky = &sticky{rec: p.rec, body: p.body}
	}
	return &put{rec: c.sticky.rec, epoch: c.epoch, sticky: c.sticky}
}

func (c *Conversation) fresh(now time.Time) *put {
	s := c.session
	if s.CanSealReal() {
		if it := c.takeBody(); it != nil {
			rec, err := s.Seal(it.body)
			if err == nil {
				c.lastSealed = now
				return &put{rec: rec, epoch: c.epoch, body: it}
			}
			c.giveBack(it)
		}
	}
	if !c.cfg.CoverPuts && !s.NeedsRecord() && now.Sub(c.lastSealed) < c.cfg.Keepalive {
		return nil
	}
	rec, err := s.SealDummy()
	if err != nil {
		return nil
	}
	c.lastSealed = now
	return &put{rec: rec, epoch: c.epoch}
}

// F follows the version and the tag of a request; written straight into the
// payload it leaves no copy in a mailbox.Request, which Bytes copies by value
const fetchAt = 1 + 2

func (c *Conversation) send(p *put, now time.Time) {
	req := mailbox.Request{Tag: c.tag}
	if p != nil {
		req.Put = c.peer.Queue
		copy(req.Record[:], p.rec)
	}
	b := req.Bytes()
	copy(b[fetchAt:fetchAt+mailbox.CapSize], c.cfg.Fetch.Bytes())
	c.pending = append(c.pending, &request{tag: c.tag, put: p, sentAt: now})
	c.tag++
	if p != nil {
		c.inflight++
	}
	err := c.circ.Send(b)
	// zeroes this copy of F only; one the circuit keeps is its own (Circuit)
	clear(b)
	if err != nil {
		c.endCircuit(now, ErrSendFailed)
		return
	}
	c.n.requests.Add(1)
	if p != nil {
		c.n.puts.Add(1)
	}
}

// the replies of a circuit come strictly in order, so a reply belongs to the
// oldest request still waiting and its tag only checks that
func (c *Conversation) onReply(b []byte) {
	if c.finished || c.circ == nil {
		return
	}
	now := c.now()
	if len(c.pending) == 0 {
		c.n.badReplies.Add(1)
		return
	}
	r := c.pending[0]
	c.pending[0] = nil
	c.pending = c.pending[1:]
	if r.put != nil {
		c.inflight--
	}
	rep, err := mailbox.ParseReply(b)
	if err == nil {
		err = rep.Answers(r.asked(c.peer.Queue))
	}
	switch {
	case err != nil:
		// not closing the circuit: the mailbox can drop everything anyway, and
		// a close would give it one more cheap lever
		c.n.badReplies.Add(1)
		c.unknown(r.put)
	case r.put != nil:
		c.outcome(r.put, rep.Status&mailbox.PutMask)
	}
	// a record in a reply that parsed has left the queue even when the reply
	// fails Answers, and the session authenticates it and drops a repeat
	opened := false
	if rep.Status&mailbox.StatusRecord != 0 {
		c.n.hits.Add(1)
		opened = c.take(rep.Record[:], now)
	}
	if err == nil && c.session != nil && !opened {
		c.session.Fetched()
	}
}

// what Reply.Answers needs: every request fetches, and the put identifier is
// non-zero exactly when there was a put
func (r *request) asked(queue [mailbox.IDSize]byte) *mailbox.Request {
	q := &mailbox.Request{Tag: r.tag}
	q.Fetch[0] = 1
	if r.put != nil {
		q.Put = queue
	}
	return q
}

func (c *Conversation) take(rec []byte, now time.Time) bool {
	if c.session == nil {
		if len(c.held) >= c.cfg.Hold {
			clear(c.held[0])
			c.held[0] = nil
			c.held = c.held[1:]
			c.n.heldDropped.Add(1)
		}
		c.held = append(c.held, bytes.Clone(rec))
		return false
	}
	ev, err := c.session.Receive(rec)
	if err != nil {
		return false
	}
	c.mu.Lock()
	c.lastOpened = now
	c.mu.Unlock()
	if ev.Kind == e2e.EventMessage {
		select {
		case c.messages <- ev.Body:
		default:
			c.n.inboxDropped.Add(1)
		}
	}
	c.syncEpoch(now)
	return true
}

// a put of a past epoch, or a copy of a sticky record already taken off,
// changes nothing
func (c *Conversation) outcome(p *put, status byte) {
	refused := status == mailbox.PutFull || status == mailbox.PutRefused
	if refused {
		c.n.putRefused.Add(1)
	}
	if p.epoch != c.epoch || p.sticky != nil && p.sticky != c.sticky {
		return
	}
	switch {
	case refused:
		c.stall = true
		if p.body != nil {
			c.giveBack(p.body)
		}
	case p.sticky != nil:
		c.sticky = nil
		if p.sticky.handshake {
			c.session.Stored(p.rec)
		} else {
			c.stall = false
			forget(p.sticky.body)
		}
	default:
		forget(p.body)
	}
}

func forget(it *item) {
	if it != nil {
		clear(it.body)
	}
}

// a bad reply or the end of the circuit: as 10, but stall mode stays as it is
func (c *Conversation) unknown(p *put) {
	if p != nil && p.epoch == c.epoch && p.body != nil {
		c.giveBack(p.body)
	}
}

// a new handshake makes the records of the previous epoch worthless to the
// peer: their bodies go back at once and their outcomes no longer count
func (c *Conversation) syncEpoch(now time.Time) {
	epoch := c.session.Epoch()
	if epoch == c.epoch {
		return
	}
	c.epoch = epoch
	if c.sticky != nil && c.sticky.body != nil {
		c.giveBack(c.sticky.body)
	}
	c.sticky = nil
	for _, r := range c.pending {
		if r.put != nil && r.put.body != nil {
			c.giveBack(r.put.body)
			r.put.body = nil
		}
	}
	c.lastSealed = now
}
