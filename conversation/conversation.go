// Package conversation drives a client's conversation with one contact over a
// circuit that ends on a mailbox: one request per tick, a window of puts in
// flight, a sticky record after a refused put, and a new circuit through the
// same entry when one ends.
package conversation

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

const (
	DefaultWindow       = 16
	DefaultKeepalive    = 30 * time.Second
	DefaultStaleAfter   = 90 * time.Second
	DefaultReplyTimeout = 10 * time.Second
	DefaultRebuildFor   = 10 * time.Minute
	DefaultMaxRefusals  = 3
	DefaultOutbox       = 256
	DefaultHold         = 16
	DefaultInbox        = 256

	firstPause = time.Second
	maxPause   = time.Minute
	// replies wait here for the loop. A circuit that dropped one when its own
	// buffer filled would shift every match after it, so the reply timeout must
	// end a circuit before this many requests are in flight
	replyBuffer = 256
)

var (
	ErrContactChanged = errors.New("conversation: another contact card after pinning")
	ErrRefused        = errors.New("conversation: too many replies refused")
	ErrRebuild        = errors.New("conversation: no new circuit in time")
	ErrClosed         = errors.New("conversation: closed")

	// the classes of a circuit end besides the circuit's own refusal: none of
	// them carries what the cause said, which could name a node
	ErrReplyTimeout = errors.New("conversation: no reply in time")
	ErrSendFailed   = errors.New("conversation: send failed")

	errSmallCircuit = errors.New("conversation: the circuit cannot carry a request")
)

// what the conversation needs of a circuit; client.Client has it. The driver
// zeroes the payload once Send returns, so Send may keep only a copy, and a
// copy holds F (client.Client queues one at a fixed rate). Replies is closed
// when the circuit ends
type Circuit interface {
	Send([]byte) error
	Replies() <-chan []byte
	Refused() error
	MaxPayload() int
	Close() error
}

type Config struct {
	Provider jcrypto.CryptoProvider
	Self     *e2e.Identity
	// F, whose queue is the one in the card of Self
	Fetch *secmem.Buffer
	First Circuit
	// builds the next circuit through the same entry to the same mailbox
	Dial      func() (Circuit, error)
	Rate      time.Duration
	CoverPuts bool
	// zero picks the default for each of these
	Window       int
	Keepalive    time.Duration
	StaleAfter   time.Duration
	ReplyTimeout time.Duration
	RebuildFor   time.Duration
	MaxRefusals  int
	// a zero StaleFetches becomes StaleAfter / Rate and a nil Now the one below
	Session             e2e.Options
	Outbox, Hold, Inbox int
	Now                 func() time.Time
	// told of every circuit end and rebuild, from the loop; it must not block
	Events func(Event)
}

type EventKind uint8

const (
	CircuitEnded EventKind = iota + 1
	CircuitRebuilt
)

// Cause of an end is the circuit's refusal class, ErrReplyTimeout,
// ErrSendFailed, or nil when the far side closed it
type Event struct {
	Kind  EventKind
	Cause error
}

// the counters of the conversation; none names a node, a queue or a message
type Stats struct {
	Paired bool
	State  e2e.State
	Epoch  uint64
	// requests sent, those with a put, puts refused (10 or 11), ticks the
	// window kept a put back, replies with a record
	Requests, Puts, PutRefused, WindowFull, Hits uint64
	BadReplies                                   uint64
	// requests whose circuit ended before their reply
	Unanswered uint64
	// circuits rebuilt, and circuits that ended in a refused reply
	Rebuilds, Refusals                       uint64
	OutboxDropped, HeldDropped, InboxDropped uint64
	// the last record of the contact that opened; zero before the first
	LastOpened time.Time
	Session    e2e.Stats
}

type counters struct {
	requests, puts, putRefused, windowFull, hits atomic.Uint64
	badReplies, unanswered, rebuilds, refusals   atomic.Uint64
	outboxDropped, heldDropped, inboxDropped     atomic.Uint64
}

type item struct {
	seq  uint64
	body []byte
}

type put struct {
	rec   []byte
	epoch uint64
	// the message a real record carries; nil for a dummy, a handshake and a
	// copy of the sticky record, which keeps its own
	body   *item
	sticky *sticky
}

// the one record put as copies until the mailbox stores one: a handshake
// record, or the probe in stall mode
type sticky struct {
	rec       []byte
	handshake bool
	body      *item
}

type request struct {
	tag    uint16
	put    *put
	sentAt time.Time
}

type circuitEvent struct {
	gen   uint64
	reply []byte
	ended bool
}

type dialResult struct {
	circ Circuit
	err  error
}

type pairRequest struct {
	card e2e.Card
	err  chan error
}

type Conversation struct {
	cfg  Config
	opts e2e.Options
	// the loop runs in its own goroutine; tests drive the handlers directly
	async      bool
	firstPause time.Duration

	// owned by the loop
	session      *e2e.Session
	peer         e2e.Card
	epoch        uint64
	circ         Circuit
	gen          uint64
	quit         chan struct{}
	tag          uint16
	pending      []*request
	inflight     int
	sticky       *sticky
	stall        bool
	lastSealed   time.Time
	held         [][]byte
	refusedAt    []time.Time
	rebuildSince time.Time
	pause        time.Duration
	nextDial     time.Time
	dialing      bool
	finished     bool
	tornDown     bool

	events   chan circuitEvent
	dialed   chan dialResult
	pairs    chan pairRequest
	stop     chan struct{}
	stopOnce sync.Once
	stopAll  chan struct{}
	wg       sync.WaitGroup
	done     chan struct{}
	messages chan []byte

	n counters

	mu         sync.Mutex
	outbox     []*item
	seq        uint64
	ended      bool
	err        error
	shared     *e2e.Session
	lastOpened time.Time
}

// Start takes the first circuit and ticks every Rate until Close or the end
// of the conversation
func Start(cfg Config) (*Conversation, error) {
	c, err := newConversation(cfg)
	if err != nil {
		return nil, err
	}
	c.launch()
	return c, nil
}

func newConversation(cfg Config) (*Conversation, error) {
	if cfg.Provider == nil || cfg.Self == nil || cfg.Fetch == nil || cfg.First == nil || cfg.Dial == nil {
		return nil, errors.New("conversation: a provider, an identity, a fetch capability, a circuit and Dial are required")
	}
	if cfg.Rate <= 0 {
		return nil, errors.New("conversation: no request period")
	}
	if got := cfg.First.MaxPayload(); got < mailbox.RequestSize {
		return nil, fmt.Errorf("%w: %d bytes for a %d-byte request", errSmallCircuit, got, mailbox.RequestSize)
	}
	own := cfg.Self.Card()
	if own.Suite != cfg.Provider.Suite() {
		return nil, e2e.ErrCard
	}
	f := cfg.Fetch.Bytes()
	if len(f) != mailbox.CapSize || allZero(f) {
		return nil, mailbox.ErrCap
	}
	queue, err := mailbox.QueueID(cfg.Provider, f)
	if err != nil {
		return nil, err
	}
	if queue != own.Queue {
		return nil, errors.New("conversation: the card names a queue the capability does not fetch")
	}

	cfg.Window = pick(cfg.Window, DefaultWindow)
	cfg.Keepalive = pick(cfg.Keepalive, DefaultKeepalive)
	cfg.StaleAfter = pick(cfg.StaleAfter, DefaultStaleAfter)
	cfg.ReplyTimeout = pick(cfg.ReplyTimeout, DefaultReplyTimeout)
	cfg.RebuildFor = pick(cfg.RebuildFor, DefaultRebuildFor)
	cfg.MaxRefusals = pick(cfg.MaxRefusals, DefaultMaxRefusals)
	cfg.Outbox = pick(cfg.Outbox, DefaultOutbox)
	cfg.Hold = pick(cfg.Hold, DefaultHold)
	cfg.Inbox = pick(cfg.Inbox, DefaultInbox)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// an idle honest session must hear from its peer before it goes stale
	if cfg.Keepalive >= cfg.StaleAfter {
		return nil, fmt.Errorf("conversation: keepalive %v not below the stale bound %v", cfg.Keepalive, cfg.StaleAfter)
	}
	if cfg.ReplyTimeout/cfg.Rate >= replyBuffer-1 {
		return nil, fmt.Errorf("conversation: a reply timeout of %v holds more than %d requests in flight", cfg.ReplyTimeout, replyBuffer-1)
	}

	opts := cfg.Session
	if opts.StaleFetches <= 0 {
		opts.StaleFetches = max(1, int(cfg.StaleAfter/cfg.Rate))
	}
	if opts.Now == nil {
		opts.Now = cfg.Now
	}
	return &Conversation{
		cfg:        cfg,
		opts:       opts,
		firstPause: firstPause,
		events:     make(chan circuitEvent, replyBuffer),
		dialed:     make(chan dialResult),
		pairs:      make(chan pairRequest),
		stop:       make(chan struct{}),
		stopAll:    make(chan struct{}),
		done:       make(chan struct{}),
		messages:   make(chan []byte, cfg.Inbox),
	}, nil
}

func pick[T int | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

func (c *Conversation) launch() {
	c.async = true
	c.attach(c.cfg.First)
	t := time.NewTicker(c.cfg.Rate)
	go c.run(t.C, t.Stop)
}

func (c *Conversation) run(ticks <-chan time.Time, stopTicks func()) {
	defer c.teardown()
	defer stopTicks()
	for !c.finished {
		select {
		case <-c.stop:
			return
		case <-ticks:
			c.onTick()
		case ev := <-c.events:
			if ev.gen != c.gen || c.circ == nil {
				continue
			}
			if ev.ended {
				c.onEnd()
			} else {
				c.onReply(ev.reply)
			}
		case res := <-c.dialed:
			c.onDial(res.circ, res.err)
		case req := <-c.pairs:
			req.err <- c.onPair(req.card)
		}
	}
}

// Pair pins the contact and starts the session; the same card again is nil,
// another one ends the conversation with ErrContactChanged
func (c *Conversation) Pair(peer e2e.Card) error {
	req := pairRequest{card: peer, err: make(chan error, 1)}
	select {
	case c.pairs <- req:
		return <-req.err
	case <-c.done:
		return ErrClosed
	}
}

// Send queues a message; when the outbox is full it is dropped and counted
func (c *Conversation) Send(body []byte) error {
	if len(body) > e2e.MaxBody {
		return e2e.ErrTooLong
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ended {
		return ErrClosed
	}
	if len(c.outbox) >= c.cfg.Outbox {
		c.n.outboxDropped.Add(1)
		return nil
	}
	c.seq++
	c.outbox = append(c.outbox, &item{seq: c.seq, body: bytes.Clone(body)})
	return nil
}

// the messages of the contact, closed when the conversation ends
func (c *Conversation) Messages() <-chan []byte { return c.messages }

func (c *Conversation) Done() <-chan struct{} { return c.done }

// why the conversation ended: ErrContactChanged, ErrRefused, ErrRebuild, or
// nil while it runs and after Close
func (c *Conversation) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// closes the circuit and the session; the identity and F stay with the caller
func (c *Conversation) Close() {
	c.stopOnce.Do(func() { close(c.stop) })
	<-c.done
}

func (c *Conversation) Stats() Stats {
	c.mu.Lock()
	s, last := c.shared, c.lastOpened
	c.mu.Unlock()
	st := Stats{
		Requests:      c.n.requests.Load(),
		Puts:          c.n.puts.Load(),
		PutRefused:    c.n.putRefused.Load(),
		WindowFull:    c.n.windowFull.Load(),
		Hits:          c.n.hits.Load(),
		BadReplies:    c.n.badReplies.Load(),
		Unanswered:    c.n.unanswered.Load(),
		Rebuilds:      c.n.rebuilds.Load(),
		Refusals:      c.n.refusals.Load(),
		OutboxDropped: c.n.outboxDropped.Load(),
		HeldDropped:   c.n.heldDropped.Load(),
		InboxDropped:  c.n.inboxDropped.Load(),
		LastOpened:    last,
	}
	if s != nil {
		st.Paired, st.State, st.Epoch, st.Session = true, s.State(), s.Epoch(), s.Stats()
	}
	return st
}

func (c *Conversation) now() time.Time { return c.cfg.Now() }

func (c *Conversation) finish(err error) {
	c.finished = true
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
}

func (c *Conversation) teardown() {
	if c.tornDown {
		return
	}
	c.tornDown, c.finished = true, true
	c.detach()
	if c.session != nil {
		c.session.Close()
	}
	close(c.stopAll)
	c.wg.Wait()
	for _, r := range c.pending {
		if r.put != nil {
			forget(r.put.body)
		}
	}
	c.pending = nil
	if c.sticky != nil {
		forget(c.sticky.body)
	}
	c.sticky = nil
	for _, rec := range c.held {
		clear(rec)
	}
	c.held = nil
	c.mu.Lock()
	c.ended = true
	for _, it := range c.outbox {
		forget(it)
	}
	c.outbox = nil
	c.mu.Unlock()
	close(c.messages)
	close(c.done)
}

func (c *Conversation) notify(ev Event) {
	if c.cfg.Events != nil {
		c.cfg.Events(ev)
	}
}

func (c *Conversation) attach(circ Circuit) {
	c.circ, c.tag = circ, 0
	c.gen++
	if !c.async {
		return
	}
	c.quit = make(chan struct{})
	c.wg.Add(1)
	go c.read(c.gen, circ, c.quit)
}

func (c *Conversation) detach() {
	if c.circ == nil {
		return
	}
	_ = c.circ.Close()
	if c.quit != nil {
		close(c.quit)
		c.quit = nil
	}
	c.circ = nil
}

func (c *Conversation) read(gen uint64, circ Circuit, quit <-chan struct{}) {
	defer c.wg.Done()
	replies := circ.Replies()
	for {
		var ev circuitEvent
		select {
		case b, ok := <-replies:
			ev = circuitEvent{gen: gen, reply: b, ended: !ok}
		case <-quit:
			return
		}
		select {
		case c.events <- ev:
		case <-quit:
			return
		}
		if ev.ended {
			return
		}
	}
}

func (c *Conversation) onPair(peer e2e.Card) error {
	if c.finished {
		return ErrClosed
	}
	if c.session != nil {
		if bytes.Equal(peer.Bytes(), c.peer.Bytes()) {
			return nil
		}
		c.finish(ErrContactChanged)
		return ErrContactChanged
	}
	// the conversation puts into the peer's queue on its own mailbox
	if peer.Mailbox != c.cfg.Self.Card().Mailbox {
		return e2e.ErrCard
	}
	s, err := e2e.NewSession(c.cfg.Provider, c.cfg.Self, peer, c.opts)
	if err != nil {
		return err
	}
	now := c.now()
	c.mu.Lock()
	c.shared = s
	c.mu.Unlock()
	peer.Static = bytes.Clone(peer.Static)
	c.session, c.peer, c.epoch, c.lastSealed = s, peer, s.Epoch(), now
	held := c.held
	c.held = nil
	for _, rec := range held {
		c.take(rec, now)
		clear(rec)
	}
	return nil
}

func (c *Conversation) onEnd() {
	if c.finished || c.circ == nil {
		return
	}
	c.endCircuit(c.now(), nil)
}

func (c *Conversation) endCircuit(now time.Time, cause error) {
	refused := c.circ.Refused()
	if refused != nil {
		cause = refused
	}
	c.detach()
	for _, r := range c.pending {
		c.unknown(r.put)
	}
	c.n.unanswered.Add(uint64(len(c.pending)))
	clear(c.pending)
	c.pending, c.inflight = c.pending[:0], 0
	c.notify(Event{Kind: CircuitEnded, Cause: cause})
	if refused != nil {
		c.n.refusals.Add(1)
		c.refusedAt = append(slices.DeleteFunc(c.refusedAt, func(t time.Time) bool {
			return now.Sub(t) >= c.cfg.RebuildFor
		}), now)
		if len(c.refusedAt) >= c.cfg.MaxRefusals {
			c.finish(ErrRefused)
			return
		}
	}
	c.rebuildSince, c.pause = now, c.firstPause
	c.nextDial = now.Add(c.pause)
}

func (c *Conversation) redial(now time.Time) {
	if c.dialing {
		return
	}
	if now.Sub(c.rebuildSince) >= c.cfg.RebuildFor {
		c.finish(ErrRebuild)
		return
	}
	if now.Before(c.nextDial) {
		return
	}
	c.dialing = true
	if !c.async {
		circ, err := c.cfg.Dial()
		c.onDial(circ, err)
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		circ, err := c.cfg.Dial()
		select {
		case c.dialed <- dialResult{circ, err}:
		case <-c.stopAll:
			if circ != nil {
				_ = circ.Close()
			}
		}
	}()
}

func (c *Conversation) onDial(circ Circuit, err error) {
	c.dialing = false
	if err == nil && (circ == nil || circ.MaxPayload() < mailbox.RequestSize) {
		err = errSmallCircuit
	}
	if err != nil || c.finished {
		if circ != nil {
			_ = circ.Close()
		}
		if c.finished {
			return
		}
		c.pause = min(2*c.pause, maxPause)
		c.nextDial = c.now().Add(c.pause)
		return
	}
	c.attach(circ)
	c.rebuildSince = time.Time{}
	c.n.rebuilds.Add(1)
	c.notify(Event{Kind: CircuitRebuilt})
}

func (c *Conversation) takeBody() *item {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.outbox) == 0 {
		return nil
	}
	it := c.outbox[0]
	c.outbox[0] = nil
	c.outbox = c.outbox[1:]
	return it
}

// a body whose record did not reach the mailbox goes back to its place by the
// order of Send
func (c *Conversation) giveBack(it *item) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ended {
		return
	}
	i, _ := slices.BinarySearchFunc(c.outbox, it.seq, func(x *item, seq uint64) int { return cmp.Compare(x.seq, seq) })
	c.outbox = slices.Insert(c.outbox, i, it)
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
