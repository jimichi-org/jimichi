package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/mailbox"
)

const (
	exitFlags = 2

	// a client at its peak locks about 19 pages: the circuit and its link about
	// 9, the identity and F 2, a handshake up to 5, the ratchet up to 3
	minPeerMemlock = 96 << 10

	// how often one process may draw new middle hops after the first chain;
	// past this it dials its last chain again however often that fails
	maxRedraws = 2
	// circuits in a row through one chain that end before any reply, after
	// which the chain counts as one that cannot be dialled: a setup the entry
	// or a middle hop does not carry on shows only as a circuit that closes
	silentCircuits = 2

	// the body of the stand: u8 kind | u32be sequence number | text
	bodyHeader  = 5
	kindMessage = 1
	kindReply   = 2
	maxText     = e2e.MaxBody - bodyHeader
	// sent messages waiting for their reply; past this the oldest is forgotten
	maxWaiting = 1024
)

// variables so that a test can shorten them in a client process of its own
var (
	reportEvery = time.Minute
	rebuildFor  = conversation.DefaultRebuildFor
)

var (
	errNoMailbox = errors.New("the entry holds no bundle for the mailbox")
	errNotServed = errors.New("the entry holds no bundle for a node of the chain")
	errSilent    = errors.New("circuits through the chain ended before any reply")
)

type peerFlags struct {
	nodes, mailbox, admin, infoPort string
	suite, keymem, ca, mode         string
	message                         string
	hops, count, missing            int
	fixed, auth, harden             bool
	coverPuts, respond              bool
	rate, jitter, cover, interval   time.Duration
	skew, handshakeTimeout          time.Duration
}

// runs the -peer mode until a signal or the end of the conversation and
// returns the exit code; every key is released by the time it returns
func runPeer(f peerFlags, logger *log.Logger, stop <-chan os.Signal) int {
	policy, err := secmem.ParsePolicy(f.keymem)
	if err != nil {
		logger.Printf("keymem: %v", err)
		return exitFlags
	}
	if err := secmem.SetPolicy(policy); err != nil {
		logger.Printf("keymem: %v", err)
		return 1
	}
	if f.harden {
		if err := secmem.HardenProcess(); err != nil {
			logger.Printf("harden: %v", err)
			return 1
		}
	}
	if policy.Lock {
		if err := checkMemlock(minPeerMemlock); err != nil {
			logger.Print(err)
			return 1
		}
		probe, err := secmem.New(32)
		if err != nil {
			logger.Printf("key memory: %v", err)
			return 1
		}
		locked := probe.Locked()
		probe.Release()
		if !locked {
			logger.Print("key memory is not locked, refusing to start")
			return 1
		}
	}

	chosen, err := suite.Parse(f.suite)
	if err != nil {
		logger.Print(err)
		return exitFlags
	}
	p, err := suite.New(chosen)
	if err != nil {
		logger.Print(err)
		return 1
	}
	addrs, exit, err := checkPeer(p, f)
	if err != nil {
		logger.Print(err)
		return exitFlags
	}
	trust, err := trustPolicy(f.auth, f.ca, chosen, f.skew)
	if err != nil {
		logger.Print(err)
		return exitFlags
	}
	if !f.auth {
		logger.Print("WARNING: -auth=false, node keys are taken unverified from whoever answers the descriptor request")
	}

	capability, id, err := newPeerIdentity(p, f.mailbox)
	if err != nil {
		logger.Printf("identity: %v", err)
		return 1
	}
	defer capability.Release()
	defer id.Close()
	own := id.Card()
	hash, err := e2e.CardHash(p, own)
	if err != nil {
		logger.Printf("identity: %v", err)
		return 1
	}
	// the card itself goes only to GET /card: this log reaches the disk of the
	// node, and whoever holds the card can put into the queue
	logger.Printf("card_hash=%x", hash)

	r := &route{
		p: p, exit: exit, logger: logger,
		sel: selection{
			addrs: addrs, hops: f.hops, fixed: f.fixed, missing: f.missing, infoPort: f.infoPort,
			auth: f.auth, trust: trust,
			web: fetch.NewClient(), attempts: fetchAttempts, pause: fetchPause,
			rnd: rand.Reader, now: time.Now,
		},
		dial: func(chain []client.Node) (conversation.Circuit, error) {
			c, err := client.Dial(client.Config{Provider: p, Chain: chain, Jitter: f.jitter})
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
	first, err := r.first()
	if err != nil {
		logger.Printf("refusing to build the circuit: %s", peerCause(err))
		return 1
	}
	logger.Printf("circuit of %d hops among %d listed nodes to the mailbox, request period %v", f.hops, len(addrs), f.rate)

	conv, err := conversation.Start(conversation.Config{
		Provider:   p,
		Self:       id,
		Fetch:      capability,
		First:      first,
		Dial:       r.rebuild,
		Rate:       f.rate,
		CoverPuts:  f.coverPuts,
		RebuildFor: rebuildFor,
		Session:    e2e.Options{HandshakeTimeout: f.handshakeTimeout},
		Events: func(ev conversation.Event) {
			switch ev.Kind {
			case conversation.CircuitEnded:
				logger.Print(endLine(ev.Cause))
			case conversation.CircuitRebuilt:
				logger.Print("circuit rebuilt through the same entry")
			}
		},
	})
	if err != nil {
		_ = first.Close()
		logger.Printf("conversation: %v", err)
		return 1
	}
	defer conv.Close()

	ct := &contact{
		p: p, own: own, text: own.String(), conv: conv, logger: logger, now: time.Now,
		paired: make(chan struct{}),
		halt:   release(conv, id, capability),
	}
	ln, err := net.Listen("tcp", f.admin)
	if err != nil {
		logger.Printf("admin: %v", err)
		return 1
	}
	srv := &http.Server{Handler: ct.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	defer srv.Close()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Printf("admin: %v", err)
		}
	}()
	logger.Printf("admin listening on %s", ln.Addr())

	tk := &talk{
		conv: conv, logger: logger, now: time.Now,
		message: []byte(f.message), count: f.count, interval: f.interval, respond: f.respond,
		waiting: make(map[uint32]time.Time),
	}
	quit := make(chan struct{})
	var loops sync.WaitGroup
	loops.Add(2)
	go func() {
		defer loops.Done()
		tk.send(ct.paired, quit)
	}()
	go func() {
		defer loops.Done()
		tk.receive()
	}()
	defer func() {
		close(quit)
		conv.Close()
		loops.Wait()
	}()

	report := time.NewTicker(reportEvery)
	defer report.Stop()
	done := conv.Done()
	for {
		select {
		case <-stop:
			logger.Print("shutting down")
			return 0
		case <-done:
			if ct.halted() {
				// the stopped state outlives the conversation: only the operator
				// ends it, by restarting the client
				done = nil
				continue
			}
			err := conv.Err()
			logger.Printf("conversation ended: %v", err)
			if errors.Is(err, conversation.ErrRefused) {
				return exitRefused
			}
			return 1
		case <-report.C:
			ct.report(conv.Stats())
		}
	}
}

// settled before any network request: a configuration the mode cannot run
// fails the same way at every start
func checkPeer(p jcrypto.CryptoProvider, f peerFlags) (addrs []string, exit int, err error) {
	addrs = splitList(f.nodes)
	if err := checkNodes(p, addrs, f.hops, f.infoPort); err != nil {
		return nil, 0, err
	}
	switch minRate := conversation.MinRate(conversation.DefaultReplyTimeout); {
	case f.hops < 2:
		return nil, 0, fmt.Errorf("-hops %d: -peer needs at least 2, or the mailbox would be the entry", f.hops)
	case f.mode != "fixed":
		return nil, 0, errors.New("-peer sends one request per tick: -mode must be fixed")
	case f.cover > 0:
		return nil, 0, errors.New("-cover: -peer sends one request per tick and no cover cells besides")
	case f.rate < minRate:
		return nil, 0, fmt.Errorf("-rate %v: want at least %v, the requests sent while one waits %v for its reply must fit the reply buffer", f.rate, minRate, conversation.DefaultReplyTimeout)
	case f.jitter < 0 || f.jitter >= f.rate:
		return nil, 0, fmt.Errorf("-jitter %v: want at least 0 and below -rate %v", f.jitter, f.rate)
	case len(f.message) > maxText:
		return nil, 0, fmt.Errorf("-message: %d bytes, -peer carries at most %d", len(f.message), maxText)
	case f.count < 0:
		return nil, 0, fmt.Errorf("-count %d: must not be negative", f.count)
	case f.interval < 0:
		return nil, 0, fmt.Errorf("-interval %v: must not be negative", f.interval)
	case f.missing < 0:
		return nil, 0, fmt.Errorf("-missing %d: must not be negative", f.missing)
	case f.handshakeTimeout <= 0:
		return nil, 0, fmt.Errorf("-handshake-timeout %v: must be positive", f.handshakeTimeout)
	case f.mailbox == "":
		return nil, 0, errors.New("-peer needs -mailbox, the node that keeps the queues of the conversation")
	}
	if err := checkAdmin(f.admin); err != nil {
		return nil, 0, err
	}
	exit = slices.Index(addrs, f.mailbox)
	switch {
	case exit < 0:
		return nil, 0, errors.New("-mailbox is not one of -nodes")
	case f.fixed && exit != f.hops-1:
		return nil, 0, fmt.Errorf("-fixed-chain: node %d of -nodes ends the chain and must be the mailbox", f.hops)
	}
	return addrs, exit, nil
}

// the admin port hands out the card and takes the contact's, so it listens on
// loopback only and is reached through a port-forward
func checkAdmin(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-admin %q: want a loopback IP literal and a port", addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
		return fmt.Errorf("-admin %q: want a loopback IP literal and a port", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("-admin %q: want a loopback IP literal and a port", addr)
	}
	return nil
}

func checkMemlock(least uint64) error {
	budget, err := secmem.MemlockBudget()
	if err != nil {
		return err
	}
	return memlockFits(budget, least)
}

func memlockFits(budget, least uint64) error {
	if budget < least {
		return fmt.Errorf("RLIMIT_MEMLOCK is %d bytes, need at least %d to lock key pages", budget, least)
	}
	return nil
}

// F is drawn straight into locked memory and the queue in the card is the one
// it fetches
func newPeerIdentity(p jcrypto.CryptoProvider, mailboxAddr string) (*secmem.Buffer, *e2e.Identity, error) {
	f, err := secmem.New(mailbox.CapSize)
	if err != nil {
		return nil, nil, err
	}
	for {
		if _, err := rand.Read(f.Bytes()); err != nil {
			f.Release()
			return nil, nil, err
		}
		if !zeroes(f.Bytes()) {
			break
		}
	}
	queue, err := mailbox.QueueID(p, f.Bytes())
	if err != nil {
		f.Release()
		return nil, nil, err
	}
	id, err := e2e.NewIdentity(p, mailboxAddr, queue)
	if err != nil {
		f.Release()
		return nil, nil, err
	}
	return f, id, nil
}

// the conversation reads F on every tick, so it goes before the keys
func release(conv *conversation.Conversation, id *e2e.Identity, f *secmem.Buffer) func() {
	return func() {
		conv.Close()
		id.Close()
		f.Release()
	}
}

func zeroes(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// the line names the class of the end and nothing of the circuit
func endLine(cause error) string {
	if cause == nil {
		return "circuit closed"
	}
	return "circuit closed: " + cause.Error()
}

// the text of a failure to build or rebuild the chain: a fixed class, a count
// or a verdict, none of which names a node
func peerCause(err error) string {
	var entry *entryError
	var node *nodeError
	switch {
	case errors.As(err, &entry), errors.As(err, &node),
		errors.Is(err, errTooFew), errors.Is(err, errNoMailbox), errors.Is(err, errNotServed), errors.Is(err, errSilent),
		errors.Is(err, client.ErrChoice):
		return err.Error()
	}
	return failureClass(err)
}

// a node of a fixed chain the mirror does not hold; a fixed chain is the
// configuration, but the line still names no node
type nodeError struct{ err error }

func (e *nodeError) Error() string { return "a node of the fixed chain: " + failureClass(e.err) }

func (e *nodeError) Unwrap() error { return e.err }

// the chain of a -peer client: the entry is drawn once for the process and the
// exit is the mailbox. A rebuild dials the chain it dialled last, through a
// fresh mirror of the same entry; it draws new middle hops only when that chain
// cannot be dialled, and at most maxRedraws times per process. An entry that
// closes every circuit through honest middle hops therefore steers the client
// at most that many times; past the bound it can only stall the conversation,
// which it can do anyway
type route struct {
	p      jcrypto.CryptoProvider
	sel    selection
	exit   int
	dial   func([]client.Node) (conversation.Circuit, error)
	logger *log.Logger

	entry int
	// listed indices of the chain dialled last, the entry first, the mailbox last
	path []int
	// the first draw of the middle hops and every redraw
	draws int
	// the circuit handed out last, and how many circuits in a row on the
	// current chain ended without a single reply
	last   *watched
	silent int
}

func (r *route) first() (conversation.Circuit, error) {
	if !r.sel.fixed {
		entry, err := client.ChooseEntryExcept(len(r.sel.addrs), r.exit, r.sel.rnd)
		if err != nil {
			return nil, err
		}
		r.entry = entry
	}
	v, err := r.mirror(r.sel.attempts)
	if err != nil {
		return nil, err
	}
	if r.sel.fixed {
		r.path = make([]int, r.sel.hops)
		for i := range r.path {
			r.path[i] = i
		}
	} else if err := r.draw(v); err != nil {
		return nil, err
	}
	return r.open(v)
}

// Dial of the conversation. A close by the far side, a reply timeout, a
// refused reply and a failed send all come here alike: the same chain is
// dialled again, and it counts as one that cannot be dialled only when the
// mirror lacks a node of it, its setup fails, or silentCircuits circuits in a
// row through it ended before any reply
func (r *route) rebuild() (conversation.Circuit, error) {
	if r.last != nil {
		if r.last.answered.Load() {
			r.silent = 0
		} else {
			r.silent++
		}
		r.last = nil
	}
	// one request per attempt: the conversation spaces the attempts out itself,
	// and a stop waits for the attempt under way
	v, err := r.mirror(1)
	if err != nil {
		r.logger.Printf("circuit rebuild failed: %s", peerCause(err))
		return nil, err
	}
	exhausted := r.sel.fixed || r.draws > maxRedraws
	err = errNotServed
	if r.silent >= silentCircuits && !exhausted {
		err = errSilent
	} else if v.holds(r.path) {
		c, dialErr := r.open(v)
		if dialErr == nil {
			return c, nil
		}
		err = dialErr
	}
	if exhausted {
		r.logger.Printf("circuit rebuild failed: %s", peerCause(err))
		return nil, err
	}
	if err := r.draw(v); err != nil {
		r.logger.Printf("circuit rebuild failed: %s", peerCause(err))
		return nil, err
	}
	r.logger.Printf("the chain could not be dialled again, new middle hops drawn, redraw %d of %d", r.draws-1, maxRedraws)
	c, err := r.open(v)
	if err != nil {
		r.logger.Printf("circuit rebuild failed: %s", peerCause(err))
		return nil, err
	}
	return c, nil
}

func (r *route) open(v mirrorView) (conversation.Circuit, error) {
	c, err := r.dial(v.chain(r.path))
	if err != nil {
		return nil, err
	}
	r.last = watch(c)
	return r.last, nil
}

func (r *route) draw(v mirrorView) error {
	rest, err := client.ChooseRestTo(v.at[r.entry], v.at[r.exit], len(v.nodes), r.sel.hops, r.sel.rnd)
	if err != nil {
		return err
	}
	r.draws, r.silent = r.draws+1, 0
	r.path = make([]int, len(rest))
	for i, place := range rest {
		r.path[i] = v.listed[place]
	}
	return nil
}

// the mirror of the entry when the client takes it: with a drawn chain the
// rule of JudgeMirrorTo, with a fixed one every node of the chain
func (r *route) mirror(attempts int) (mirrorView, error) {
	sel := r.sel
	sel.attempts = attempts
	v, err := sel.mirror(r.p, r.entry)
	if err != nil {
		return v, err
	}
	if r.sel.fixed {
		for i := 0; i < r.sel.hops; i++ {
			if v.at[i] < 0 {
				return v, &nodeError{v.missing(i)}
			}
		}
		return v, nil
	}
	switch verdict, absent, allowed := client.JudgeMirrorTo(v.usable(), r.entry, r.exit, r.sel.hops, r.sel.missing); verdict {
	case client.MirrorTaken:
		return v, nil
	case client.MirrorLacksEntry:
		return v, &entryError{v.missing(r.entry)}
	case client.MirrorLacksExit:
		return v, errNoMailbox
	default:
		return v, fmt.Errorf("%w: %d of %d listed nodes, at most %d may be", errTooFew, absent, len(r.sel.addrs), allowed)
	}
}

func (v mirrorView) holds(path []int) bool {
	for _, i := range path {
		if v.at[i] < 0 {
			return false
		}
	}
	return true
}

func (v mirrorView) chain(path []int) []client.Node {
	places := make([]int, len(path))
	for i, listed := range path {
		places[i] = v.at[listed]
	}
	return chainOf(v.nodes, places)
}

// the messages of the stand: the sender's and the answers of -respond
type talk struct {
	conv     *conversation.Conversation
	logger   *log.Logger
	now      func() time.Time
	message  []byte
	count    int
	interval time.Duration
	respond  bool

	mu      sync.Mutex
	next    uint32
	waiting map[uint32]time.Time
	order   []uint32
}

func body(kind byte, seq uint32, text []byte) []byte {
	b := make([]byte, bodyHeader, bodyHeader+len(text))
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:], seq)
	return append(b, text...)
}

// one message every interval once the contact is pinned, count of them or
// without end for 0; the process goes on fetching and answering afterwards,
// since an exit would take the identity with it
func (t *talk) send(paired, quit <-chan struct{}) {
	if t.interval <= 0 {
		return
	}
	select {
	case <-paired:
	case <-quit:
		return
	}
	tick := time.NewTicker(t.interval)
	defer tick.Stop()
	for sent := 0; t.count == 0 || sent < t.count; sent++ {
		if sent > 0 {
			select {
			case <-tick.C:
			case <-quit:
				return
			}
		}
		t.mu.Lock()
		seq := t.next
		t.next++
		t.waiting[seq] = t.now()
		t.order = append(t.order, seq)
		if len(t.order) > maxWaiting {
			delete(t.waiting, t.order[0])
			t.order = t.order[1:]
		}
		t.mu.Unlock()
		b := body(kindMessage, seq, t.message)
		err := t.conv.Send(b)
		clear(b)
		if err != nil {
			return
		}
	}
}

// neither the text nor the number of a message is logged; a reply logs only
// how long its round trip took
func (t *talk) receive() {
	for m := range t.conv.Messages() {
		if len(m) < bodyHeader {
			continue
		}
		seq := binary.BigEndian.Uint32(m[1:bodyHeader])
		switch m[0] {
		case kindMessage:
			if t.respond {
				b := body(kindReply, seq, m[bodyHeader:])
				_ = t.conv.Send(b)
				clear(b)
			}
		case kindReply:
			t.mu.Lock()
			sentAt, ok := t.waiting[seq]
			delete(t.waiting, seq)
			t.mu.Unlock()
			// a duplicate finds nothing waiting
			if ok {
				t.logger.Printf("e2e round trip in %s", t.now().Sub(sentAt).Round(time.Microsecond))
			}
		}
		clear(m)
	}
}

// a circuit that tells whether any reply came through it. Replies pass on
// one by one in order; Close stops the passing, as the conversation stops
// reading when it closes a circuit
type watched struct {
	conversation.Circuit
	out      chan []byte
	quit     chan struct{}
	once     sync.Once
	answered atomic.Bool
}

func watch(c conversation.Circuit) *watched {
	w := &watched{Circuit: c, out: make(chan []byte), quit: make(chan struct{})}
	go w.pass(c.Replies())
	return w
}

func (w *watched) pass(in <-chan []byte) {
	defer close(w.out)
	for {
		select {
		case b, ok := <-in:
			if !ok {
				return
			}
			w.answered.Store(true)
			select {
			case w.out <- b:
			case <-w.quit:
				return
			}
		case <-w.quit:
			return
		}
	}
}

func (w *watched) Replies() <-chan []byte { return w.out }

func (w *watched) Close() error {
	w.once.Do(func() { close(w.quit) })
	return w.Circuit.Close()
}
