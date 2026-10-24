package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"maps"
	"math"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

// a peer that is missing or due is asked again this soon and no sooner, so one
// that answers late does not keep the node from extending for a whole refresh
// period, and no state of the cache makes the node ask without a pause
const peerRetry = 5 * time.Second

// the pause for a peer whose last entry ran out with its certificate
const expiredRetry = maxCheckEvery

// the consistency check reads the mirrors of this many roster peers per pass,
// drawn at random, so its cost stays flat as the roster grows
const (
	crossPeers        = 4
	defaultCrossEvery = time.Minute
	minCrossEvery     = 30 * time.Second
	maxCrossEvery     = time.Hour
	// an epoch is forgotten this many passes after it expired for every clock:
	// time enough for a proof against it to reach every node of a large roster
	forgetPasses = 8
)

// what a failed check of a peer's bundle is reported as
var pkiFailures = []error{
	pki.ErrFormat, pki.ErrVersion, pki.ErrSuite, pki.ErrUnknownCA, pki.ErrCertSignature, pki.ErrCertTime,
	pki.ErrWrongAddr, pki.ErrCertMismatch, pki.ErrDescSignature, pki.ErrDescTime, pki.ErrDescLife, pki.ErrKeySize,
	pki.ErrDuplicate, pki.ErrNoConflict,
}

// why a peer's descriptor was not taken, as one of a fixed set of texts: the
// cause goes to the log and stays in the cache, and an error itself may carry
// bytes the peer chose or the ports of one connection
func failureClass(err error, otherwise string) string {
	var status *fetch.StatusError
	switch {
	case errors.As(err, &status):
		return fmt.Sprintf("answered status %d", status.Code)
	case errors.Is(err, fetch.ErrTooLarge):
		return fetch.ErrTooLarge.Error()
	}
	for _, known := range pkiFailures {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return otherwise
}

func peerFetcher(web *http.Client, infoPort string) func(addr string) ([]byte, error) {
	return func(addr string) ([]byte, error) {
		url, err := fetch.URL(addr, infoPort, "/descriptor")
		if err != nil {
			return nil, err
		}
		return fetch.Bundle(web, url, 1, 0)
	}
}

// the mirror of a peer over the path nodes use, so the counters tell peer
// traffic from the requests of clients
func mirrorFetcher(web *http.Client, infoPort string) func(addr string) ([]pki.MirrorEntry, error) {
	return func(addr string) ([]pki.MirrorEntry, error) {
		url, err := fetch.URL(addr, infoPort, "/descriptors/peer")
		if err != nil {
			return nil, err
		}
		return fetch.Mirror(web, url, 1, 0)
	}
}

// which k of n peers a pass reads: drawn here, so whom a node asks says
// nothing about what it holds
func drawPeers(n, k int) ([]int, error) {
	return client.Choose(n, k, rand.Reader)
}

var (
	errRosterEarly = errors.New("no certificate installed: the roster follows the certificate")
	errRosterLate  = fmt.Errorf("roster refused: it is accepted within %v of the certificate", pki.InstallWindow)
	errRosterSet   = errors.New("roster already installed: a new one needs a relay restart")
	errRosterSelf  = errors.New("roster does not list this node under its name and address")
	errNoBundle    = errors.New("no valid descriptor to check the roster's anchor against")
)

type peerEntry struct {
	bundle []byte
	peer   relay.Peer
	// the statement the bundle makes, with the consistency check on: what a
	// later statement of the peer has to be newer than to replace the entry
	stmt *pki.Verified
	// unix seconds: when a client may take the bundle, the later of the
	// descriptor's published time and the certificate's not_before, when the
	// bundle is fetched again and when it is dropped
	from    int64
	due     int64
	expires int64
	// the descriptor runs out with its certificate: the peer signs none that
	// lasts longer, and none at all once the certificate has run out
	final bool
}

// what the info port serves as /descriptors, with the moment the next bundle
// leaves or joins it; no body until this node's own bundle starts
type mirror struct {
	body  []byte
	until int64
}

// the bundles of the other roster nodes, fetched and checked by this node:
// public data, kept in memory only
type peerCache struct {
	p      jcrypto.CryptoProvider
	self   string
	addrs  []string
	listed map[string]bool
	// the bundle this node serves itself, when it starts and when it runs out
	own    func(now int64) ([]byte, int64, int64, bool)
	fetch  func(addr string) ([]byte, error)
	read   func(addr string, bundle []byte, now time.Time) (*peerEntry, error)
	now    func() time.Time
	retry  time.Duration
	logger *log.Logger

	// the consistency check: every statement of a peer goes into its record,
	// the mirrors of other peers are read once a period, and a peer whose
	// statements break a rule is refused with the pair as proof
	check       bool
	trust       pki.Policy
	fetchMirror func(addr string) ([]pki.MirrorEntry, error)
	draw        func(n, k int) ([]int, error)
	crossEvery  time.Duration

	mu      sync.Mutex
	entries map[string]*peerEntry
	// the class of the last failure per peer, so a peer that stays down for one
	// reason is one line
	failed map[string]string
	// the classes of what went wrong with the mirror of a peer at the last
	// pass that read it, one line per class while it stays
	failedMirror map[string]map[string]bool
	// whether the mirror of a peer was seen carrying a proof against this node
	accused bool
	records map[string]*verify.Record
	refused map[string]*pki.Conflict
	// on the running clock: the pass keeps its cadence whatever the wall says
	lastCross time.Time

	mirror atomic.Pointer[mirror]
}

func newPeerCache(n *node, addrs []string, read func(string, []byte, time.Time) (*peerEntry, error)) *peerCache {
	retry := n.peerRetry
	if retry <= 0 {
		retry = peerRetry
	}
	every := n.crossEvery
	if every <= 0 {
		every = defaultCrossEvery
	}
	draw := n.drawPeers
	if draw == nil {
		draw = drawPeers
	}
	listed := make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		listed[addr] = true
	}
	return &peerCache{
		p:            n.p,
		self:         n.addr,
		addrs:        addrs,
		listed:       listed,
		own:          n.current,
		fetch:        n.fetchPeer,
		read:         read,
		now:          n.now,
		retry:        retry,
		logger:       n.logger,
		check:        n.check,
		trust:        n.trust,
		fetchMirror:  n.fetchMirror,
		draw:         draw,
		crossEvery:   every,
		entries:      make(map[string]*peerEntry, len(addrs)),
		failed:       make(map[string]string),
		failedMirror: make(map[string]map[string]bool),
		records:      make(map[string]*verify.Record, len(addrs)),
		refused:      make(map[string]*pki.Conflict),
		lastCross:    time.Now(),
	}
}

// a client checks a bundle on its own clock, up to Skew ahead of this node's,
// once the mirror has arrived, up to fetch.Timeout after the check here, which
// reads whole seconds: the mirror holds a peer's bundle only while such a
// clock finds it valid, whatever lifetime the peer signed it for
const mirrorMargin = pki.Skew + fetch.Timeout + time.Second

// on the from edge a clock up to Skew behind this node's is covered by the
// verifier's allowance, so the node's own clock decides there
func (c *peerCache) mirrored(e *peerEntry, now int64) bool {
	return now >= e.from && now < e.expires-int64(mirrorMargin/time.Second)
}

// Verify bounds the descriptor by its certificate, so expires alone ends the entry
func verifiedPeer(p jcrypto.CryptoProvider, pol pki.Policy) func(string, []byte, time.Time) (*peerEntry, error) {
	return func(addr string, bundle []byte, now time.Time) (*peerEntry, error) {
		peer, err := verify.Peer(p, pol, addr, bundle, now)
		if err != nil {
			return nil, err
		}
		s, err := servedFrom(bundle)
		if err != nil {
			return nil, err
		}
		e := &peerEntry{
			bundle:  bundle,
			peer:    peer,
			from:    max(s.published, s.notBefore),
			due:     s.published + (s.expires-s.published)/2,
			expires: s.expires,
			final:   s.expires >= s.notAfter,
		}
		if e.final {
			// no later descriptor of the peer ends later, and the peer holds a
			// replaced onion key until every descriptor naming it has run out
			e.due = e.expires
		}
		return e, nil
	}
}

// the baseline without node authentication: an unsigned bundle carries no
// times, so it is fetched again every minute and never runs out
func unverifiedPeer(p jcrypto.CryptoProvider) func(string, []byte, time.Time) (*peerEntry, error) {
	return func(addr string, bundle []byte, now time.Time) (*peerEntry, error) {
		peer, err := verify.UnverifiedPeer(p, addr, bundle)
		if err != nil {
			return nil, err
		}
		return &peerEntry{bundle: bundle, peer: peer, due: now.Add(maxCheckEvery).Unix(), expires: math.MaxInt64}, nil
	}
}

// reports whether every peer that is not refused is held afterwards
func (c *peerCache) refresh() bool {
	for _, addr := range c.addrs {
		now := c.now()
		c.mu.Lock()
		e := c.entries[addr]
		_, refused := c.refused[addr]
		c.mu.Unlock()
		// due is not after expires, so an entry that ran out is asked for again,
		// except a final one after its pause
		if refused || e != nil && now.Unix() < e.due {
			continue
		}
		cause := ""
		if bundle, err := c.fetch(addr); err != nil {
			cause = failureClass(err, "no answer")
		} else {
			cause = c.take(addr, bundle, now)
		}
		c.mu.Lock()
		if cause != "" {
			// the entry held so far stays until it runs out
			if e != nil && e.final && now.Unix() >= e.expires {
				// a node takes one certificate per process and enroll discards the CA
				// key, so no new bundle of this peer is expected to verify under the
				// roster's anchor
				spent := *e
				spent.due = now.Add(expiredRetry).Unix()
				c.entries[addr] = &spent
			}
			if c.failed[addr] != cause {
				c.failed[addr] = cause
				c.logger.Printf("peer %s: descriptor: %s", addr, cause)
			}
		} else {
			delete(c.failed, addr)
		}
		c.mu.Unlock()
	}
	c.publish()
	c.mu.Lock()
	refused := len(c.refused)
	c.mu.Unlock()
	return c.held() == len(c.addrs)-refused
}

// a bundle of a roster peer, fetched from it or read in a mirror. With the
// check on it is first a statement for the peer's record, whose conflict
// refuses the peer; then, live and newer than the held entry, it becomes the
// entry. The result is the failure class, empty when the bundle was taken or
// is simply not newer
func (c *peerCache) take(addr string, bundle []byte, now time.Time) string {
	c.mu.Lock()
	e := c.entries[addr]
	same := c.check && e != nil && now.Unix() < e.expires && bytes.Equal(e.bundle, bundle)
	c.mu.Unlock()
	// the bundle held and still live: nothing to verify or compare, the peer
	// stays due. One that ran out goes through the check, which names the
	// class and sets the pause; an unsigned bundle carries no times, so the
	// baseline takes it again to set the next minute
	if same {
		return ""
	}
	var stmt *pki.Verified
	if c.check {
		v, err := pki.VerifyStatement(c.p, c.trust, addr, bundle)
		if err != nil {
			return failureClass(err, "not verified")
		}
		c.mu.Lock()
		conflict, admitted := c.record(addr).Take(bundle, v, now)
		c.mu.Unlock()
		if conflict != nil {
			c.refuse(addr, conflict)
			return ""
		}
		if !admitted {
			return pki.ErrDescTime.Error()
		}
		stmt = v
	}
	fresh, err := c.read(addr, bundle, now)
	if err != nil {
		return failureClass(err, "not verified")
	}
	fresh.stmt = stmt
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, refused := c.refused[addr]; refused {
		return ""
	}
	// read again: the refresh may have replaced the entry meanwhile
	e = c.entries[addr]
	if c.check && e != nil && e.stmt != nil && !verify.Newer(e.stmt, stmt) {
		// the peer stays due and is asked again after the retry pause
		return ""
	}
	// a bundle the mirror cannot hold yet does not displace one it holds
	if e == nil || c.mirrored(fresh, now.Unix()) || !c.mirrored(e, now.Unix()) {
		c.entries[addr] = fresh
		if c.check {
			c.record(addr).Hold(stmt.Epoch)
		}
	}
	return ""
}

// callers hold mu
func (c *peerCache) record(addr string) *verify.Record {
	r := c.records[addr]
	if r == nil {
		r = verify.NewRecord(pki.Skew, time.Duration(forgetPasses)*c.crossEvery)
		c.records[addr] = r
	}
	return r
}

// a peer whose statements broke a rule: out of the cache, out of the mirror
// in favour of the proof, and asked for nothing again. One line, with the
// rule and never a byte the peer sent
func (c *peerCache) refuse(addr string, conflict *pki.Conflict) {
	c.mu.Lock()
	if _, done := c.refused[addr]; done {
		c.mu.Unlock()
		return
	}
	c.refused[addr] = conflict
	delete(c.entries, addr)
	delete(c.failed, addr)
	delete(c.failedMirror, addr)
	c.mu.Unlock()
	c.logger.Printf("peer %s: refused: %s", addr, conflict.Rule)
	c.publish()
}

func (c *peerCache) isRefused(addr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, refused := c.refused[addr]
	return refused
}

// one pass of the consistency check: the mirrors of up to crossPeers peers,
// drawn among those not refused, every item of a roster peer fed to that
// peer's record, a newer live statement adopted, a proof verified and acted on
func (c *peerCache) cross() {
	c.mu.Lock()
	candidates := make([]string, 0, len(c.addrs))
	for _, addr := range c.addrs {
		if _, refused := c.refused[addr]; !refused {
			candidates = append(candidates, addr)
		}
	}
	c.mu.Unlock()
	if len(candidates) == 0 {
		return
	}
	picked, err := c.draw(len(candidates), min(crossPeers, len(candidates)))
	if err != nil {
		c.logger.Printf("consistency pass: %v", err)
		return
	}
	for _, i := range picked {
		q := candidates[i]
		// refused by a proof read earlier in this pass
		if c.isRefused(q) {
			continue
		}
		entries, err := c.fetchMirror(q)
		if err != nil {
			c.mirrorOutcome(q, map[string]bool{failureClass(err, "no answer"): true})
			continue
		}
		// the clock after the fetch: a pass may spend a timeout per peer
		now := c.now()
		causes := map[string]bool{}
		for _, it := range entries {
			if got := c.takeItem(it, now); got != "" {
				causes[got] = true
			}
		}
		c.mirrorOutcome(q, causes)
	}
	// what the pass adopted goes into the mirror now, not at the next refresh
	c.publish()
}

// the classes of what went wrong with the mirror of a peer at this pass: one
// line per class that was not there at the pass before, none while they stay
func (c *peerCache) mirrorOutcome(q string, causes map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(causes) == 0 {
		delete(c.failedMirror, q)
		return
	}
	before := c.failedMirror[q]
	for _, cause := range slices.Sorted(maps.Keys(causes)) {
		if !before[cause] {
			c.logger.Printf("peer %s: mirror: %s", q, cause)
		}
	}
	c.failedMirror[q] = causes
}

// an item of a mirror about a roster peer other than this node; the result is
// the failure class, empty when the item was taken or skipped
func (c *peerCache) takeItem(it pki.MirrorEntry, now time.Time) string {
	if it.Addr == c.self {
		c.accusation(it)
		return ""
	}
	if !c.listed[it.Addr] || c.isRefused(it.Addr) {
		return ""
	}
	if it.Proof == nil {
		return c.take(it.Addr, it.Bundle, now)
	}
	conflict, a, b, err := pki.VerifyProof(c.p, c.trust, it.Addr, *it.Proof)
	if err != nil {
		if errors.Is(err, pki.ErrNoConflict) {
			// two statements the peer made all the same
			for _, b := range [][]byte{it.Proof.A, it.Proof.B} {
				c.take(it.Addr, b, now)
			}
		}
		return pki.ErrNoConflict.Error()
	}
	// the conflict comes out of the record of this node, as if it had fetched
	// both bundles: what it publishes is a proof it verified, not one it copied
	c.mu.Lock()
	found := c.record(it.Addr).TakeProof(conflict, a, b)
	c.mu.Unlock()
	c.refuse(it.Addr, found)
	return ""
}

// a proof against this node in the mirror of a peer is the one sign its
// operator gets that the peers refuse it: one line for the process, the rule
// and no byte of the proof
func (c *peerCache) accusation(it pki.MirrorEntry) {
	if it.Proof == nil {
		return
	}
	conflict, err := pki.VerifyConflict(c.p, c.trust, c.self, *it.Proof)
	if err != nil {
		return
	}
	c.mu.Lock()
	first := !c.accused
	c.accused = true
	c.mu.Unlock()
	if first {
		c.logger.Printf("a peer serves a proof against this node: %s", conflict.Rule)
	}
}

func (c *peerCache) forget() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.records {
		r.Forget(now)
	}
}

// whether a pass is due on the running clock, and how long until the next
func (c *peerCache) crossDue() (bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	left := c.crossEvery - time.Since(c.lastCross)
	return left <= 0, max(left, 0)
}

func (c *peerCache) crossed() {
	c.mu.Lock()
	c.lastCross = time.Now()
	c.mu.Unlock()
}

// encoded here, on a refresh, on a refusal or when this node signs its own
// descriptor again, so a request for the descriptors only copies bytes
func (c *peerCache) publish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix()
	own, from, until, ok := c.own(now)
	switch {
	case !ok:
		c.mirror.Store(nil)
		return
	case now < from:
		c.mirror.Store(&mirror{until: from})
		return
	}
	entries := make([]pki.MirrorEntry, 0, len(c.addrs)+1)
	entries = append(entries, pki.MirrorEntry{Addr: c.self, Bundle: own})
	// a peer whose bundle this node does not hold is left out: were the mirror
	// to wait for every roster node, one node that withholds its descriptor
	// would empty the mirror of every node it withholds from
	for _, addr := range c.addrs {
		e := c.entries[addr]
		switch {
		case e == nil:
		case now < e.from:
			until = min(until, e.from)
		case c.mirrored(e, now):
			entries = append(entries, pki.MirrorEntry{Addr: addr, Bundle: e.bundle})
			until = min(until, e.expires-int64(mirrorMargin/time.Second))
		}
	}
	// a refused peer is listed by the proof against it, which every reader
	// verifies under its own anchor
	for addr, conflict := range c.refused {
		entries = append(entries, pki.MirrorEntry{Addr: addr, Proof: &conflict.Proof})
	}
	body, err := pki.MarshalMirror(entries)
	if err != nil {
		c.logger.Printf("descriptors: %v", err)
		c.mirror.Store(nil)
		return
	}
	c.mirror.Store(&mirror{body: body, until: until})
}

// until the next refresh: the nearest moment an entry is due, at most a minute
// because the timer runs on the monotonic clock while ages are read off the
// wall clock, and never less than the retry pause, which is also the wait while
// a peer is missing, unless its last entry ran out with its certificate
func (c *peerCache) wait() time.Duration {
	now := c.now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	wait := maxCheckEvery
	for _, addr := range c.addrs {
		if _, refused := c.refused[addr]; refused {
			continue
		}
		e := c.entries[addr]
		if e == nil || e.due <= now {
			return c.retry
		}
		if left := e.due - now; left < int64(wait/time.Second) {
			wait = time.Duration(left) * time.Second
		}
	}
	return max(wait, c.retry)
}

func (c *peerCache) peer(addr string) (relay.Peer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[addr]
	if e == nil || c.now().Unix() >= e.expires {
		return relay.Peer{}, false
	}
	return e.peer, true
}

func (c *peerCache) held() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix()
	held := 0
	for _, e := range c.entries {
		if now < e.expires {
			held++
		}
	}
	return held
}

func (c *peerCache) refusedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.refused)
}

func (c *peerCache) descriptors() ([]byte, bool) {
	m := c.mirror.Load()
	if m != nil && c.now().Unix() >= m.until {
		// a bundle left or joined since the last refresh: the mirror is rebuilt here
		// once and lasts until the next such moment
		c.publish()
		m = c.mirror.Load()
	}
	if m == nil || m.body == nil || c.now().Unix() >= m.until {
		return nil, false
	}
	return m.body, true
}

// what relay.Config.Peers asks: before a roster there is no peer at all
func (n *node) peerKey(addr string) (relay.Peer, bool) {
	c := n.peers.Load()
	if c == nil {
		return relay.Peer{}, false
	}
	return c.peer(addr)
}

// the roster size, how many of the other nodes are held and how many are
// refused by proof
func (n *node) peerState() (roster, held, refused int) {
	c := n.peers.Load()
	if c == nil {
		return 0, 0, 0
	}
	return len(c.addrs) + 1, c.held(), c.refusedCount()
}

func (n *node) setPeers(addrs []string, read func(string, []byte, time.Time) (*peerEntry, error)) {
	c := newPeerCache(n, addrs, read)
	c.publish()
	n.peers.Store(c)
	if n.wake != nil {
		close(n.wake)
	}
}

// peers are fetched on this timer and never because someone asked for the
// descriptors; it starts once the node has peers and ends with stop. With the
// check on, a pass over the mirrors of other peers follows the refresh once a
// period
func (n *node) keepPeers(stop <-chan struct{}) {
	select {
	case <-n.wake:
	case <-stop:
		return
	}
	c := n.peers.Load()
	for {
		c.refresh()
		wait := c.wait()
		if c.check {
			c.forget()
			// stamped before the pass, so passes start one period apart however
			// long the fetches of one take
			if due, _ := c.crossDue(); due {
				c.crossed()
				c.cross()
			}
			_, left := c.crossDue()
			wait = min(wait, left)
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-stop:
			t.Stop()
			return
		}
	}
}

// whoever reaches the loopback port within the window could send a roster, so
// a process takes one and it must name an anchor under which this node's own
// certificate verifies: a roster of another CA is refused. Sending the same
// bytes again succeeds, so a retry after a lost answer does not fail
func (n *node) handleRoster(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	roster, err := pki.ParseRoster(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	switch {
	case n.roster != nil && bytes.Equal(raw, n.roster):
		w.WriteHeader(http.StatusNoContent)
		return
	case n.roster != nil:
		http.Error(w, errRosterSet.Error(), http.StatusConflict)
		return
	case n.installed == nil:
		http.Error(w, errRosterEarly.Error(), http.StatusConflict)
		return
	case now.Sub(n.installedAt) > pki.InstallWindow:
		http.Error(w, errRosterLate.Error(), http.StatusConflict)
		return
	}
	bundle, ok := n.descriptor()
	if !ok {
		http.Error(w, errNoBundle.Error(), http.StatusConflict)
		return
	}
	if !roster.Has(n.name, n.addr) {
		http.Error(w, errRosterSelf.Error(), http.StatusBadRequest)
		return
	}
	pol := pki.Policy{Anchor: roster.Anchor, Skew: pki.Skew}
	if n.check {
		pol.MinLife = pki.MinDescriptorLife
	}
	if _, err := verify.Peer(n.p, pol, n.addr, bundle, now); err != nil {
		http.Error(w, fmt.Sprintf("this node's bundle does not verify under the roster's anchor: %v", err), http.StatusBadRequest)
		return
	}
	addrs := make([]string, 0, len(roster.Nodes)-1)
	for _, node := range roster.Nodes {
		if node.Addr != n.addr {
			addrs = append(addrs, node.Addr)
		}
	}
	n.roster = raw
	n.trust = pol
	n.setPeers(addrs, verifiedPeer(n.p, pol))
	n.logger.Printf("roster installed nodes=%d ca=%x", len(roster.Nodes), roster.Anchor.ID(n.p))
	w.WriteHeader(http.StatusNoContent)
}
