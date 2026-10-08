package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	fetchAttempts = 30
	fetchPause    = time.Second
)

// 1 is any other failure and 2 is what the flag package exits with
const exitRefused = 3

var (
	errNoBundle = errors.New("the entry holds no bundle for it")
	errTooFew   = errors.New("too many listed nodes left out by the entry or not passing the check")
)

func main() {
	nodes := flag.String("nodes", "", "comma separated host:port of the nodes the chain is drawn from, at least -hops of them")
	hops := flag.Int("hops", 3, "nodes in the chain; one setup cell carries at most 4 on c25519 and 3 on gost")
	fixed := flag.Bool("fixed-chain", false, "take the first -hops nodes of -nodes in the listed order instead of drawing the chain at random, for measurements that need a known path")
	infoPort := flag.String("info-port", "9100", "port where the entry publishes the descriptors of every listed node")
	message := flag.String("message", "hello from the chain", "payload to send")
	count := flag.Int("count", 1, "how many messages to send, 0 for endless; with -peer the process goes on fetching and answering after the last")
	interval := flag.Duration("interval", time.Second, "pause between messages; with -peer 0 sends none")
	cover := flag.Duration("cover", 0, "cover traffic added on top of payload, 0 disables it")
	mode := flag.String("mode", "immediate", "immediate or fixed: fixed sends one cell per tick and a payload takes a cover slot")
	rate := flag.Duration("rate", 200*time.Millisecond, "cell period in fixed mode, the request period with -peer")
	jitter := flag.Duration("jitter", 0, "random delay added before each cell")
	suiteName := flag.String("suite", suite.Default.String(), "primitive suite: gost or c25519, must match the nodes")
	harden := flag.Bool("harden", true, "disable core dumps and ptrace access for the process")
	keymem := flag.String("keymem", "all", "key memory measures: all, none, or a list of offheap, lock, dontdump, zero")
	auth := flag.Bool("auth", true, "verify the descriptor of every listed node against -ca before building the circuit; false takes the keys unverified")
	ca := flag.String("ca", "", "trust anchor <suite>:<base64>, the CA public key printed by jimichi enroll")
	skew := flag.Duration("skew", pki.Skew, "tolerated lag of this clock behind the nodes' clocks")
	missing := flag.Int("missing", 1, "listed nodes the entry may leave out of its descriptors, at most the nodes beyond -hops; a listed node whose bundle does not pass the check counts as left out; the chain is drawn among the rest, and the entry's own bundle must pass")
	peer := flag.Bool("peer", false, "talk to one contact through a mailbox at the exit: print card_hash, hand out the card on GET /card of -admin and pin the contact's card on PUT /contact")
	mailboxAddr := flag.String("mailbox", "", "with -peer: host:port of the node of -nodes that keeps the queues of the conversation and ends every chain")
	admin := flag.String("admin", "127.0.0.1:9201", "with -peer: loopback IP literal and port of the admin listener")
	coverPuts := flag.Bool("cover-puts", true, "with -peer: put a record into the contact's queue with every request, a dummy when no message waits, so the mailbox does not see when messages go")
	respond := flag.Bool("respond", false, "with -peer: answer every message of the contact with its number and text")
	handshakeTimeout := flag.Duration("handshake-timeout", 60*time.Second, "with -peer: how long the initiator waits for the answer to its handshake once the mailbox holds it, then starts over")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	if *peer {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		os.Exit(runPeer(peerFlags{
			nodes: *nodes, mailbox: *mailboxAddr, admin: *admin, infoPort: *infoPort,
			suite: *suiteName, keymem: *keymem, ca: *ca, mode: *mode, message: *message,
			hops: *hops, count: *count, missing: *missing,
			fixed: *fixed, auth: *auth, harden: *harden, coverPuts: *coverPuts, respond: *respond,
			rate: *rate, jitter: *jitter, cover: *cover, interval: *interval,
			skew: *skew, handshakeTimeout: *handshakeTimeout,
		}, logger, stop))
	}

	policy, err := secmem.ParsePolicy(*keymem)
	if err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if err := secmem.SetPolicy(policy); err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if *harden {
		if err := secmem.HardenProcess(); err != nil {
			logger.Fatalf("harden: %v", err)
		}
	}
	// the circuit keys come later, so a probe buffer tells now whether locking
	// works at all; a client that asked for it must not run without it
	if policy.Lock {
		probe, err := secmem.New(32)
		if err != nil {
			logger.Fatalf("key memory: %v", err)
		}
		locked := probe.Locked()
		probe.Release()
		if !locked {
			logger.Fatal("key memory is not locked, refusing to start")
		}
	}

	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		logger.Fatal(err)
	}
	provider, err := suite.New(chosen)
	if err != nil {
		logger.Fatal(err)
	}
	addrs := splitList(*nodes)
	if err := checkNodes(provider, addrs, *hops, *infoPort); err != nil {
		logger.Fatal(err)
	}
	trust, err := trustPolicy(*auth, *ca, chosen, *skew)
	if err != nil {
		logger.Fatal(err)
	}
	if !*auth {
		logger.Print("WARNING: -auth=false, node keys are taken unverified from whoever answers the descriptor request")
	}
	if *missing < 0 {
		logger.Fatalf("-missing %d: must not be negative", *missing)
	}
	if *hops == 1 {
		logger.Print("WARNING: -hops 1, a single node sees both the sender and what it sends on")
	}

	sel := selection{
		addrs: addrs, hops: *hops, fixed: *fixed, missing: *missing, infoPort: *infoPort,
		auth: *auth, trust: trust,
		web: fetch.NewClient(), attempts: fetchAttempts, pause: fetchPause,
		rnd: rand.Reader, now: time.Now,
	}
	chain, err := sel.chain(provider, logger)
	if err != nil {
		logger.Fatalf("refusing to build the circuit: %v", err)
	}

	cfg := client.Config{
		Provider:  provider,
		Chain:     chain,
		CoverRate: *cover,
		Jitter:    *jitter,
	}
	if *mode == "fixed" {
		cfg.Mode = client.ConstantRate
		cfg.Rate = *rate
	}

	c, err := client.Dial(cfg)
	if err != nil {
		logger.Fatalf("dial: %s", sel.cause(err))
	}
	// Fatal would skip a deferred Close and leave the circuit keys unzeroed
	exit := func(code int, line string) {
		_ = c.Close()
		logger.Print(line)
		os.Exit(code)
	}
	defer c.Close()

	logger.Printf("circuit of %d hops among %d listed nodes, payload limit %d bytes, mode %s", len(chain), len(addrs), c.MaxPayload(), *mode)

	if code, line := exchange(c, logger, []byte(*message), *count, *interval, sel.cause); code != 0 {
		exit(code, line)
	}
}

type circuit interface {
	Send(payload []byte) error
	Replies() <-chan []byte
	Refused() error
}

// sends count messages, endlessly for 0, and waits for the reply to each. A
// code other than 0 is the end of the circuit and comes with its line
func exchange(c circuit, logger *log.Logger, message []byte, count int, interval time.Duration, cause func(error) string) (code int, line string) {
	for i := 0; count == 0 || i < count; i++ {
		start := time.Now()
		if err := c.Send(message); err != nil {
			// the class is set before the link closes, so a send that failed on
			// that close is reported as the refusal it follows, and a send refused
			// after the link ended as that end
			if refused := c.Refused(); refused != nil || errors.Is(err, client.ErrCircuitClosed) {
				return ending(refused)
			}
			return 1, "send: " + cause(err)
		}
		select {
		case reply, open := <-c.Replies():
			if !open {
				// a dead circuit would otherwise swallow every message silently;
				// exiting lets the orchestrator restart the client on a fresh one
				return ending(c.Refused())
			}
			logger.Printf("round trip %d bytes in %s", len(reply), time.Since(start).Round(time.Microsecond))
		case <-time.After(5 * time.Second):
			logger.Print("no reply within 5s")
		}
		if count == 0 || i+1 < count {
			time.Sleep(interval)
		}
	}
	return 0, ""
}

// the line of a refusal names the check the reply failed and nothing of the
// circuit; the plain line is any other end and does not mean an honest path
func ending(refused error) (code int, line string) {
	if refused != nil {
		return exitRefused, "circuit closed: " + refused.Error()
	}
	return 1, "circuit closed"
}

func splitList(s string) []string {
	out := make([]string, 0, 3)
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// settled before any network request and before anything is drawn: a list the
// client cannot build a chain from must fail the same way at every start, not
// only when the draw reaches the bad entry
func checkNodes(p jcrypto.CryptoProvider, addrs []string, hops int, infoPort string) error {
	if len(addrs) == 0 {
		return errors.New("no nodes given")
	}
	limit, err := wire.MaxLayers(p)
	if err != nil {
		return err
	}
	switch {
	case hops < 1:
		return fmt.Errorf("-hops %d: want at least 1", hops)
	case hops > limit:
		return fmt.Errorf("-hops %d: a setup cell of suite %s carries at most %d hops", hops, p.Suite(), limit)
	case len(addrs) < hops:
		return fmt.Errorf("-nodes lists %d nodes, -hops %d needs at least as many", len(addrs), hops)
	case !pki.ValidPort(infoPort):
		return fmt.Errorf("-info-port %q: want a port number", infoPort)
	}
	// the refusals name a place in the list and not the address, which a -peer
	// client never writes to its log
	seen := make(map[string]int, len(addrs))
	for i, addr := range addrs {
		if !pki.ValidAddr(addr) {
			return fmt.Errorf("-nodes: node %d: want host:port in printable ASCII, lower case, at most %d bytes", i+1, wire.AddrSize)
		}
		if first, ok := seen[addr]; ok {
			return fmt.Errorf("-nodes: node %d repeats node %d", i+1, first)
		}
		seen[addr] = i + 1
	}
	return nil
}

// settled before any network request, so a client that cannot check what it
// fetches never asks for it
func trustPolicy(auth bool, ca string, s jcrypto.Suite, skew time.Duration) (pki.Policy, error) {
	if !auth {
		return pki.Policy{}, nil
	}
	if ca == "" {
		return pki.Policy{}, errors.New("-auth needs -ca, the anchor printed by jimichi enroll")
	}
	anchor, err := pki.ParseAnchor(ca)
	if err != nil {
		return pki.Policy{}, fmt.Errorf("-ca: %w", err)
	}
	if anchor.Suite != s {
		return pki.Policy{}, fmt.Errorf("-ca is an anchor for suite %s, the client runs %s: %w", anchor.Suite, s, pki.ErrSuite)
	}
	if skew < 0 {
		return pki.Policy{}, fmt.Errorf("-skew %v: must not be negative", skew)
	}
	return pki.Policy{Anchor: anchor, Skew: skew}, nil
}

// how the chain is taken from the listed nodes
type selection struct {
	addrs []string
	hops  int
	fixed bool
	// listed nodes the entry may leave out of its descriptors
	missing  int
	infoPort string
	auth     bool
	trust    pki.Policy
	web      *http.Client
	attempts int
	pause    time.Duration
	rnd      io.Reader
	now      func() time.Time
}

// the entry is drawn first and asked for the bundles of every listed node, so
// the request is the same whatever path follows; the other hops are drawn only
// once the bundles the entry served have been checked. Nothing here logs the
// entry or any other node of the path: the lines are the same for every draw
func (s selection) chain(p jcrypto.CryptoProvider, logger *log.Logger) ([]client.Node, error) {
	entry := 0
	if !s.fixed {
		var err error
		if entry, err = client.ChooseEntry(len(s.addrs), s.rnd); err != nil {
			return nil, err
		}
	}
	view, err := s.mirror(p, entry)
	if err != nil {
		return nil, s.named(err)
	}
	nodes, at := view.nodes, view.at
	if err := s.enough(view, entry); err != nil {
		return nil, err
	}
	if s.auth {
		for _, v := range nodes {
			// the entry's own descriptor is the freshest in its mirror, so its time
			// stays out of the log unless the chain is fixed anyway
			if s.fixed {
				logger.Printf("node %s identity=%s certificate until %s, descriptor until %s",
					v.Name, pki.Fingerprint(p, v.Identity),
					v.CertUntil.UTC().Format(time.RFC3339), v.DescUntil.UTC().Format(time.RFC3339))
				continue
			}
			logger.Printf("node %s identity=%s certificate until %s",
				v.Name, pki.Fingerprint(p, v.Identity), v.CertUntil.UTC().Format(time.RFC3339))
		}
	}
	if s.auth {
		logger.Printf("%d of %d listed nodes verified", len(nodes), len(s.addrs))
	}
	path := make([]int, s.hops)
	for i := range path {
		path[i] = at[i]
	}
	if !s.fixed {
		if path, err = client.ChooseRest(at[entry], len(nodes), s.hops, s.rnd); err != nil {
			return nil, err
		}
	}
	return chainOf(nodes, path), nil
}

// the nodes of an entry's mirror whose bundles pass the check
type mirrorView struct {
	nodes []pki.Verified
	// position in nodes of every listed node, or -1
	at []int
	// listed index of every node in nodes
	listed []int
	// why a served bundle of a listed node did not pass
	failed []error
}

// the entry lists a bundle from the moment its own clock reaches the bundle's
// start, so the time is read once the mirror is here, after any retries. Every
// bundle is read on its own, and one that does not pass is a node left out
// like one the entry does not serve; bundles are not compared with each other,
// since the setup and the link of a node bind its own identity
func (s selection) mirror(p jcrypto.CryptoProvider, entry int) (mirrorView, error) {
	bundles, err := nodeBundles(s.web, s.addrs, entry, s.infoPort, s.attempts, s.pause)
	if err != nil {
		return mirrorView{}, err
	}
	now := s.now()
	v := mirrorView{at: make([]int, len(s.addrs)), failed: make([]error, len(s.addrs))}
	for i, b := range bundles {
		v.at[i] = -1
		if b == nil {
			continue
		}
		node, err := readNode(p, s.auth, s.trust, s.addrs[i], b, now)
		if err != nil {
			v.failed[i] = err
			continue
		}
		v.at[i] = len(v.nodes)
		v.nodes = append(v.nodes, *node)
		v.listed = append(v.listed, i)
	}
	return v, nil
}

// why listed node i is not usable
func (v mirrorView) missing(i int) error {
	if v.failed[i] != nil {
		return v.failed[i]
	}
	return errNoBundle
}

func (v mirrorView) usable() []bool {
	usable := make([]bool, len(v.at))
	for i, place := range v.at {
		usable[i] = place >= 0
	}
	return usable
}

// a mirror that waits for every node would let one node that withholds its
// descriptor empty the mirrors of all the others, so the entry may leave out a
// bounded number of nodes, and a fixed chain needs exactly its own
func (s selection) enough(v mirrorView, entry int) error {
	if s.fixed {
		for i := 0; i < s.hops; i++ {
			if v.at[i] < 0 {
				return fmt.Errorf("node %s: %w", s.addrs[i], v.missing(i))
			}
		}
		return nil
	}
	switch verdict, absent, allowed := client.JudgeMirror(v.usable(), entry, s.hops, s.missing); verdict {
	case client.MirrorTaken:
		return nil
	case client.MirrorLacksEntry:
		// the client connects to the entry, so it needs the entry's own bundle
		// to pass
		return &entryError{v.missing(entry)}
	default:
		return fmt.Errorf("%w: %d of %d listed nodes, at most %d may be", errTooFew, absent, len(s.addrs), allowed)
	}
}

// with a fixed chain the entry is the first listed node, which the
// configuration already says, so its failure is reported in full
func (s selection) named(err error) error {
	var failed *entryError
	if s.fixed && errors.As(err, &failed) {
		return fmt.Errorf("node %s: %w", s.addrs[0], failed.err)
	}
	return err
}

// what a failure on the circuit is reported as: with a drawn chain only its
// class, since the error of a connection names the entry it was made to
func (s selection) cause(err error) string {
	if s.fixed {
		return err.Error()
	}
	return failureClass(err)
}

// a request to the entry that failed. The entry is the first node of the
// path, so the text carries neither its address nor the error itself, which
// names the address dialled
type entryError struct{ err error }

func (e *entryError) Error() string { return "the entry: " + failureClass(e.err) }

func (e *entryError) Unwrap() error { return e.err }

var knownFailures = []error{
	errNoBundle, fetch.ErrTooLarge,
	pki.ErrFormat, pki.ErrVersion, pki.ErrDuplicate, pki.ErrSuite, pki.ErrUnknownCA, pki.ErrCertSignature, pki.ErrCertTime,
	pki.ErrWrongAddr, pki.ErrCertMismatch, pki.ErrDescSignature, pki.ErrDescTime, pki.ErrKeySize,
	link.ErrHandshake, client.ErrNodeKey, wire.ErrPayloadSize,
}

// one of a fixed set of texts, none of which names a node
func failureClass(err error) string {
	var status *fetch.StatusError
	if errors.As(err, &status) {
		return status.Error()
	}
	for _, known := range knownFailures {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "timed out"
	}
	return "connection failed"
}

// every bundle comes from the entry, the one node the client connects to
// anyway; each is verified afterwards, so the entry can withhold a bundle, and
// one it alters counts as withheld
func nodeBundles(web *http.Client, addrs []string, entry int, infoPort string, attempts int, pause time.Duration) ([][]byte, error) {
	url, err := fetch.URL(addrs[entry], infoPort, "/descriptors")
	if err != nil {
		return nil, &entryError{err}
	}
	entries, err := fetch.Mirror(web, url, attempts, pause)
	if err != nil {
		return nil, &entryError{err}
	}
	held := make(map[string][]byte, len(entries))
	for _, e := range entries {
		held[e.Addr] = e.Bundle
	}
	// a listed node the entry does not serve stays nil
	bundles := make([][]byte, len(addrs))
	for i, addr := range addrs {
		bundles[i] = held[addr]
	}
	return bundles, nil
}

func readNode(p jcrypto.CryptoProvider, auth bool, trust pki.Policy, addr string, bundle []byte, now time.Time) (*pki.Verified, error) {
	if auth {
		return pki.Verify(p, trust, addr, bundle, now)
	}
	return pki.Unverified(p, addr, bundle)
}

// the identity is empty without authentication, and then nothing binds one
func chainOf(nodes []pki.Verified, path []int) []client.Node {
	chain := make([]client.Node, len(path))
	for i, node := range path {
		v := nodes[node]
		chain[i] = client.Node{Addr: v.Addr, StaticPub: v.OnionPub, LinkPub: v.LinkPub, Identity: v.Identity}
	}
	return chain
}
