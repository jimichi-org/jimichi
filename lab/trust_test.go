package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	mrand "math/rand"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

const (
	trustNodes   = 5 // the testbed's five relays
	trustHops    = 3
	trustMissing = 1 // cmd/client's default -missing
	trustForeign = 4 // relay-5, certified by the second CA
	trustSeed    = 1
	trustSamples = 3000
	trustShort   = 300
	trustLevel   = 0.95
	trustMargin  = 0.05
	trustAtOnce  = 8
)

type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

var plainDial dialFunc = (&net.Dialer{}).DialContext

type trustRelay struct {
	name, addr string
	bundle     []byte
	identity   []byte
	linkPub    []byte
	relay      *relay.Relay
	links      atomic.Int64
	mu         sync.Mutex
	dials      map[string]int
	peers      map[string]relay.Peer
	refused    map[string]error
	mirror     []byte
}

type trustStand struct {
	p               jcrypto.CryptoProvider
	at              time.Time
	session, second *pki.CA
	relays          []*trustRelay
	addrs           []string
}

// onward is the dial each relay's counting hook ends in
func startTrustStand(t *testing.T, s jcrypto.Suite, onward dialFunc) *trustStand {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	st := &trustStand{p: p, at: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), session: mustCA(t, p), second: mustCA(t, p)}
	listeners := make([]net.Listener, trustNodes)
	for i := range listeners {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		tr := &trustRelay{name: fmt.Sprintf("relay-%d", i+1), addr: ln.Addr().String(), dials: map[string]int{}}
		listeners[i] = countingListener{Listener: ln, accepted: &tr.links}
		st.relays = append(st.relays, tr)
		st.addrs = append(st.addrs, tr.addr)
	}
	configs := make([]relay.Config, trustNodes)
	for i, tr := range st.relays {
		ca := st.session
		if i == trustForeign {
			ca = st.second
		}
		configs[i] = st.enroll(t, tr, ca)
	}
	for x, tr := range st.relays {
		// the anchor its roster would name: cmd/relay refuses a roster under
		// whose anchor its own bundle does not verify
		anchor := st.session.Anchor()
		if x == trustForeign {
			anchor = st.second.Anchor()
		}
		tr.peers, tr.refused = map[string]relay.Peer{}, map[string]error{}
		for y, other := range st.relays {
			if y == x {
				continue
			}
			peer, err := verify.Peer(p, anchor, other.addr, other.bundle, st.at)
			if err != nil {
				tr.refused[other.addr] = err
				continue
			}
			tr.peers[other.addr] = peer
		}
		entries := []pki.MirrorEntry{{Addr: tr.addr, Bundle: tr.bundle}}
		for _, other := range st.relays {
			if _, held := tr.peers[other.addr]; held {
				entries = append(entries, pki.MirrorEntry{Addr: other.addr, Bundle: other.bundle})
			}
		}
		if tr.mirror, err = pki.MarshalMirror(entries); err != nil {
			t.Fatal(err)
		}
	}
	for i, tr := range st.relays {
		cfg := configs[i]
		cfg.Peers = func(addr string) (relay.Peer, bool) {
			peer, ok := tr.peers[addr]
			return peer, ok
		}
		cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			tr.mu.Lock()
			tr.dials[addr]++
			tr.mu.Unlock()
			return onward(ctx, network, addr)
		}
		r, err := relay.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		tr.relay = r
		ln := listeners[i]
		go func() { _ = r.Serve(ln) }()
		t.Cleanup(func() {
			r.Close()
			_ = ln.Close()
		})
	}
	return st
}

// the keys of cmd/relay with its default -onion-rotate, a link key and an
// onion key apart, and the certificate the steps of jimichi enroll give
func (st *trustStand) enroll(t *testing.T, tr *trustRelay, ca *pki.CA) relay.Config {
	t.Helper()
	p := st.p
	linkPriv, linkPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(linkPriv.Release)
	onionPriv, onionPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := relay.NewOnionRing(p, onionPriv, onionPub, 0)
	if err != nil {
		onionPriv.Release()
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	id, err := pki.NewIdentity(p, tr.name, tr.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	var nonce [pki.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := id.Request(nonce)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Check(p, nonce, tr.name, tr.addr); err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(req, st.at, st.at.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), st.at); err != nil {
		t.Fatal(err)
	}
	id.SetKeys(linkPub, onionPub, 0)
	if err := id.Refresh(st.at, time.Hour); err != nil {
		t.Fatal(err)
	}
	bundle, ok := id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	tr.bundle, tr.identity, tr.linkPub = bundle, id.Public(), linkPub
	return relay.Config{
		Provider:   p,
		StaticPriv: linkPriv,
		StaticPub:  linkPub,
		Identity:   tr.identity,
		Onion:      ring,
		Deliver:    func(_ uint64, payload []byte) []byte { return payload },
		// every connection comes from the loopback address, as in the harness
		MaxHandshakesPerSource: -1,
		MaxLinksPerSource:      -1,
		SourceLinkRate:         -1,
		SourceSetupRate:        -1,
	}
}

// as cmd/client nodeBundles: ParseMirror, then by address, nil where absent
func (st *trustStand) bundlesOf(t *testing.T, entry int) [][]byte {
	t.Helper()
	entries, err := pki.ParseMirror(st.relays[entry].mirror)
	if err != nil {
		t.Fatal(err)
	}
	held := make(map[string][]byte, len(entries))
	for _, e := range entries {
		held[e.Addr] = e.Bundle
	}
	bundles := make([][]byte, len(st.addrs))
	for i, addr := range st.addrs {
		bundles[i] = held[addr]
	}
	return bundles
}

func (st *trustStand) view(t *testing.T, anchor pki.Anchor, entry int) verify.View {
	t.Helper()
	v, err := verify.Mirror(st.p, true, pki.Policy{Anchor: anchor, Skew: pki.Skew}, st.addrs, st.bundlesOf(t, entry), st.at)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (st *trustStand) counters() []relay.Counters {
	out := make([]relay.Counters, len(st.relays))
	for i, tr := range st.relays {
		out[i] = tr.relay.Stats().Snapshot()
	}
	return out
}

func (st *trustStand) dialled(from, to int) int {
	tr := st.relays[from]
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.dials[st.addrs[to]]
}

type countingListener struct {
	net.Listener
	accepted *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// thousands of circuits in one test: a plain close leaves each port in
// TIME_WAIT, two minutes on Windows against a dynamic range of 16384
func abortiveDial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := plainDial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	return c, nil
}

func echoOnce(p jcrypto.CryptoProvider, chain []client.Node, dial dialFunc) error {
	c, err := client.Dial(client.Config{Provider: p, Chain: chain, Dial: dial})
	if err != nil {
		return err
	}
	defer c.Close()
	msg := make([]byte, 16)
	if _, err := rand.Read(msg); err != nil {
		return err
	}
	if err := c.Send(msg); err != nil {
		return err
	}
	select {
	case got, ok := <-c.Replies():
		if !ok {
			return fmt.Errorf("the circuit ended without the echo, refused: %v", c.Refused())
		}
		if !bytes.Equal(got, msg) {
			return fmt.Errorf("the echo %x is not the message %x", got, msg)
		}
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("no echo within 5 s")
	}
}

// Refused() nil: the far side ended the link, the client refused nothing
func endsUnanswered(p jcrypto.CryptoProvider, chain []client.Node) error {
	c, err := client.Dial(client.Config{Provider: p, Chain: chain})
	if err != nil {
		return err
	}
	defer c.Close()
	select {
	case _, ok := <-c.Replies():
		if ok {
			return errors.New("a reply came back")
		}
	case <-time.After(5 * time.Second):
		return errors.New("the circuit did not end within 5 s")
	}
	if err := c.Refused(); err != nil {
		return fmt.Errorf("the client refused the circuit: %w", err)
	}
	return nil
}

var trustSuiteList = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

// five relays, relay 4 certified by a second CA. Every relay verifies the
// other four under its CA's anchor: 4 x 3 = 12 pairs within the session CA
// pass, the 4 + 4 = 8 pairs with relay 4 on either side fail with
// ErrUnknownCA. A client with the session anchor finds one node not served in
// every honest mirror and relay 4's own bundle failing in its mirror; with
// allowed = min(missing, 5 - 3) it refuses every entry at missing 0 and relay
// 4 alone at missing 1 and 2, which is SecondCAProbability(5, 3, 1, missing):
// refused 1, 1/5, 1/5. No chain comes up at missing 0, so the shares of chains
// are NaN there. Relay 4's bundle put into an honest mirror fails the check
// and is counted like the bundle the mirror does not serve
func TestRelayOfASecondCAIsInNoPeerSetAndNoMirror(t *testing.T) {
	for _, s := range trustSuiteList {
		t.Run(s.String(), func(t *testing.T) {
			st := startTrustStand(t, s, plainDial)
			passed, failed := 0, 0
			sizes := make([]int, trustNodes)
			for x, tr := range st.relays {
				sizes[x] = len(tr.peers)
				for y, other := range st.relays {
					if y == x {
						continue
					}
					peer, held := tr.peers[other.addr]
					err := tr.refused[other.addr]
					if x != trustForeign && y != trustForeign {
						if !held || !bytes.Equal(peer.LinkPub, other.linkPub) || !bytes.Equal(peer.Identity, other.identity) {
							t.Errorf("relay %d takes relay %d: held %v, %v; want its link key and identity", x, y, held, err)
							continue
						}
						passed++
						continue
					}
					if held || !errors.Is(err, pki.ErrUnknownCA) {
						t.Errorf("relay %d takes relay %d: held %v, %v; want %v", x, y, held, err, pki.ErrUnknownCA)
						continue
					}
					failed++
				}
			}
			if passed != 12 || failed != 8 || !slices.Equal(sizes, []int{3, 3, 3, 3, 0}) {
				t.Fatalf("%d pairs pass and %d fail, peer sets %v; want 12, 8 and [3 3 3 3 0]", passed, failed, sizes)
			}

			honestMask := []bool{true, true, true, true, false}
			policy := pki.Policy{Anchor: st.session.Anchor(), Skew: pki.Skew}
			views := make([]verify.View, trustNodes)
			for e := range st.relays {
				views[e] = st.view(t, st.session.Anchor(), e)
				want := honestMask
				if e == trustForeign {
					want = make([]bool, trustNodes)
				}
				if got := views[e].Usable(); !slices.Equal(got, want) {
					t.Errorf("entry %d: the client holds %v, want %v", e, got, want)
				}
				for i := range st.relays {
					var want error
					switch {
					case i == trustForeign && e == trustForeign:
						want = pki.ErrUnknownCA
					case i == trustForeign || e == trustForeign:
						want = verify.ErrNoBundle
					}
					if got := views[e].Missing(i); !errors.Is(got, want) {
						t.Errorf("entry %d: node %d missing %v, want %v", e, i, got, want)
					}
				}
			}

			for missing := 0; missing <= 2; missing++ {
				refusedEntries := 0
				for e, v := range views {
					wantVerdict, wantAbsent := client.MirrorTaken, 1
					switch {
					case e == trustForeign:
						wantVerdict, wantAbsent = client.MirrorLacksEntry, trustNodes
					case missing == 0:
						wantVerdict = client.MirrorLacksTooMany
					}
					verdict, absent, allowed := v.Judge(e, trustHops, missing)
					if verdict != wantVerdict || absent != wantAbsent || allowed != missing {
						t.Errorf("missing %d, entry %d: Judge = %d, %d, %d, want %d, %d, %d", missing, e, verdict, absent, allowed, wantVerdict, wantAbsent, missing)
					}
					if verdict != client.MirrorTaken {
						refusedEntries++
					}
				}
				ends, touched, refused, failedShare := metrics.SecondCAProbability(trustNodes, trustHops, 1, missing, metrics.DrawnExit)
				if got := float64(refusedEntries) / float64(trustNodes); got != refused {
					t.Errorf("missing %d: %v of the entries refused, the model gives %v", missing, got, refused)
				}
				undefined := missing == 0
				if undefined != math.IsNaN(ends) || undefined != math.IsNaN(touched) || !undefined && (ends != 0 || touched != 0) || failedShare != 0 {
					t.Errorf("missing %d: SecondCAProbability = %v, %v, %v, %v", missing, ends, touched, refused, failedShare)
				}
			}

			for e := range trustForeign {
				bundles := st.bundlesOf(t, e)
				bundles[trustForeign] = st.relays[trustForeign].bundle
				v, err := verify.Mirror(st.p, true, policy, st.addrs, bundles, st.at)
				if err != nil {
					t.Fatal(err)
				}
				if got := v.Usable(); !slices.Equal(got, honestMask) {
					t.Errorf("entry %d serving relay 4: the client holds %v, want %v", e, got, honestMask)
				}
				if err := v.Missing(trustForeign); !errors.Is(err, pki.ErrUnknownCA) {
					t.Errorf("entry %d serving relay 4: missing %v, want %v", e, err, pki.ErrUnknownCA)
				}
				for missing := 0; missing <= 2; missing++ {
					verdict, absent, allowed := v.Judge(e, trustHops, missing)
					wantVerdict, wantAbsent, wantAllowed := views[e].Judge(e, trustHops, missing)
					if verdict != wantVerdict || absent != wantAbsent || allowed != wantAllowed {
						t.Errorf("entry %d serving relay 4, missing %d: Judge = %d, %d, %d, without it %d, %d, %d",
							e, missing, verdict, absent, allowed, wantVerdict, wantAbsent, wantAllowed)
					}
				}
			}
		})
	}
}

// relays dial onward through a counting hook into a plain dial, the client
// dials plainly. Stand A, the 24 chains of distinct relays among 0..3, the
// chains a client can draw, each with its echo: relay j is on 3 x 3 x 2 = 18
// of them, one inbound link per visit, and the exit of 3 x 2 = 6; an ordered
// pair is consecutive in 2 chains at positions 0-1 and in 2 at 1-2, so 4 dials
// per pair, 12 per relay and 48 in all; relay 4 is on none. Stand B, for each
// of the 12 ordered pairs (a, b) of honest relays the chains [4 a b], [a 4 b]
// and [a b 4], nodes read from honest mirrors under the session anchor and
// relay 4 from its own mirror under the anchor of its CA: a client that
// composes its chain past its own choice, since that choice never puts relay 4
// on one. An honest relay holds no key for relay 4, so when relay 4 is next it
// refuses the setup without a dial (RefusedExtend, and the setup cell in
// Dropped); relay 4 holds no key for an honest relay and refuses the same way.
// Per honest j: entry of 3 chains [a 4 b], entry of 3 and middle of 3 chains
// [a b 4], so 9 links and 6 refusals, and 1 dial to each other honest relay,
// only on [a b 4]; relay 4 is the entry of 12 chains, 12 links and 12
// refusals. The client sends nothing, so a link carries exactly its setup
// cell. Relays open one link per extend, and every counter is incremented
// before the client can observe the outcome
func TestHonestRelaysExtendOnlyToRelaysOfTheSessionCA(t *testing.T) {
	for _, s := range trustSuiteList {
		t.Run(s.String(), func(t *testing.T) {
			if s == jcrypto.SuiteGOST && testing.Short() {
				t.Skip("the GOST suite costs seconds of circuits")
			}
			honestPair := func(x, y int) bool { return x != y && x != trustForeign && y != trustForeign }

			st := startTrustStand(t, s, plainDial)
			chains := 0
			for a := range trustForeign {
				v := st.view(t, st.session.Anchor(), a)
				for b := range trustForeign {
					for c := range trustForeign {
						if a == b || b == c || a == c {
							continue
						}
						if err := echoOnce(st.p, v.Chain([]int{a, b, c}), nil); err != nil {
							t.Fatalf("chain %d %d %d: %v", a, b, c, err)
						}
						chains++
					}
				}
			}
			if chains != 24 {
				t.Fatalf("%d chains, want 24", chains)
			}
			counters := st.counters()
			for j, tr := range st.relays {
				links, delivered := int64(18), uint64(6)
				if j == trustForeign {
					links, delivered = 0, 0
					if counters[j].Accepted != 0 {
						t.Errorf("stand A: relay 4 accepted %d cells, want 0", counters[j].Accepted)
					}
				}
				c := counters[j]
				if got := tr.links.Load(); got != links || c.Delivered != delivered || c.RefusedExtend != 0 || c.FailedExtend != 0 {
					t.Errorf("stand A, relay %d: %d links, delivered %d, refused %d and failed %d extends; want %d, %d, 0, 0",
						j, got, c.Delivered, c.RefusedExtend, c.FailedExtend, links, delivered)
				}
				for y := range st.relays {
					want := 0
					if honestPair(j, y) {
						want = 4
					}
					if got := st.dialled(j, y); got != want {
						t.Errorf("stand A: relay %d dialled relay %d %d times, want %d", j, y, got, want)
					}
				}
			}

			st = startTrustStand(t, s, plainDial)
			honest := st.view(t, st.session.Anchor(), 0)
			foreign := st.view(t, st.second.Anchor(), trustForeign).Chain([]int{trustForeign})[0]
			node := func(i int) client.Node { return honest.Chain([]int{i})[0] }
			chains = 0
			for a := range trustForeign {
				for b := range trustForeign {
					if a == b {
						continue
					}
					for _, chain := range [][]client.Node{
						{foreign, node(a), node(b)},
						{node(a), foreign, node(b)},
						{node(a), node(b), foreign},
					} {
						if err := endsUnanswered(st.p, chain); err != nil {
							t.Fatalf("chain through %s, %s, %s: %v", chain[0].Addr, chain[1].Addr, chain[2].Addr, err)
						}
						chains++
					}
				}
			}
			if chains != 36 {
				t.Fatalf("%d chains, want 36", chains)
			}
			counters = st.counters()
			for j, tr := range st.relays {
				links, refusals := int64(9), uint64(6)
				if j == trustForeign {
					links, refusals = 12, 12
				}
				c := counters[j]
				if got := tr.links.Load(); got != links || c.Accepted != uint64(links) || c.RefusedExtend != refusals || c.Dropped != refusals {
					t.Errorf("stand B, relay %d: %d links, %d cells accepted, %d extends refused, %d dropped; want %d, %d, %d, %d",
						j, got, c.Accepted, c.RefusedExtend, c.Dropped, links, links, refusals, refusals)
				}
				if c.FailedExtend != 0 || c.Delivered != 0 {
					t.Errorf("stand B, relay %d: %d extends failed and %d delivered, want 0 and 0", j, c.FailedExtend, c.Delivered)
				}
				for y := range st.relays {
					want := 0
					if honestPair(j, y) {
						want = 1
					}
					if got := st.dialled(j, y); got != want {
						t.Errorf("stand B: relay %d dialled relay %d %d times, want %d", j, y, got, want)
					}
				}
			}
		})
	}
}

// relays dial onward through a counting hook into an abortive dial, and so
// does the client. Each attempt takes the steps of cmd/client on the path
// stream of the seed: the entry among all five, its mirror read and verified
// anew, the client's rule for -missing 1, the rest of the chain among the
// nodes that passed. The client refuses the mirror of relay 4, whose own
// bundle fails, and takes the others, which lack one node within
// min(1, 5 - 3) = 1, so it refuses 1/5 of the attempts and puts relay 4 on no
// chain: SecondCAProbability(5, 3, 1, 1, DrawnExit) = (0, 0, 1/5, 0). Each of
// the 24 honest chains has chance 4/5 x 1/4 x 1/3 x 1/2 = 1/30 per attempt. At
// p = 1/5 and n = 3000 the claim (Wilson at 0.95 inside [0.15, 0.25],
// z = 1.959964) holds for 489 to 703 refusals. The low bound is at least 0.15
// iff x/n >= 0.15 and n(x/n - 0.15)^2 >= z^2 x 0.15 x 0.85 = 0.48979, first
// true at x = 489 (0.50700; 488 gives 0.48133, low bound 0.14989). The high
// bound is at most 0.25 iff x/n <= 0.25 and n(0.25 - x/n)^2 >= z^2 x 0.25 x
// 0.75 = 0.72027, last true at x = 703 (0.73633; 704 gives 0.70533, high
// bound 0.25016). Exact power, X ~ Bin(3000, 1/5): 1 - P(X <= 488) -
// P(X >= 704) = 1 - 9.2e-8 - 1.79e-6 = 0.999998. Seed 1 refuses 614 of 3000:
// 0.2047, Wilson [0.1906, 0.2195]. A refusal is exactly a draw of relay 4 as
// the entry, so the interval checks the choice of the entry, and the exact
// checks check the boundary. The paths and refusals are those of
// SampleMirrorPaths on the masks the client read, at the same seed
func TestDrawnChainsNeverReachTheRelayOfASecondCA(t *testing.T) {
	samples := trustSamples
	if testing.Short() {
		samples = trustShort
	}
	st := startTrustStand(t, jcrypto.SuiteC25519, abortiveDial)
	trust := st.session.Anchor()
	stream := mrand.New(mrand.NewSource(Derive(trustSeed, streamPaths)))
	var paths [][]int
	var chains [][]client.Node
	refused := 0
	for attempt := range samples {
		entry, err := client.ChooseEntry(trustNodes, stream)
		if err != nil {
			t.Fatal(err)
		}
		v := st.view(t, trust, entry)
		verdict, _, _ := v.Judge(entry, trustHops, trustMissing)
		if verdict != client.MirrorTaken {
			if entry != trustForeign || verdict != client.MirrorLacksEntry || !errors.Is(v.Missing(trustForeign), pki.ErrUnknownCA) {
				t.Fatalf("attempt %d: entry %d refused with verdict %d, missing %v", attempt, entry, verdict, v.Missing(trustForeign))
			}
			refused++
			continue
		}
		if entry == trustForeign {
			t.Fatalf("attempt %d: the client takes the mirror of relay 4", attempt)
		}
		path, err := v.Draw(entry, trustHops, stream)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(path, trustForeign) {
			t.Fatalf("attempt %d: the client draws %v", attempt, path)
		}
		paths = append(paths, path)
		chains = append(chains, v.Chain(path))
	}
	if refused+len(paths) != samples {
		t.Fatalf("%d refused and %d paths of %d attempts", refused, len(paths), samples)
	}
	masks := make([][]bool, trustNodes)
	for e := range masks {
		masks[e] = st.view(t, trust, e).Usable()
	}
	sampled, sampledRefused, err := SampleMirrorPaths(masks, trustHops, trustMissing, samples, trustSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(paths, sampled, slices.Equal) || refused != sampledRefused {
		t.Fatalf("the client gives %d paths and %d refused, SampleMirrorPaths %d and %d, or other paths", len(paths), refused, len(sampled), sampledRefused)
	}
	modelEnds, modelTouched, modelRefused, modelFailed := metrics.SecondCAProbability(trustNodes, trustHops, 1, trustMissing, metrics.DrawnExit)
	if ends, touched := metrics.CompromiseFraction(paths, map[int]bool{trustForeign: true}); ends != 0 || touched != 0 || ends != modelEnds || touched != modelTouched {
		t.Errorf("CompromiseFraction = %v, %v, the model %v, %v, want 0 and 0", ends, touched, modelEnds, modelTouched)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []error
	slots := make(chan struct{}, trustAtOnce)
	for _, chain := range chains {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			if err := echoOnce(st.p, chain, abortiveDial); err != nil {
				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for _, err := range failures[:min(len(failures), 3)] {
		t.Error(err)
	}
	if got := float64(len(failures)) / float64(samples); got != modelFailed {
		t.Fatalf("%d of %d chains did not come up, %v of the attempts; the model fails %v", len(failures), len(chains), got, modelFailed)
	}

	visits := make([]int64, trustNodes)
	exits := make([]uint64, trustNodes)
	steps := make([][]int, trustNodes)
	for i := range steps {
		steps[i] = make([]int, trustNodes)
	}
	for _, path := range paths {
		for i, n := range path {
			visits[n]++
			if i > 0 {
				steps[path[i-1]][n]++
			}
		}
		exits[path[len(path)-1]]++
	}
	counters := st.counters()
	for j, tr := range st.relays {
		c := counters[j]
		if got := tr.links.Load(); got != visits[j] || c.Delivered != exits[j] || c.RefusedExtend != 0 || c.FailedExtend != 0 {
			t.Errorf("relay %d: %d links, delivered %d, refused %d and failed %d extends; want %d, %d, 0, 0",
				j, got, c.Delivered, c.RefusedExtend, c.FailedExtend, visits[j], exits[j])
		}
		if j == trustForeign && c.Accepted != 0 {
			t.Errorf("relay 4 accepted %d cells, want 0", c.Accepted)
		}
		for y := range st.relays {
			if got := st.dialled(j, y); got != steps[j][y] {
				t.Errorf("relay %d dialled relay %d %d times, the paths step there %d times", j, y, got, steps[j][y])
			}
		}
	}

	// under -short a share of 300 attempts has power 0.17
	if testing.Short() {
		return
	}
	iv := metrics.WilsonInterval(refused, samples, trustLevel)
	if got := metrics.Equivalence(iv, modelRefused, trustMargin); got != "equivalent" {
		t.Errorf("%d of %d attempts refused, Wilson [%v, %v] at %v against %v within %v: %q, want equivalent",
			refused, samples, iv.Low, iv.High, trustLevel, modelRefused, trustMargin, got)
	}
}
