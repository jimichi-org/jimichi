package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/pki"
)

func (f *fixture) resign(t *testing.T) {
	t.Helper()
	f.n.mu.Lock()
	defer f.n.mu.Unlock()
	if err := f.n.sign(f.clock.Now()); err != nil {
		t.Fatalf("sign: %v", err)
	}
}

func (f *fixture) setTTL(ttl time.Duration) {
	f.n.mu.Lock()
	defer f.n.mu.Unlock()
	f.n.ttl = ttl
}

// a node of the cluster's CA that reads its own clock
func (c *cluster) add(t *testing.T, name string, own *clock, ttl time.Duration) *fixture {
	t.Helper()
	f := newNode(t, c.p, c.ca, own, name)
	f.setTTL(ttl)
	f.n.fetchPeer = c.fetch
	c.route(f.n.addr, f.info.URL)
	c.nodes = append(c.nodes, f)
	return f
}

// what a client that drew f as its entry makes of f's mirror when its clock is
// ahead of the cluster's by the given time, behind when negative: every listed
// bundle has to verify, stricter than cmd/client, where a bundle that fails is a
// node left out, and the client's own rule decides on
// the set, for -missing 1 and a chain one hop shorter than the roster, so that
// one node may be left out: min(1, n - (n-1)) = 1
func (c *cluster) clientTakes(t *testing.T, f *fixture, ahead time.Duration) ([]string, error) {
	t.Helper()
	code, raw := f.descriptors(t)
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /descriptors = %d", code)
	}
	return c.judge(t, f, raw, ahead)
}

func (c *cluster) judge(t *testing.T, f *fixture, raw []byte, ahead time.Duration) ([]string, error) {
	t.Helper()
	entries, err := pki.ParseMirror(raw)
	if err != nil {
		t.Fatalf("ParseMirror: %v", err)
	}
	listed := make([]string, len(entries))
	bundles := make([][]byte, len(entries))
	for i, e := range entries {
		listed[i], bundles[i] = e.Addr, e.Bundle
	}
	policy := pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}
	if _, err := pki.VerifyChain(c.p, policy, listed, bundles, c.clock.Now().Add(ahead)); err != nil {
		return listed, err
	}
	served := make([]bool, len(c.nodes))
	entry := -1
	for i, node := range c.nodes {
		served[i] = slices.Contains(listed, node.n.addr)
		if node == f {
			entry = i
		}
	}
	if verdict, absent, allowed := client.JudgeMirror(served, entry, len(c.nodes)-1, 1); verdict != client.MirrorTaken {
		return listed, fmt.Errorf("verdict %d with %d absent of %d allowed", verdict, absent, allowed)
	}
	return listed, nil
}

// the margin is Skew, 120 s, plus the request timeout, 5 s, plus 1 s for the
// whole seconds the node reads: 126 s. The node lists a bundle while its clock
// reads at most expires - 127 s, and a client 119 s ahead that reads its clock
// 5 s later is at expires - 3 s at most
//
// the shortest lifetime is 960 s. A peer signs again once the age of its
// descriptor reaches 960/2 = 480 s, found by a timer every
// checkEvery(960) = min(240, 60) = 60 s, so by an age of 540 s on its own
// clock. The held bundle leaves the mirror at an age of 960 - 126 = 834 s on
// the node's clock. With the peer's clock up to 120 s behind the node's,
// 834 - 540 - 120 = 174 s remain for the pass that brings the new bundle; a
// peer ahead is taken at its published time and leaves 834 - 540 = 294 s.
// The testbed's 1200 s leaves 1074 - 660 - 120 = 294 s behind
func TestShortestLifetimeLeavesTheMirrorSlack(t *testing.T) {
	if mirrorMargin != 126*time.Second || minDescriptorTTL != 16*time.Minute {
		t.Fatalf("margin %v and shortest lifetime %v, want 2m6s and 16m", mirrorMargin, minDescriptorTTL)
	}
	if last := -mirrorMargin - time.Second + fetch.Timeout + pki.Skew - time.Second; last != -3*time.Second {
		t.Fatalf("a client 119 s ahead reads the last listed bundle %v from its expiry, want -3s", last)
	}
	slack := func(ttl time.Duration) (behind, ahead time.Duration) {
		signed := ttl/2 + checkEvery(ttl)
		left := ttl - mirrorMargin
		return left - signed - pki.Skew, left - signed
	}
	if behind, ahead := slack(minDescriptorTTL); behind != 174*time.Second || ahead != 294*time.Second {
		t.Fatalf("slack with the peer behind %v and ahead %v, want 174s and 294s", behind, ahead)
	}
	if behind, _ := slack(20 * time.Minute); behind != 294*time.Second {
		t.Fatalf("slack on the testbed with the peer behind = %v, want 294s", behind)
	}
}

// the cluster's clock reads T. relay-4's clock is 55 s behind and its
// descriptors live 1 min, so each one has published = T - 55 and
// expires = T + 5, and its expires falls inside relay-1's margin of 126 s.
// The other three sign for 1 h at t0
//
// relay-1 at T: T >= published holds, T < expires - 126 = T - 121 does not, so
// the bundle stays out of the mirror; T < expires, so relay-4 is still a peer,
// and its bundle is due at once (published + 30 < T), one request per pass
//
// a client 119 s ahead reads T + 119 >= T + 5, outside relay-4's bundle; the
// three listed ones pass, the latest T being t0 + 20: t0 + 139 < t0 + 3600.
// A client 119 s behind reads T - 119 and adds its allowance of 120:
// T + 1 >= t0, the published time of the three. The mirror lacks 1 of 4
// nodes; 3 hops and -missing 1 allow min(1, 4-3) = 1
func TestMirrorLeavesOutABundleCloseToItsExpiry(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	late := &clock{now: t0.Add(-55 * time.Second)}
	n4 := c.add(t, "relay-4", late, time.Minute)
	c.enroll(t, t0.Add(72*time.Hour))
	n1 := c.nodes[0]
	cache := n1.takeRoster(t, c.roster())
	policy := pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}
	rest := []string{addrOf("relay-1"), addrOf("relay-2"), addrOf("relay-3")}

	for round := range 5 {
		if round > 0 {
			c.clock.advance(5 * time.Second)
			late.advance(5 * time.Second)
			n4.resign(t)
		}
		asked := n4.n.descriptorRequests.Load()
		cache.refresh()
		if got := n4.n.descriptorRequests.Load(); got != asked+1 {
			t.Fatalf("round %d: relay-4 was asked %d times in one pass, want once", round, got-asked)
		}
		if _, ok := n1.n.peerKey(n4.n.addr); !ok {
			t.Fatalf("round %d: relay-4 is no peer while its descriptor is valid: %s", round, n1.log.String())
		}
		_, edge := n4.descriptor(t)
		if _, err := pki.Verify(c.p, policy, n4.n.addr, edge, c.clock.Now()); err != nil {
			t.Fatalf("round %d: relay-4's bundle on the node's clock: %v", round, err)
		}
		if _, err := pki.Verify(c.p, policy, n4.n.addr, edge, c.clock.Now().Add(119*time.Second)); !errors.Is(err, pki.ErrDescTime) {
			t.Fatalf("round %d: relay-4's bundle on a clock 119 s ahead: %v, want ErrDescTime", round, err)
		}
		for _, ahead := range []time.Duration{119 * time.Second, 0, -119 * time.Second} {
			listed, err := c.clientTakes(t, n1, ahead)
			if err != nil || !slices.Equal(listed, rest) {
				t.Fatalf("round %d: a client %v ahead got %v, %v, want the mirror of the three other nodes taken", round, ahead, listed, err)
			}
		}
	}
}

// relay-4 runs on the cluster's clock and its descriptors live 10 s: signed
// at t0, published = t0 and expires = t0 + 10. relay-1's margin stays 126 s
// whatever lifetime the peer chose: t0 < t0 + 10 - 126 does not hold, so the
// bundle stays out of the mirror from the first pass, while t0 < t0 + 10 keeps
// relay-4 a peer. A client 119 s ahead reads t0 + 119 >= t0 + 10, outside
// relay-4's bundle, and takes the mirror of the other three, whose descriptors
// expire at t0 + 3600. At t0 + 9 the same holds, 9 + 119 = 128 >= 10, and
// relay-4 is still a peer, 9 < 10
func TestMirrorMarginDoesNotShrinkWithThePeersLifetime(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	n4 := c.add(t, "relay-4", c.clock, 10*time.Second)
	c.enroll(t, t0.Add(72*time.Hour))
	n1 := c.nodes[0]
	cache := n1.takeRoster(t, c.roster())
	rest := []string{addrOf("relay-1"), addrOf("relay-2"), addrOf("relay-3")}
	for _, at := range []time.Duration{0, 9 * time.Second} {
		c.clock.advance(at - c.clock.Now().Sub(t0))
		cache.refresh()
		if _, ok := n1.n.peerKey(n4.n.addr); !ok {
			t.Fatalf("t0 + %v: relay-4 is no peer while its descriptor is valid: %s", at, n1.log.String())
		}
		listed, err := c.clientTakes(t, n1, 119*time.Second)
		if err != nil || !slices.Equal(listed, rest) {
			t.Fatalf("t0 + %v: a client 119 s ahead got %v, %v, want the mirror of the three other nodes taken", at, listed, err)
		}
	}
}

// relay-4's certificate starts 60 s after its first descriptor: a node takes a
// certificate whose not_before is up to Skew ahead of its own clock, and signs
// at once. All clocks read t0, so published = t0 and not_before = t0 + 60.
// relay-1 verifies the bundle at t0, since t0 + 120 >= t0 + 60, and holds it
// as a peer, but the mirror takes it from max(t0, t0 + 60) = t0 + 60: at t0 a
// client 119 s behind would read t0 - 119 + 120 = t0 + 1 < not_before. At
// t0 + 60 the first request takes the bundle in with no fetch, and the client
// 119 s behind reads t0 + 61 >= t0 + 60
func TestMirrorWaitsForTheCertificatesStart(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3", "relay-4")
	for _, f := range c.nodes[:3] {
		f.enroll(t, t0.Add(72*time.Hour))
	}
	n1, n4 := c.nodes[0], c.nodes[3]
	cert := n4.issue(t, n4.request(t), t0.Add(60*time.Second), t0.Add(72*time.Hour))
	if code, body := n4.put(t, cert); code != http.StatusNoContent {
		t.Fatalf("PUT /cert with not_before 60 s ahead = %d %s, want 204", code, body)
	}
	cache := n1.takeRoster(t, c.roster())
	if !cache.refresh() {
		t.Fatalf("refresh: %s", n1.log.String())
	}
	rest := []string{addrOf("relay-1"), addrOf("relay-2"), addrOf("relay-3")}
	clients := []time.Duration{-119 * time.Second, 0, 119 * time.Second}
	for _, ahead := range clients {
		if listed, err := c.clientTakes(t, n1, ahead); err != nil || !slices.Equal(listed, rest) {
			t.Fatalf("before not_before a client %v ahead got %v, %v, want the three other nodes", ahead, listed, err)
		}
	}
	c.clock.advance(59 * time.Second)
	if listed := n1.mirrored(t); slices.Contains(listed, n4.n.addr) {
		t.Fatalf("the mirror lists %v one second before relay-4's certificate starts", listed)
	}
	c.clock.advance(time.Second)
	asked := n4.n.descriptorRequests.Load()
	for _, ahead := range clients {
		if listed, err := c.clientTakes(t, n1, ahead); err != nil || len(listed) != 4 {
			t.Fatalf("at not_before a client %v ahead got %v, %v, want all four nodes", ahead, listed, err)
		}
	}
	if n4.n.descriptorRequests.Load() != asked {
		t.Fatal("the bundle joined the mirror by a fetch; the node held it already")
	}
}

// relay-1's own certificate starts 60 s after its first descriptor, all clocks
// at t0: published = t0 and not_before = t0 + 60. A client 119 s behind would
// read t0 - 119 + 120 = t0 + 1 < not_before and refuse relay-1's bundle, so
// relay-1 serves no mirror before t0 + 60, while /descriptor answers at once:
// its peers mirror it from not_before and enroll checks it at t0 + 60 or later
// on the clock that issued it. At t0 + 60 the client 119 s behind reads
// t0 + 61 >= t0 + 60 and takes the mirror of all three
func TestOwnMirrorWaitsForTheCertificatesStart(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	n1 := c.nodes[0]
	cert := n1.issue(t, n1.request(t), t0.Add(60*time.Second), t0.Add(72*time.Hour))
	if code, body := n1.put(t, cert); code != http.StatusNoContent {
		t.Fatalf("PUT /cert with not_before 60 s ahead = %d %s, want 204", code, body)
	}
	for _, f := range c.nodes[1:] {
		f.enroll(t, t0.Add(72*time.Hour))
	}
	cache := n1.takeRoster(t, c.roster())
	if !cache.refresh() {
		t.Fatalf("refresh: %s", n1.log.String())
	}
	code, own := n1.descriptor(t)
	if code != http.StatusOK {
		t.Fatalf("GET /descriptor before not_before = %d, want 200", code)
	}
	policy := pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}
	if _, err := pki.Verify(c.p, policy, n1.n.addr, own, c.clock.Now().Add(-119*time.Second)); !errors.Is(err, pki.ErrCertTime) {
		t.Fatalf("relay-1's bundle on a clock 119 s behind at t0 = %v, want %v", err, pki.ErrCertTime)
	}
	for _, at := range []time.Duration{0, 59 * time.Second} {
		c.clock.advance(at - c.clock.Now().Sub(t0))
		if code, body := n1.descriptors(t); code != http.StatusServiceUnavailable {
			t.Fatalf("t0 + %v: GET /descriptors = %d %s, want 503 before relay-1's certificate starts", at, code, body)
		}
	}
	c.clock.advance(time.Second)
	for _, ahead := range []time.Duration{-119 * time.Second, 0, 119 * time.Second} {
		if listed, err := c.clientTakes(t, n1, ahead); err != nil || len(listed) != 3 {
			t.Fatalf("at not_before a client %v ahead got %v, %v, want all three nodes", ahead, listed, err)
		}
	}
}

// relay-4 runs 120 s ahead, the most a node accepts, and signs for 1 h:
// published = t0 + 120 and expires = t0 + 3720 on the cluster's clock.
// relay-1 verifies it at t0, since t0 + 120 >= published, and holds it as a
// peer, but t0 >= published does not hold, so the mirror waits: a client
// 119 s behind would read t0 - 119 + 120 = t0 + 1 < published
//
// at t0 + 120 the first request takes the bundle into the mirror with no
// fetch: now >= published and now < expires - 126 = t0 + 3594. The client
// 119 s behind reads t0 + 1 + 120 = t0 + 121 >= published, and a client
// 119 s ahead reads t0 + 239, before t0 + 3600 where the first descriptors
// expire
func TestMirrorWaitsForThePublishedTime(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	n4 := c.add(t, "relay-4", &clock{now: t0.Add(pki.Skew)}, time.Hour)
	c.enroll(t, t0.Add(72*time.Hour))
	n1 := c.nodes[0]
	cache := n1.takeRoster(t, c.roster())
	if !cache.refresh() {
		t.Fatalf("refresh: %s", n1.log.String())
	}
	if _, ok := n1.n.peerKey(n4.n.addr); !ok {
		t.Fatal("relay-4 is no peer although its descriptor verifies with the allowance")
	}
	rest := []string{addrOf("relay-1"), addrOf("relay-2"), addrOf("relay-3")}
	clients := []time.Duration{-119 * time.Second, 0, 119 * time.Second}
	for _, ahead := range clients {
		if listed, err := c.clientTakes(t, n1, ahead); err != nil || !slices.Equal(listed, rest) {
			t.Fatalf("before the published time a client %v ahead got %v, %v, want the three other nodes", ahead, listed, err)
		}
	}

	c.clock.advance(119 * time.Second)
	if listed := n1.mirrored(t); slices.Contains(listed, n4.n.addr) {
		t.Fatalf("the mirror lists %v one second before relay-4's published time", listed)
	}
	c.clock.advance(time.Second)
	asked := n4.n.descriptorRequests.Load()
	for _, ahead := range clients {
		if listed, err := c.clientTakes(t, n1, ahead); err != nil || len(listed) != 4 {
			t.Fatalf("at the published time a client %v ahead got %v, %v, want all four nodes", ahead, listed, err)
		}
	}
	if n4.n.descriptorRequests.Load() != asked {
		t.Fatal("the bundle joined the mirror by a fetch; the node held it already")
	}
}

// relay-2 runs 30 s ahead of relay-1 and both sign for 1 h. The first bundle
// of relay-2 has published = t0 + 30 and expires = t0 + 3630, and joins
// relay-1's mirror at t0 + 30. At t0 + 1830 relay-1 finds it due
// (published + 1800), and relay-2, reading t0 + 1860, has just signed again:
// published = t0 + 1860. relay-1 fetches that bundle 30 s before its published
// time, so the mirror keeps the first one, which it may hold while
// now < t0 + 3630 - 126, and the peer is asked again after the retry pause.
// The pass at t0 + 1860 takes the new bundle. The peer is listed at every step
func TestPeerAheadStaysInTheMirrorWhileItsNewDescriptorWaits(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1")
	ahead := &clock{now: t0.Add(30 * time.Second)}
	n2 := c.add(t, "relay-2", ahead, time.Hour)
	c.enroll(t, t0.Add(72*time.Hour))
	n1 := c.nodes[0]
	cache := n1.takeRoster(t, c.roster())
	cache.refresh()
	if listed := n1.mirrored(t); slices.Contains(listed, n2.n.addr) {
		t.Fatalf("the mirror lists %v before relay-2's published time", listed)
	}
	both := func(d time.Duration) {
		c.clock.advance(d)
		ahead.advance(d)
	}
	inMirror := func() []byte {
		t.Helper()
		_, raw := n1.descriptors(t)
		entries, err := pki.ParseMirror(raw)
		if err != nil || len(entries) != 2 {
			t.Fatalf("the mirror holds %d entries, %v, want relay-1 and relay-2", len(entries), err)
		}
		return entries[1].Bundle
	}
	both(30 * time.Second)
	_, first := n2.descriptor(t)
	if !bytes.Equal(inMirror(), first) {
		t.Fatal("the mirror does not hold relay-2's first bundle at its published time")
	}

	both(1800 * time.Second)
	n1.n.refreshIfDue()
	n2.n.refreshIfDue()
	_, second := n2.descriptor(t)
	if bytes.Equal(first, second) {
		t.Fatal("relay-2 did not sign again at half of its descriptor's life")
	}
	cache.refresh()
	if !bytes.Equal(inMirror(), first) {
		t.Fatal("a bundle not yet published on this node's clock displaced the one in the mirror")
	}
	if got := cache.wait(); got != peerRetry {
		t.Fatalf("wait while the new bundle is not taken = %v, want %v", got, peerRetry)
	}
	both(30 * time.Second)
	cache.refresh()
	if !bytes.Equal(inMirror(), second) {
		t.Fatal("the mirror did not take relay-2's new bundle at its published time")
	}
	if got := cache.wait(); got != time.Minute {
		t.Fatalf("wait with the new bundle taken = %v, want %v", got, time.Minute)
	}
}

// three nodes sign for 1 h at t0: each descriptor expires at t0 + 3600 and is
// due at t0 + 1800, and the margin is 126 s. relay-1 and relay-3 sign again at
// 1800 s, relay-2 does not. Its bundle is in relay-1's mirror while
// now < 3600 - 126 = 3474: listed at 3473, where a client 119 s ahead reads
// 3592 < 3600, and left out at 3474. It stays a peer for extending circuits
// until 3600. relay-2 signs again at 3474 and the next pass brings it back
func TestStaleBundleLeavesTheMirrorAndAFreshOneReturns(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	cache := n1.takeRoster(t, c.roster())
	cache.refresh()

	c.clock.advance(1800 * time.Second)
	n1.n.refreshIfDue()
	n3.n.refreshIfDue()
	cache.refresh()

	c.clock.advance(1673 * time.Second)
	if listed, err := c.clientTakes(t, n1, 119*time.Second); err != nil || len(listed) != 3 {
		t.Fatalf("3473 s: a client 119 s ahead got %v, %v, want all three nodes", listed, err)
	}
	c.clock.advance(time.Second)
	asked := n2.n.descriptorRequests.Load()
	listed, err := c.clientTakes(t, n1, 119*time.Second)
	if err != nil || !slices.Equal(listed, []string{n1.n.addr, n3.n.addr}) {
		t.Fatalf("3474 s: a client 119 s ahead got %v, %v, want the mirror without relay-2", listed, err)
	}
	if n2.n.descriptorRequests.Load() != asked {
		t.Fatal("a request for the descriptors fetched from a peer")
	}
	if key, ok := n1.n.peerKey(n2.n.addr); !ok || !bytes.Equal(key.LinkPub, n2.pub) {
		t.Fatal("relay-2 is no peer 126 s before its descriptor expires")
	}
	if got := n1.stats(t); !strings.Contains(got, `"peers":2`) {
		t.Fatalf("stats 126 s before the descriptor expires: %s", got)
	}

	n2.n.refreshIfDue()
	if !cache.refresh() {
		t.Fatalf("refresh: %s", n1.log.String())
	}
	_, own := n2.descriptor(t)
	_, raw := n1.descriptors(t)
	entries, err := pki.ParseMirror(raw)
	if err != nil || len(entries) != 3 || !bytes.Equal(entries[1].Bundle, own) {
		t.Fatalf("the mirror holds %d entries, %v, want relay-2 back with its new bundle", len(entries), err)
	}
	if _, err := c.clientTakes(t, n1, 119*time.Second); err != nil {
		t.Fatalf("a client 119 s ahead refuses the mirror with relay-2 back: %v", err)
	}
}

// relay-2's certificate ends at t0 + 600 and it signs for 1 h, so its
// descriptor is cut to expires = t0 + 600 and signing again cannot move that.
// With relay-1's margin of 126 s the bundle is in its mirror while
// now < 600 - 126 = 474. At 473 a client 119 s ahead reads 592 < 600 and
// accepts it, and so does one that receives the mirror of 473 and reads its
// clock 5 s later, at 478 + 119 = 597 < 600; from 474 the mirror goes on
// without relay-2, which serves its own descriptor and stays a peer for
// extending circuits until 600
func TestPeerLeavesTheMirrorAMarginBeforeItsCertificateEnds(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	n1.enroll(t, t0.Add(72*time.Hour))
	n2.enroll(t, t0.Add(600*time.Second))
	n3.enroll(t, t0.Add(72*time.Hour))
	cache := n1.takeRoster(t, c.roster())
	cache.refresh()

	c.clock.advance(473 * time.Second)
	n2.n.refreshIfDue()
	cache.refresh()
	if listed, err := c.clientTakes(t, n1, 119*time.Second); err != nil || len(listed) != 3 {
		t.Fatalf("473 s: a client 119 s ahead got %v, %v, want all three nodes", listed, err)
	}
	code, last := n1.descriptors(t)
	if code != http.StatusOK {
		t.Fatalf("473 s: GET /descriptors = %d", code)
	}
	c.clock.advance(time.Second)
	cache.refresh()
	listed, err := c.clientTakes(t, n1, 119*time.Second)
	if err != nil || !slices.Equal(listed, []string{n1.n.addr, n3.n.addr}) {
		t.Fatalf("474 s: a client 119 s ahead got %v, %v, want the mirror without relay-2", listed, err)
	}
	c.clock.advance(4 * time.Second)
	if listed, err := c.judge(t, n1, last, 119*time.Second); err != nil || len(listed) != 3 {
		t.Fatalf("478 s: a client 119 s ahead refuses the mirror of 473 s: %v, %v", listed, err)
	}
	c.clock.advance(121 * time.Second)
	if code, _ := n2.descriptor(t); code != http.StatusOK {
		t.Fatalf("599 s: relay-2 serves its own descriptor with %d, want 200 until the certificate ends", code)
	}
	if _, ok := n1.n.peerKey(n2.n.addr); !ok {
		t.Fatal("599 s: relay-2 is no peer one second before its certificate ends")
	}
	c.clock.advance(time.Second)
	if _, ok := n1.n.peerKey(n2.n.addr); ok {
		t.Fatal("600 s: relay-2 is a peer after its certificate ended")
	}
}

// every node signs for ttl and its timer looks every checkEvery(ttl); a pass of
// relay-1 follows its own wait, as keepPeers does. relay-2's clock is off ahead
// of relay-1's and relay-3's off behind; every node enrolls on its own clock.
// Times are seconds after t0 on relay-1's clock, in steps of 1 s; the age of a
// descriptor is the same on every clock. The margin is 126 s
//
// ttl = 960, off = 119: checkEvery = 60. All three sign at 0. The timers of
// relay-2 and relay-3 fire at 59 + 60k: at 479 the age is under 480, so both
// sign again at 539, the latest the timer allows, then at 1019, 1499, 1979,
// 2459. relay-1's timer fires at 30 + 60k and signs at 510.
// relay-3's first bundle has published = t0 - 119 and expires = t0 + 841, so
// it is in relay-1's mirror while now < 841 - 126 = 715 and is due at
// -119 + 480 = 361; relay-1 asks every 5 s from then, gets the same bundle
// until 539 and the new one by 544, 171 s before 715. A client 119 s ahead
// reads at most 714 + 119 = 833 < 841 on the old bundle.
// relay-2's first bundle has published = t0 + 119 and expires = t0 + 1079: in
// the mirror while 119 <= now < 953, absent before 119, which -missing 1
// allows. It is due at 599 and the fetch brings the bundle signed at 539,
// published 539 + 119 = 658, ahead of relay-1's clock: the held one stays and
// relay-1 asks every 5 s, taking the new one by 663, 290 s before 953. A client
// 119 s behind reads 119 - 119 + 120 = 120 >= 119 on the first bundle, the
// same edge as relay-2's not_before. The later periods sign on time at 480 and
// leave more
//
// ttl = 1200, off = 0: checkEvery = 60. The timers of relay-2 and relay-3 fire
// at 59 + 60k: at 599 the descriptor is 599 s old, under 600, so they sign at
// 659. Passes of relay-1: 600, then every 5, and 660 brings the bundles of 659.
// The bundles of t0 may stay while now < 1200 - 126 = 1074, so the new ones
// come 414 s early, and a client 119 s ahead reads at most 659 + 119 = 778 <
// 1200 on the old bundles
//
// the later periods repeat the first with the same offsets
func TestHonestPeersStayInTheMirrorAcrossReSigning(t *testing.T) {
	for _, tc := range []struct {
		ttl time.Duration
		off time.Duration
	}{
		{minDescriptorTTL, 119 * time.Second},
		{20 * time.Minute, 0},
	} {
		t.Run(tc.ttl.String(), func(t *testing.T) {
			c := newCluster(t, jcrypto.SuiteC25519, "relay-1")
			c.nodes[0].setTTL(tc.ttl)
			ahead := &clock{now: t0.Add(tc.off)}
			behind := &clock{now: t0.Add(-tc.off)}
			c.add(t, "relay-2", ahead, tc.ttl)
			c.add(t, "relay-3", behind, tc.ttl)
			clocks := []*clock{c.clock, ahead, behind}
			c.enroll(t, t0.Add(72*time.Hour))
			n1 := c.nodes[0]
			cache := n1.takeRoster(t, c.roster())
			cache.refresh()
			every := int(checkEvery(tc.ttl) / time.Second)
			phase := []int{every / 2, every - 1, every - 1}
			joined := int(tc.off / time.Second)
			pass := c.clock.Now().Add(cache.wait())
			for s := 1; s <= int(3*tc.ttl/time.Second); s++ {
				for _, k := range clocks {
					k.advance(time.Second)
				}
				for i, f := range c.nodes {
					if s%every == phase[i] {
						f.n.refreshIfDue()
					}
				}
				if now := c.clock.Now(); !now.Before(pass) {
					cache.refresh()
					pass = now.Add(cache.wait())
				}
				raw, ok := cache.descriptors()
				if !ok {
					t.Fatalf("%d s: relay-1 serves no mirror", s)
				}
				for _, ahead := range []time.Duration{119 * time.Second, -119 * time.Second} {
					if listed, err := c.judge(t, n1, raw, ahead); err != nil || s >= joined && len(listed) != 3 {
						t.Fatalf("%d s: a client %v ahead got %v, %v, want all three nodes from %d s", s, ahead, listed, err, joined)
					}
				}
			}
		})
	}
}
