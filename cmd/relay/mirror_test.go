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
// bundle has to verify, as in cmd/client, and the client's own rule decides on
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

func TestMirrorMarginKnownAnswers(t *testing.T) {
	// min(Skew, ttl/8) with Skew = 120 s: 60/8 = 7.5 s, 480/8 = 60 s,
	// 960/8 = 120 s, and Skew for every longer lifetime
	for _, c := range []struct {
		ttl  time.Duration
		want time.Duration
	}{
		{time.Minute, 7500 * time.Millisecond},
		{8 * time.Minute, time.Minute},
		{16 * time.Minute, 2 * time.Minute},
		{20 * time.Minute, 2 * time.Minute},
		{time.Hour, 2 * time.Minute},
		{24 * time.Hour, 2 * time.Minute},
		{0, 0},
		{-time.Hour, 0},
	} {
		if got := mirrorMargin(c.ttl); got != c.want {
			t.Errorf("mirrorMargin(%v) = %v, want %v", c.ttl, got, c.want)
		}
	}
}

// relay-4 holds a valid certificate and every descriptor it signs is close to
// its expiry from the start. The cluster's clock reads T; relay-4 runs 55 s
// behind and signs for 1 min, so each of its descriptors has
// published = T - 55 and expires = T + 5. The other three sign for 1 h at t0,
// and the margin of relay-1 is min(120, 3600/8) = 120 s.
//
// relay-1 at T: T >= published holds, T < expires - 120 = T - 115 does not, so
// the bundle stays out of the mirror; T < expires, so relay-4 is still a peer,
// and its bundle is due at once (published + 30 < T), one request per pass.
//
// A client 119 s ahead reads T + 119 >= T + 5, where relay-4's bundle fails;
// the three listed ones pass, the latest T being t0 + 20: t0 + 139 < t0 + 3600.
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

// relay-4 runs 120 s ahead, the most a node accepts, and signs for 1 h:
// published = t0 + 120 and expires = t0 + 3720 on the cluster's clock.
// relay-1 verifies it at t0, since t0 + 120 >= published, and holds it as a
// peer, but t0 >= published does not hold, so the mirror waits: a client
// 119 s behind would read t0 - 119 + 120 = t0 + 1 < published.
//
// At t0 + 120 the first request takes the bundle into the mirror with no
// fetch: now >= published and now < expires - 120 = t0 + 3600. The client
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
// now < t0 + 3630 - 120, and the peer is asked again after the retry pause.
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
// due at t0 + 1800, and the margin is 120 s. relay-1 and relay-3 sign again at
// 1800 s, relay-2 does not. Its bundle is in relay-1's mirror while
// now < 3600 - 120 = 3480: listed at 3479, where a client 119 s ahead reads
// 3598 < 3600, and left out at 3480. It stays a peer for extending circuits
// until 3600. relay-2 signs again at 3480 and the next pass brings it back
func TestStaleBundleLeavesTheMirrorAndAFreshOneReturns(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	cache := n1.takeRoster(t, c.roster())
	cache.refresh()

	c.clock.advance(1800 * time.Second)
	n1.n.refreshIfDue()
	n3.n.refreshIfDue()
	cache.refresh()

	c.clock.advance(1679 * time.Second)
	if listed, err := c.clientTakes(t, n1, 119*time.Second); err != nil || len(listed) != 3 {
		t.Fatalf("3479 s: a client 119 s ahead got %v, %v, want all three nodes", listed, err)
	}
	c.clock.advance(time.Second)
	asked := n2.n.descriptorRequests.Load()
	listed, err := c.clientTakes(t, n1, 119*time.Second)
	if err != nil || !slices.Equal(listed, []string{n1.n.addr, n3.n.addr}) {
		t.Fatalf("3480 s: a client 119 s ahead got %v, %v, want the mirror without relay-2", listed, err)
	}
	if n2.n.descriptorRequests.Load() != asked {
		t.Fatal("a request for the descriptors fetched from a peer")
	}
	if key, ok := n1.n.peerKey(n2.n.addr); !ok || !bytes.Equal(key, n2.pub) {
		t.Fatal("relay-2 is no peer 120 s before its descriptor expires")
	}
	if got := n1.stats(t); !strings.Contains(got, `"peers":2`) {
		t.Fatalf("stats 120 s before the descriptor expires: %s", got)
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
// With relay-1's margin of 120 s the bundle is in its mirror while
// now < 600 - 120 = 480. At 479 a client 119 s ahead reads 598 < 600 and
// accepts it; from 480 the mirror goes on without relay-2, which serves its
// own descriptor and stays a peer for extending circuits until 600
func TestPeerLeavesTheMirrorAMarginBeforeItsCertificateEnds(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	n1.enroll(t, t0.Add(72*time.Hour))
	n2.enroll(t, t0.Add(600*time.Second))
	n3.enroll(t, t0.Add(72*time.Hour))
	cache := n1.takeRoster(t, c.roster())
	cache.refresh()

	c.clock.advance(479 * time.Second)
	n2.n.refreshIfDue()
	cache.refresh()
	if listed, err := c.clientTakes(t, n1, 119*time.Second); err != nil || len(listed) != 3 {
		t.Fatalf("479 s: a client 119 s ahead got %v, %v, want all three nodes", listed, err)
	}
	c.clock.advance(time.Second)
	cache.refresh()
	listed, err := c.clientTakes(t, n1, 119*time.Second)
	if err != nil || !slices.Equal(listed, []string{n1.n.addr, n3.n.addr}) {
		t.Fatalf("480 s: a client 119 s ahead got %v, %v, want the mirror without relay-2", listed, err)
	}
	c.clock.advance(119 * time.Second)
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
// relay-1 follows its own wait, as keepPeers does. Times are seconds after t0,
// in steps of 1 s.
//
// ttl = 60: checkEvery = 15, margin = 60/8 = 7. relay-2's timer fires at 14,
// 29, 44: at 29 its descriptor of t0 (expires 60) is 29 s old, under the half
// of 30, so it signs again at 44, the latest its timer allows (published 44,
// expires 104). Passes of relay-1: the first entries are due at 30, so 30,
// then every 5 while relay-2 is due: 35, 40, 45, and 45 brings the bundle of
// 44. The bundle of t0 may stay in the mirror while now < 60 - 7 = 53, so the
// new one comes 8 s early. A client 6 s ahead reads at most 44 + 6 = 50 < 60
// on the old bundle. relay-1's own timer fires at 7, 22, 37 and signs at 37,
// 23 s before its descriptor expires.
//
// ttl = 1200: checkEvery = 60, margin = min(120, 150) = 120. relay-2's timer
// fires at 59 + 60k: at 599 the descriptor is 599 s old, under 600, so it
// signs at 659. Passes of relay-1: 600, then every 5, and 660 brings the bundle
// of 659. The bundle of t0 may stay while now < 1200 - 120 = 1080, so the new
// one comes 420 s early, and a client 119 s ahead reads at most
// 659 + 119 = 778 < 1200 on the old bundle.
//
// The later periods repeat the first with the same offsets
func TestHonestPeersStayInTheMirrorAcrossReSigning(t *testing.T) {
	for _, tc := range []struct {
		ttl   time.Duration
		ahead time.Duration
	}{
		{time.Minute, 6 * time.Second},
		{20 * time.Minute, 119 * time.Second},
	} {
		t.Run(tc.ttl.String(), func(t *testing.T) {
			c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
			for _, f := range c.nodes {
				f.setTTL(tc.ttl)
			}
			c.enroll(t, t0.Add(72*time.Hour))
			n1 := c.nodes[0]
			cache := n1.takeRoster(t, c.roster())
			if !cache.refresh() {
				t.Fatalf("refresh: %s", n1.log.String())
			}
			every := int(checkEvery(tc.ttl) / time.Second)
			phase := []int{every / 2, every - 1, 0}
			pass := c.clock.Now().Add(cache.wait())
			for s := 1; s <= int(3*tc.ttl/time.Second); s++ {
				c.clock.advance(time.Second)
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
				for _, ahead := range []time.Duration{tc.ahead, -119 * time.Second} {
					if listed, err := c.judge(t, n1, raw, ahead); err != nil || len(listed) != 3 {
						t.Fatalf("%d s: a client %v ahead got %v, %v, want all three nodes", s, ahead, listed, err)
					}
				}
			}
		})
	}
}
