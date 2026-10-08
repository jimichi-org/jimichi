package main

import (
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/pki"
)

// how often relay-1 asked for each peer by every second after the start, one
// second at a time on the cluster's clock: relay-1's passes follow its own wait
// as in keepPeers, the timers of the other nodes fire at 59 + 60k s and
// relay-1's at 30 + 60k s, and at runs before the pass of its second
func (c *cluster) run(t *testing.T, cache *peerCache, seconds int, at func(s int)) map[string][]int {
	t.Helper()
	var mu sync.Mutex
	count := make(map[string]int)
	get := cache.fetch
	cache.fetch = func(addr string) ([]byte, error) {
		mu.Lock()
		count[addr]++
		mu.Unlock()
		return get(addr)
	}
	asked := make(map[string][]int)
	pass := c.clock.Now()
	for s := 0; s <= seconds; s++ {
		if s > 0 {
			c.clock.advance(time.Second)
		}
		for i, f := range c.nodes {
			if f.n.id != nil && (i == 0 && s%60 == 30 || i > 0 && s%60 == 59) {
				f.n.refreshIfDue()
			}
		}
		if at != nil {
			at(s)
		}
		if now := c.clock.Now(); !now.Before(pass) {
			cache.refresh()
			pass = now.Add(cache.wait())
		}
		for _, addr := range cache.addrs {
			asked[addr] = append(asked[addr], count[addr])
		}
	}
	return asked
}

func wantAsked(t *testing.T, who string, asked []int, want map[int]int) {
	t.Helper()
	for _, s := range slices.Sorted(maps.Keys(want)) {
		if n := want[s]; asked[s] != n {
			t.Errorf("%s was asked %d times by %d s, want %d", who, asked[s], s, n)
		}
	}
}

// relay-2 and relay-3 sign for an hour at 0 and again when their timer first
// finds the age at 1800 s or more, at 1859. Both are due at 1800, so relay-1
// asks every 5 s from 1800 and gets the same bundle until 1855; the pass at
// 1860 brings the bundle of 1859, due at 1859 + 1800 = 3659, and the passes
// go back to a minute apart
func TestPeerServingItsOldDescriptorIsAskedEveryRetryPause(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2 := c.nodes[0], c.nodes[1]
	cache := n1.takeRoster(t, c.roster())
	asked := c.run(t, cache, 3600, nil)

	for _, f := range c.nodes[1:] {
		want := map[int]int{0: 1, 1799: 1, 1860: 14, 3600: 14}
		for s := 1800; s < 1860; s++ {
			want[s] = 2 + (s-1800)/5
		}
		wantAsked(t, f.n.name, asked[f.n.addr], want)
	}
	if _, ok := n1.n.peerKey(n2.n.addr); !ok {
		t.Fatal("relay-2 is no peer after it signed again")
	}
	if got := cache.wait(); got != 59*time.Second {
		t.Fatalf("wait at 3600 s = %v, want 59 s to the bundles due at 3659", got)
	}
}

// relay-2's certificate ends at 2400 s, so each of its descriptors ends there
// too and none is fetched again before it ends, although relay-2 signs at 1859
// and relay-1 asks relay-3 every 5 s from 1800 to 1860. At 2400 relay-2 answers
// 503 and is asked once a minute from then, at 2460, 2520 and so on, while
// relay-3 stays at a minute between passes
func TestPeerIsNotAskedInTheLastStretchOfItsCertificateNorAfter(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	n1.enroll(t, t0.Add(72*time.Hour))
	n2.enroll(t, t0.Add(2400*time.Second))
	n3.enroll(t, t0.Add(72*time.Hour))
	cache := n1.takeRoster(t, c.roster())
	asked := c.run(t, cache, 2700, func(s int) {
		_, ok := n1.n.peerKey(n2.n.addr)
		if s > 0 && ok != (s < 2400) {
			t.Fatalf("%d s: relay-2 held %v, want held while its certificate is valid", s, ok)
		}
	})

	wantAsked(t, "relay-2", asked[n2.n.addr], map[int]int{0: 1, 1800: 1, 2399: 1, 2400: 2, 2459: 2, 2460: 3, 2700: 7})
	wantAsked(t, "relay-3", asked[n3.n.addr], map[int]int{0: 1, 1799: 1, 1860: 14, 2700: 14})
	if got := strings.Count(n1.log.String(), "peer "+n2.n.addr+": descriptor:"); got != 1 {
		t.Fatalf("relay-2 failed into the log %d times, want once: %q", got, n1.log.String())
	}
	if got := cache.wait(); got != time.Minute {
		t.Fatalf("wait with relay-2 past its certificate = %v, want a minute", got)
	}
	if code, _ := n1.descriptors(t); code != http.StatusOK {
		t.Fatalf("GET /descriptors past relay-2's certificate = %d, want the mirror without it", code)
	}
}

// without node authentication a bundle carries no times: each peer is asked a
// minute after its last fetch, and one that fails is asked after the retry
// pause and stays held, since nothing ends its entry
func TestUnsignedPeersAreAskedEveryMinute(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	c := &cluster{p: p, web: fetch.NewClient(), routes: make(map[string]string), clock: &clock{now: t0}}
	for _, name := range []string{"relay-1", "relay-2", "relay-3"} {
		_, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := pki.Unsigned(p, pub, pub)
		if err != nil {
			t.Fatal(err)
		}
		f := &fixture{p: p, pub: pub, log: &logBuffer{}}
		f.n = &node{p: p, addr: addrOf(name), unsigned: unsigned, ttl: time.Hour, now: c.clock.Now, fetchPeer: c.fetch}
		f.n.logger = log.New(f.log, "", 0)
		f.serve(t)
		c.route(f.n.addr, f.info.URL)
		c.nodes = append(c.nodes, f)
	}
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	n1.n.setPeers([]string{n2.n.addr, n3.n.addr}, unverifiedPeer(p))
	cache := n1.n.peers.Load()

	asked := c.run(t, cache, 300, func(s int) {
		switch s {
		case 90:
			c.route(n2.n.addr, "")
		case 150:
			c.route(n2.n.addr, n2.info.URL)
		}
		if _, ok := cache.peer(n2.n.addr); s > 0 && !ok {
			t.Fatalf("%d s: relay-2 is not held", s)
		}
	})

	// relay-2 fails at 120 and every 5 s after it until it answers at 150, a
	// minute after which it is due again
	wantAsked(t, "relay-2", asked[n2.n.addr], map[int]int{0: 1, 59: 1, 60: 2, 119: 2, 120: 3, 124: 3, 125: 4, 145: 8, 150: 9, 209: 9, 210: 10, 270: 11, 300: 11})
	wantAsked(t, "relay-3", asked[n3.n.addr], map[int]int{0: 1, 59: 1, 60: 2, 120: 3, 179: 3, 180: 4, 240: 5, 300: 6})
	if listed := n1.mirrored(t); len(listed) != 3 {
		t.Fatalf("GET /descriptors lists %v, want all three nodes", listed)
	}
}
