package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/pki"
)

var consistencySuites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

// the mirror of a roster node over the peer path, routed like a descriptor
func (c *cluster) fetchMirror(addr string) ([]pki.MirrorEntry, error) {
	c.mu.Lock()
	url, ok := c.routes[addr]
	c.mu.Unlock()
	if !ok {
		return nil, errors.New("no node at " + addr)
	}
	return fetch.Mirror(c.web, url+"/descriptors/peer", 1, 0)
}

// the peers in the listed order, so a test knows which mirror a pass reads first
func listedOrder(n, k int) ([]int, error) {
	idx := make([]int, k)
	for i := range idx {
		idx[i] = i
	}
	return idx, nil
}

// a fixed order of the candidates, by their places in the listed order
func order(places ...int) func(n, k int) ([]int, error) {
	return func(n, k int) ([]int, error) {
		return places[:k], nil
	}
}

// turns the consistency check on at every node of the cluster; before the roster
func (c *cluster) checking(every time.Duration, draw func(n, k int) ([]int, error)) {
	for _, f := range c.nodes {
		f.n.check = true
		f.n.fetchMirror = c.fetchMirror
		f.n.drawPeers = draw
		f.n.crossEvery = every
	}
}

func agreement(t *testing.T, p jcrypto.CryptoProvider) []byte {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	return pub
}

// a roster node certified by the cluster's CA that signs whatever a test needs
// and serves every honest node an answer of its own; its own info port answers
// 503 to the mirror
type rogue struct {
	c        *cluster
	id       *pki.Identity
	addr     string
	link     []byte
	requests atomic.Uint64
	mirrors  atomic.Uint64
	mu       sync.Mutex
	served   map[string][]byte
	blocked  map[string]bool
}

func (c *cluster) newRogue(t *testing.T, name string, notAfter time.Time) *rogue {
	t.Helper()
	id, err := pki.NewIdentity(c.p, name, addrOf(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	n := nonce(t)
	raw, err := id.Request(n)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := c.ca.Issue(req, t0, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), t0); err != nil {
		t.Fatal(err)
	}
	r := &rogue{c: c, id: id, addr: addrOf(name), link: agreement(t, c.p), served: map[string][]byte{}, blocked: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /descriptors/peer", func(w http.ResponseWriter, _ *http.Request) {
		r.mirrors.Add(1)
		http.Error(w, "no descriptors: the node has no roster", http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c.route(r.addr, srv.URL)
	return r
}

func (r *rogue) sign(t *testing.T, epoch uint32, onion []byte, now time.Time, ttl time.Duration) []byte {
	t.Helper()
	r.id.SetKeys(r.link, onion, epoch)
	if err := r.id.Refresh(now, ttl); err != nil {
		t.Fatal(err)
	}
	b, ok := r.id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	return b
}

func (r *rogue) serveTo(f *fixture, bundle []byte) {
	r.mu.Lock()
	r.served[f.n.addr] = bundle
	r.mu.Unlock()
}

// the honest node's fetch hook answers the rogue's address with what the
// rogue serves that node
func (r *rogue) hook(f *fixture) {
	inner := f.n.fetchPeer
	r.mu.Lock()
	r.blocked[f.n.addr] = false
	r.mu.Unlock()
	f.n.fetchPeer = func(addr string) ([]byte, error) {
		if addr != r.addr {
			return inner(addr)
		}
		r.requests.Add(1)
		r.mu.Lock()
		b := r.served[f.n.addr]
		r.mu.Unlock()
		if b == nil {
			return nil, errors.New("no answer")
		}
		return b, nil
	}
}

func (f *fixture) cache() *peerCache { return f.n.peers.Load() }

// the mirror a node serves, read without a request so the counters stay as
// the test left them
func mirrorItems(t *testing.T, c *peerCache) []pki.MirrorEntry {
	t.Helper()
	raw, ok := c.descriptors()
	if !ok {
		t.Fatal("no mirror in service")
	}
	entries, err := pki.ParseMirror(raw)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func itemOf(entries []pki.MirrorEntry, addr string) (pki.MirrorEntry, bool) {
	for _, e := range entries {
		if e.Addr == addr {
			return e, true
		}
	}
	return pki.MirrorEntry{}, false
}

// what a client that drew f as its entry makes of its mirror, every listed
// node read on its own, proofs read or not
func (c *cluster) clientView(t *testing.T, cache *peerCache, addrs []string, proofs bool) verify.View {
	t.Helper()
	entries := mirrorItems(t, cache)
	aligned := make([]pki.MirrorEntry, len(addrs))
	for i, addr := range addrs {
		if e, ok := itemOf(entries, addr); ok {
			aligned[i] = e
		}
	}
	pol := pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}
	if proofs {
		pol.MinLife = pki.MinDescriptorLife
	}
	v, err := verify.MirrorEntries(c.p, verify.Options{Auth: true, Trust: pol, Proofs: proofs}, addrs, aligned, c.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// the acceptance test of #176: relay-5 signs two onion keys under epoch 1 and
// serves relays 1 and 2 one and relays 3 and 4 the other. Each honest node
// holds what it fetched, so two mirrors show different keys. The first pass
// at relay-2 reads relay-1 (the key it holds), then relay-3, whose mirror
// carries the other key: the pair breaks the rule, relay-5 is refused with the
// pair as proof, relay-4 is still read and relay-5 is skipped as refused, so 3
// mirror fetches. Relay-3 draws relay-5 first and gets its 503, then takes the
// proof from relay-2's mirror; relays 4 and 1 take it from relay-2 as well.
// With the check off the same node stays a peer everywhere and the mirrors
// show the two keys
func TestTwoKeysInOneEpochAreProvenAndRefused(t *testing.T) {
	for _, s := range consistencySuites {
		t.Run(s.String(), func(t *testing.T) {
			names := []string{"relay-1", "relay-2", "relay-3", "relay-4", "relay-5"}
			addrs := make([]string, len(names))
			for i, name := range names {
				addrs[i] = addrOf(name)
			}
			stand := func(check bool) (*cluster, *rogue, [][]byte) {
				c := newCluster(t, s, names[:4]...)
				if check {
					c.checking(time.Minute, listedOrder)
				}
				c.enroll(t, t0.Add(72*time.Hour))
				r := c.newRogue(t, "relay-5", t0.Add(72*time.Hour))
				k1, k2 := agreement(t, c.p), agreement(t, c.p)
				a, b := r.sign(t, 1, k1, t0, time.Hour), r.sign(t, 1, k2, t0, time.Hour)
				for i, f := range c.nodes {
					r.hook(f)
					if i < 2 {
						r.serveTo(f, a)
					} else {
						r.serveTo(f, b)
					}
					f.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
				}
				for _, f := range c.nodes {
					f.cache().refresh()
				}
				return c, r, [][]byte{a, b}
			}

			c, r, keys := stand(true)
			for i, f := range c.nodes {
				if got := f.cache().held(); got != 4 {
					t.Fatalf("relay-%d holds %d peers after the refresh, want 4", i+1, got)
				}
			}
			if got := r.requests.Load(); got != 4 {
				t.Fatalf("relay-5 answered %d descriptor requests, want 4", got)
			}
			one, _ := itemOf(mirrorItems(t, c.nodes[0].cache()), r.addr)
			three, _ := itemOf(mirrorItems(t, c.nodes[2].cache()), r.addr)
			pol := pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}
			if bytes.Equal(one.Bundle, three.Bundle) || !bytes.Equal(one.Bundle, keys[0]) || !bytes.Equal(three.Bundle, keys[1]) {
				t.Fatal("the mirrors of relay-1 and relay-3 do not show the two bundles relay-5 served")
			}
			for _, b := range [][]byte{one.Bundle, three.Bundle} {
				if _, err := pki.VerifyStatement(c.p, pol, r.addr, b); err != nil {
					t.Fatalf("a bundle relay-5 served does not verify: %v", err)
				}
			}

			n2 := c.nodes[1]
			n2.cache().cross()
			for i, want := range []uint64{1, 0, 1, 1} {
				if got := c.nodes[i].n.peerMirrorRequests.Load(); got != want {
					t.Errorf("relay-%d answered %d mirror requests from peers after the pass at relay-2, want %d", i+1, got, want)
				}
			}
			if r.mirrors.Load() != 0 {
				t.Error("relay-2 asked the refused relay-5 for its mirror")
			}
			if _, ok := n2.n.peerKey(r.addr); ok || n2.cache().held() != 3 || n2.cache().refusedCount() != 1 {
				t.Fatalf("after the pass relay-2 extends to relay-5 %v, holds %d, refuses %d; want false, 3, 1", ok, n2.cache().held(), n2.cache().refusedCount())
			}
			want := "peer " + r.addr + ": refused: two onion keys in one epoch\n"
			if log := n2.log.String(); strings.Count(log, r.addr) != 1 || !strings.Contains(log, want) {
				t.Fatalf("relay-2 logged %q, want one line %q", log, want)
			}
			items := mirrorItems(t, n2.cache())
			proofItem, ok := itemOf(items, r.addr)
			if len(items) != 5 || !ok || proofItem.Proof == nil {
				t.Fatalf("relay-2 serves %d items, relay-5 as a proof %v; want 5 with the proof", len(items), ok && proofItem.Proof != nil)
			}
			conflict, err := pki.VerifyConflict(c.p, pol, r.addr, *proofItem.Proof)
			if err != nil || conflict.Rule != pki.RuleOnionKeyPerEpoch || bytes.Compare(proofItem.Proof.A, proofItem.Proof.B) >= 0 {
				t.Fatalf("the proof relay-2 serves: %+v, %v", conflict, err)
			}

			n3 := c.nodes[2]
			n3.cache().draw = order(3, 1, 0, 2)
			n3.cache().cross()
			log := n3.log.String()
			if strings.Count(log, "peer "+r.addr+": mirror: answered status 503\n") != 1 || strings.Count(log, want) != 1 || strings.Count(log, r.addr) != 2 {
				t.Fatalf("relay-3 logged %q, want the 503 line and the refused line once each", log)
			}
			if r.mirrors.Load() != 1 {
				t.Fatalf("relay-5 answered %d mirror requests, want the one from relay-3", r.mirrors.Load())
			}
			c.nodes[3].cache().draw = order(1, 0, 2, 3)
			c.nodes[3].cache().cross()
			c.nodes[0].cache().cross()
			for i, f := range c.nodes {
				if f.cache().refusedCount() != 1 || strings.Count(f.log.String(), want) != 1 {
					t.Fatalf("relay-%d: refused %d, refused lines %d; want 1 and 1", i+1, f.cache().refusedCount(), strings.Count(f.log.String(), want))
				}
				item, _ := itemOf(mirrorItems(t, f.cache()), r.addr)
				if item.Proof == nil || !bytes.Equal(item.Proof.A, proofItem.Proof.A) || !bytes.Equal(item.Proof.B, proofItem.Proof.B) {
					t.Fatalf("relay-%d does not serve the same proof as relay-2", i+1)
				}
				if f.n.mirrorRequests.Load() != 0 {
					t.Fatalf("relay-%d counted a client mirror request", i+1)
				}
			}

			c.clock.advance(40 * time.Minute)
			for range 3 {
				for _, f := range c.nodes {
					f.cache().refresh()
				}
			}
			if r.requests.Load() != 4 || c.nodes[0].cache().refusedCount() != 1 {
				t.Fatalf("after the refusal relay-5 answered %d requests, refused at relay-1 %d; want 4 and 1", r.requests.Load(), c.nodes[0].cache().refusedCount())
			}

			for i, f := range c.nodes {
				v := c.clientView(t, f.cache(), addrs, true)
				if !equalBools(v.Usable(), []bool{true, true, true, true, false}) || !errors.Is(v.Missing(4), pki.ErrConflict) {
					t.Fatalf("entry relay-%d with proofs: usable %v, missing %v", i+1, v.Usable(), v.Missing(4))
				}
				if verdict, absent, allowed := v.Judge(i, 3, 0); verdict != client.MirrorTaken || absent != 0 || allowed != 0 {
					t.Fatalf("entry relay-%d with proofs: Judge = %d, %d, %d, want taken with 0 of 0", i+1, verdict, absent, allowed)
				}
				v = c.clientView(t, f.cache(), addrs, false)
				if v.Missing(4) != verify.ErrNoBundle {
					t.Fatalf("entry relay-%d without proofs: missing %v, want %v", i+1, v.Missing(4), verify.ErrNoBundle)
				}
				if verdict, _, _ := v.Judge(i, 3, 0); verdict != client.MirrorLacksTooMany {
					t.Fatalf("entry relay-%d without proofs: Judge at missing 0 = %d, want too many", i+1, verdict)
				}
				if verdict, _, _ := v.Judge(i, 3, 1); verdict != client.MirrorTaken {
					t.Fatalf("entry relay-%d without proofs: Judge at missing 1 = %d, want taken", i+1, verdict)
				}
			}

			c, r, keys = stand(false)
			stop := make(chan struct{})
			var loops sync.WaitGroup
			for _, f := range c.nodes {
				f.n.wake = make(chan struct{})
				close(f.n.wake)
				f.n.peerRetry = 5 * time.Millisecond
				loops.Add(1)
				go func() {
					defer loops.Done()
					f.n.keepPeers(stop)
				}()
			}
			time.Sleep(100 * time.Millisecond)
			close(stop)
			loops.Wait()
			served := map[int]int{}
			for i, f := range c.nodes {
				if f.n.peerMirrorRequests.Load() != 0 || r.mirrors.Load() != 0 {
					t.Fatalf("the baseline made a pass: relay-%d answered %d, relay-5 %d", i+1, f.n.peerMirrorRequests.Load(), r.mirrors.Load())
				}
				if _, ok := f.n.peerKey(r.addr); !ok {
					t.Fatalf("the baseline relay-%d does not extend to relay-5", i+1)
				}
				item, ok := itemOf(mirrorItems(t, f.cache()), r.addr)
				switch {
				case !ok || item.Proof != nil:
					t.Fatalf("the baseline relay-%d does not serve a bundle for relay-5", i+1)
				case bytes.Equal(item.Bundle, keys[0]):
					served[0]++
				case bytes.Equal(item.Bundle, keys[1]):
					served[1]++
				}
			}
			if served[0] != 2 || served[1] != 2 {
				t.Fatalf("the baseline mirrors serve the first key %d times and the second %d, want 2 and 2", served[0], served[1])
			}
		})
	}
}

// relay-5 rotates at t0 + 1 h. The honest nodes fetch it at t0 (4 requests)
// and at t0 + 30 min when their entries are due (8); at t0 + 1 h only relay-1
// refreshes (9) and holds epoch 1 while relays 2 to 4 hold epoch 0. A pass at
// relay-2 adopts epoch 1 from relay-1's mirror without a request to relay-5;
// a pass that sees epoch 0 elsewhere changes nothing; the adopted entry is due
// at its published plus 30 min, t0 + 1 h 30, where the refresh asks relay-5
// once more (10)
func TestNewerEpochInAPeersMirrorIsAdopted(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3", "relay-4", "relay-5"}
	c := newCluster(t, jcrypto.SuiteC25519, names...)
	c.checking(time.Minute, listedOrder)
	n5 := c.nodes[4]
	n5.rotating(t, time.Hour)
	c.enroll(t, t0.Add(72*time.Hour))
	honest := c.nodes[:4]
	// relay-5 takes the roster too, so its mirror answers the passes
	for _, f := range c.nodes {
		f.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
		f.cache().refresh()
	}
	asked := func(want uint64, what string) {
		t.Helper()
		if got := n5.n.descriptorRequests.Load(); got != want {
			t.Fatalf("%s: relay-5 answered %d descriptor requests, want %d", what, got, want)
		}
	}
	asked(4, "after the first refresh")

	// the honest nodes re-sign their own descriptors as their timers would
	c.clock.advance(30 * time.Minute)
	n5.n.refreshIfDue()
	for _, f := range honest {
		f.n.refreshIfDue()
		f.cache().refresh()
	}
	asked(8, "after the re-signing at half the life")

	c.clock.advance(30 * time.Minute)
	n5.n.rotateIfDue()
	for _, f := range honest {
		f.n.refreshIfDue()
	}
	honest[0].cache().refresh()
	asked(9, "after the rotation")
	epochAt := func(f *fixture) uint32 {
		t.Helper()
		item, ok := itemOf(mirrorItems(t, f.cache()), n5.n.addr)
		if !ok || item.Bundle == nil {
			t.Fatalf("%s serves no bundle for relay-5", f.n.name)
		}
		v, err := pki.Verify(c.p, pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}, n5.n.addr, item.Bundle, c.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		return v.Epoch
	}
	for i, want := range []uint32{1, 0, 0, 0} {
		if got := epochAt(honest[i]); got != want {
			t.Fatalf("relay-%d holds epoch %d of relay-5, want %d", i+1, got, want)
		}
	}

	n2 := honest[1]
	before := len(n2.log.String())
	n2.cache().cross()
	if got := epochAt(n2); got != 1 {
		t.Fatalf("relay-2 holds epoch %d after its pass, want 1 adopted from relay-1", got)
	}
	one, _ := itemOf(mirrorItems(t, honest[0].cache()), n5.n.addr)
	two, _ := itemOf(mirrorItems(t, n2.cache()), n5.n.addr)
	if !bytes.Equal(one.Bundle, two.Bundle) {
		t.Fatal("the adopted entry is not the bundle relay-1 holds")
	}
	if n2.log.String()[before:] != "" || n2.cache().refusedCount() != 0 || n2.cache().held() != 4 {
		t.Fatalf("adoption logged %q, refused %d, held %d", n2.log.String()[before:], n2.cache().refusedCount(), n2.cache().held())
	}
	asked(9, "after the adoption")
	n2.cache().cross()
	if got := epochAt(n2); got != 1 {
		t.Fatalf("a pass that saw epoch 0 in the mirrors of relays 3 and 4 moved relay-2 to epoch %d", got)
	}
	honest[2].cache().cross()
	honest[3].cache().cross()
	for i, f := range honest {
		if got := epochAt(f); got != 1 {
			t.Fatalf("relay-%d holds epoch %d after the passes, want 1", i+1, got)
		}
	}
	if got := n2.cache().records[n5.n.addr].Epochs(); got != 2 {
		t.Fatalf("relay-2's record of relay-5 holds %d epochs, want 2", got)
	}

	c.clock.advance(30 * time.Minute)
	n2.n.refreshIfDue()
	n2.cache().refresh()
	asked(10, "at the adopted due")
}

// relay-4 cannot fetch relay-5 and holds three peers; a pass takes relay-5's
// statement from relay-1's mirror into the empty slot, due at its published
// plus half its life, where the direct fetch comes once relay-5 answers
func TestAdoptionFillsAnEmptySlot(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3", "relay-4", "relay-5"}
	c := newCluster(t, jcrypto.SuiteC25519, names...)
	c.checking(time.Minute, listedOrder)
	c.enroll(t, t0.Add(72*time.Hour))
	n4, n5 := c.nodes[3], c.nodes[4]
	inner := n4.n.fetchPeer
	var blocked atomic.Bool
	blocked.Store(true)
	n4.n.fetchPeer = func(addr string) ([]byte, error) {
		if addr == n5.n.addr && blocked.Load() {
			return nil, errors.New("no answer")
		}
		return inner(addr)
	}
	for _, f := range c.nodes[:4] {
		f.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
		f.cache().refresh()
	}
	if n4.cache().held() != 3 {
		t.Fatalf("relay-4 holds %d peers, want 3 without relay-5", n4.cache().held())
	}
	n4.cache().cross()
	if _, ok := n4.n.peerKey(n5.n.addr); !ok || n4.cache().held() != 4 {
		t.Fatalf("after the pass relay-4 extends to relay-5 %v and holds %d, want true and 4", ok, n4.cache().held())
	}
	asked := n5.n.descriptorRequests.Load()
	n4.cache().refresh()
	if n5.n.descriptorRequests.Load() != asked {
		t.Fatal("the adopted entry was fetched before it was due")
	}
	blocked.Store(false)
	c.clock.advance(30 * time.Minute)
	n4.cache().refresh()
	if n5.n.descriptorRequests.Load() != asked+1 {
		t.Fatal("the adopted entry was not fetched at its due")
	}
}

// epoch 0 lives from t0 for 20 min; epoch 2 published at t0 + 10 min overlaps
// it and is refused; published at t0 + 22 min, Skew past the expiry, it is
// taken as the entry
func TestEpochsTwoApartMustNotOverlap(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3", "relay-4", "relay-5"}
	for _, late := range []time.Duration{10 * time.Minute, 22 * time.Minute} {
		c := newCluster(t, jcrypto.SuiteC25519, names[:4]...)
		c.checking(time.Minute, listedOrder)
		c.enroll(t, t0.Add(72*time.Hour))
		r := c.newRogue(t, "relay-5", t0.Add(72*time.Hour))
		n1 := c.nodes[0]
		r.hook(n1)
		r.serveTo(n1, r.sign(t, 0, agreement(t, c.p), t0, 20*time.Minute))
		n1.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
		n1.cache().refresh()
		if _, ok := n1.n.peerKey(r.addr); !ok {
			t.Fatal("epoch 0 was not taken")
		}
		c.clock.advance(late)
		r.serveTo(n1, r.sign(t, 2, agreement(t, c.p), c.clock.Now(), 20*time.Minute))
		n1.cache().refresh()
		_, ok := n1.n.peerKey(r.addr)
		refused := n1.cache().refusedCount()
		want := "peer " + r.addr + ": refused: epochs two apart overlap\n"
		switch {
		case late < 20*time.Minute && (ok || refused != 1 || !strings.Contains(n1.log.String(), want)):
			t.Fatalf("epoch 2 at %v: held %v, refused %d, log %q; want refused with %q", late, ok, refused, n1.log.String(), want)
		case late >= 20*time.Minute && (!ok || refused != 0):
			t.Fatalf("epoch 2 at %v: held %v, refused %d; want taken", late, ok, refused)
		}
	}
}

// a descriptor of 959 s is not taken and logged once under its class; one of
// 960 s is; a certificate that ends in 300 s cuts a one hour descriptor, which
// is exempt
func TestShortDescriptorIsRefusedUnlessTruncated(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3", "relay-4", "relay-5"}
	c := newCluster(t, jcrypto.SuiteC25519, names[:4]...)
	c.checking(time.Minute, listedOrder)
	c.enroll(t, t0.Add(72*time.Hour))
	r := c.newRogue(t, "relay-5", t0.Add(72*time.Hour))
	n1 := c.nodes[0]
	r.hook(n1)
	k := agreement(t, c.p)
	r.serveTo(n1, r.sign(t, 0, k, t0, 959*time.Second))
	n1.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
	n1.cache().refresh()
	n1.cache().refresh()
	want := "peer " + r.addr + ": descriptor: " + pki.ErrDescLife.Error() + "\n"
	if _, ok := n1.n.peerKey(r.addr); ok || n1.cache().held() != 3 || strings.Count(n1.log.String(), want) != 1 {
		t.Fatalf("a 959 s descriptor: held %v, peers %d, log %q", ok, n1.cache().held(), n1.log.String())
	}
	r.serveTo(n1, r.sign(t, 0, k, t0.Add(time.Second), 960*time.Second))
	n1.cache().refresh()
	if _, ok := n1.n.peerKey(r.addr); !ok || n1.cache().held() != 4 {
		t.Fatalf("a 960 s descriptor: held %v, peers %d, want taken", ok, n1.cache().held())
	}

	c = newCluster(t, jcrypto.SuiteC25519, names[:4]...)
	c.checking(time.Minute, listedOrder)
	c.enroll(t, t0.Add(72*time.Hour))
	r = c.newRogue(t, "relay-5", t0.Add(300*time.Second))
	n1 = c.nodes[0]
	r.hook(n1)
	r.serveTo(n1, r.sign(t, 0, k, t0, time.Hour))
	n1.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
	n1.cache().refresh()
	if _, ok := n1.n.peerKey(r.addr); !ok {
		t.Fatalf("a descriptor cut by its certificate was not taken: %s", n1.log.String())
	}
}

// eight pairwise consistent statements of epochs 1 to 8 published 100 h ahead
// are served one per retry pass: none is admitted, the entry stays epoch 0
// and due, and the record holds that one epoch, so the second key of epoch 0
// still meets the first and is proven
func TestFutureStatementsCannotFillTheRecord(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3", "relay-4", "relay-5"}
	c := newCluster(t, jcrypto.SuiteC25519, names[:4]...)
	c.checking(time.Minute, listedOrder)
	c.enroll(t, t0.Add(72*time.Hour))
	r := c.newRogue(t, "relay-5", t0.Add(200*time.Hour))
	n2 := c.nodes[1]
	r.hook(n2)
	k, k2 := agreement(t, c.p), agreement(t, c.p)
	a := r.sign(t, 0, k, t0, time.Hour)
	b := r.sign(t, 0, k2, t0.Add(time.Second), time.Hour)
	far := t0.Add(100 * time.Hour)
	var ahead [][]byte
	for e := uint32(1); e <= 8; e++ {
		at := far.Add(time.Duration((e-1)/2) * (time.Hour + pki.Skew))
		ahead = append(ahead, r.sign(t, e, agreement(t, c.p), at, time.Hour))
	}
	r.serveTo(n2, a)
	n2.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
	n2.cache().refresh()
	if _, ok := n2.n.peerKey(r.addr); !ok {
		t.Fatal("epoch 0 was not taken")
	}
	c.clock.advance(30 * time.Minute)
	want := "peer " + r.addr + ": descriptor: " + pki.ErrDescTime.Error() + "\n"
	for i, f := range ahead {
		r.serveTo(n2, f)
		n2.cache().refresh()
		if _, ok := n2.n.peerKey(r.addr); !ok || n2.cache().records[r.addr].Epochs() != 1 || n2.cache().refusedCount() != 0 {
			t.Fatalf("future epoch %d: held %v, epochs %d, refused %d", i+1, ok, n2.cache().records[r.addr].Epochs(), n2.cache().refusedCount())
		}
	}
	if strings.Count(n2.log.String(), want) != 1 {
		t.Fatalf("the future statements were logged as %q, want once %q", n2.log.String(), want)
	}
	asked := r.requests.Load()
	r.serveTo(n2, b)
	n2.cache().refresh()
	if r.requests.Load() != asked+1 {
		t.Fatal("the due entry was not fetched on the next pass")
	}
	if n2.cache().refusedCount() != 1 || !strings.Contains(n2.log.String(), "peer "+r.addr+": refused: two onion keys in one epoch\n") {
		t.Fatalf("the second key of epoch 0 was not proven: %s", n2.log.String())
	}
}

// relay-1 serves a mirror whose items are a proof of two consistent bundles
// of relay-3 and a proof about relay-2 itself: relay-2 keeps relay-3 a peer,
// ignores the item about itself and logs the bad proof once over three passes
func TestProofFromAPeerMustVerify(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3", "relay-4"}
	c := newCluster(t, jcrypto.SuiteC25519, names...)
	c.checking(time.Minute, listedOrder)
	c.enroll(t, t0.Add(72*time.Hour))
	n1, n2, n3, n4 := c.nodes[0], c.nodes[1], c.nodes[2], c.nodes[3]
	for _, f := range c.nodes {
		f.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
		f.cache().refresh()
	}
	resigned := func(f *fixture) *pki.Proof {
		t.Helper()
		_, first := f.descriptor(t)
		c.clock.advance(time.Second)
		f.resign(t)
		_, second := f.descriptor(t)
		pr, err := pki.NewProof(first, second)
		if err != nil {
			t.Fatal(err)
		}
		return pr
	}
	_, own := n1.descriptor(t)
	_, four := n4.descriptor(t)
	crafted, err := pki.MarshalMirror([]pki.MirrorEntry{
		{Addr: n1.n.addr, Bundle: own}, {Addr: n2.n.addr, Proof: resigned(n2)}, {Addr: n3.n.addr, Proof: resigned(n3)}, {Addr: n4.n.addr, Bundle: four},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		b, _ := n1.n.descriptor()
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /descriptors/peer", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(crafted) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c.route(n1.n.addr, srv.URL)

	for range 3 {
		n2.cache().cross()
	}
	if _, ok := n2.n.peerKey(n3.n.addr); !ok || n2.cache().refusedCount() != 0 {
		t.Fatalf("relay-3 is no peer of relay-2 after the crafted proof: held %v, refused %d", ok, n2.cache().refusedCount())
	}
	want := "peer " + n1.n.addr + ": mirror: " + pki.ErrNoConflict.Error() + "\n"
	if log := n2.log.String(); strings.Count(log, want) != 1 || strings.Contains(log, n2.n.addr) {
		t.Fatalf("relay-2 logged %q, want once %q and nothing about itself", log, want)
	}
}

// a roster of six: one pass reads the mirrors of four of the five peers,
// fifty reach every one, no pass asks a client's path or a descriptor, and
// with every peer refused a pass draws nothing
func TestCrossPassAsksFourPeersAtMost(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3", "relay-4", "relay-5", "relay-6"}
	c := newCluster(t, jcrypto.SuiteC25519, names...)
	c.checking(time.Minute, nil)
	c.enroll(t, t0.Add(72*time.Hour))
	for _, f := range c.nodes {
		f.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
		f.cache().refresh()
	}
	n1 := c.nodes[0]
	descriptors := func() (total uint64) {
		for _, f := range c.nodes {
			total += f.n.descriptorRequests.Load()
		}
		return total
	}
	before := descriptors()
	n1.cache().cross()
	asked := 0
	for _, f := range c.nodes[1:] {
		got := f.n.peerMirrorRequests.Load()
		if got > 1 {
			t.Fatalf("%s answered %d mirror requests in one pass", f.n.name, got)
		}
		asked += int(got)
	}
	if asked != crossPeers {
		t.Fatalf("one pass asked %d peers, want %d", asked, crossPeers)
	}
	for range 50 {
		n1.cache().cross()
	}
	for _, f := range c.nodes {
		if f != n1 && f.n.peerMirrorRequests.Load() == 0 {
			t.Fatalf("%s was never asked over 51 passes", f.n.name)
		}
		if f.n.mirrorRequests.Load() != 0 {
			t.Fatalf("%s counted a client mirror request", f.n.name)
		}
	}
	if descriptors() != before {
		t.Fatal("a pass fetched a descriptor")
	}

	draws := 0
	n1.cache().draw = func(n, k int) ([]int, error) {
		draws++
		return listedOrder(n, k)
	}
	n1.cache().mu.Lock()
	for _, addr := range n1.cache().addrs {
		n1.cache().refused[addr] = &pki.Conflict{Addr: addr, Rule: pki.RuleLinkKey}
	}
	n1.cache().mu.Unlock()
	asked = 0
	for _, f := range c.nodes[1:] {
		asked += int(f.n.peerMirrorRequests.Load())
	}
	n1.cache().cross()
	after := 0
	for _, f := range c.nodes[1:] {
		after += int(f.n.peerMirrorRequests.Load())
	}
	if draws != 0 || after != asked {
		t.Fatalf("with every peer refused a pass drew %d times and asked %d peers", draws, after-asked)
	}
}

// the timer of a running node with the check: nothing before the roster, then
// a pass every period, so every peer is asked for its mirror within seconds
func TestKeepPeersRunsThePassOnItsTimer(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3"}
	c := newCluster(t, jcrypto.SuiteC25519, names...)
	c.checking(10*time.Millisecond, nil)
	c.enroll(t, t0.Add(72*time.Hour))
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	n1.n.wake = make(chan struct{})
	n1.n.peerRetry = 5 * time.Millisecond
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		n1.n.keepPeers(stop)
		close(done)
	}()
	defer func() {
		close(stop)
		<-done
	}()
	time.Sleep(30 * time.Millisecond)
	if n2.n.peerMirrorRequests.Load()+n3.n.peerMirrorRequests.Load() != 0 {
		t.Fatal("a pass ran before the roster")
	}
	n1.takeRoster(t, c.roster())
	deadline := time.Now().Add(3 * time.Second)
	for n2.n.peerMirrorRequests.Load() == 0 || n3.n.peerMirrorRequests.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no pass over both peers within 3 s: %s", n1.log.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
	if n1.cache().refusedCount() != 0 || strings.Contains(n1.log.String(), "refused") {
		t.Fatalf("honest peers were refused: %s", n1.log.String())
	}
}

// passes start one period apart however long the fetches of one take: the
// pass is stamped before it runs, so with a period of 300 ms and mirrors that
// take 200 ms to answer the starts come 300 ms apart, not 500
func TestPassesStartOnePeriodApart(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3"}
	c := newCluster(t, jcrypto.SuiteC25519, names...)
	c.checking(300*time.Millisecond, nil)
	c.enroll(t, t0.Add(72*time.Hour))
	n1 := c.nodes[0]
	var mu sync.Mutex
	var starts []time.Time
	inner := c.fetchMirror
	n1.n.fetchMirror = func(addr string) ([]pki.MirrorEntry, error) {
		time.Sleep(200 * time.Millisecond)
		return inner(addr)
	}
	n1.n.drawPeers = func(n, k int) ([]int, error) {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		return listedOrder(n, k)
	}
	n1.n.wake = make(chan struct{})
	n1.n.peerRetry = 50 * time.Millisecond
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		n1.n.keepPeers(stop)
		close(done)
	}()
	n1.takeRoster(t, c.roster())
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(starts)
		mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(starts) < 3 {
		t.Fatalf("%d passes within 5 s, want 3", len(starts))
	}
	for i := 1; i < 3; i++ {
		gap := starts[i].Sub(starts[i-1])
		if gap < 300*time.Millisecond || gap > 450*time.Millisecond {
			t.Fatalf("pass %d started %v after the one before, want the period of 300 ms and not the period plus the fetches", i, gap)
		}
	}
}

// a proof against the node itself in the mirror of a peer is logged once,
// with the rule and nothing else, and does not refuse anyone; the mirror
// classes of one pass are logged one line each, and a class that stays is not
// logged again
func TestProofAgainstThisNodeIsLoggedOnce(t *testing.T) {
	names := []string{"relay-1", "relay-2", "relay-3"}
	c := newCluster(t, jcrypto.SuiteC25519, names...)
	c.checking(time.Minute, listedOrder)
	c.enroll(t, t0.Add(72*time.Hour))
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	for _, f := range c.nodes {
		f.takeRoster(t, rosterOf(c.ca.Anchor(), names...))
		f.cache().refresh()
	}
	// two keys of relay-2 under epoch 0: a real proof against it
	_, first := n2.descriptor(t)
	n2.n.mu.Lock()
	n2.n.id.SetKeys(n2.pub, agreement(t, c.p), 0)
	n2.n.mu.Unlock()
	c.clock.advance(time.Second)
	n2.resign(t)
	_, second := n2.descriptor(t)
	pr, err := pki.NewProof(first, second)
	if err != nil {
		t.Fatal(err)
	}
	_, own := n1.descriptor(t)
	_, three := n3.descriptor(t)
	crafted, err := pki.MarshalMirror([]pki.MirrorEntry{
		{Addr: n1.n.addr, Bundle: own}, {Addr: n2.n.addr, Proof: pr}, {Addr: n3.n.addr, Bundle: altered(t, three)},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		b, _ := n1.n.descriptor()
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /descriptors/peer", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(crafted) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c.route(n1.n.addr, srv.URL)

	n2.cache().draw = order(0, 1)
	for range 3 {
		n2.cache().cross()
	}
	log := n2.log.String()
	accusation := "a peer serves a proof against this node: two onion keys in one epoch\n"
	badItem := "peer " + n1.n.addr + ": mirror: " + pki.ErrDescSignature.Error() + "\n"
	if strings.Count(log, accusation) != 1 || strings.Count(log, badItem) != 1 || strings.Contains(log, "refused") {
		t.Fatalf("relay-2 logged %q, want the accusation and the altered bundle once each and no refusal", log)
	}
	if n2.cache().refusedCount() != 0 || n2.cache().held() != 2 {
		t.Fatalf("relay-2 refuses %d and holds %d, want 0 and 2", n2.cache().refusedCount(), n2.cache().held())
	}
}

// the bundle of an altered descriptor signature
func altered(t *testing.T, bundle []byte) []byte {
	t.Helper()
	b, err := pki.ParseBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	b.Descriptor[len(b.Descriptor)-1] ^= 1
	return b.Marshal()
}

// the period is checked whatever the switch says
func TestConsistencyFlags(t *testing.T) {
	for _, c := range []struct {
		every time.Duration
		ok    bool
	}{
		{time.Minute, true}, {30 * time.Second, true}, {time.Hour, true},
		{29 * time.Second, false}, {61 * time.Minute, false}, {0, false}, {-time.Minute, false},
	} {
		if err := checkConsistencyFlags(c.every); (err == nil) != c.ok {
			t.Errorf("checkConsistencyFlags(%v) = %v, want ok %v", c.every, err, c.ok)
		}
	}
}

// the peer path serves the same bytes as the client path and counts apart
func TestInfoMuxCountsPeerMirrorRequestsApart(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1 := c.nodes[0]
	before, beforeBody := call(t, http.MethodGet, n1.info.URL+"/descriptors", nil)
	peerBefore, peerBeforeBody := call(t, http.MethodGet, n1.info.URL+"/descriptors/peer", nil)
	if before != http.StatusServiceUnavailable || peerBefore != before || !bytes.Equal(beforeBody, peerBeforeBody) {
		t.Fatalf("before the roster: /descriptors %d %q, /descriptors/peer %d %q", before, beforeBody, peerBefore, peerBeforeBody)
	}
	n1.takeRoster(t, c.roster())
	n1.cache().refresh()
	code, body := call(t, http.MethodGet, n1.info.URL+"/descriptors", nil)
	peerCode, peerBody := call(t, http.MethodGet, n1.info.URL+"/descriptors/peer", nil)
	if code != http.StatusOK || peerCode != code || !bytes.Equal(body, peerBody) {
		t.Fatalf("/descriptors %d, /descriptors/peer %d, same bytes %v", code, peerCode, bytes.Equal(body, peerBody))
	}
	if n1.n.mirrorRequests.Load() != 2 || n1.n.peerMirrorRequests.Load() != 2 {
		t.Fatalf("mirror_requests %d, peer_mirror_requests %d, want 2 and 2", n1.n.mirrorRequests.Load(), n1.n.peerMirrorRequests.Load())
	}
	if got := n1.stats(t); !strings.Contains(got, `"peer_mirror_requests":2`) || !strings.Contains(got, `"peers_refused":0`) {
		t.Fatalf("stats: %s", got)
	}
}
