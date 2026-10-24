package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

// the epoch of node x in the mirror of node y; -1 when the mirror lacks x or
// y serves none. Read without the signatures: every bundle in a mirror was
// verified when it was taken, and the simulation reads nine of them a second
func epochHeld(t *testing.T, y, x *fixture) int64 {
	t.Helper()
	raw, ok := y.cache().descriptors()
	if !ok {
		return -1
	}
	entries, err := pki.ParseMirror(raw)
	if err != nil {
		t.Fatal(err)
	}
	item, ok := itemOf(entries, x.n.addr)
	if !ok || item.Bundle == nil {
		return -1
	}
	b, err := pki.ParseBundle(item.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.ParseDescriptor(b.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return int64(d.Epoch)
}

// three nodes run re-signing, rotation, refresh and passes in 1 s steps
// through two rotations, relay-2's clock 119 s ahead and relay-3's 119 s
// behind, in the stand's configuration (ttl 20 min, rotation 1 h, 2 h 15 min
// of steps) and the least (16 min, 16 min, rotations 18 min apart by the
// grace, 50 min of steps). No node is ever refused, the epochs the mirrors hold for one node
// differ by at most one, and once any mirror lists a new epoch of a node
// every mirror lists it within the pass period, the fetches and a second,
// 60 + 2 x 5 + 1 = 71 s, plus how far the mirror's clock lags the node's: a
// statement joins a mirror once the mirror's clock reaches its published
// time, so the lag of 238 s between relay-3 and relay-2 adds to the window,
// as Skew does in W for a lag up to Skew. Then relay-2's wall clock
// jumps back 12 min between its first and second rotation: still no refusal,
// its published times never decrease, the first descriptor of its epoch 2 is
// published Skew past the expiry of its last epoch 0 descriptor, relays 1 and
// 3 stay in every mirror, and relay-2's own mirror answers 503 exactly while
// its wall is below its last published
//
// c25519 only: the rules compare times and epochs, which the suite does not
// touch, and the steps verify tens of thousands of signatures, minutes of
// GOST. Under the race detector the least configuration alone
func TestCrossCheckLeavesHonestRotationAlone(t *testing.T) {
	for _, tc := range []struct {
		ttl, rotate, steps time.Duration
	}{
		{20 * time.Minute, time.Hour, 2*time.Hour + 15*time.Minute},
		{16 * time.Minute, 16 * time.Minute, 50 * time.Minute},
	} {
		if raceDetector && tc.rotate == time.Hour {
			continue
		}
		t.Run(tc.rotate.String(), func(t *testing.T) {
			runHonestRotation(t, jcrypto.SuiteC25519, tc.ttl, tc.rotate, tc.steps)
		})
	}
}

func runHonestRotation(t *testing.T, s jcrypto.Suite, ttl, rotate, horizon time.Duration) {
	t.Helper()
	const window = 71
	offsets := []int{0, 119, -119}
	lag := func(x, y int) int { return max(offsets[x]-offsets[y], 0) }
	base := time.Now()
	c := newCluster(t, s, "relay-1")
	c.clock.mu.Lock()
	c.clock.now = base
	c.clock.mu.Unlock()
	c.nodes[0].setTTL(ttl)
	ahead := &clock{now: base.Add(119 * time.Second)}
	behind := &clock{now: base.Add(-119 * time.Second)}
	c.add(t, "relay-2", ahead, ttl)
	c.add(t, "relay-3", behind, ttl)
	clocks := []*clock{c.clock, ahead, behind}
	c.checking(time.Minute, listedOrder)
	for _, f := range c.nodes {
		f.rotating(t, rotate)
	}
	c.enroll(t, base.Add(72*time.Hour))
	for _, f := range c.nodes {
		f.takeRoster(t, c.roster())
		f.cache().refresh()
	}
	n2 := c.nodes[1]

	every := int(checkEvery(ttl) / time.Second)
	phase := []int{every / 2, every - 1, every - 1}
	passes := make([]time.Time, 3)
	for i, f := range c.nodes {
		passes[i] = clocks[i].Now().Add(f.cache().wait())
	}
	// the second at which any mirror first listed epoch e of node x
	first := map[[2]int64]int{}
	// a bundle published on the clock 119 s ahead joins the mirror of the node
	// 119 s behind 238 s later
	const joined = 238
	var served [][]byte
	var lastPublished int64
	servedBy2 := func(s int) {
		t.Helper()
		b, ok := n2.n.descriptor()
		if !ok {
			return
		}
		if len(served) > 0 && bytes.Equal(served[len(served)-1], b) {
			return
		}
		v, err := pki.VerifyStatement(c.p, pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}, n2.n.addr, b)
		if err != nil {
			t.Fatalf("%d s: relay-2 serves %v", s, err)
		}
		if v.DescFrom.Unix() < lastPublished {
			t.Fatalf("%d s: relay-2 published %d after %d", s, v.DescFrom.Unix(), lastPublished)
		}
		lastPublished = v.DescFrom.Unix()
		served = append(served, b)
	}
	servedBy2(0)
	jumped := false
	rotations := 0
	refreshed2 := 0
	steps := int(horizon / time.Second)
	for step := 1; step <= steps; step++ {
		for _, k := range clocks {
			k.advance(time.Second)
		}
		for i, f := range c.nodes {
			if step%every == phase[i] {
				f.n.refreshIfDue()
			}
			before := f.n.onionEpoch()
			f.n.rotateIfDue()
			if f == n2 && f.n.onionEpoch() != before {
				rotations++
				// between the first and the second rotation the wall goes back
				if rotations == 1 && !jumped {
					jumped = true
					ahead.jump(t, -12*time.Minute)
				}
			}
			if now := clocks[i].Now(); !now.Before(passes[i]) {
				f.cache().refresh()
				passes[i] = now.Add(f.cache().wait())
				if f == n2 {
					refreshed2 = step
				}
			}
			if step%60 == i*20 {
				f.cache().forget()
				f.cache().cross()
			}
		}
		servedBy2(step)
		for i, f := range c.nodes {
			if f.cache().refusedCount() != 0 || strings.Contains(f.log.String(), "refused") {
				t.Fatalf("%d s: relay-%d refused a peer: %s", step, i+1, f.log.String())
			}
		}
		for x, fx := range c.nodes {
			lo, hi := int64(-1), int64(-1)
			held := make([]int64, len(c.nodes))
			for y, fy := range c.nodes {
				e := epochHeld(t, fy, fx)
				held[y] = e
				if e < 0 {
					// a mirror relay-2 does not serve, or lacks it, after the jump
					if step >= joined && (fx != n2 && fy != n2 || !jumped) {
						t.Fatalf("%d s: the mirror of %s lacks %s", step, fy.n.name, fx.n.name)
					}
					continue
				}
				if lo < 0 || e < lo {
					lo = e
				}
				if e > hi {
					hi = e
				}
				if _, seen := first[[2]int64{int64(x), e}]; !seen {
					first[[2]int64{int64(x), e}] = step
				}
			}
			if hi-lo > 1 {
				t.Fatalf("%d s: the mirrors hold epochs %d to %d of %s", step, lo, hi, fx.n.name)
			}
			if jumped {
				continue
			}
			at := first[[2]int64{int64(x), hi}]
			for y, fy := range c.nodes {
				if held[y] >= 0 && held[y] < hi && step-at > window+lag(x, y) {
					t.Fatalf("%d s: epoch %d of %s was first listed at %d s and %s still holds %d", step, hi, fx.n.name, at, fy.n.name, held[y])
				}
			}
		}
		// the mirror follows the wall at the next refresh, within a minute
		if jumped && refreshed2 == step {
			_, ok := n2.cache().descriptors()
			if wall := ahead.Now().Unix(); ok != (wall >= lastPublished) {
				t.Fatalf("%d s: relay-2 serves its mirror %v with the wall at %d and its last published at %d", step, ok, wall, lastPublished)
			}
		}
	}
	if rotations < 2 || !jumped {
		t.Fatalf("relay-2 rotated %d times, jumped %v; want at least 2 and a jump", rotations, jumped)
	}
	// every descriptor relay-2 served, pairwise consistent, and the first of
	// epoch 2 published Skew past the last expiry of epoch 0
	var lastOfOne, firstOfThree *pki.Verified
	stmts := make([]*pki.Verified, len(served))
	for i, b := range served {
		v, err := pki.VerifyStatement(c.p, pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}, n2.n.addr, b)
		if err != nil {
			t.Fatal(err)
		}
		stmts[i] = v
		switch {
		case v.Epoch == 0 && (lastOfOne == nil || v.DescUntil.After(lastOfOne.DescUntil)):
			lastOfOne = v
		case v.Epoch == 2 && firstOfThree == nil:
			firstOfThree = v
		}
	}
	for i := range stmts {
		for j := range i {
			if rule := pki.Compare(stmts[j], stmts[i]); rule != 0 {
				t.Fatalf("descriptors %d and %d of relay-2 break %v", j, i, rule)
			}
		}
	}
	if lastOfOne == nil || firstOfThree == nil || firstOfThree.DescFrom.Before(lastOfOne.DescUntil.Add(pki.Skew)) {
		t.Fatalf("epoch 2 of relay-2 starts %v, the last of epoch 0 ends %v; want Skew between them", firstOfThree, lastOfOne)
	}
}

// a node with 16 min descriptors rotating every 16 min, times in minutes of
// running time from the start: epoch 0 signed at 0, at 8 and, by the timer
// in the minute of the rotation, at 16 (expires 32); epoch 1 at 16 (expires
// 32), then the wall jumps back 12 min. Key 0 is released at running 34 by
// the grace by running time and epoch 2 starts at the same tick with
// published 34, the floor expires(last of epoch 0) + Skew, where the wall
// reads 22. The node's own mirror answers 503 while its wall is below its
// last published: from 16 to 28, then from 34 to 46; /descriptor answers
// throughout. With a rotation attempt that fails and correct clocks the floor
// is taken only in the attempt that succeeds, one tick later, so epoch 1 is
// published at the wall of that attempt
func TestRotationFloorHoldsAcrossASetBack(t *testing.T) {
	f := newRunningFixture(t)
	f.setTTL(16 * time.Minute)
	ring := f.rotating(t, 16*time.Minute)
	start := f.clock.Now()
	f.enroll(t, start.Add(72*time.Hour))
	// a roster of itself, so the node serves a mirror
	f.takeRoster(t, rosterOf(f.ca.Anchor(), testName))
	minute := func(m int) time.Time { return start.Add(time.Duration(m) * time.Minute) }
	var bundles [][]byte
	record := func() {
		t.Helper()
		b, ok := f.n.descriptor()
		if ok && (len(bundles) == 0 || !bytes.Equal(bundles[len(bundles)-1], b)) {
			bundles = append(bundles, b)
		}
	}
	serves := func(m int, mirror bool) {
		t.Helper()
		code, _ := call(t, http.MethodGet, f.info.URL+"/descriptors", nil)
		if (code == http.StatusOK) != mirror {
			t.Fatalf("minute %d: /descriptors = %d, want served %v", m, code, mirror)
		}
		if code, _ := call(t, http.MethodGet, f.info.URL+"/descriptor", nil); code != http.StatusOK {
			t.Fatalf("minute %d: /descriptor = %d", m, code)
		}
	}
	record()
	_, k0 := ring.Current()
	for m := 1; m <= 48; m++ {
		f.clock.advance(time.Minute)
		f.n.refreshIfDue()
		f.n.rotateIfDue()
		if m == 16 {
			if _, v := f.inService(t); v.Epoch != 1 || v.DescFrom.Unix() != minute(16).Unix() {
				t.Fatalf("minute 16: epoch %d published %v, want 1 at minute 16", v.Epoch, v.DescFrom)
			}
			f.clock.jump(t, -12*time.Minute)
		}
		// the refresh the peer timer makes every minute rebuilds the mirror
		f.cache().refresh()
		record()
		switch {
		case m < 16, m >= 28 && m < 34, m >= 46:
			serves(m, true)
		default:
			serves(m, false)
		}
		if m == 33 && !opensFor(t, f.p, ring, k0) {
			t.Fatal("key 0 was released before its grace by running time")
		}
		if m == 34 {
			if opensFor(t, f.p, ring, k0) {
				t.Fatal("key 0 outlived its grace by running time")
			}
			// read without the clock: the wall is behind the floor
			b, _ := f.n.descriptor()
			v, err := pki.VerifyStatement(f.p, pki.Policy{Anchor: f.ca.Anchor(), Skew: pki.Skew}, f.n.addr, b)
			if err != nil {
				t.Fatal(err)
			}
			if v.Epoch != 2 || v.DescFrom.Unix() != minute(34).Unix() || v.DescUntil.Unix() != minute(50).Unix() {
				t.Fatalf("minute 34: epoch %d published %v until %v, want 2 from %v to %v", v.Epoch, v.DescFrom, v.DescUntil, minute(34), minute(50))
			}
		}
	}
	stmts := make([]*pki.Verified, len(bundles))
	for i, b := range bundles {
		v, err := pki.VerifyStatement(f.p, pki.Policy{Anchor: f.ca.Anchor(), Skew: pki.Skew}, f.n.addr, b)
		if err != nil {
			t.Fatal(err)
		}
		stmts[i] = v
	}
	if len(stmts) != 4 {
		t.Fatalf("%d descriptors served, want epoch 0 at 0 and 8, epoch 1 and epoch 2", len(stmts))
	}
	for i := range stmts {
		for j := range i {
			if rule := pki.Compare(stmts[j], stmts[i]); rule != 0 {
				t.Fatalf("descriptors %d and %d break %v", j, i, rule)
			}
		}
	}

	// a failed attempt: the floor moves only with the attempt that succeeds
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	g := newNode(t, p, newCA(t, p), &clock{now: time.Now()}, testName)
	g.setTTL(16 * time.Minute)
	short := &shortProvider{CryptoProvider: g.p}
	priv, pub, err := g.p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ring, err = relay.NewOnionRing(short, priv, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	g.n.mu.Lock()
	g.n.p = short
	g.n.link = g.pub
	g.n.onion = newOnionKeys(ring, 16*time.Minute, g.n.ttl, false, g.clock.Now())
	g.n.mu.Unlock()
	t.Cleanup(g.n.closeOnion)
	signed := g.clock.Now()
	g.enroll(t, signed.Add(72*time.Hour))
	g.clock.advance(16 * time.Minute)
	short.failAt("generate")
	g.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 0 || g.n.onion.prevExpires != 0 {
		t.Fatalf("after the failed attempt: epoch %d, remembered expiry %d; want 0 and none", epoch, g.n.onion.prevExpires)
	}
	g.clock.advance(time.Second)
	short.failAt("")
	g.n.rotateIfDue()
	_, v := g.inService(t)
	if epoch, _ := ring.Current(); epoch != 1 || v.Epoch != 1 || v.DescFrom.Unix() != g.clock.Now().Unix() {
		t.Fatalf("after the attempt that succeeded: epoch %d, published %v, want 1 at the wall of that attempt %v", epoch, v.DescFrom, g.clock.Now())
	}
	if want := signed.Add(16 * time.Minute).Unix(); g.n.onion.prevExpires != want {
		t.Fatalf("the attempt that succeeded remembered %d as the expiry of epoch 0, want %d", g.n.onion.prevExpires, want)
	}
}
