package verify

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

var suites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

func TestReadNodeRefusesWhatDoesNotVerify(t *testing.T) {
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			p := provider(t, s)
			ca := newCA(t, p)
			until := t0.Add(72 * time.Hour)
			trust := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
			keys := make([]relayKeys, 3)
			bundles := make([][]byte, 3)
			nodes := make([]pki.Verified, 3)
			for i := range keys {
				keys[i], bundles[i] = enrolled(t, p, ca, fmt.Sprintf("relay-%d", i+1), until)
				v, err := readNode(p, true, trust, keys[i].addr, bundles[i], t0)
				if err != nil {
					t.Fatalf("readNode: %v", err)
				}
				nodes[i] = *v
			}
			chain := chainOf(nodes, []int{0, 1, 2})
			for i, k := range keys {
				if chain[i].Addr != k.addr || !bytes.Equal(chain[i].StaticPub, k.onion) || !bytes.Equal(chain[i].LinkPub, k.link) {
					t.Fatalf("hop %d: %+v, want the onion key as StaticPub and the link key as LinkPub", i, chain[i])
				}
				if !bytes.Equal(chain[i].Identity, k.identity) {
					t.Fatalf("hop %d does not carry the identity its certificate certifies", i)
				}
			}

			k2, b2 := keys[1], bundles[1]
			foreign := pki.Policy{Anchor: newCA(t, p).Anchor(), Skew: pki.Skew}
			_, eb := enrolled(t, p, newCA(t, p), "relay-2", until)
			unsigned, err := pki.Unsigned(p, k2.link, k2.onion)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				name   string
				trust  pki.Policy
				bundle []byte
				now    time.Time
				want   error
			}{
				{"foreign anchor", foreign, b2, t0, pki.ErrUnknownCA},
				{"node certified by another CA", trust, eb, t0, pki.ErrUnknownCA},
				{"bundle of another address", trust, bundles[2], t0, pki.ErrWrongAddr},
				{"unsigned bundle", trust, unsigned, t0, pki.ErrFormat},
				{"descriptor expired", trust, b2, t0.Add(time.Hour), pki.ErrDescTime},
				{"certificate expired", trust, b2, until, pki.ErrCertTime},
				{"not yet valid", trust, b2, t0.Add(-pki.Skew - time.Second), pki.ErrCertTime},
			} {
				if v, err := readNode(p, true, c.trust, k2.addr, c.bundle, c.now); !errors.Is(err, c.want) || v != nil {
					t.Errorf("%s: readNode = %v, %v, want %v", c.name, v, err, c.want)
				}
			}

			v, err := readNode(p, false, pki.Policy{}, k2.addr, unsigned, t0.Add(1000*time.Hour))
			if err != nil {
				t.Fatalf("readNode without auth: %v", err)
			}
			if !bytes.Equal(v.OnionPub, k2.onion) || len(v.Identity) != 0 {
				t.Fatal("readNode without auth lost the unsigned onion key or found an identity")
			}
			if v, err := readNode(p, false, pki.Policy{}, k2.addr, b2, t0); err != nil || len(chainOf([]pki.Verified{*v}, []int{0})[0].Identity) != 0 {
				t.Fatalf("readNode without auth of a signed bundle: %v, or the chain binds an identity", err)
			}
		})
	}
}

// six listed nodes: node 1 is served the bundle of node 3, node 2 one under
// another CA, node 4 nothing, node 5 one with its signature altered. Nodes 0
// and 3 pass and are numbered 0 and 1
func TestMirrorCountsAFailedBundleAsLeftOut(t *testing.T) {
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			p := provider(t, s)
			ca := newCA(t, p)
			keys, addrs, bundles := enrolledNodes(t, p, ca, 6)
			_, foreign := enrolled(t, p, newCA(t, p), "relay-3", t0.Add(72*time.Hour))
			served := [][]byte{bundles[0], bundles[3], foreign, bundles[3], nil, altered(t, bundles[5])}
			trust := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
			v, err := Mirror(p, true, trust, addrs, served, t0)
			if err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(v.at, []int{0, -1, -1, 1, -1, -1}) || !slices.Equal(v.listed, []int{0, 3}) {
				t.Fatalf("At %v, Listed %v, want [0 -1 -1 1 -1 -1] and [0 3]", v.at, v.listed)
			}
			if n := v.Nodes(); len(n) != 2 || n[0].Addr != addrs[0] || n[1].Addr != addrs[3] || !bytes.Equal(n[1].Identity, keys[3].identity) {
				t.Fatalf("Nodes %+v, want nodes 0 and 3 with their identities", n)
			}
			n := v.Nodes()
			for _, key := range [][]byte{n[1].Identity, n[1].LinkPub, n[1].OnionPub} {
				key[0] ^= 0xff
			}
			if c := v.Chain([]int{3}); !bytes.Equal(c[0].Identity, keys[3].identity) || bytes.Equal(c[0].LinkPub, n[1].LinkPub) || bytes.Equal(c[0].StaticPub, n[1].OnionPub) {
				t.Fatal("a key written through Nodes reached the chain")
			}
			if !slices.Equal(v.Usable(), []bool{true, false, false, true, false, false}) {
				t.Fatalf("Usable %v", v.Usable())
			}
			// the error is the one pki.Verify gives, passed on as it is: the client
			// prints it when it refuses a fixed chain
			for i, want := range []error{nil, pki.ErrWrongAddr, pki.ErrUnknownCA, nil, ErrNoBundle, pki.ErrDescSignature} {
				got := v.Missing(i)
				switch {
				case want == nil:
					if v.failed[i] != nil || got != nil {
						t.Errorf("node %d failed with %v, missing for %v", i, v.failed[i], got)
					}
				case served[i] == nil:
					if got != ErrNoBundle {
						t.Errorf("node %d is missing for %v, want %v itself", i, got, ErrNoBundle)
					}
				default:
					_, direct := pki.Verify(p, trust, addrs[i], served[i], t0)
					if !errors.Is(got, want) || fmt.Sprint(got) != fmt.Sprint(direct) {
						t.Errorf("node %d is missing for %v, want %v as pki.Verify gives it: %v", i, got, want, direct)
					}
				}
			}
			if v.failed[4] != nil {
				t.Fatalf("a node the entry does not serve failed with %v", v.failed[4])
			}

			// four of six lacking: two hops allow min(missing, 6 - 2)
			for _, c := range []struct {
				entry, exit, missing int
				want                 client.MirrorVerdict
			}{
				{0, -1, 4, client.MirrorTaken},
				{0, -1, 3, client.MirrorLacksTooMany},
				{1, -1, 4, client.MirrorLacksEntry},
				{4, -1, 4, client.MirrorLacksEntry},
				{0, 3, 4, client.MirrorTaken},
				{0, 5, 4, client.MirrorLacksExit},
				{0, 0, 4, client.MirrorLacksExit},
			} {
				var verdict client.MirrorVerdict
				var absent, allowed int
				if c.exit < 0 {
					verdict, absent, allowed = v.Judge(c.entry, 2, c.missing)
				} else {
					verdict, absent, allowed = v.JudgeTo(c.entry, c.exit, 2, c.missing)
				}
				if verdict != c.want || absent != 4 || allowed != min(c.missing, 4) {
					t.Errorf("entry %d exit %d -missing %d: %d, %d absent of %d allowed, want %d", c.entry, c.exit, c.missing, verdict, absent, allowed, c.want)
				}
			}
		})
	}
}

// the draws are worked by hand in client.TestChooseKnownAnswer. Node 0 fails,
// so the usable nodes 1 2 3 4 are numbered 0 1 2 3: entry 2 is number 1, the
// others 1 3 4 are numbers 0 2 3, 6 mod 3 = 0 takes node 1 and 5 mod 2 = 1
// node 4. With every node usable and four hops, 6 mod 4 = 2 takes node 3 of
// 0 1 3 4, 5 mod 3 = 2 node 4 of 1 0 4 after the swap, 9 mod 2 = 1 node 1 of
// 0 1. To the exit 4 the middle hop is drawn among 0 1 3, or among 1 3 when
// node 0 fails
func TestDrawNumbersTheNodesThatPassInTheListedOrder(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	ca := newCA(t, p)
	_, addrs, bundles := enrolledNodes(t, p, ca, 5)
	trust := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
	full, err := Mirror(p, true, trust, addrs, bundles, t0)
	if err != nil {
		t.Fatal(err)
	}
	bad := slices.Clone(bundles)
	bad[0] = altered(t, bundles[0])
	lacking, err := Mirror(p, true, trust, addrs, bad, t0)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name  string
		v     View
		exit  int
		hops  int
		words []uint64
		want  []int
	}{
		{"node 0 failing", lacking, -1, 3, []uint64{6, 5}, []int{2, 1, 4}},
		{"four hops", full, -1, 4, []uint64{6, 5, 9}, []int{2, 3, 4, 1}},
		{"one hop", full, -1, 1, nil, []int{2}},
		{"to the exit", full, 4, 3, []uint64{pick(3, 0)}, []int{2, 0, 4}},
		{"to the exit, node 0 failing", lacking, 4, 3, []uint64{pick(2, 1)}, []int{2, 3, 4}},
	} {
		stream := words(c.words...)
		var path []int
		var err error
		if c.exit < 0 {
			path, err = c.v.Draw(2, c.hops, stream)
		} else {
			path, err = c.v.DrawTo(2, c.exit, c.hops, stream)
		}
		if err != nil || !slices.Equal(path, c.want) || stream.Len() != 0 {
			t.Fatalf("%s: %v, %v with %d bytes left, want %v", c.name, path, err, stream.Len(), c.want)
		}
		if !c.v.Holds(path) {
			t.Fatalf("%s: the view does not hold its own draw", c.name)
		}
		for i, n := range c.v.Chain(path) {
			if n.Addr != addrs[path[i]] {
				t.Fatalf("%s: hop %d is %s, want listed node %d", c.name, i, n.Addr, path[i])
			}
		}
	}

	if lacking.Holds([]int{2, 0}) {
		t.Fatal("the view holds a node that failed")
	}
	for _, c := range []struct {
		name        string
		entry, exit int
	}{
		{"an entry that failed", 0, -1},
		{"an entry before the list", -1, -1},
		{"an entry past the list", 5, -1},
		{"an exit that failed", 2, 0},
		{"an exit past the list", 2, 5},
		{"the entry as the exit", 2, 2},
	} {
		stream := words(6, 5)
		var err error
		if c.exit < 0 {
			_, err = lacking.Draw(c.entry, 3, stream)
		} else {
			_, err = lacking.DrawTo(c.entry, c.exit, 3, stream)
		}
		if !errors.Is(err, client.ErrChoice) || stream.Len() != 16 {
			t.Errorf("%s: %v with %d of 16 bytes left, want %v and the stream unread", c.name, err, stream.Len(), client.ErrChoice)
		}
	}
}

func TestPeerTakesTheCertifiedKeys(t *testing.T) {
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			p := provider(t, s)
			ca := newCA(t, p)
			until := t0.Add(72 * time.Hour)
			keys, _, bundles := enrolledNodes(t, p, ca, 3)
			k, b := keys[1], bundles[1]
			peer, err := Peer(p, ca.Anchor(), k.addr, b, t0)
			if err != nil || !bytes.Equal(peer.LinkPub, k.link) || !bytes.Equal(peer.Identity, k.identity) {
				t.Fatalf("Peer = %+v, %v, want the link key and the certified identity", peer, err)
			}
			if _, err := Peer(p, ca.Anchor(), k.addr, b, t0.Add(-pki.Skew)); err != nil {
				t.Fatalf("a bundle that starts Skew after the node's clock: %v", err)
			}

			_, second := enrolled(t, p, newCA(t, p), "relay-2", until)
			unsigned, err := pki.Unsigned(p, k.link, k.onion)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				name   string
				anchor pki.Anchor
				bundle []byte
				now    time.Time
				want   error
			}{
				{"another roster's anchor", newCA(t, p).Anchor(), b, t0, pki.ErrUnknownCA},
				{"a node of a second CA", ca.Anchor(), second, t0, pki.ErrUnknownCA},
				{"the bundle of another roster node", ca.Anchor(), bundles[2], t0, pki.ErrWrongAddr},
				{"an unsigned bundle", ca.Anchor(), unsigned, t0, pki.ErrFormat},
				{"altered", ca.Anchor(), altered(t, b), t0, pki.ErrDescSignature},
				{"descriptor expired", ca.Anchor(), b, t0.Add(time.Hour), pki.ErrDescTime},
				{"certificate expired", ca.Anchor(), b, until, pki.ErrCertTime},
				{"beyond the skew", ca.Anchor(), b, t0.Add(-pki.Skew - time.Second), pki.ErrCertTime},
			} {
				// the roster check sends this error back in its answer
				_, direct := pki.Verify(p, pki.Policy{Anchor: c.anchor, Skew: pki.Skew}, k.addr, c.bundle, c.now)
				if peer, err := Peer(p, c.anchor, k.addr, c.bundle, c.now); !errors.Is(err, c.want) || fmt.Sprint(err) != fmt.Sprint(direct) || peer.LinkPub != nil || peer.Identity != nil {
					t.Errorf("%s: Peer = %+v, %v, want %v as pki.Verify gives it (%v) and no keys", c.name, peer, err, c.want, direct)
				}
			}

			for _, bundle := range [][]byte{unsigned, b} {
				peer, err := UnverifiedPeer(p, k.addr, bundle)
				if err != nil || !bytes.Equal(peer.LinkPub, k.link) || peer.Identity != nil {
					t.Fatalf("UnverifiedPeer = %+v, %v, want the link key and no identity", peer, err)
				}
			}
			other := jcrypto.SuiteGOST
			if s == other {
				other = jcrypto.SuiteC25519
			}
			o := provider(t, other)
			_, ob := enrolled(t, o, newCA(t, o), "relay-2", until)
			for _, c := range []struct {
				name   string
				bundle []byte
				want   error
			}{
				{"a bundle of the other suite", ob, pki.ErrSuite},
				{"a truncated bundle", b[:len(b)/2], pki.ErrFormat},
			} {
				_, direct := pki.Unverified(p, k.addr, c.bundle)
				if peer, err := UnverifiedPeer(p, k.addr, c.bundle); !errors.Is(err, c.want) || fmt.Sprint(err) != fmt.Sprint(direct) || peer.LinkPub != nil || peer.Identity != nil {
					t.Errorf("%s: UnverifiedPeer = %+v, %v, want %v as pki.Unverified gives it (%v) and no keys", c.name, peer, err, c.want, direct)
				}
			}
		})
	}
}

// five listed nodes, node 4 certified by a second CA. A node of the session
// CA takes no key from it; a client whose entry serves every bundle counts it
// as left out, which -missing 1 allows: min(1, 5 - 3) = 1, so the mirror is
// taken from every other entry and no draw reaches node 4, and refused from
// node 4 itself, one entry of five
func TestSecondCANodeIsLeftOutAndRefusedAsEntry(t *testing.T) {
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			p := provider(t, s)
			session := newCA(t, p)
			_, addrs, bundles := enrolledNodes(t, p, session, 4)
			rogue, b := enrolled(t, p, newCA(t, p), "relay-5", t0.Add(72*time.Hour))
			addrs, bundles = append(addrs, rogue.addr), append(bundles, b)

			for i := range addrs {
				_, err := Peer(p, session.Anchor(), addrs[i], bundles[i], t0)
				if i < 4 && err != nil || i == 4 && !errors.Is(err, pki.ErrUnknownCA) {
					t.Fatalf("peer %d: %v", i, err)
				}
			}

			v, err := Mirror(p, true, pki.Policy{Anchor: session.Anchor(), Skew: pki.Skew}, addrs, bundles, t0)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(v.Missing(4), pki.ErrUnknownCA) {
				t.Fatalf("node 4 is missing for %v", v.Missing(4))
			}
			refused := 0
			for entry := range addrs {
				switch verdict, _, _ := v.Judge(entry, 3, 1); {
				case entry == 4 && verdict == client.MirrorLacksEntry:
					refused++
				case entry < 4 && verdict == client.MirrorTaken:
				default:
					t.Fatalf("entry %d: verdict %d", entry, verdict)
				}
				if verdict, _, _ := v.Judge(entry, 3, 0); verdict == client.MirrorTaken {
					t.Fatalf("entry %d: taken without -missing", entry)
				}
			}
			if refused != 1 {
				t.Fatalf("%d of 5 entries refused, want 1", refused)
			}

			seen := map[string]bool{}
			for k1 := range 3 {
				for k2 := range 2 {
					path, err := v.Draw(1, 3, words(pick(3, k1), pick(2, k2)))
					if err != nil || slices.Contains(path, 4) {
						t.Fatalf("draw %d %d: %v, %v", k1, k2, path, err)
					}
					seen[fmt.Sprint(path)] = true
				}
			}
			if len(seen) != 6 {
				t.Fatalf("%d distinct paths from entry 1, want the 3 x 2 orders of nodes 0 2 3", len(seen))
			}

			if verdict, _, _ := v.JudgeTo(0, 4, 3, 1); verdict != client.MirrorLacksExit {
				t.Fatalf("a mailbox of the second CA: verdict %d, want %d", verdict, client.MirrorLacksExit)
			}
			if verdict, _, _ := v.JudgeTo(4, 3, 3, 1); verdict != client.MirrorLacksEntry {
				t.Fatalf("an entry of the second CA to the mailbox: verdict %d, want %d", verdict, client.MirrorLacksEntry)
			}
		})
	}
}

// the time is the one given for every bundle: an hour after t0 the descriptor
// of every node has run out
func TestMirrorChecksEveryBundleAtTheTimeGiven(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	ca := newCA(t, p)
	_, addrs, bundles := enrolledNodes(t, p, ca, 3)
	v, err := Mirror(p, true, pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}, addrs, bundles, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for i := range addrs {
		if !errors.Is(v.Missing(i), pki.ErrDescTime) {
			t.Errorf("node %d is missing for %v, want %v", i, v.Missing(i), pki.ErrDescTime)
		}
	}
	if len(v.Nodes()) != 0 || slices.Contains(v.Usable(), true) {
		t.Fatalf("an hour late the view holds %d nodes", len(v.Nodes()))
	}
}

// without authentication an unsigned bundle and a signed one are both taken,
// and neither gives an identity
func TestMirrorWithoutAuthTakesTheKeysAndNoIdentity(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	keys, addrs, bundles := enrolledNodes(t, p, newCA(t, p), 2)
	unsigned, err := pki.Unsigned(p, keys[0].link, keys[0].onion)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Mirror(p, false, pki.Policy{}, addrs, [][]byte{unsigned, bundles[1]}, t0.Add(1000*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	chain := v.Chain([]int{0, 1})
	for i, k := range keys {
		if !bytes.Equal(chain[i].StaticPub, k.onion) || !bytes.Equal(chain[i].LinkPub, k.link) || len(chain[i].Identity) != 0 {
			t.Fatalf("hop %d: %+v, want its keys and no identity", i, chain[i])
		}
	}
}

// bundles that do not line up with the list are refused before any is read: a
// shorter slice would otherwise leave the nodes past its end at position 0
func TestMirrorRefusesBundlesThatDoNotLineUp(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	ca := newCA(t, p)
	_, addrs, bundles := enrolledNodes(t, p, ca, 3)
	trust := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
	for _, served := range [][][]byte{bundles[:2], append(slices.Clone(bundles), bundles[0]), nil} {
		v, err := Mirror(p, true, trust, addrs, served, t0)
		if err == nil || len(v.Usable()) != 0 || len(v.Nodes()) != 0 {
			t.Fatalf("%d bundles for 3 addresses: %d listed, %v", len(served), len(v.Usable()), err)
		}
	}
}
