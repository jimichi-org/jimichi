package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

// node 3 is under proof: its listed bundle and one it signed a second later in
// the same epoch with another onion key. With -consistency the client verifies
// both under its anchor, refuses node 3 and counts it apart from -missing, so
// the list is four long and -missing 0 allows min(0, 4 - 3) = 0 absent nodes,
// which is what there is. Over every outcome of the three draws, the entry
// among 5 and the two other hops among the 3 usable others: 4 entries x 3 x 2
// = 24 distinct chains, none through node 3, and the 6 outcomes that draw
// node 3 as the entry refuse the mirror without naming it
func TestNodeUnderProofIsRefusedAndCountedApart(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			tb := newTestbed(t, s, 5)
			refused := 3
			tb.publishWithProofs(t, map[int]*pki.Proof{refused: tb.proofAgainst(t, refused, agreementKey(t, tb.p))})

			chains := map[string]bool{}
			var refusals int
			eachStream([]int{5, 3, 2}, func(values []uint64) {
				stream := words(values...)
				sel := tb.selection(3, stream)
				sel.missing = 0
				chain, logged, err := build(sel, tb.p)
				if int(values[0])%5 == refused {
					var failed *entryError
					if !errors.Is(err, pki.ErrConflict) || !errors.As(err, &failed) || err.Error() != "the entry: "+pki.ErrConflict.Error() {
						t.Fatalf("the refused node as the entry: %v, want the entry: %v", err, pki.ErrConflict)
					}
					if logged != "" || chain != nil || stream.Len() != 16 {
						t.Fatalf("the refused node as the entry logged %q, chain %v, %d bytes of the stream left", logged, chain, stream.Len())
					}
					refusals++
					return
				}
				if err != nil || len(chain) != 3 || stream.Len() != 0 {
					t.Fatalf("stream %v: chain = %v, %v, %d bytes left", values, chain, err, stream.Len())
				}
				if chain[0].Addr != tb.addrs[int(values[0])%5] {
					t.Fatalf("stream %v: the entry is %s", values, chain[0].Addr)
				}
				var path []string
				for _, hop := range chain {
					if hop.Addr == tb.addrs[refused] {
						t.Fatalf("stream %v: the refused node is on the chain %v", values, chain)
					}
					path = append(path, hop.Addr)
				}
				chains[strings.Join(path, " ")] = true
				lines := strings.Split(strings.TrimSuffix(logged, "\n"), "\n")
				if len(lines) != 5 || lines[4] != "4 of 5 listed nodes verified, 1 refused by proof" {
					t.Fatalf("stream %v logged:\n%s", values, logged)
				}
				if namesAny(logged, []string{tb.addrs[refused]}) || strings.Contains(logged, "node relay-4 ") {
					t.Fatalf("the log names the refused node:\n%s", logged)
				}
			})
			if len(chains) != 24 || refusals != 6 {
				t.Fatalf("%d distinct chains and %d refusals, want 24 and 6", len(chains), refusals)
			}
			// every node is the entry in 6 of the 30 outcomes, the refused one too:
			// the mirror is fetched before it is read
			if got := tb.requests(); !slices.Equal(got, []int32{6, 6, 6, 6, 6}) {
				t.Fatalf("requests per node %v, want 6 at each", got)
			}
		})
	}
}

// the same mirror read with -consistency=false: the proof item is a node the
// entry does not serve, within -missing. 5 listed, 3 hops: -missing 0 allows
// min(0, 5 - 3) = 0 absent and there is 1, -missing 1 allows 1. The stream
// 5, 3, 2 takes entry 0, then the first of the usable others 1 2 4 and the
// first of the two left: the chain 0 1 2
func TestWithoutConsistencyAProofIsANodeNotServed(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 5)
	tb.publishWithProofs(t, map[int]*pki.Proof{3: tb.proofAgainst(t, 3, agreementKey(t, tb.p))})

	sel := tb.selection(3, words(pick(5, 0), pick(3, 0), pick(2, 0)))
	sel.consistency, sel.missing = false, 0
	chain, logged, err := build(sel, tb.p)
	if !errors.Is(err, errTooFew) || err.Error() != errTooFew.Error()+": 1 of 5 listed nodes, at most 0 may be" || chain != nil || logged != "" {
		t.Fatalf("-missing 0: chain = %v, %v, logged %q", chain, err, logged)
	}

	sel = tb.selection(3, words(pick(5, 0), pick(3, 0), pick(2, 0)))
	sel.consistency, sel.missing = false, 1
	chain, logged, err = build(sel, tb.p)
	if err != nil || len(chain) != 3 || chain[0].Addr != tb.addrs[0] || chain[1].Addr != tb.addrs[1] || chain[2].Addr != tb.addrs[2] {
		t.Fatalf("-missing 1: chain = %v, %v, want nodes 0 1 2", chain, err)
	}
	if !strings.HasSuffix(logged, "4 of 5 listed nodes verified\n") || strings.Contains(logged, "refused") {
		t.Fatalf("-missing 1 logged:\n%s", logged)
	}
}

// two consistent bundles of node 3, its listed one and a re-signing with the
// same onion key, are no proof: with -consistency the node counts as not
// served, within -missing, and a fixed chain through it reports the class. 5
// listed, 3 hops: -missing 0 allows 0 absent, -missing 1 allows 1
func TestProofOfConsistentBundlesCountsAsNotServed(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 5)
	tb.publishWithProofs(t, map[int]*pki.Proof{3: tb.proofAgainst(t, 3, tb.keys[3].onion)})

	sel := tb.selection(3, words(pick(5, 0), pick(3, 0), pick(2, 0)))
	sel.missing = 0
	chain, logged, err := build(sel, tb.p)
	if !errors.Is(err, errTooFew) || err.Error() != errTooFew.Error()+": 1 of 5 listed nodes, at most 0 may be" || chain != nil || logged != "" {
		t.Fatalf("-missing 0: chain = %v, %v, logged %q", chain, err, logged)
	}

	sel = tb.selection(3, words(pick(5, 0), pick(3, 0), pick(2, 0)))
	sel.missing = 1
	chain, logged, err = build(sel, tb.p)
	if err != nil || len(chain) != 3 || chain[0].Addr != tb.addrs[0] || chain[1].Addr != tb.addrs[1] || chain[2].Addr != tb.addrs[2] {
		t.Fatalf("-missing 1: chain = %v, %v, want nodes 0 1 2", chain, err)
	}
	if !strings.HasSuffix(logged, "4 of 5 listed nodes verified\n") || strings.Contains(logged, "refused") {
		t.Fatalf("-missing 1 logged:\n%s", logged)
	}

	sel = tb.selection(4, nil)
	sel.fixed = true
	chain, _, err = build(sel, tb.p)
	if !errors.Is(err, pki.ErrNoConflict) || err.Error() != "node "+tb.addrs[3]+": "+pki.ErrNoConflict.Error() || chain != nil {
		t.Fatalf("fixed chain through the node: %v, %v", chain, err)
	}
}

// a fixed chain is the configuration, so a node of it under proof is named
// with the rule the pair breaks; a node under proof off the chain is counted
// in the verified line and nowhere else
func TestFixedChainThroughARefusedNodeNamesIt(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			tb := newTestbed(t, s, 5)
			for _, refused := range []int{1, 0} {
				tb.publishWithProofs(t, map[int]*pki.Proof{refused: tb.proofAgainst(t, refused, agreementKey(t, tb.p))})
				sel := tb.selection(3, nil)
				sel.fixed, sel.missing = true, 2
				chain, logged, err := build(sel, tb.p)
				want := "node " + tb.addrs[refused] + ": pki: the node signed descriptors that contradict each other: two onion keys in one epoch"
				if !errors.Is(err, pki.ErrConflict) || err.Error() != want || chain != nil || logged != "" {
					t.Fatalf("node %d under proof: chain = %v, %v, logged %q, want %q", refused, chain, err, logged, want)
				}
			}

			tb.publishWithProofs(t, map[int]*pki.Proof{4: tb.proofAgainst(t, 4, agreementKey(t, tb.p))})
			sel := tb.selection(3, nil)
			sel.fixed, sel.missing = true, 0
			chain, logged, err := build(sel, tb.p)
			if err != nil || len(chain) != 3 {
				t.Fatalf("fixed chain with the fifth node under proof: %v, %v", chain, err)
			}
			lines := strings.Split(strings.TrimSuffix(logged, "\n"), "\n")
			if len(lines) != 5 || lines[4] != "4 of 5 listed nodes verified, 1 refused by proof" || strings.Contains(logged, "node relay-5 ") {
				t.Fatalf("logged:\n%s", logged)
			}
		})
	}
}

// the mailbox under proof is an exit the mirror does not hold, on the first
// chain and on a rebuild alike, and the text stays the one of a mailbox left
// out; a middle node under proof is counted apart, so -missing 0 still draws
// among the usable others: entry 0, exit 4, node 2 refused leaves 1 and 3 for
// the middle, and the first of them is node 1
func TestPeerRouteRefusesAMailboxUnderProof(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, bedNodes)
	against := func(i int) *pki.Proof { return tb.proofAgainst(t, i, agreementKey(t, tb.p)) }

	tb.publishWithProofs(t, map[int]*pki.Proof{bedExit: against(bedExit)})
	for _, consistency := range []bool{true, false} {
		var d dialLog
		var out bytes.Buffer
		r := newRoute(tb, words(pick(4, rogue)), &d, &out)
		r.sel.consistency = consistency
		_, err := r.first()
		if !errors.Is(err, errNoMailbox) || err.Error() != "the entry holds no bundle for the mailbox" || r.draws != 0 || len(d.chains) != 0 {
			t.Fatalf("consistency %v, first: %v after %d draws and %d dials", consistency, err, r.draws, len(d.chains))
		}
	}

	tb.publish(t, tb.bundles)
	var d dialLog
	var out bytes.Buffer
	r := newRoute(tb, words(pick(4, rogue), pick(3, 0)), &d, &out)
	c, err := r.first()
	if err != nil {
		t.Fatal(err)
	}
	end(c)
	tb.publishWithProofs(t, map[int]*pki.Proof{bedExit: against(bedExit)})
	for range 3 {
		if _, err := r.rebuild(); !errors.Is(err, errNoMailbox) || r.draws != 1 {
			t.Fatalf("rebuild over a mirror with the mailbox under proof: %v, %d draws", err, r.draws)
		}
	}
	if !strings.Contains(out.String(), "circuit rebuild failed: the entry holds no bundle for the mailbox") || namesAny(out.String(), tb.addrs) {
		t.Fatalf("log %q", out.String())
	}

	tb.publishWithProofs(t, map[int]*pki.Proof{honestOne: against(honestOne)})
	d = dialLog{}
	out.Reset()
	r = newRoute(tb, words(pick(4, rogue), pick(2, 0)), &d, &out)
	r.sel.missing = 0
	c, err = r.first()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.chains[0], []int{rogue, colluder, bedExit}) {
		t.Fatalf("dialled %v, want the chain 0 1 4", d.chains[0])
	}
	for range 3 {
		d.answer(t, c)
		end(c)
		if c, err = r.rebuild(); err != nil {
			t.Fatal(err)
		}
	}
	end(c)
	for i, chain := range d.chains {
		if slices.Contains(chain, honestOne) {
			t.Fatalf("dial %d took the refused node: %v", i, chain)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("rebuilds of the same chain logged %q", out.String())
	}
}

// -consistency sets the least descriptor life a client takes, 16 min, and
// only together with -auth; a descriptor of 15 min then fails as a node left
// out, with its class, and passes without the flag
func TestTrustPolicyFloorsTheLifeWithConsistency(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 3)
	anchor := tb.trust.Anchor.String()
	for _, c := range []struct {
		auth, consistency bool
		minLife           time.Duration
	}{
		{true, true, pki.MinDescriptorLife},
		{true, false, 0},
		{false, true, 0},
		{false, false, 0},
	} {
		ca := anchor
		if !c.auth {
			ca = ""
		}
		pol, err := trustPolicy(c.auth, ca, jcrypto.SuiteC25519, pki.Skew, c.consistency)
		if err != nil || pol.MinLife != c.minLife || (len(pol.Anchor.Pub) > 0) != c.auth {
			t.Fatalf("auth %v consistency %v: %+v, %v, want MinLife %v", c.auth, c.consistency, pol, err, c.minLife)
		}
	}

	short := slices.Clone(tb.bundles)
	short[1] = tb.resigned(t, 1, tb.keys[1].onion, t0, 15*time.Minute)
	tb.publish(t, short)
	for _, c := range []struct {
		consistency bool
		want        error
	}{
		{true, pki.ErrDescLife},
		{false, nil},
	} {
		trust, err := trustPolicy(true, anchor, jcrypto.SuiteC25519, pki.Skew, c.consistency)
		if err != nil {
			t.Fatal(err)
		}
		sel := tb.selection(3, nil)
		sel.fixed, sel.trust, sel.consistency = true, trust, c.consistency
		chain, _, err := build(sel, tb.p)
		if c.want == nil {
			if err != nil || len(chain) != 3 {
				t.Fatalf("consistency off: chain = %v, %v, want the 15 min descriptor taken", chain, err)
			}
			continue
		}
		if !errors.Is(err, c.want) || err.Error() != "node "+tb.addrs[1]+": "+c.want.Error() || chain != nil {
			t.Fatalf("consistency on: chain = %v, %v, want node %s: %v", chain, err, tb.addrs[1], c.want)
		}
	}
}

// the three new failures are classes of their own in the texts a drawn chain
// reports, so none of them falls back to connection failed or names a node
func TestConsistencyFailuresAreKnownClasses(t *testing.T) {
	addr := "relay-3.jimichi.svc.cluster.local:9000"
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("node %s: %w: two onion keys in one epoch", addr, pki.ErrConflict), pki.ErrConflict.Error()},
		{fmt.Errorf("node %s: %w", addr, pki.ErrNoConflict), pki.ErrNoConflict.Error()},
		{fmt.Errorf("node %s: %w", addr, pki.ErrDescLife), pki.ErrDescLife.Error()},
	} {
		if got := failureClass(c.err); got != c.want || strings.Contains(got, "relay-3") {
			t.Errorf("class of %v is %q, want %q", c.err, got, c.want)
		}
		if got := (&entryError{c.err}).Error(); got != "the entry: "+c.want {
			t.Errorf("the entry failing with %v reads %q", c.err, got)
		}
	}
}
