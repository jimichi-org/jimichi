package lab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

const (
	twoKeyRelay = 4 // relay-5, signing two onion keys for epoch 0
	// cmd/relay's default -consistency-every, which with the Skew sets how long
	// a record keeps an expired epoch
	crossEvery = time.Minute
)

// five relays under the session CA; relay-5 serves statement A to relays 1 and
// 2 and statement B to relays 3 and 4. With check the honest relays keep a
// verify.Record per peer and run one pass over each other's mirrors, as
// cmd/relay does with -consistency; without it they take what they fetched,
// the baseline
type consistencyStand struct {
	*trustStand
	// relay-5's two statements of epoch 0: A under K_A, B under K_B signed a
	// minute later, so B is the newer statement
	a, b []byte
	// what each relay holds for each peer, by address, and the conflict it
	// refused a peer over
	held      []map[string][]byte
	conflicts []map[string]*pki.Conflict
	policy    pki.Policy
}

func startConsistencyStand(t *testing.T, s jcrypto.Suite, check bool) *consistencyStand {
	t.Helper()
	st, listeners := newTrustStand(t, s)
	cs := &consistencyStand{
		trustStand: st,
		held:       make([]map[string][]byte, trustNodes),
		conflicts:  make([]map[string]*pki.Conflict, trustNodes),
		policy:     pki.Policy{Anchor: st.session.Anchor(), Skew: pki.Skew},
	}
	if check {
		cs.policy.MinLife = pki.MinDescriptorLife
	}
	configs := make([]relay.Config, trustNodes)
	for i, tr := range st.relays {
		if i == twoKeyRelay {
			configs[i] = cs.enrollTwoKeys(t, tr)
			continue
		}
		configs[i] = st.enroll(t, tr, st.session)
	}
	records := make([]map[string]*verify.Record, trustNodes)
	for x, tr := range st.relays {
		tr.peers, tr.refused = map[string]relay.Peer{}, map[string]error{}
		cs.held[x], cs.conflicts[x] = map[string][]byte{}, map[string]*pki.Conflict{}
		records[x] = map[string]*verify.Record{}
		for y, other := range st.relays {
			if y == x {
				continue
			}
			statement := cs.fetched(x, y)
			if check && x != twoKeyRelay {
				rec := verify.NewRecord(pki.Skew, 8*crossEvery)
				records[x][other.addr] = rec
				v, err := pki.VerifyStatement(st.p, cs.policy, other.addr, statement)
				if err != nil {
					t.Fatal(err)
				}
				if c, admitted := rec.Take(statement, v, st.at); c != nil || !admitted {
					t.Fatalf("relay %d: the direct fetch of relay %d alone gives %v, admitted %v", x, y, c, admitted)
				}
				rec.Hold(v.Epoch)
			}
			peer, err := verify.Peer(st.p, cs.policy, other.addr, statement, st.at)
			if err != nil {
				t.Fatalf("relay %d takes relay %d: %v", x, y, err)
			}
			tr.peers[other.addr], cs.held[x][other.addr] = peer, statement
		}
		cs.publish(t, x)
	}
	if check {
		cs.cross(t, records)
	}
	st.serve(t, configs, listeners, plainDial)
	return cs
}

// relay-5's ring opens setups under K_A and K_B, as a ring does for a grace
// period after a rotation; its identity signs both keys for epoch 0 and its own
// mirror lists A
func (cs *consistencyStand) enrollTwoKeys(t *testing.T, tr *trustRelay) relay.Config {
	t.Helper()
	p := cs.p
	linkPriv, linkPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(linkPriv.Release)
	privA, pubA, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := relay.NewOnionRing(p, privA, pubA, 0)
	if err != nil {
		privA.Release()
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	privB, pubB, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Rotate(privB, pubB); err != nil {
		privB.Release()
		t.Fatal(err)
	}
	id := cs.certify(t, tr, cs.session)
	id.SetKeys(linkPub, pubA, 0)
	cs.a = cs.sign(t, id, cs.at)
	id.SetKeys(linkPub, pubB, 0)
	cs.b = cs.sign(t, id, cs.at.Add(time.Minute))
	tr.bundle, tr.identity, tr.linkPub = cs.a, id.Public(), linkPub
	return relayConfig(p, linkPriv, linkPub, tr.identity, ring)
}

// what relay x's direct fetch of relay y's /descriptor returns
func (cs *consistencyStand) fetched(x, y int) []byte {
	if y != twoKeyRelay {
		return cs.relays[y].bundle
	}
	if x < 2 {
		return cs.a
	}
	return cs.b
}

// the mirror of relay x: its own bundle, a bundle item for every peer it holds
// and a proof item for every peer it refused
func (cs *consistencyStand) publish(t *testing.T, x int) {
	t.Helper()
	tr := cs.relays[x]
	entries := []pki.MirrorEntry{{Addr: tr.addr, Bundle: tr.bundle}}
	for _, other := range cs.relays {
		if c, refused := cs.conflicts[x][other.addr]; refused {
			entries = append(entries, pki.MirrorEntry{Addr: other.addr, Proof: &c.Proof})
			continue
		}
		if statement, held := cs.held[x][other.addr]; held {
			entries = append(entries, pki.MirrorEntry{Addr: other.addr, Bundle: statement})
		}
	}
	var err error
	if tr.mirror, err = pki.MarshalMirror(entries); err != nil {
		t.Fatal(err)
	}
}

// one pass of every honest relay, in the listed order, over the mirrors of the
// other three honest relays and relay-5's own as they stand at that moment:
// every item about a roster peer other than the reader goes into that peer's
// record, a bundle through VerifyStatement and Take, a proof through
// VerifyConflict and TakeProof, so the conflict a reader publishes comes out
// of its own record. A refused peer leaves the peer set and its item in the
// mirror becomes the proof
func (cs *consistencyStand) cross(t *testing.T, records []map[string]*verify.Record) {
	t.Helper()
	for x, tr := range cs.relays {
		if x == twoKeyRelay {
			continue
		}
		for m, other := range cs.relays {
			if m == x {
				continue
			}
			entries, err := pki.ParseMirror(other.mirror)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Addr == tr.addr {
					continue
				}
				rec, roster := records[x][e.Addr]
				if !roster {
					t.Fatalf("relay %d lists %s, which is not on the roster", m, e.Addr)
				}
				if c := cs.feed(t, rec, e); c != nil {
					cs.conflicts[x][e.Addr] = c
				}
			}
		}
		for addr, c := range cs.conflicts[x] {
			delete(tr.peers, addr)
			tr.refused[addr] = fmt.Errorf("%w: %s", pki.ErrConflict, c.Rule)
		}
		cs.publish(t, x)
	}
}

func (cs *consistencyStand) feed(t *testing.T, rec *verify.Record, e pki.MirrorEntry) *pki.Conflict {
	t.Helper()
	if e.Proof != nil {
		c, err := pki.VerifyConflict(cs.p, cs.policy, e.Addr, *e.Proof)
		if err != nil {
			t.Fatalf("the proof about %s: %v", e.Addr, err)
		}
		a, err := pki.VerifyStatement(cs.p, cs.policy, e.Addr, c.Proof.A)
		if err != nil {
			t.Fatal(err)
		}
		b, err := pki.VerifyStatement(cs.p, cs.policy, e.Addr, c.Proof.B)
		if err != nil {
			t.Fatal(err)
		}
		return rec.TakeProof(c, a, b)
	}
	v, err := pki.VerifyStatement(cs.p, cs.policy, e.Addr, e.Bundle)
	if err != nil {
		t.Fatalf("the bundle of %s: %v", e.Addr, err)
	}
	c, _ := rec.Take(e.Bundle, v, cs.at)
	return c
}

// as cmd/client nodeBundles: ParseMirror, then by address, the zero entry
// where absent
func (cs *consistencyStand) entriesOf(t *testing.T, entry int) []pki.MirrorEntry {
	t.Helper()
	entries, err := pki.ParseMirror(cs.relays[entry].mirror)
	if err != nil {
		t.Fatal(err)
	}
	served := make(map[string]pki.MirrorEntry, len(entries))
	for _, e := range entries {
		served[e.Addr] = e
	}
	aligned := make([]pki.MirrorEntry, len(cs.addrs))
	for i, addr := range cs.addrs {
		aligned[i] = served[addr]
	}
	return aligned
}

// the client's reading of an entry's mirror with -consistency set as the stand's
// switch is: proof items verified under the session anchor and the nodes they
// prove against refused
func (cs *consistencyStand) clientView(t *testing.T, entry int, proofs bool) verify.View {
	t.Helper()
	v, err := verify.MirrorEntries(cs.p, verify.Options{Auth: true, Trust: cs.policy, Proofs: proofs}, cs.addrs, cs.entriesOf(t, entry), cs.at)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// a stream of the given 64-bit values, one per draw
func words(values ...uint64) *bytes.Reader {
	b := make([]byte, 0, 8*len(values))
	for _, v := range values {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	return bytes.NewReader(b)
}

// a draw among m nodes reads m+k for the k-th of them: 2^64 mod m is 1 for
// m = 3, 0 for m = 2 and m = 4, so no value from 2 up is thrown away
func pick(m, k int) uint64 { return uint64(m + k) }

// the 3 x 2 streams a client with four usable nodes reads for a chain of
// three, the first word for the second hop and the second for the exit
func pathStreams() [][]uint64 {
	var streams [][]uint64
	for k1 := range 3 {
		for k2 := range 2 {
			streams = append(streams, []uint64{pick(3, k1), pick(2, k2)})
		}
	}
	return streams
}

// the known answers of one stand, with the check on or off
type consistencyAnswers struct {
	// per honest relay: whether relay-5 is refused, and the number of bundle
	// and proof items in its mirror
	refusing            bool
	bundleItems, proofs int
	usable              []bool
	// of the 24 paths the fixed streams draw from entries 1..4, those with
	// relay-5 on them, and which: drawn(e) are the six from entry e in stream
	// order, nil when they are the six orders of the other honest nodes
	drawnWithRogue int
	drawn          func(e int) [][]int
	// the 36 composed chains with relay-5: which echo
	echoes func(pattern int) bool
	// per honest relay after them
	honestLinks, honestAccepted, honestDelivered, honestRefused int64
	honestToHonest, honestToRogue                               int
	// relay-5 after them
	rogueLinks, rogueAccepted, rogueDelivered int64
	rogueToHonest                             int
}

// the six paths the streams draw from entry e among all five nodes, in
// stream order; o3 is relay-5 for every honest entry
func drawnWithoutCheck(e int) [][]int {
	others := []int{}
	for i := range trustNodes {
		if i != e {
			others = append(others, i)
		}
	}
	o0, o1, o3 := others[0], others[1], others[3]
	return [][]int{{e, o3, o0}, {e, o3, o1}, {e, o0, o3}, {e, o0, o1}, {e, o1, o3}, {e, o1, o0}}
}

// relay-5, enrolled under the session CA like the others, runs a ring that
// opens setups under two onion keys K_A and K_B and signs two descriptors of
// epoch 0 with one identity, A under K_A and B under K_B a minute later;
// relays 1 and 2 fetch A, relays 3 and 4 fetch B. Every direct fetch alone
// passes the rules, so a record of one statement refuses nothing. One pass:
// relay-1 holds A and reads B in the mirror of relay-3, two onion keys in one
// epoch; relays 2, 3 and 4 read relay-1's mirror first, where the pair is now
// a proof, verify both bundles under the anchor and feed them into their own
// records, which find the same pair; every later item about relay-5 returns
// the conflict already held. The proof is pki.NewProof(A, B): the smaller
// bundle first, so the four mirrors carry the same bytes whichever statement
// their owner fetched. Each honest mirror: its own bundle, the three other
// honest bundles and the proof, 4 bundle items and 1 proof item. A client
// reading an honest mirror under the session anchor with -consistency: Usable
// [t t t t f], Missing(4) pki.ErrConflict with the rule text, Refused
// [f f f f t], and Judge(e, 3, 0) MirrorTaken with absent 0 of allowed
// min(0, 4 - 3) = 0, the refused node counted apart from -missing. A client
// with four usable nodes draws among the three others of its entry:
// ChooseRest swaps others[0] with others[k1] and takes it, then others[1] with
// others[1+k2] and takes it, so the 3 x 2 streams give the six orders of the
// other three honest nodes, from the four entries the 24 orders of three
// distinct honest nodes, none with relay-5, and CompromiseFraction over them
// with {relay-5} is (0, 0).
//
// Then the 36 chains of 3 distinct relays with relay-5 on them, composed past
// the client's choice as in TestHonestRelaysExtendOnlyToRelaysOfTheSessionCA,
// relay-5's node read from its own mirror: for each of the 12 ordered pairs
// (a, b) of honest relays [5 a b], [a 5 b] and [a b 5]. Relay-5 holds every
// honest key and no honest relay holds relay-5's, so [5 a b] echoes, a
// refuses the extend to relay-5 on [a 5 b] without a dial and b does the same
// on [a b 5]. Links are accepted connections, one per chain a relay is on; an
// accepted cell is one read on such a link, so a link of a chain that echoes
// carries the setup cell and the message, 2, and a link of a chain that ends
// unanswered its setup cell alone, 1; the echo comes back on the outbound
// link and is not counted. Per honest j: on [5 a b] 3 chains as a and 3 as b,
// 6 links and 12 cells, exit of the 3 as b, 3 delivered; on [a 5 b] 3 as a,
// 3 links, 3 cells, 3 refused extends; on [a b 5] 3 as a and 3 as b, 6 links,
// 6 cells, 3 refused as b: links 15, accepted 21, delivered 3, RefusedExtend 6
// and the 6 setup cells in Dropped; dials 1 to each other honest relay as a on
// [5 a b] and 1 as a on [a b 5], 2, none to relay-5. Relay-5: entry of the 12
// [5 a b], 12 links, 24 cells, delivered 0, refused 0, dials 3 to each honest
// relay (as a, b varying). The 24 honest chains dialled afterwards all echo
// and add per honest relay what stand A of that test counts: 18 links, 36
// cells, 6 delivered, 4 dials to each other honest relay, nothing at relay-5.
//
// The baseline leaves the records aside: every mirror lists relay-5 with a
// bundle, A in those of relays 1 and 2 and B in those of relays 3 and 4; the
// client holds all five, Judge(e, 3, 0) MirrorTaken with absent 0 of allowed
// min(0, 5 - 3) = 0. The same streams now draw among the four others o0 < o1
// < o2 < o3 = relay-5: 3 + k1 modulo 4 is 3, 0, 1 and 2 + k2 modulo 3 is 2,
// 0, so k1 = 0 takes o3 and then o0 or o1, k1 = 1 takes o0 and then o3 or o1,
// k1 = 2 takes o1 and then o3 or o0: [e 5 o0], [e 5 o1], [e o0 5], [e o0 o1],
// [e o1 5], [e o1 o0] (drawnWithoutCheck), four of six from every entry, 16
// of 24 with relay-5, CompromiseFraction (0, 16/24) since no entry is relay-5.
// All 36 composed chains echo: per honest j 6 links on each pattern, 18 links
// and 36 cells; exit of [5 a b] and of [a 5 b] as b, 6 delivered; dials 2 to
// each other honest relay as before and 6 to relay-5, 3 as a on [a 5 b] and 3
// as b on [a b 5]. Relay-5: 36 links, 72 cells, exit of the 12 [a b 5],
// dials 6 to each honest relay, 3 as the entry of [5 a b] and 3 as the middle
// of [a 5 b]. The 24 honest chains add the same as with the check on
func TestNodeWithTwoOnionKeysIsRefusedByEveryHonestNode(t *testing.T) {
	for _, s := range trustSuiteList {
		t.Run(s.String(), func(t *testing.T) {
			if s == jcrypto.SuiteGOST && testing.Short() {
				t.Skip("the GOST suite costs seconds of circuits")
			}
			t.Run("check", func(t *testing.T) {
				runConsistencyStand(t, s, true, consistencyAnswers{
					refusing:        true,
					bundleItems:     4,
					proofs:          1,
					usable:          []bool{true, true, true, true, false},
					drawnWithRogue:  0,
					echoes:          func(pattern int) bool { return pattern == 0 },
					honestLinks:     15,
					honestAccepted:  21,
					honestDelivered: 3,
					honestRefused:   6,
					honestToHonest:  2,
					honestToRogue:   0,
					rogueLinks:      12,
					rogueAccepted:   24,
					rogueDelivered:  0,
					rogueToHonest:   3,
				})
			})
			t.Run("baseline", func(t *testing.T) {
				runConsistencyStand(t, s, false, consistencyAnswers{
					refusing:        false,
					bundleItems:     5,
					proofs:          0,
					usable:          []bool{true, true, true, true, true},
					drawnWithRogue:  16,
					drawn:           drawnWithoutCheck,
					echoes:          func(int) bool { return true },
					honestLinks:     18,
					honestAccepted:  36,
					honestDelivered: 6,
					honestRefused:   0,
					honestToHonest:  2,
					honestToRogue:   6,
					rogueLinks:      36,
					rogueAccepted:   72,
					rogueDelivered:  12,
					rogueToHonest:   6,
				})
			})
		})
	}
}

func runConsistencyStand(t *testing.T, s jcrypto.Suite, check bool, want consistencyAnswers) {
	cs := startConsistencyStand(t, s, check)
	rogue := cs.relays[twoKeyRelay]
	canonical, err := pki.NewProof(cs.a, cs.b)
	if err != nil {
		t.Fatal(err)
	}

	wantConflicts := 0
	if want.refusing {
		wantConflicts = 1
	}
	for x := range twoKeyRelay {
		tr := cs.relays[x]
		c, refusing := cs.conflicts[x][rogue.addr]
		if refusing != want.refusing || len(cs.conflicts[x]) != wantConflicts {
			t.Fatalf("relay %d refuses %d peers, relay-5 among them %v; want %d and %v", x, len(cs.conflicts[x]), refusing, wantConflicts, want.refusing)
		}
		if refusing && (c.Addr != rogue.addr || c.Rule != pki.RuleOnionKeyPerEpoch || !bytes.Equal(c.Proof.A, canonical.A) || !bytes.Equal(c.Proof.B, canonical.B)) {
			t.Errorf("relay %d refuses relay-5 over %q with a proof %v the canonical pair", x, c.Rule, bytes.Equal(c.Proof.A, canonical.A) && bytes.Equal(c.Proof.B, canonical.B))
		}
		if _, held := tr.peers[rogue.addr]; held == want.refusing || len(tr.peers) != trustNodes-1-len(cs.conflicts[x]) {
			t.Errorf("relay %d holds relay-5 %v among %d peers; want %v and %d", x, held, len(tr.peers), !want.refusing, trustNodes-1-len(cs.conflicts[x]))
		}
		entries, err := pki.ParseMirror(tr.mirror)
		if err != nil {
			t.Fatal(err)
		}
		bundleItems, proofs := 0, 0
		for _, e := range entries {
			switch {
			case e.Proof != nil:
				proofs++
				if e.Addr != rogue.addr || !bytes.Equal(e.Proof.A, canonical.A) || !bytes.Equal(e.Proof.B, canonical.B) {
					t.Errorf("relay %d: the proof item is about %s and carries the canonical pair %v", x, e.Addr, bytes.Equal(e.Proof.A, canonical.A) && bytes.Equal(e.Proof.B, canonical.B))
				}
			case e.Addr == rogue.addr:
				bundleItems++
				if !bytes.Equal(e.Bundle, cs.fetched(x, twoKeyRelay)) {
					t.Errorf("relay %d lists relay-5 with another statement than it fetched", x)
				}
			default:
				bundleItems++
			}
		}
		if bundleItems != want.bundleItems || proofs != want.proofs {
			t.Errorf("relay %d: %d bundle items and %d proof items, want %d and %d", x, bundleItems, proofs, want.bundleItems, want.proofs)
		}
	}
	if len(rogue.peers) != trustNodes-1 {
		t.Fatalf("relay-5 holds %d peers, want 4", len(rogue.peers))
	}

	var paths [][]int
	for e := range twoKeyRelay {
		v := cs.clientView(t, e, check)
		if got := v.Usable(); !slices.Equal(got, want.usable) {
			t.Errorf("entry %d: the client holds %v, want %v", e, got, want.usable)
		}
		wantRefused := make([]bool, trustNodes)
		wantRefused[twoKeyRelay] = want.refusing
		if got := v.Refused(); !slices.Equal(got, wantRefused) {
			t.Errorf("entry %d: refused %v, want %v", e, got, wantRefused)
		}
		missing := v.Missing(twoKeyRelay)
		if want.refusing && (!errors.Is(missing, pki.ErrConflict) || !strings.HasSuffix(missing.Error(), pki.RuleOnionKeyPerEpoch.String())) || !want.refusing && missing != nil {
			t.Errorf("entry %d: relay-5 missing for %v", e, missing)
		}
		if verdict, absent, allowed := v.Judge(e, trustHops, 0); verdict != client.MirrorTaken || absent != 0 || allowed != 0 {
			t.Errorf("entry %d: Judge = %d, %d, %d, want %d, 0, 0", e, verdict, absent, allowed, client.MirrorTaken)
		}
		for k, stream := range pathStreams() {
			rnd := words(stream...)
			path, err := v.Draw(e, trustHops, rnd)
			if err != nil || rnd.Len() != 0 {
				t.Fatalf("entry %d, stream %d: %v, %v with %d bytes left", e, k, path, err, rnd.Len())
			}
			if want.drawn != nil && !slices.Equal(path, want.drawn(e)[k]) {
				t.Errorf("entry %d, stream %d: the client draws %v, want %v", e, k, path, want.drawn(e)[k])
			}
			paths = append(paths, path)
		}
	}
	distinct := map[string]bool{}
	withRogue := 0
	for _, path := range paths {
		distinct[fmt.Sprint(path)] = true
		if slices.Contains(path, twoKeyRelay) {
			withRogue++
		}
	}
	if len(paths) != 24 || len(distinct) != 24 || withRogue != want.drawnWithRogue {
		t.Fatalf("%d paths, %d distinct, %d with relay-5; want 24, 24, %d", len(paths), len(distinct), withRogue, want.drawnWithRogue)
	}
	if want.drawnWithRogue == 0 {
		for a := range twoKeyRelay {
			for b := range twoKeyRelay {
				for c := range twoKeyRelay {
					if a != b && b != c && a != c && !distinct[fmt.Sprint([]int{a, b, c})] {
						t.Errorf("the client never draws %d %d %d", a, b, c)
					}
				}
			}
		}
	}
	wantTouched := float64(want.drawnWithRogue) / float64(len(paths))
	if ends, touched := metrics.CompromiseFraction(paths, map[int]bool{twoKeyRelay: true}); ends != 0 || touched != wantTouched {
		t.Errorf("CompromiseFraction = %v, %v, want 0 and %v", ends, touched, wantTouched)
	}

	honestPair := func(x, y int) bool { return x != y && x != twoKeyRelay && y != twoKeyRelay }
	honest := cs.clientView(t, 0, check)
	node := func(i int) client.Node { return honest.Chain([]int{i})[0] }
	foreign := cs.view(t, cs.session.Anchor(), twoKeyRelay).Chain([]int{twoKeyRelay})[0]
	chains := 0
	for a := range twoKeyRelay {
		for b := range twoKeyRelay {
			if a == b {
				continue
			}
			for pattern, chain := range [][]client.Node{
				{foreign, node(a), node(b)},
				{node(a), foreign, node(b)},
				{node(a), node(b), foreign},
			} {
				var err error
				if want.echoes(pattern) {
					err = echoOnce(cs.p, chain, nil)
				} else {
					err = endsUnanswered(cs.p, chain)
				}
				if err != nil {
					t.Fatalf("chain through %s, %s, %s: %v", chain[0].Addr, chain[1].Addr, chain[2].Addr, err)
				}
				chains++
			}
		}
	}
	if chains != 36 {
		t.Fatalf("%d chains, want 36", chains)
	}
	counters := cs.counters()
	for j, tr := range cs.relays {
		links, accepted, delivered, refused := want.honestLinks, want.honestAccepted, want.honestDelivered, want.honestRefused
		if j == twoKeyRelay {
			links, accepted, delivered, refused = want.rogueLinks, want.rogueAccepted, want.rogueDelivered, 0
		}
		c := counters[j]
		if got := tr.links.Load(); got != links || c.Accepted != uint64(accepted) || c.Delivered != uint64(delivered) || c.RefusedExtend != uint64(refused) || c.Dropped != uint64(refused) || c.FailedExtend != 0 {
			t.Errorf("relay %d: %d links, %d cells accepted, %d delivered, %d extends refused, %d dropped, %d extends failed; want %d, %d, %d, %d, %d, 0",
				j, got, c.Accepted, c.Delivered, c.RefusedExtend, c.Dropped, c.FailedExtend, links, accepted, delivered, refused, refused)
		}
		for y := range cs.relays {
			dials := 0
			switch {
			case honestPair(j, y):
				dials = want.honestToHonest
			case j != y && y == twoKeyRelay:
				dials = want.honestToRogue
			case j != y:
				dials = want.rogueToHonest
			}
			if got := cs.dialled(j, y); got != dials {
				t.Errorf("relay %d dialled relay %d %d times, want %d", j, y, got, dials)
			}
		}
	}

	linksBefore := make([]int64, trustNodes)
	dialsBefore := make([][]int, trustNodes)
	for j, tr := range cs.relays {
		linksBefore[j] = tr.links.Load()
		dialsBefore[j] = make([]int, trustNodes)
		for y := range cs.relays {
			dialsBefore[j][y] = cs.dialled(j, y)
		}
	}
	chains = 0
	for a := range twoKeyRelay {
		v := cs.clientView(t, a, check)
		for b := range twoKeyRelay {
			for c := range twoKeyRelay {
				if a == b || b == c || a == c {
					continue
				}
				if err := echoOnce(cs.p, v.Chain([]int{a, b, c}), nil); err != nil {
					t.Fatalf("chain %d %d %d: %v", a, b, c, err)
				}
				chains++
			}
		}
	}
	if chains != 24 {
		t.Fatalf("%d chains, want 24", chains)
	}
	after := cs.counters()
	for j, tr := range cs.relays {
		links, accepted, delivered, dials := int64(18), uint64(36), uint64(6), 4
		if j == twoKeyRelay {
			links, accepted, delivered, dials = 0, 0, 0, 0
		}
		before, c := counters[j], after[j]
		if got := tr.links.Load() - linksBefore[j]; got != links || c.Accepted-before.Accepted != accepted || c.Delivered-before.Delivered != delivered || c.RefusedExtend != before.RefusedExtend || c.Dropped != before.Dropped || c.FailedExtend != 0 {
			t.Errorf("honest chains, relay %d: %d more links, %d more cells, %d more delivered, %d more refused extends, %d more dropped, %d failed; want %d, %d, %d, 0, 0, 0",
				j, got, c.Accepted-before.Accepted, c.Delivered-before.Delivered, c.RefusedExtend-before.RefusedExtend, c.Dropped-before.Dropped, c.FailedExtend, links, accepted, delivered)
		}
		for y := range cs.relays {
			more := 0
			if honestPair(j, y) {
				more = dials
			}
			if got := cs.dialled(j, y) - dialsBefore[j][y]; got != more {
				t.Errorf("honest chains: relay %d dialled relay %d %d more times, want %d", j, y, got, more)
			}
		}
	}
}
