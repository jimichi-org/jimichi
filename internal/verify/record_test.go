package verify

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

// a node that goes on signing: statements with chosen epochs, keys and times
type signer struct {
	p        jcrypto.CryptoProvider
	trust    pki.Policy
	id       *pki.Identity
	name     string
	addr     string
	link     []byte
	identity []byte
}

func newSigner(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, name string, notAfter time.Time) *signer {
	t.Helper()
	id, err := pki.NewIdentity(p, name, addrOf(name))
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
	cert, err := ca.Issue(req, t0, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), t0); err != nil {
		t.Fatal(err)
	}
	return &signer{p: p, trust: pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}, id: id, name: name, addr: addrOf(name),
		link: agreementKey(t, p), identity: id.Public()}
}

// signs under the given epoch and onion key at now for ttl; the link key is
// the signer's unless another is given
func (s *signer) stmt(t *testing.T, epoch uint32, onion []byte, now time.Time, ttl time.Duration, link ...[]byte) ([]byte, *pki.Verified) {
	t.Helper()
	l := s.link
	if len(link) > 0 {
		l = link[0]
	}
	s.id.SetKeys(l, onion, epoch)
	if err := s.id.Refresh(now, ttl); err != nil {
		t.Fatal(err)
	}
	b, ok := s.id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	v, err := pki.VerifyStatement(s.p, s.trust, s.addr, b)
	if err != nil {
		t.Fatal(err)
	}
	return b, v
}

func sec(n int) time.Time { return t0.Add(time.Duration(n) * time.Second) }

// one node, statements in the order a reader meets them; now past every
// published. Step 5 signs epoch 0 again after epoch 1 was out: the proof
// names the earliest statement of epoch 1 and the late one of epoch 0
func TestRecordFindsTheConflictAcrossWhatItHolds(t *testing.T) {
	for _, st := range suites {
		t.Run(st.String(), func(t *testing.T) {
			p := provider(t, st)
			ca := newCA(t, p)
			s := newSigner(t, p, ca, "relay-1", t0.Add(200*time.Hour))
			k0, k1 := agreementKey(t, p), agreementKey(t, p)
			h := time.Hour
			now := sec(6000)
			r := NewRecord(pki.Skew, 8*time.Minute)
			if r.Refused() != nil {
				t.Fatal("a fresh record refuses")
			}
			var step3 []byte
			for i, c := range []struct {
				epoch uint32
				onion []byte
				at    int
				want  pki.Rule
			}{
				{0, k0, 0, 0}, {0, k0, 1800, 0}, {1, k1, 3600, 0}, {1, k1, 5400, 0}, {0, k0, 5401, pki.RuleEpochOrder},
			} {
				b, v := s.stmt(t, c.epoch, c.onion, sec(c.at), h)
				if i == 2 {
					step3 = b
				}
				got, admitted := r.Take(b, v, now)
				switch {
				case c.want == 0 && (got != nil || !admitted):
					t.Fatalf("step %d: Take = %+v, %v, want nil and admitted", i+1, got, admitted)
				case c.want != 0 && (got == nil || got.Rule != c.want || !admitted):
					t.Fatalf("step %d: Take = %+v, %v, want %v", i+1, got, admitted, c.want)
				case c.want != 0:
					lo, hi := step3, b
					if bytes.Compare(lo, hi) > 0 {
						lo, hi = hi, lo
					}
					if !bytes.Equal(got.Proof.A, lo) || !bytes.Equal(got.Proof.B, hi) || got.Addr != s.addr {
						t.Fatalf("step %d: the proof is not steps 3 and 5 in canonical order", i+1)
					}
					if r.Refused() != got {
						t.Fatal("Refused differs from the conflict Take returned")
					}
				}
			}
			b, v := s.stmt(t, 1, k1, sec(5402), h)
			if got, admitted := r.Take(b, v, now); got != r.Refused() || admitted {
				t.Fatalf("after the refusal Take = %+v, %v, want the same conflict and nothing admitted", got, admitted)
			}

			type pair struct {
				name string
				a, b func() ([]byte, *pki.Verified)
				want pki.Rule
			}
			k2 := agreementKey(t, p)
			other := newSigner(t, p, ca, "relay-1", t0.Add(200*time.Hour))
			for _, c := range []pair{
				{"epochs two apart a second short of Skew", func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k0, sec(0), h) },
					func() ([]byte, *pki.Verified) { return s.stmt(t, 2, k2, sec(3719), h) }, pki.RuleEpochOverlap},
				{"epochs two apart Skew apart", func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k0, sec(0), h) },
					func() ([]byte, *pki.Verified) { return s.stmt(t, 2, k2, sec(3720), h) }, 0},
				{"two onion keys in one epoch", func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k0, sec(0), h) },
					func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k1, sec(1), h) }, pki.RuleOnionKeyPerEpoch},
				{"one onion key in two epochs", func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k0, sec(0), h) },
					func() ([]byte, *pki.Verified) { return s.stmt(t, 1, k0, sec(1), h) }, pki.RuleEpochPerKey},
				{"two link keys", func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k0, sec(0), h) },
					func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k0, sec(1), h, agreementKey(t, p)) }, pki.RuleLinkKey},
				{"two identities", func() ([]byte, *pki.Verified) { return s.stmt(t, 0, k0, sec(0), h) },
					func() ([]byte, *pki.Verified) { return other.stmt(t, 0, k0, sec(0), h) }, pki.RuleIdentity},
			} {
				// a new signer per pair: published never goes back within one identity
				s = newSigner(t, p, ca, "relay-1", t0.Add(200*time.Hour))
				r := NewRecord(pki.Skew, 8*time.Minute)
				ba, va := c.a()
				if got, admitted := r.Take(ba, va, sec(4000)); got != nil || !admitted {
					t.Fatalf("%s: the first statement: %+v, %v", c.name, got, admitted)
				}
				bb, vb := c.b()
				got, admitted := r.Take(bb, vb, sec(4000))
				switch {
				case !admitted:
					t.Fatalf("%s: the second statement was not admitted", c.name)
				case c.want == 0 && got != nil, c.want != 0 && (got == nil || got.Rule != c.want):
					t.Fatalf("%s: Take = %+v, want %v", c.name, got, c.want)
				case c.want != 0 && !(bytes.Equal(got.Proof.A, ba) && bytes.Equal(got.Proof.B, bb) || bytes.Equal(got.Proof.A, bb) && bytes.Equal(got.Proof.B, ba)):
					t.Fatalf("%s: the proof is not the pair", c.name)
				}
			}
		})
	}
}

// eight consistent epochs from the future stay out of the record, so the live
// epoch is still there to show the second key; a proof is taken whatever its
// times
func TestRecordAdmitsNoFutureStatement(t *testing.T) {
	for _, st := range suites {
		t.Run(st.String(), func(t *testing.T) {
			p := provider(t, st)
			ca := newCA(t, p)
			s := newSigner(t, p, ca, "relay-1", t0.Add(200*time.Hour))
			k, k2 := agreementKey(t, p), agreementKey(t, p)
			h := time.Hour
			live, liveV := s.stmt(t, 0, k, t0, h)
			second, secondV := s.stmt(t, 0, k2, t0.Add(time.Second), h)
			far := t0.Add(100 * h)
			type future struct {
				b []byte
				v *pki.Verified
			}
			var ahead []future
			for e := uint32(1); e <= 8; e++ {
				// pairs share a window, the next pair starts a life and Skew later
				at := far.Add(time.Duration((e-1)/2) * (h + pki.Skew))
				b, v := s.stmt(t, e, agreementKey(t, p), at, h)
				ahead = append(ahead, future{b, v})
			}

			r := NewRecord(pki.Skew, 8*time.Minute)
			now := t0.Add(10 * time.Second)
			if got, admitted := r.Take(live, liveV, now); got != nil || !admitted {
				t.Fatalf("the live statement: %+v, %v", got, admitted)
			}
			r.Hold(0)
			for i, f := range ahead {
				if got, admitted := r.Take(f.b, f.v, now); got != nil || admitted {
					t.Fatalf("future epoch %d: Take = %+v, admitted %v, want nothing admitted", i+1, got, admitted)
				}
			}
			if r.Epochs() != 1 {
				t.Fatalf("the record holds %d epochs, want the live one alone", r.Epochs())
			}
			got, admitted := r.Take(second, secondV, now)
			if got == nil || got.Rule != pki.RuleOnionKeyPerEpoch || !admitted {
				t.Fatalf("the second key of the live epoch: %+v, %v", got, admitted)
			}
			if !bytes.Equal(got.Proof.A, live) && !bytes.Equal(got.Proof.B, live) {
				t.Fatal("the proof does not hold the live statement")
			}

			// the future epochs admitted at their time are consistent
			r = NewRecord(pki.Skew, 8*time.Minute)
			for i, f := range ahead {
				if got, admitted := r.Take(f.b, f.v, far.Add(10*h)); got != nil || !admitted {
					t.Fatalf("future epoch %d at its time: %+v, %v", i+1, got, admitted)
				}
			}

			// a proof is taken whatever the times of its bundles
			a, _ := s.stmt(t, 9, agreementKey(t, p), far.Add(10*h), h)
			b, _ := s.stmt(t, 9, agreementKey(t, p), far.Add(10*h+time.Second), h)
			proof, err := pki.NewProof(a, b)
			if err != nil {
				t.Fatal(err)
			}
			c, err := pki.VerifyConflict(p, s.trust, s.addr, *proof)
			if err != nil {
				t.Fatal(err)
			}
			va, _ := pki.VerifyStatement(p, s.trust, s.addr, c.Proof.A)
			vb, _ := pki.VerifyStatement(p, s.trust, s.addr, c.Proof.B)
			r = NewRecord(pki.Skew, 8*time.Minute)
			if got := r.TakeProof(c, va, vb); got == nil || got.Rule != pki.RuleOnionKeyPerEpoch || r.Refused() == nil {
				t.Fatalf("TakeProof = %+v, refused %v", got, r.Refused())
			}
		})
	}
}

// nine epochs in pairs that share a window, each pair a life and Skew after
// the one before: no rule is broken, the ninth drops the smallest epoch that
// is not held, and Forget drops an epoch once its last expiry lies Skew plus
// the allowance in the past
func TestRecordForgetsExpiredEpochsAndHoldsEightAtMost(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	ca := newCA(t, p)
	s := newSigner(t, p, ca, "relay-1", t0.Add(200*time.Hour))
	life := 16 * time.Minute
	r := NewRecord(pki.Skew, 8*time.Minute)
	now := t0.Add(5 * time.Hour)
	at := func(epoch uint32) time.Time { return t0.Add(time.Duration(epoch/2) * (life + pki.Skew)) }
	for e := uint32(0); e <= 7; e++ {
		b, v := s.stmt(t, e, agreementKey(t, p), at(e), life)
		if got, admitted := r.Take(b, v, now); got != nil || !admitted {
			t.Fatalf("epoch %d: Take = %+v, %v", e, got, admitted)
		}
	}
	if r.Epochs() != 8 {
		t.Fatalf("%d epochs after eight, want 8", r.Epochs())
	}
	r.Hold(1)
	b, v := s.stmt(t, 8, agreementKey(t, p), at(8), life)
	if got, admitted := r.Take(b, v, now); got != nil || !admitted {
		t.Fatalf("the ninth epoch: Take = %+v, %v", got, admitted)
	}
	if r.Epochs() != 8 || r.epochs[0] != nil || r.epochs[1] == nil || r.epochs[8] == nil {
		t.Fatalf("after the ninth: %d epochs, epoch 0 held %v, 1 %v, 8 %v; want 8 with 0 dropped and the held 1 kept",
			r.Epochs(), r.epochs[0] != nil, r.epochs[1] != nil, r.epochs[8] != nil)
	}
	count := 0
	r.each(func(*statement) bool { count++; return true })
	if count > 3*MaxEpochs+1 {
		t.Fatalf("%d statements held, want at most %d", count, 3*MaxEpochs+1)
	}

	horizon := at(2).Add(life).Add(pki.Skew + 8*time.Minute)
	r.Forget(horizon.Add(-time.Second))
	if r.epochs[2] == nil || r.epochs[3] == nil {
		t.Fatal("Forget dropped epochs 2 and 3 a second before their horizon")
	}
	r.Forget(horizon)
	if r.epochs[2] != nil || r.epochs[3] != nil || r.epochs[4] == nil {
		t.Fatal("Forget at the horizon did not drop epochs 2 and 3, or dropped 4")
	}
	r.Forget(horizon.Add(100 * time.Hour))
	if r.epochs[1] == nil || r.Epochs() != 1 {
		t.Fatalf("Forget far later: %d epochs, held 1 kept %v; want the held epoch alone", r.Epochs(), r.epochs[1] != nil)
	}

	if !Newer(&pki.Verified{Epoch: 1, DescFrom: t0}, &pki.Verified{Epoch: 2, DescFrom: t0}) ||
		!Newer(&pki.Verified{Epoch: 1, DescFrom: t0}, &pki.Verified{Epoch: 1, DescFrom: t0.Add(time.Second)}) ||
		Newer(&pki.Verified{Epoch: 1, DescFrom: t0}, &pki.Verified{Epoch: 1, DescFrom: t0}) ||
		Newer(&pki.Verified{Epoch: 2, DescFrom: t0}, &pki.Verified{Epoch: 1, DescFrom: t0.Add(time.Hour)}) {
		t.Fatal("Newer does not order by epoch, then by published")
	}
}

// five listed nodes; the entry, node 0, serves bundles for 0 1 2 4 and a proof
// against node 3. With proofs read, node 3 is refused and the list is four
// long: 3 hops and missing 0 allow min(0, 4 - 3) = 0 absent, which is what
// there is. Two consistent bundles are no proof: the node counts as not served
func TestMirrorEntriesRefuseANodeByProofAndCountItApart(t *testing.T) {
	for _, st := range suites {
		t.Run(st.String(), func(t *testing.T) {
			p := provider(t, st)
			ca := newCA(t, p)
			h := time.Hour
			signers := make([]*signer, 5)
			addrs := make([]string, 5)
			bundles := make([][]byte, 5)
			for i := range signers {
				signers[i] = newSigner(t, p, ca, "relay-"+string(rune('1'+i)), t0.Add(72*h))
				addrs[i] = signers[i].addr
				bundles[i], _ = signers[i].stmt(t, 0, agreementKey(t, p), t0, h)
			}
			second, _ := signers[3].stmt(t, 0, agreementKey(t, p), t0.Add(time.Second), h)
			proof, err := pki.NewProof(bundles[3], second)
			if err != nil {
				t.Fatal(err)
			}
			resigned, _ := signers[2].stmt(t, 0, func() []byte {
				v, err := pki.VerifyStatement(p, signers[2].trust, addrs[2], bundles[2])
				if err != nil {
					t.Fatal(err)
				}
				return v.OnionPub
			}(), t0.Add(time.Second), h)
			noProof, err := pki.NewProof(bundles[2], resigned)
			if err != nil {
				t.Fatal(err)
			}
			trust := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
			entries := func(proofs map[int]*pki.Proof) []pki.MirrorEntry {
				out := make([]pki.MirrorEntry, 5)
				for i := range out {
					if pr, ok := proofs[i]; ok {
						out[i] = pki.MirrorEntry{Addr: addrs[i], Proof: pr}
						continue
					}
					out[i] = pki.MirrorEntry{Addr: addrs[i], Bundle: bundles[i]}
				}
				return out
			}
			on := Options{Auth: true, Trust: trust, Proofs: true}

			v, err := MirrorEntries(p, on, addrs, entries(map[int]*pki.Proof{3: proof}), t0)
			if err != nil {
				t.Fatal(err)
			}
			if u, r := v.Usable(), v.Refused(); !equalBools(u, []bool{true, true, true, false, true}) || !equalBools(r, []bool{false, false, false, true, false}) {
				t.Fatalf("Usable %v Refused %v", u, r)
			}
			if err := v.Missing(3); !errors.Is(err, pki.ErrConflict) || err.Error() != pki.ErrConflict.Error()+": two onion keys in one epoch" {
				t.Fatalf("Missing(3) = %v", err)
			}
			if verdict, absent, allowed := v.Judge(0, 3, 0); verdict != client.MirrorTaken || absent != 0 || allowed != 0 {
				t.Fatalf("Judge(0, 3, 0) = %d, %d, %d, want taken with 0 of 0", verdict, absent, allowed)
			}
			seen := map[string]bool{}
			for first := 0; first < 3; first++ {
				for second := 0; second < 2; second++ {
					path, err := v.Draw(0, 3, words(pick(3, first), pick(2, second)))
					if err != nil {
						t.Fatal(err)
					}
					for _, n := range path {
						if n == 3 {
							t.Fatalf("a draw took the refused node: %v", path)
						}
					}
					seen[string(rune('0'+path[0]))+string(rune('0'+path[1]))+string(rune('0'+path[2]))] = true
				}
			}
			if len(seen) != 6 {
				t.Fatalf("%d distinct paths over the six streams, want 6", len(seen))
			}
			if verdict, _, _ := v.JudgeTo(0, 3, 3, 1); verdict != client.MirrorLacksExit {
				t.Fatalf("JudgeTo with the refused exit = %d, want %d", verdict, client.MirrorLacksExit)
			}
			if verdict, _, _ := v.JudgeTo(3, 4, 3, 1); verdict != client.MirrorLacksEntry {
				t.Fatalf("JudgeTo with the refused entry = %d, want %d", verdict, client.MirrorLacksEntry)
			}

			v, err = MirrorEntries(p, on, addrs, entries(map[int]*pki.Proof{2: noProof}), t0)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Missing(2); !errors.Is(err, pki.ErrNoConflict) || v.Refused()[2] {
				t.Fatalf("a proof of two consistent bundles: Missing(2) = %v, refused %v", err, v.Refused()[2])
			}
			if verdict, absent, allowed := v.Judge(0, 3, 0); verdict != client.MirrorLacksTooMany || absent != 1 || allowed != 0 {
				t.Fatalf("Judge(0, 3, 0) = %d, %d, %d, want too many with 1 of 0", verdict, absent, allowed)
			}
			if verdict, _, _ := v.Judge(0, 3, 1); verdict != client.MirrorTaken {
				t.Fatalf("Judge(0, 3, 1) = %d, want taken", verdict)
			}

			v, err = MirrorEntries(p, on, addrs, entries(map[int]*pki.Proof{0: proof}), t0)
			if err != nil {
				t.Fatal(err)
			}
			if verdict, _, _ := v.Judge(0, 3, 1); verdict != client.MirrorLacksEntry {
				t.Fatalf("a proof against the entry: Judge = %d, want lacks entry", verdict)
			}

			for _, o := range []Options{{Auth: true, Trust: trust}, {Auth: false, Proofs: true}} {
				v, err := MirrorEntries(p, o, addrs, entries(map[int]*pki.Proof{3: proof}), t0)
				if err != nil {
					t.Fatal(err)
				}
				if err := v.Missing(3); err != ErrNoBundle || v.Refused()[3] {
					t.Fatalf("proofs %v auth %v: Missing(3) = %v, refused %v, want a node not served", o.Proofs, o.Auth, err, v.Refused()[3])
				}
				if verdict, _, _ := v.Judge(0, 3, 0); verdict != client.MirrorLacksTooMany {
					t.Fatalf("proofs %v auth %v: Judge(0, 3, 0) = %d, want too many", o.Proofs, o.Auth, verdict)
				}
			}

			plain := [][]byte{bundles[0], nil, bundles[2], altered(t, bundles[3]), bundles[4]}
			old, err := Mirror(p, true, trust, addrs, plain, t0)
			if err != nil {
				t.Fatal(err)
			}
			rows := make([]pki.MirrorEntry, 5)
			for i := range rows {
				rows[i] = pki.MirrorEntry{Addr: addrs[i], Bundle: plain[i]}
			}
			same, err := MirrorEntries(p, on, addrs, rows, t0)
			if err != nil {
				t.Fatal(err)
			}
			if !equalBools(old.Usable(), same.Usable()) {
				t.Fatalf("Mirror holds %v, MirrorEntries %v", old.Usable(), same.Usable())
			}
			for i := range addrs {
				a, b := old.Missing(i), same.Missing(i)
				if (a == nil) != (b == nil) || a != nil && a.Error() != b.Error() {
					t.Fatalf("node %d: Mirror gives %v, MirrorEntries %v", i, a, b)
				}
			}
		})
	}
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

func TestPeerTakesThePolicy(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	ca := newCA(t, p)
	s := newSigner(t, p, ca, "relay-1", t0.Add(72*time.Hour))
	least := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew, MinLife: pki.MinDescriptorLife}
	short, _ := s.stmt(t, 0, agreementKey(t, p), t0, 15*time.Minute)
	if _, err := Peer(p, least, s.addr, short, t0); !errors.Is(err, pki.ErrDescLife) {
		t.Fatalf("a 15 min descriptor under the least lifetime: %v, want %v", err, pki.ErrDescLife)
	}
	if _, err := Peer(p, s.trust, s.addr, short, t0); err != nil {
		t.Fatalf("a 15 min descriptor without a least lifetime: %v", err)
	}
	long, _ := s.stmt(t, 0, agreementKey(t, p), t0.Add(time.Second), 16*time.Minute)
	if peer, err := Peer(p, least, s.addr, long, t0.Add(time.Second)); err != nil || !bytes.Equal(peer.LinkPub, s.link) || !bytes.Equal(peer.Identity, s.identity) {
		t.Fatalf("a 16 min descriptor under the least lifetime: %+v, %v", peer, err)
	}
}
