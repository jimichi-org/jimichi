package pki

import (
	"bytes"
	"errors"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func statement(identity, certHash byte, link, onion []byte, epoch uint32, published, expires int64) *Verified {
	v := &Verified{Identity: []byte{identity}, LinkPub: link, OnionPub: onion, Epoch: epoch,
		DescFrom: time.Unix(published, 0), DescUntil: time.Unix(expires, 0)}
	v.CertHash[0] = certHash
	return v
}

// pairs worked by hand, times in unix seconds, Skew 120 s: an epoch two apart
// may start at expires + 120 and not a second earlier; adjacent epochs may
// overlap; the same second is in order; a cut descriptor keeps its expires
func TestCompareKnownAnswers(t *testing.T) {
	k, k2, l, l2 := []byte("K"), []byte("K2"), []byte("L"), []byte("L2")
	for _, c := range []struct {
		name string
		a, b *Verified
		want Rule
	}{
		{"re-signing", statement(1, 1, l, k, 3, 100, 1300), statement(1, 1, l, k, 3, 700, 1900), 0},
		{"two identities", statement(1, 1, l, k, 3, 100, 1300), statement(2, 1, l, k, 3, 100, 1300), RuleIdentity},
		{"two certificates", statement(1, 1, l, k, 3, 100, 1300), statement(1, 2, l, k, 3, 100, 1300), RuleCert},
		{"two link keys", statement(1, 1, l, k, 3, 100, 1300), statement(1, 1, l2, k, 3, 100, 1300), RuleLinkKey},
		{"two onion keys in one epoch", statement(1, 1, l, k, 3, 100, 1300), statement(1, 1, l, k2, 3, 100, 1300), RuleOnionKeyPerEpoch},
		{"one onion key in two epochs", statement(1, 1, l, k, 3, 100, 1300), statement(1, 1, l, k, 4, 100, 1300), RuleEpochPerKey},
		{"the same second", statement(1, 1, l, k, 3, 100, 1300), statement(1, 1, l, k2, 4, 100, 1300), 0},
		{"an older epoch published later", statement(1, 1, l, k, 3, 100, 1300), statement(1, 1, l, k2, 4, 99, 1299), RuleEpochOrder},
		{"Skew apart", statement(1, 1, l, k, 3, 7200, 8400), statement(1, 1, l, k2, 5, 8520, 9720), 0},
		{"a second short of Skew", statement(1, 1, l, k, 3, 7200, 8400), statement(1, 1, l, k2, 5, 8519, 9719), RuleEpochOverlap},
		{"touching", statement(1, 1, l, k, 3, 7200, 8400), statement(1, 1, l, k2, 5, 8400, 9600), RuleEpochOverlap},
		{"order before overlap", statement(1, 1, l, k, 3, 100, 1300), statement(1, 1, l, k2, 5, 50, 1250), RuleEpochOrder},
		{"adjacent epochs overlap", statement(1, 1, l, k, 3, 7200, 8400), statement(1, 1, l, k2, 4, 7300, 8500), 0},
		{"one key for the life of the process", statement(1, 1, l, l, 0, 100, 1300), statement(1, 1, l, l, 0, 700, 1900), 0},
		{"no wrap at the top", statement(1, 1, l, k, 4294967294, 100, 1300), statement(1, 1, l, k2, 4294967295, 700, 1900), 0},
		{"both cut by the certificate", statement(1, 1, l, k, 3, 9500, 10000), statement(1, 1, l, k2, 4, 9700, 10000), 0},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("%s: Compare = %v, want %v", c.name, got, c.want)
		}
		if got := Compare(c.b, c.a); got != c.want {
			t.Errorf("%s: Compare the other way round = %v, want %v", c.name, got, c.want)
		}
	}
	for r, text := range map[Rule]string{
		0: "consistent", RuleIdentity: "two identities at one address", RuleCert: "two certificates for one identity",
		RuleLinkKey: "two link keys", RuleOnionKeyPerEpoch: "two onion keys in one epoch",
		RuleEpochPerKey: "one onion key in two epochs", RuleEpochOrder: "an older epoch published after a newer one",
		RuleEpochOverlap: "epochs two apart overlap", 200: "consistent",
	} {
		if r.String() != text {
			t.Errorf("Rule(%d).String() = %q, want %q", r, r.String(), text)
		}
	}
}

// one identity signs every pair; the descriptor is built by hand, so its
// times and keys are whatever the case needs, as a node off the protocol would
// sign them
func TestVerifyConflictOnBothSuites(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		k, k2, l2 := n.onion, agreementKey(t, p), agreementKey(t, p)
		h := time.Hour
		at := func(epoch uint32, onion, link []byte, published, expires time.Time) []byte {
			d := n.descriptor(published, expires)
			d.Epoch, d.OnionPub, d.LinkPub = epoch, onion, link
			return n.pack(t, d)
		}
		e0 := at(0, k, k, t0, t0.Add(h))
		e1 := at(1, k2, k, t0.Add(20*time.Minute), t0.Add(80*time.Minute))

		// a second identity certified at the same name and address
		twin := e.node(t, "relay-1").bundle(t, t0, h)
		// a second certificate for the same identity
		cert2, err := e.ca.Issue(requestFor(t, n.id, n.name, n.addr), t0, until)
		if err != nil {
			t.Fatal(err)
		}
		raw2 := cert2.Marshal()
		d := n.descriptor(t0, t0.Add(h))
		copy(d.CertHash[:], p.Hash(raw2))
		d.Sig = n.sign(t, descriptorDomain, d.body())
		recertified := pack(p, raw2, d.Marshal())
		// a signature that does not verify
		d = n.descriptor(t0.Add(time.Second), t0.Add(h))
		d.Sig = n.sign(t, descriptorDomain, d.body())
		d.Sig[0] ^= 1
		altered := pack(p, n.raw, d.Marshal())

		for _, c := range []struct {
			name string
			a, b []byte
			want Rule
		}{
			{"two onion keys in one epoch", e0, at(0, k2, k, t0.Add(time.Second), t0.Add(h)), RuleOnionKeyPerEpoch},
			{"one onion key in two epochs", e0, at(1, k, k, t0.Add(30*time.Minute), t0.Add(90*time.Minute)), RuleEpochPerKey},
			{"two link keys", e0, at(0, k, l2, t0.Add(time.Second), t0.Add(h)), RuleLinkKey},
			{"an older epoch published later", at(1, k2, k, t0.Add(10*time.Minute), t0.Add(70*time.Minute)), at(0, k, k, t0.Add(20*time.Minute), t0.Add(80*time.Minute)), RuleEpochOrder},
			{"epochs two apart overlap", e0, at(2, k2, k, t0.Add(30*time.Minute), t0.Add(90*time.Minute)), RuleEpochOverlap},
			{"two certificates", e0, recertified, RuleCert},
			{"two identities", e0, twin, RuleIdentity},
			{"both expired long ago", at(0, k, k, t0.Add(-48*h), t0.Add(-47*h)), at(0, k2, k, t0.Add(-48*h), t0.Add(-47*h)), RuleOnionKeyPerEpoch},
		} {
			for i, order := range [][2][]byte{{c.a, c.b}, {c.b, c.a}} {
				got, err := VerifyConflict(p, e.pol, n.addr, Proof{A: order[0], B: order[1]})
				if err != nil || got.Rule != c.want || got.Addr != n.addr {
					t.Errorf("%s, order %d: VerifyConflict = %+v, %v, want %v", c.name, i, got, err, c.want)
					continue
				}
				ab := bytes.Equal(got.Proof.A, c.a) && bytes.Equal(got.Proof.B, c.b)
				ba := bytes.Equal(got.Proof.A, c.b) && bytes.Equal(got.Proof.B, c.a)
				if bytes.Compare(got.Proof.A, got.Proof.B) >= 0 || !ab && !ba {
					t.Errorf("%s, order %d: the proof is not the pair in canonical order", c.name, i)
				}
			}
		}

		foreign := Policy{Anchor: newEnv(t, p).ca.Anchor(), Skew: Skew}
		other := e.node(t, "relay-2").bundle(t, t0, h)
		for _, c := range []struct {
			name string
			pol  Policy
			pr   Proof
			want error
		}{
			{"the same bundle twice", e.pol, Proof{A: e0, B: e0}, ErrNoConflict},
			{"two epochs of an honest rotation", e.pol, Proof{A: e0, B: e1}, ErrNoConflict},
			{"the bundle of another node", e.pol, Proof{A: e0, B: other}, ErrWrongAddr},
			{"an altered signature", e.pol, Proof{A: e0, B: altered}, ErrDescSignature},
			{"another anchor", foreign, Proof{A: e0, B: at(0, k2, k, t0.Add(time.Second), t0.Add(h))}, ErrUnknownCA},
			{"not a bundle", e.pol, Proof{A: e0, B: []byte("x")}, ErrFormat},
		} {
			if got, err := VerifyConflict(p, c.pol, n.addr, c.pr); !errors.Is(err, c.want) || got != nil {
				t.Errorf("%s: VerifyConflict = %+v, %v, want %v", c.name, got, err, c.want)
			}
		}

		if _, err := NewProof(e0, e0); !errors.Is(err, ErrNoConflict) {
			t.Errorf("NewProof of one bundle twice: %v, want %v", err, ErrNoConflict)
		}
		pr, err := NewProof(e1, e0)
		if err != nil || bytes.Compare(pr.A, pr.B) >= 0 {
			t.Fatalf("NewProof = %v, or the smaller bundle is not first", err)
		}
	})
}

func TestVerifyStatementIgnoresTheClockNotTheSignatures(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		h := time.Hour
		live := n.bundle(t, t0, h)
		v, err := VerifyStatement(p, e.pol, n.addr, live)
		if err != nil {
			t.Fatalf("VerifyStatement of a live bundle: %v", err)
		}
		w, err := Verify(p, e.pol, n.addr, live, t0)
		if err != nil {
			t.Fatalf("Verify of a live bundle: %v", err)
		}
		switch {
		case v.Addr != w.Addr, v.Name != w.Name, !bytes.Equal(v.Identity, w.Identity), v.CertHash != w.CertHash,
			!bytes.Equal(v.LinkPub, w.LinkPub), !bytes.Equal(v.OnionPub, w.OnionPub), v.Epoch != w.Epoch,
			!v.CertUntil.Equal(w.CertUntil), !v.DescFrom.Equal(w.DescFrom), !v.DescUntil.Equal(w.DescUntil):
			t.Fatalf("VerifyStatement gives %+v, Verify %+v", v, w)
		case !v.DescFrom.Equal(t0), !v.DescUntil.Equal(t0.Add(h)), !bytes.Equal(v.CertHash[:], p.Hash(n.raw)):
			t.Fatalf("published %v, expires %v, certificate hash %x", v.DescFrom, v.DescUntil, v.CertHash)
		}

		cert := *n.cert
		cert.NotBefore, cert.NotAfter = t0.Unix(), t0.Unix()
		sig, err := e.ca.sign(certDomain, cert.body())
		if err != nil {
			t.Fatal(err)
		}
		cert.Sig = sig
		empty := cert.Marshal()
		d := n.descriptor(t0, t0.Add(h))
		copy(d.CertHash[:], p.Hash(empty))
		d.Sig = n.sign(t, descriptorDomain, d.body())
		emptyWindow := pack(p, empty, d.Marshal())

		least := Policy{Anchor: e.ca.Anchor(), Skew: Skew, MinLife: MinDescriptorLife}
		short := n.pack(t, n.descriptor(t0, t0.Add(959*time.Second)))
		for _, c := range []struct {
			name              string
			pol               Policy
			bundle            []byte
			now               time.Time
			statement, verify error
		}{
			{"a descriptor that expired", e.pol, live, t0.Add(2 * h), nil, ErrDescTime},
			{"a certificate that expired", e.pol, live, until, nil, ErrCertTime},
			{"published an hour ahead", e.pol, n.pack(t, n.descriptor(t0.Add(h), t0.Add(2*h))), t0, nil, ErrDescTime},
			{"expires at published", e.pol, n.pack(t, n.descriptor(t0, t0)), t0, ErrDescTime, ErrDescTime},
			{"a life above the longest", e.pol, n.pack(t, n.descriptor(t0, t0.Add(MaxDescriptorLife+time.Second))), t0, ErrDescTime, ErrDescTime},
			{"a life below the least", least, short, t0, ErrDescLife, ErrDescLife},
			{"the same without a least", e.pol, short, t0, nil, nil},
			{"the least life itself", least, n.pack(t, n.descriptor(t0, t0.Add(MinDescriptorLife))), t0, nil, nil},
			{"a short life cut by the certificate", least, n.pack(t, n.descriptor(until.Add(-time.Minute), until)), until.Add(-time.Minute), nil, nil},
			{"not_after at not_before", e.pol, emptyWindow, t0, ErrCertTime, ErrCertTime},
		} {
			if got, err := VerifyStatement(p, c.pol, n.addr, c.bundle); !errors.Is(err, c.statement) || (err == nil) != (got != nil) {
				t.Errorf("%s: VerifyStatement = %v, %v, want %v", c.name, got != nil, err, c.statement)
			}
			if got, err := Verify(p, c.pol, n.addr, c.bundle, c.now); !errors.Is(err, c.verify) || (err == nil) != (got != nil) {
				t.Errorf("%s: Verify = %v, %v, want %v", c.name, got != nil, err, c.verify)
			}
		}
	})
}
