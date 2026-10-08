package scenario

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/noise"
)

// opens with the sender, so with the sender as responder the recipient's
// confirming dummy comes first
var script = []Line{
	{FromSender: true, Body: []byte("the meeting moves to thursday")},
	{Body: []byte("noted")},
	{FromSender: true, Dummy: true},
	{Dummy: true},
	{FromSender: true, Body: []byte("bring the signed copy")},
	{Body: []byte{}},
}

var roles = []e2e.Role{e2e.RoleInitiator, e2e.RoleResponder}

// every test runs on both suites, each side in both roles, on a provider that
// fails the test on any signing call
func eachCase(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role)) {
	t.Helper()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		base, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range roles {
			t.Run(s.String()+"/recipient-"+role.String(), func(t *testing.T) {
				run(t, noSigning{CryptoProvider: base, t: t}, role)
			})
		}
	}
}

type noSigning struct {
	jcrypto.CryptoProvider
	t testing.TB
}

func (p noSigning) GenerateSigning() (*secmem.Buffer, []byte, error) {
	p.t.Error("GenerateSigning called")
	return p.CryptoProvider.GenerateSigning()
}

func (p noSigning) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	p.t.Error("Sign called")
	return p.CryptoProvider.Sign(priv, msg)
}

func (p noSigning) Verify(pub, msg, sig []byte) bool {
	p.t.Error("Verify called")
	return p.CryptoProvider.Verify(pub, msg, sig)
}

func pair(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) (sender, recipient *e2e.Identity) {
	t.Helper()
	s, r, err := Identities(p, role)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	t.Cleanup(r.Close)
	return s, r
}

func genuine(t *testing.T, p jcrypto.CryptoProvider, sender, recipient *e2e.Identity, lines []Line) (*Transcript, *Evidence) {
	t.Helper()
	tr, ev, err := Genuine(p, sender, recipient, lines)
	if err != nil {
		t.Fatalf("Genuine: %v", err)
	}
	t.Cleanup(ev.Release)
	return tr, ev
}

func forge(t *testing.T, p jcrypto.CryptoProvider, recipient *e2e.Identity, sender e2e.Card, lines []Line) (*Transcript, *Evidence) {
	t.Helper()
	tr, ev, err := Forge(p, recipient, sender, lines)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	t.Cleanup(ev.Release)
	return tr, ev
}

func messages(lines []Line, fromSender bool) [][]byte {
	var out [][]byte
	for _, l := range lines {
		if l.FromSender == fromSender && !l.Dummy {
			out = append(out, l.Body)
		}
	}
	return out
}

func sameBodies(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// the records the session must produce for the script: kk1 by the initiator,
// kk2 by the responder, the initiator's confirming dummy when the script opens
// with the responder, then the script line by line
func wantShape(role e2e.Role, lines []Line) []Record {
	senderInitiates := role == e2e.RoleResponder
	out := []Record{{FromSender: senderInitiates, Kind: KindKK1}, {FromSender: !senderInitiates, Kind: KindKK2}}
	if len(lines) == 0 || lines[0].FromSender != senderInitiates {
		out = append(out, Record{FromSender: senderInitiates, Dummy: true, Kind: KindData})
	}
	for _, l := range lines {
		out = append(out, Record{FromSender: l.FromSender, Dummy: l.Dummy, Kind: KindData, Body: l.Body})
	}
	return out
}

func checkShape(t *testing.T, what string, tr *Transcript, role e2e.Role, lines []Line) {
	t.Helper()
	want := wantShape(role, lines)
	if len(tr.Records) != len(want) {
		t.Fatalf("%s: %d records, want %d", what, len(tr.Records), len(want))
	}
	// every direction numbers its data records from 0, in the clear after the kind
	next := map[bool]uint32{}
	for i, r := range tr.Records {
		w := want[i]
		if r.FromSender != w.FromSender || r.Dummy != w.Dummy || r.Kind != w.Kind || !bytes.Equal(r.Body, w.Body) ||
			len(r.Bytes) != e2e.RecordSize || r.Bytes[0] != r.Kind {
			t.Fatalf("%s: record %d is %+v (%d bytes, first %d), want %+v", what, i, r, len(r.Bytes), r.Bytes[0], w)
		}
		if r.Kind != KindData {
			continue
		}
		if n := binary.BigEndian.Uint32(r.Bytes[1:5]); n != next[r.FromSender] {
			t.Fatalf("%s: record %d has the number %d, want %d", what, i, n, next[r.FromSender])
		}
		next[r.FromSender]++
	}
}

// the claim of the scenario: a transcript the recipient forged alone has the
// shape of a real one and passes the same check, and both read as the sender
// saying the script's lines
func TestForgedTranscriptVerifiesAsTheGenuineOne(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		sender, recipient := pair(t, p, role)
		gen, genEv := genuine(t, p, sender, recipient, script)
		fake, fakeEv := forge(t, p, recipient, sender.Card(), script)

		checkShape(t, "genuine", gen, role, script)
		checkShape(t, "forged", fake, role, script)
		if !SameShape(gen, fake) {
			t.Fatal("the forged transcript is shaped otherwise")
		}
		// fresh ephemeral keys on both: the forgery is not a copy
		for i := range gen.Records {
			if bytes.Equal(gen.Records[i].Bytes, fake.Records[i].Bytes) {
				t.Fatalf("record %d is the same in both transcripts", i)
			}
		}
		if !bytes.Equal(fake.Sender.Bytes(), sender.Card().Bytes()) || !bytes.Equal(fake.Recipient.Bytes(), recipient.Card().Bytes()) {
			t.Fatal("the forged transcript names other cards")
		}

		want := messages(script, true)
		for _, c := range []struct {
			name string
			tr   *Transcript
			ev   *Evidence
		}{{"genuine", gen, genEv}, {"forged", fake, fakeEv}} {
			said, err := Verify(p, recipient, c.ev, c.tr)
			if err != nil {
				t.Fatalf("Verify(%s): %v", c.name, err)
			}
			if !sameBodies(said, want) {
				t.Fatalf("Verify(%s) read %q, want %q", c.name, said, want)
			}
		}
	})
}

// the role of the recipient decides which handshake record carries its
// ephemeral key, and the evidence is that key
func TestEvidenceIsTheKeyOfTheRecipientsHandshakeRecord(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		sender, recipient := pair(t, p, role)
		for _, c := range []struct {
			name string
			make func() (*Transcript, *Evidence)
		}{
			{"genuine", func() (*Transcript, *Evidence) { return genuine(t, p, sender, recipient, script) }},
			{"forged", func() (*Transcript, *Evidence) { return forge(t, p, recipient, sender.Card(), script) }},
		} {
			tr, ev := c.make()
			at := 1
			if role == e2e.RoleInitiator {
				at = 0
			}
			r := tr.Records[at]
			size := len(recipient.Card().Static)
			if r.FromSender || !bytes.Equal(r.Bytes[1:1+size], ev.Public) || ev.Ephemeral.Len() == 0 {
				t.Fatalf("%s: the evidence is not the key in record %d", c.name, at)
			}
		}
	})
}

// without the recipient's key there is no forgery that passes: one made with
// a fresh key in its place verifies under that key, and the recipient's key
// refuses its first record, which is cryptography and not a check of names
func TestControlWithAFreshKeyIsRejected(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		spy := NewSpy(p)
		sender, recipient := pair(t, spy, role)
		run, err := Control(spy, recipient, sender.Card(), script)
		if err != nil {
			t.Fatalf("Control: %v", err)
		}
		t.Cleanup(run.Close)

		own, fresh := recipient.Card(), run.Stand.Card()
		if bytes.Equal(fresh.Static, own.Static) || !spy.Drew(fresh.Static) {
			t.Fatal("the control did not draw a fresh key")
		}
		if fresh.Mailbox != own.Mailbox || fresh.Queue != own.Queue || fresh.Suite != own.Suite {
			t.Fatalf("the fresh card %v differs from the recipient's %v in more than the key", fresh, own)
		}
		if !bytes.Equal(run.Transcript.Recipient.Bytes(), fresh.Bytes()) || !bytes.Equal(run.Transcript.Sender.Bytes(), sender.Card().Bytes()) {
			t.Fatal("the control names other cards")
		}
		checkShape(t, "control", run.Transcript, role, script)
		said, err := Verify(p, run.Stand, run.Evidence, run.Transcript)
		if err != nil {
			t.Fatalf("the control does not verify under its own key: %v", err)
		}
		if !sameBodies(said, messages(script, true)) {
			t.Fatalf("the control reads %q", said)
		}

		named := *run.Transcript
		named.Recipient = own
		_, err = Verify(p, recipient, run.Evidence, &named)
		if RefusedAt(err) != 0 || RefusedAt(run.Refusal) != 0 || !run.Rejected() || run.RefusedAt() != 0 {
			t.Fatalf("the recipient's key refuses the control with %v, the run says %v, want a refusal of record 0", err, run.Refusal)
		}
		if _, err := Verify(p, recipient, run.Evidence, run.Transcript); RefusedAt(err) != -1 || !errors.Is(err, ErrMismatch) {
			t.Fatalf("the control under its own name: %v, want a refusal of the name", err)
		}
	})
}

// a refusal at a record counts, a refusal of the name or a run that verified
// does not
func TestControlRunRejectedOnlyAtARecord(t *testing.T) {
	for _, c := range []struct {
		err  error
		at   int
		want bool
	}{
		{nil, -1, false},
		{&Mismatch{Record: -1, Reason: "the transcript names another recipient"}, -1, false},
		{fmt.Errorf("wrapped: %w", &Mismatch{Record: 3}), 3, true},
		{&Mismatch{Record: 0}, 0, true},
		{errors.New("no session"), -1, false},
	} {
		run := &ControlRun{Refusal: c.err}
		if run.RefusedAt() != c.at || run.Rejected() != c.want {
			t.Fatalf("%v: at %d rejected %v, want %d and %v", c.err, run.RefusedAt(), run.Rejected(), c.at, c.want)
		}
	}
}

// a Static that shows the recipient's public key and agrees with a fresh one
type impostor struct {
	pub []byte
	kp  *noise.KeyPair
}

func (i impostor) Public() []byte { return bytes.Clone(i.pub) }

func (i impostor) Agree(remote []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	return i.kp.Agree(remote, ctx)
}

// Verify rests on the recipient's key, the evidence, the claimed bodies and
// every byte of every record: a change to any of them is refused
func TestVerifyRefusesWhatTheRecipientCannotMakeAgain(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		// some thousands of Verify calls a case
		t.Parallel()
		sender, recipient := pair(t, p, role)
		tr, ev := genuine(t, p, sender, recipient, script)
		_, otherEv := forge(t, p, recipient, sender.Card(), script)

		refused := func(what string, rcp *e2e.Identity, e *Evidence, x *Transcript) {
			t.Helper()
			if _, err := Verify(p, rcp, e, x); !errors.Is(err, ErrMismatch) {
				t.Fatalf("%s: %v, want ErrMismatch", what, err)
			}
		}
		clone := func() *Transcript {
			c := *tr
			c.Records = make([]Record, len(tr.Records))
			for i, r := range tr.Records {
				r.Bytes, r.Body = bytes.Clone(r.Bytes), bytes.Clone(r.Body)
				c.Records[i] = r
			}
			return &c
		}

		refusedAt := func(what string, x *Transcript, want int) {
			t.Helper()
			if _, err := Verify(p, recipient, ev, x); RefusedAt(err) != want {
				t.Fatalf("%s: %v, want a refusal of record %d", what, err, want)
			}
		}
		rng := rand.New(rand.NewPCG(uint64(role), 19))
		for i, r := range tr.Records {
			for _, at := range flipped(p.Suite(), rng) {
				x := clone()
				x.Records[i].Bytes[at] ^= 0x01
				refusedAt(fmt.Sprintf("record %d, by the sender %v, with byte %d flipped", i, r.FromSender, at), x, i)
			}
			x := clone()
			x.Records[i].Body = append(x.Records[i].Body, []byte("I agree to the deal")...)
			refusedAt(fmt.Sprintf("record %d (kind %d, dummy %v, by the sender %v) claiming another body", i, r.Kind, r.Dummy, r.FromSender), x, i)
		}
		x := clone()
		x.Records = x.Records[:1]
		refused("kk1 alone", recipient, ev, x)
		// two data records of one author out of turn: the sender's comes too
		// late to open, the recipient's is sealed with the other's body
		for _, fromSender := range []bool{true, false} {
			x := clone()
			var at []int
			for i, r := range x.Records {
				if r.Kind == KindData && r.FromSender == fromSender {
					at = append(at, i)
				}
			}
			x.Records[at[0]], x.Records[at[1]] = x.Records[at[1]], x.Records[at[0]]
			refused(fmt.Sprintf("records %d and %d swapped", at[0], at[1]), recipient, ev, x)
		}
		refused("the evidence of another session", recipient, otherEv, tr)

		x = clone()
		x.Recipient = sender.Card()
		refused("another recipient named", recipient, ev, x)

		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		fresh := &Evidence{Ephemeral: priv, Public: ev.Public}
		t.Cleanup(fresh.Release)
		refused("another private key behind the same public one", recipient, fresh, tr)
		freshPub := &Evidence{Ephemeral: priv, Public: pub}
		refused("a fresh ephemeral key", recipient, freshPub, tr)

		kpPriv, kpPub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		kp := noise.NewKeyPair(p, kpPriv, kpPub)
		t.Cleanup(kp.Close)
		fake, err := e2e.NewIdentityFrom(p, impostor{pub: recipient.Card().Static, kp: kp}, recipient.Card())
		if err != nil {
			t.Fatal(err)
		}
		refused("a fresh key behind the recipient's card", fake, ev, tr)
	})
}

// every byte of a record on c25519. A GOST Verify costs twenty times more
// and Verify is the same code on both suites, so GOST takes the clear header,
// the edges and a seeded sample
func flipped(s jcrypto.Suite, rng *rand.Rand) []int {
	var out []int
	if s == jcrypto.SuiteC25519 {
		for at := range e2e.RecordSize {
			out = append(out, at)
		}
		return out
	}
	out = []int{0, 1, 2, 3, 4, 5, 40, 200, e2e.RecordSize - 17, e2e.RecordSize - 1}
	for range 16 {
		out = append(out, rng.IntN(e2e.RecordSize))
	}
	return out
}

// the forger never holds the sender's private key, and the spy, which sees
// every agreement, sees it in the genuine run and not in the forgery, nor
// when either transcript is checked
func TestForgeryNeverUsesTheSendersKey(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		spy := NewSpy(p)
		sender, recipient := pair(t, spy, role)
		if !spy.Drew(sender.Card().Static) || !spy.Drew(recipient.Card().Static) {
			t.Fatal("the spy did not draw the identity keys")
		}

		spy.Forget()
		gen, genEv := genuine(t, spy, sender, recipient, script)
		if !spy.Used(sender.Card().Static) || !spy.Used(recipient.Card().Static) {
			t.Fatal("the spy did not see the identity keys of a genuine conversation")
		}

		spy.Forget()
		fake, fakeEv := forge(t, spy, recipient, sender.Card(), script)
		for _, c := range []struct {
			tr *Transcript
			ev *Evidence
		}{{gen, genEv}, {fake, fakeEv}} {
			if _, err := Verify(spy, recipient, c.ev, c.tr); err != nil {
				t.Fatal(err)
			}
		}
		run, err := Control(spy, recipient, sender.Card(), script)
		if err != nil {
			t.Fatal(err)
		}
		run.Close()
		if spy.Used(sender.Card().Static) {
			t.Fatal("the sender's private key reached an agreement while forging or checking")
		}
		if !spy.Used(recipient.Card().Static) {
			t.Fatal("the forgery did without the recipient's key, so the spy missed agreements")
		}
	})
}

func TestScriptRules(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		sender, recipient := pair(t, p, role)
		for _, bad := range [][]Line{
			{{FromSender: true, Dummy: true, Body: []byte("x")}},
			{{FromSender: true, Body: make([]byte, e2e.MaxBody+1)}},
			{{Body: make([]byte, e2e.MaxBody+1)}},
		} {
			if _, _, err := Genuine(p, sender, recipient, bad); !errors.Is(err, ErrScript) {
				t.Fatalf("Genuine: %v, want ErrScript", err)
			}
			if _, _, err := Forge(p, recipient, sender.Card(), bad); !errors.Is(err, ErrScript) {
				t.Fatalf("Forge: %v, want ErrScript", err)
			}
		}

		// an empty script is the handshake and the initiator's confirmation; a
		// full body fits
		for _, lines := range [][]Line{nil, {{Body: bytes.Repeat([]byte{'a'}, e2e.MaxBody)}}} {
			tr, ev := forge(t, p, recipient, sender.Card(), lines)
			checkShape(t, "forged", tr, role, lines)
			if _, err := Verify(p, recipient, ev, tr); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// a recipient that is the sender, and a forgery for oneself, are refused by
// the session
func TestNoForgeryWithOneself(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	_, recipient := pair(t, p, e2e.RoleInitiator)
	if _, _, err := Forge(p, recipient, recipient.Card(), script); !errors.Is(err, e2e.ErrSelf) {
		t.Fatalf("Forge for oneself: %v, want ErrSelf", err)
	}
}

// the recorder keeps a copy of every draw, answers for it and hands out a copy
// as evidence; release leaves only the evidence
func TestRecorderReleasesItsCopies(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{CryptoProvider: p}
	var pubs [][]byte
	for range 3 {
		priv, pub, err := r.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		priv.Release()
		pubs = append(pubs, pub)
	}
	kept := make([]*secmem.Buffer, len(r.drawn))
	for i, d := range r.drawn {
		kept[i] = d.priv
		if d.priv.Bytes() == nil {
			t.Fatalf("copy %d released with the key it copies", i)
		}
	}
	ev, err := r.evidence(pubs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Release()
	if !ev.Ephemeral.Equal(kept[1]) || !bytes.Equal(ev.Public, pubs[1]) {
		t.Fatal("the evidence is not the second draw")
	}
	if _, err := r.evidence([]byte("no such key")); err == nil {
		t.Fatal("evidence for a key never drawn")
	}
	ctx, err := jcrypto.NewContext(p, "test", []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.agree([]byte("no such key"), pubs[0], ctx); !errors.Is(err, errNoKey) {
		t.Fatalf("agreement for a key never drawn: %v", err)
	}
	r.release()
	for i, b := range kept {
		if b.Bytes() != nil {
			t.Fatalf("copy %d still held", i)
		}
	}
	if ev.Ephemeral.Bytes() == nil {
		t.Fatal("the evidence went with the copies")
	}
}

// SameShape tells apart two transcripts that differ in anything but the
// pseudorandom bytes of their records
func TestSameShapeSeesEveryDifferenceOutsideTheCiphertext(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		sender, recipient := pair(t, p, role)
		gen, _ := genuine(t, p, sender, recipient, script)
		fake, _ := forge(t, p, recipient, sender.Card(), script)
		if !SameShape(gen, fake) || !SameShape(fake, gen) {
			t.Fatal("the genuine and the forged transcript are shaped otherwise")
		}
		clone := func() *Transcript {
			c := *fake
			c.Records = make([]Record, len(fake.Records))
			for i, r := range fake.Records {
				r.Bytes, r.Body = bytes.Clone(r.Bytes), bytes.Clone(r.Body)
				c.Records[i] = r
			}
			return &c
		}
		data := func(x *Transcript, fromSender, dummy bool) int {
			for i, r := range x.Records {
				if r.Kind == KindData && r.FromSender == fromSender && r.Dummy == dummy {
					return i
				}
			}
			t.Fatal("no such record")
			return 0
		}
		for _, c := range []struct {
			name   string
			change func(x *Transcript)
		}{
			{"a record fewer", func(x *Transcript) { x.Records = x.Records[:len(x.Records)-1] }},
			{"a record more", func(x *Transcript) { x.Records = append(x.Records, x.Records[len(x.Records)-1]) }},
			{"another author", func(x *Transcript) { x.Records[3].FromSender = !x.Records[3].FromSender }},
			{"a dummy that is not", func(x *Transcript) { x.Records[data(x, true, true)].Dummy = false }},
			{"another kind", func(x *Transcript) { x.Records[0].Kind = KindKK2 }},
			{"another body", func(x *Transcript) { x.Records[data(x, true, false)].Body = []byte("the meeting is off") }},
			{"a shorter record", func(x *Transcript) { x.Records[4].Bytes = x.Records[4].Bytes[:e2e.RecordSize-1] }},
			{"another first byte of kk1", func(x *Transcript) { x.Records[0].Bytes[0] ^= 0x80 }},
			{"another first byte of kk2", func(x *Transcript) { x.Records[1].Bytes[0] ^= 0x80 }},
			{"another ratchet number of the sender", func(x *Transcript) { x.Records[data(x, true, false)].Bytes[4]++ }},
			{"another ratchet number of the recipient", func(x *Transcript) { x.Records[data(x, false, false)].Bytes[1] ^= 0x01 }},
			{"another sender", func(x *Transcript) { x.Sender = recipient.Card() }},
			{"another recipient", func(x *Transcript) { x.Recipient = sender.Card() }},
		} {
			x := clone()
			c.change(x)
			if SameShape(gen, x) || SameShape(x, gen) {
				t.Errorf("%s: same shape", c.name)
			}
		}
		// the ciphertext after the clear header is not compared
		x := clone()
		x.Records[data(x, true, false)].Bytes[5] ^= 0x01
		x.Records[0].Bytes[1] ^= 0x01
		if !SameShape(gen, x) {
			t.Fatal("a change in the ciphertext changed the shape")
		}
		if SameShape(nil, gen) || SameShape(gen, nil) {
			t.Fatal("a missing transcript has a shape")
		}
	})
}

// every forgery draws fresh ephemeral keys on both sides: two forgeries of one
// script share neither a key nor a record, as two genuine conversations would
func TestTwoForgeriesShareNoEphemeralKey(t *testing.T) {
	eachCase(t, func(t *testing.T, p jcrypto.CryptoProvider, role e2e.Role) {
		sender, recipient := pair(t, p, role)
		one, oneEv := forge(t, p, recipient, sender.Card(), script)
		two, twoEv := forge(t, p, recipient, sender.Card(), script)
		if !SameShape(one, two) {
			t.Fatal("two forgeries of one script are shaped otherwise")
		}
		size := len(sender.Card().Static)
		var keys [2][]byte
		for k, tr := range []*Transcript{one, two} {
			for _, r := range tr.Records {
				if r.FromSender && r.Kind != KindData {
					keys[k] = r.Bytes[1 : 1+size]
				}
			}
		}
		if keys[0] == nil || bytes.Equal(keys[0], keys[1]) {
			t.Fatal("the forged sender used one ephemeral key twice")
		}
		if bytes.Equal(oneEv.Public, twoEv.Public) || oneEv.Ephemeral.Equal(twoEv.Ephemeral) {
			t.Fatal("the recipient used one ephemeral key twice")
		}
		for i := range one.Records {
			if bytes.Equal(one.Records[i].Bytes, two.Records[i].Bytes) {
				t.Fatalf("record %d is the same in both forgeries", i)
			}
		}
	})
}
