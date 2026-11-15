package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/lab/scenario"
)

// the command runs both roles of the recipient on the suite, prints the
// verdicts with the assumption and writes them to deny-<suite>-<time>.json
// with the fields a reader needs to check the claim
func TestDenySetWritesItsReport(t *testing.T) {
	for _, name := range []string{"c25519", "gost"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var out, errOut bytes.Buffer
			status := command([]string{"-set", "deny", "-suite", name, "-rev", "abc", "-out", dir}, &out, &errOut)
			if status != 0 || errOut.Len() != 0 {
				t.Fatalf("status %d, stderr %q", status, errOut.String())
			}
			names := reports(t, dir)
			if len(names) != 1 || !regexp.MustCompile(`^deny-`+name+`-\d{8}-\d{6}\.json$`).MatchString(names[0]) {
				t.Fatalf("reports %v, want one deny-%s-<time>.json", names, name)
			}
			path := filepath.Join(dir, names[0])
			for _, line := range []string{"report: " + path, "assumption: " + denyAssumption, "claim: " + denyClaim} {
				if !strings.Contains(out.String(), line) {
					t.Errorf("the output lacks %q:\n%s", line, out.String())
				}
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"set", "suite", "rev", "claim", "assumption", "roles"} {
				if _, ok := fields[k]; !ok {
					t.Errorf("no field %s", k)
				}
			}
			for _, row := range fields["roles"].([]any) {
				for _, k := range []string{"recipient_role", "genuine_verified", "forged_verified", "structure_equal",
					"control_rejected", "control_refused_at_record", "sender_private_key_used", "sender_private_key_seen_in_genuine",
					"recipient_private_key_seen_in_forgery", "genuine", "forged"} {
					if _, ok := row.(map[string]any)[k]; !ok {
						t.Errorf("a role without %s", k)
					}
				}
			}

			var rep denyReport
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Set != "deny" || rep.Suite != name || rep.Rev != "abc" || rep.Claim != denyClaim || rep.Assumption != denyAssumption {
				t.Fatalf("report head %+v", rep)
			}
			if len(rep.Roles) != 2 || rep.Roles[0].RecipientRole != "initiator" || rep.Roles[1].RecipientRole != "responder" {
				t.Fatalf("roles %+v", rep.Roles)
			}
			for _, r := range rep.Roles {
				if err := r.holds(); err != nil {
					t.Errorf("recipient %s: %v", r.RecipientRole, err)
				}
				if r.SenderMessagesInGenuine != 2 || r.SenderMessagesInForged != 2 {
					t.Errorf("recipient %s read %d and %d messages of the sender, want 2 and 2", r.RecipientRole, r.SenderMessagesInGenuine, r.SenderMessagesInForged)
				}
				checkDenyRecords(t, r)
			}
		})
	}
}

// kk1 by the initiator, kk2 by the responder, the initiator's confirming dummy
// when the script opens with the responder, then the script; every record 392
// bytes in hex, the forged ones as long as the genuine ones and not the same
func checkDenyRecords(t *testing.T, r denyRow) {
	t.Helper()
	ini, resp := "recipient", "sender"
	if r.RecipientRole == "responder" {
		ini, resp = resp, ini
	}
	want := []denyRecord{{From: ini, Kind: "kk1"}, {From: resp, Kind: "kk2"}}
	if ini == "recipient" {
		want = append(want, denyRecord{From: ini, Kind: "data", Dummy: true})
	}
	for _, l := range denyScript {
		from := "recipient"
		if l.FromSender {
			from = "sender"
		}
		want = append(want, denyRecord{From: from, Kind: "data", Dummy: l.Dummy, Body: string(l.Body)})
	}
	for _, records := range [][]denyRecord{r.GenuineRecords, r.ForgedRecords} {
		if len(records) != len(want) {
			t.Fatalf("recipient %s: %d records, want %d", r.RecipientRole, len(records), len(want))
		}
		for i, rec := range records {
			w := want[i]
			raw, err := hex.DecodeString(rec.Hex)
			if err != nil || rec.From != w.From || rec.Kind != w.Kind || rec.Dummy != w.Dummy || rec.Body != w.Body ||
				rec.Size != e2e.RecordSize || len(raw) != e2e.RecordSize {
				t.Fatalf("recipient %s, record %d: %+v, want %+v of %d bytes", r.RecipientRole, i, rec, w, e2e.RecordSize)
			}
		}
	}
	for i := range r.GenuineRecords {
		if r.GenuineRecords[i].Hex == r.ForgedRecords[i].Hex {
			t.Fatalf("recipient %s: record %d is the same in both transcripts", r.RecipientRole, i)
		}
	}
}

// keeps the bytes of every secret the provider hands out and the public half
// of every key pair
type secretKeeper struct {
	jcrypto.CryptoProvider
	mu      sync.Mutex
	secrets [][]byte
	publics [][]byte
}

func (k *secretKeeper) keep(b *secmem.Buffer) {
	if b == nil {
		return
	}
	k.mu.Lock()
	k.secrets = append(k.secrets, bytes.Clone(b.Bytes()))
	k.mu.Unlock()
}

func (k *secretKeeper) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := k.CryptoProvider.GenerateEphemeral()
	k.keep(priv)
	k.mu.Lock()
	k.publics = append(k.publics, bytes.Clone(pub))
	k.mu.Unlock()
	return priv, pub, err
}

func (k *secretKeeper) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := k.CryptoProvider.Agree(priv, pub, ctx)
	k.keep(b)
	return b, err
}

func (k *secretKeeper) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := k.CryptoProvider.MixKey(chain, secret, ctx)
	k.keep(b)
	return b, err
}

func (k *secretKeeper) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	b, err := k.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	k.keep(b)
	return b, err
}

// the identities and transcripts of a run, kept by steps that pass every call
// on to the real ones
type denyRun struct {
	mu                 sync.Mutex
	senders, recipient []e2e.Card
	genuine, forged    []*scenario.Transcript
}

func (r *denyRun) steps() denySteps {
	return denySteps{
		identities: func(p jcrypto.CryptoProvider, role e2e.Role) (*e2e.Identity, *e2e.Identity, error) {
			s, rc, err := scenario.Identities(p, role)
			if err == nil {
				r.mu.Lock()
				r.senders, r.recipient = append(r.senders, s.Card()), append(r.recipient, rc.Card())
				r.mu.Unlock()
			}
			return s, rc, err
		},
		genuine: func(p jcrypto.CryptoProvider, s, rc *e2e.Identity, lines []scenario.Line) (*scenario.Transcript, *scenario.Evidence, error) {
			t, ev, err := scenario.Genuine(p, s, rc, lines)
			r.mu.Lock()
			r.genuine = append(r.genuine, t)
			r.mu.Unlock()
			return t, ev, err
		},
		forge: func(p jcrypto.CryptoProvider, rc *e2e.Identity, s e2e.Card, lines []scenario.Line) (*scenario.Transcript, *scenario.Evidence, error) {
			t, ev, err := scenario.Forge(p, rc, s, lines)
			r.mu.Lock()
			r.forged = append(r.forged, t)
			r.mu.Unlock()
			return t, ev, err
		},
		control: scenario.Control,
	}
}

// the report is closed: these fields and no other, each with a value the test
// can account for from the public cards and the transcripts of the run
var (
	denyHead      = []string{"set", "suite", "rev", "claim", "assumption", "roles"}
	denyRowFields = []string{"recipient_role", "sender_card_hash", "recipient_card_hash", "genuine_verified", "forged_verified",
		"structure_equal", "control_rejected", "control_refused_at_record", "sender_private_key_used",
		"sender_private_key_seen_in_genuine", "recipient_private_key_seen_in_forgery", "genuine", "forged",
		"sender_messages_read_from_genuine", "sender_messages_read_from_forged"}
	denyRecordFields = []string{"from", "kind", "dummy", "size", "body", "hex"}
)

func onlyFields(t *testing.T, what string, obj map[string]any, allowed []string, required ...string) {
	t.Helper()
	for k := range obj {
		if !slices.Contains(allowed, k) {
			t.Fatalf("%s carries the field %s", what, k)
		}
	}
	for _, k := range required {
		if _, ok := obj[k]; !ok {
			t.Fatalf("%s lacks the field %s", what, k)
		}
	}
}

// every value of the report is a verdict, a count, a fixed text, a card hash
// recomputed from the public card or a record of the run in hex
func checkClosedReport(t *testing.T, raw []byte, p jcrypto.CryptoProvider, run *denyRun) {
	t.Helper()
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	var rep denyReport
	if err := strict.Decode(&rep); err != nil {
		t.Fatalf("strict decode: %v", err)
	}

	var top map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		t.Fatal(err)
	}
	onlyFields(t, "the report", top, denyHead, denyHead...)
	for k, want := range map[string]string{"set": "deny", "suite": p.Suite().String(), "rev": "abc", "claim": denyClaim, "assumption": denyAssumption} {
		if top[k] != want {
			t.Fatalf("%s is %v, want %q", k, top[k], want)
		}
	}
	rows, _ := top["roles"].([]any)
	if len(rows) != 2 || len(run.genuine) != 2 || len(run.forged) != 2 || len(run.senders) != 2 {
		t.Fatalf("%d rows for %d runs", len(rows), len(run.genuine))
	}
	for i, x := range rows {
		row, _ := x.(map[string]any)
		what := fmt.Sprintf("row %d", i)
		onlyFields(t, what, row, denyRowFields, denyRowFields...)
		if row["recipient_role"] != []string{"initiator", "responder"}[i] {
			t.Fatalf("%s: role %v", what, row["recipient_role"])
		}
		for k, card := range map[string]e2e.Card{"sender_card_hash": run.senders[i], "recipient_card_hash": run.recipient[i]} {
			h, err := e2e.CardHash(p, card)
			if err != nil {
				t.Fatal(err)
			}
			if row[k] != hex.EncodeToString(h) {
				t.Fatalf("%s: %s is not the hash of the public card", what, k)
			}
		}
		for k, want := range map[string]json.Number{"control_refused_at_record": "0", "sender_messages_read_from_genuine": "2", "sender_messages_read_from_forged": "2"} {
			if row[k] != want {
				t.Fatalf("%s: %s is %v, want %s", what, k, row[k], want)
			}
		}
		for _, k := range []string{"genuine_verified", "forged_verified", "structure_equal", "control_rejected",
			"sender_private_key_used", "sender_private_key_seen_in_genuine", "recipient_private_key_seen_in_forgery"} {
			if _, ok := row[k].(bool); !ok {
				t.Fatalf("%s: %s is %v, not a verdict", what, k, row[k])
			}
		}
		for k, tr := range map[string]*scenario.Transcript{"genuine": run.genuine[i], "forged": run.forged[i]} {
			records, _ := row[k].([]any)
			if len(records) != len(tr.Records) {
				t.Fatalf("%s: %d %s records, the run had %d", what, len(records), k, len(tr.Records))
			}
			for j, y := range records {
				rec, _ := y.(map[string]any)
				r := tr.Records[j]
				where := fmt.Sprintf("%s, %s record %d", what, k, j)
				onlyFields(t, where, rec, denyRecordFields, "from", "kind", "size", "hex")
				if rec["hex"] != hex.EncodeToString(r.Bytes) || rec["size"] != json.Number(fmt.Sprint(e2e.RecordSize)) {
					t.Fatalf("%s is not the record of the run", where)
				}
				if body, ok := rec["body"]; ok && body != string(r.Body) || !ok && len(r.Body) != 0 {
					t.Fatalf("%s claims the body %v, the run %q", where, body, r.Body)
				}
				if dummy, ok := rec["dummy"]; ok && dummy != true || ok != r.Dummy {
					t.Fatalf("%s: dummy %v, the run %v", where, dummy, r.Dummy)
				}
				if !slices.Contains([]any{"sender", "recipient"}, rec["from"]) || !slices.Contains([]any{"kk1", "kk2", "data"}, rec["kind"]) {
					t.Fatalf("%s: from %v, kind %v", where, rec["from"], rec["kind"])
				}
			}
		}
	}
}

// every piece of a secret long enough to matter, in the encodings a report
// could carry it in: hex of any 8 bytes, base64 of any 9 in both alphabets
func secretPieces(sec []byte) []string {
	var out []string
	for at := 0; at+8 <= len(sec); at++ {
		h := hex.EncodeToString(sec[at : at+8])
		out = append(out, h, strings.ToUpper(h))
	}
	for at := 0; at+9 <= len(sec); at++ {
		out = append(out, base64.StdEncoding.EncodeToString(sec[at:at+9]), base64.URLEncoding.EncodeToString(sec[at:at+9]))
	}
	if len(sec) < 9 {
		out = append(out, hex.EncodeToString(sec), base64.RawStdEncoding.EncodeToString(sec), base64.RawURLEncoding.EncodeToString(sec))
	}
	return out
}

// no piece of a secret of the run, private keys and every derived key alike,
// appears in the report, and the report holds nothing but what the test can
// account for. The public halves of the ephemeral keys do appear, in the
// handshake records, which shows the search finds what is there
func TestDenyReportHoldsNoKeyBytes(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			base, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			k := &secretKeeper{CryptoProvider: base}
			run := &denyRun{}
			rep, err := runDeny(run.steps(), k, "abc")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := write(io.Discard, dir, "deny", rep); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "deny.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkClosedReport(t, raw, base, run)

			text := string(raw)
			if len(k.secrets) < 100 {
				t.Fatalf("only %d secrets kept, the provider was bypassed", len(k.secrets))
			}
			for _, sec := range k.secrets {
				for _, piece := range secretPieces(sec) {
					if strings.Contains(text, piece) {
						t.Fatalf("the report holds a piece of a secret of %d bytes", len(sec))
					}
				}
			}
			found := 0
			for _, pub := range k.publics {
				if strings.Contains(text, hex.EncodeToString(pub)) {
					found++
				}
			}
			if found < 4 {
				t.Fatalf("%d public keys found in the report, want the ephemeral keys of the handshakes", found)
			}
		})
	}
}

// the search finds a piece of a key however it is written
func TestSecretPiecesFindAKeyInAnyEncoding(t *testing.T) {
	sec := make([]byte, 32)
	for i := range sec {
		sec[i] = byte(7*i + 3)
	}
	pieces := secretPieces(sec)
	for _, leak := range []string{
		hex.EncodeToString(sec[16:]),
		strings.ToUpper(hex.EncodeToString(sec[5:15])),
		base64.RawStdEncoding.EncodeToString(sec),
		base64.StdEncoding.EncodeToString(sec[1:12]),
		base64.RawURLEncoding.EncodeToString(sec[20:]),
	} {
		found := false
		for _, piece := range pieces {
			found = found || strings.Contains(`{"x": "`+leak+`"}`, piece)
		}
		if !found {
			t.Errorf("%s is not found", leak)
		}
	}
}

func TestDenyVerdicts(t *testing.T) {
	good := denyRow{GenuineVerified: true, ForgedVerified: true, StructureEqual: true, ControlRejected: true,
		SenderKeySeenInGenuine: true, RecipientKeySeenInForgery: true}
	if err := good.holds(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(r *denyRow){
		func(r *denyRow) { r.GenuineVerified = false },
		func(r *denyRow) { r.ForgedVerified = false },
		func(r *denyRow) { r.StructureEqual = false },
		func(r *denyRow) { r.ControlRejected = false },
		func(r *denyRow) { r.ControlRefusedAt = -1 },
		func(r *denyRow) { r.SenderPrivateKeyUsed = true },
		func(r *denyRow) { r.SenderKeySeenInGenuine = false },
		func(r *denyRow) { r.RecipientKeySeenInForgery = false },
	} {
		r := good
		bad(&r)
		if r.holds() == nil {
			t.Fatalf("%+v holds", r)
		}
	}
}

// every verdict is computed: a step that breaks it shows in the report, in
// both rows, and the command exits with 1 after writing it
func TestDenyVerdictFollowsTheRun(t *testing.T) {
	flip := func(tr *scenario.Transcript) {
		last := &tr.Records[len(tr.Records)-1]
		last.Bytes = bytes.Clone(last.Bytes)
		last.Bytes[100] ^= 0x01
	}
	for _, c := range []struct {
		name  string
		steps func(denySteps) denySteps
		field string
		want  any
	}{
		{"a forgery with the sender's key", func(s denySteps) denySteps {
			var mu sync.Mutex
			var sender *e2e.Identity
			identities := s.identities
			s.identities = func(p jcrypto.CryptoProvider, role e2e.Role) (*e2e.Identity, *e2e.Identity, error) {
				snd, rc, err := identities(p, role)
				mu.Lock()
				sender = snd
				mu.Unlock()
				return snd, rc, err
			}
			s.forge = func(p jcrypto.CryptoProvider, rc *e2e.Identity, _ e2e.Card, lines []scenario.Line) (*scenario.Transcript, *scenario.Evidence, error) {
				mu.Lock()
				defer mu.Unlock()
				return scenario.Genuine(p, sender, rc, lines)
			}
			return s
		}, "sender_private_key_used", true},
		{"identities the spy never drew", func(s denySteps) denySteps {
			identities := s.identities
			s.identities = func(p jcrypto.CryptoProvider, role e2e.Role) (*e2e.Identity, *e2e.Identity, error) {
				return identities(p.(*scenario.Spy).CryptoProvider, role)
			}
			return s
		}, "recipient_private_key_seen_in_forgery", false},
		{"a genuine record changed", func(s denySteps) denySteps {
			s.genuine = func(p jcrypto.CryptoProvider, snd, rc *e2e.Identity, lines []scenario.Line) (*scenario.Transcript, *scenario.Evidence, error) {
				tr, ev, err := scenario.Genuine(p, snd, rc, lines)
				if err == nil {
					flip(tr)
				}
				return tr, ev, err
			}
			return s
		}, "genuine_verified", false},
		{"a forged record changed", func(s denySteps) denySteps {
			s.forge = func(p jcrypto.CryptoProvider, rc *e2e.Identity, snd e2e.Card, lines []scenario.Line) (*scenario.Transcript, *scenario.Evidence, error) {
				tr, ev, err := scenario.Forge(p, rc, snd, lines)
				if err == nil {
					flip(tr)
				}
				return tr, ev, err
			}
			return s
		}, "forged_verified", false},
		{"a forgery of other lines", func(s denySteps) denySteps {
			s.forge = func(p jcrypto.CryptoProvider, rc *e2e.Identity, snd e2e.Card, lines []scenario.Line) (*scenario.Transcript, *scenario.Evidence, error) {
				other := slices.Clone(lines)
				other[0].Body = []byte("the meeting is off")
				return scenario.Forge(p, rc, snd, other)
			}
			return s
		}, "structure_equal", false},
		{"a control with the recipient's own key", func(s denySteps) denySteps {
			s.control = func(p jcrypto.CryptoProvider, rc *e2e.Identity, snd e2e.Card, lines []scenario.Line) (*scenario.ControlRun, error) {
				tr, ev, err := scenario.Forge(p, rc, snd, lines)
				if err != nil {
					return nil, err
				}
				_, refusal := scenario.Verify(p, rc, ev, tr)
				return &scenario.ControlRun{Transcript: tr, Evidence: ev, Refusal: refusal}, nil
			}
			return s
		}, "control_rejected", false},
		{"a control refused by its name", func(s denySteps) denySteps {
			control := s.control
			s.control = func(p jcrypto.CryptoProvider, rc *e2e.Identity, snd e2e.Card, lines []scenario.Line) (*scenario.ControlRun, error) {
				run, err := control(p, rc, snd, lines)
				if err != nil {
					return nil, err
				}
				_, run.Refusal = scenario.Verify(p, rc, run.Evidence, run.Transcript)
				return run, nil
			}
			return s
		}, "control_refused_at_record", json.Number("-1")},
	} {
		t.Run(c.name, func(t *testing.T) {
			fixture := newDenyVerdictFixture(t)
			dir := t.TempDir()
			var out, errOut bytes.Buffer
			status := deny(c.steps(fixture.steps()), "c25519", "abc", dir, &out, &errOut)
			fixture.close()
			if status != 1 {
				t.Fatalf("status %d, stderr %q", status, errOut.String())
			}
			if strings.Count(errOut.String(), "deny: recipient ") != 2 {
				t.Fatalf("stderr %q, want both roles refused", errOut.String())
			}
			names := reports(t, dir)
			if len(names) != 1 {
				t.Fatalf("reports %v", names)
			}
			raw, err := os.ReadFile(filepath.Join(dir, names[0]))
			if err != nil {
				t.Fatal(err)
			}
			var top struct {
				Roles []map[string]any `json:"roles"`
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&top); err != nil {
				t.Fatal(err)
			}
			if len(top.Roles) != 2 {
				t.Fatalf("%d rows", len(top.Roles))
			}
			for _, row := range top.Roles {
				if row[c.field] != c.want {
					t.Fatalf("recipient %v: %s is %v, want %v", row["recipient_role"], c.field, row[c.field], c.want)
				}
			}
		})
	}
	exercisePreparedDenyControls(t)
}

type denyFixturePair struct {
	private *secmem.Buffer
	public  []byte
}

type denyFixtureDraws struct {
	jcrypto.CryptoProvider
	pairs                     []*denyFixturePair
	next, requests            int
	issued                    []*secmem.Buffer
	fallback                  bool
	failure                   error
	failureAt                 int
	agreements, noiseDH, aead int
}

func (d *denyFixtureDraws) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	d.requests++
	if d.failure != nil && d.next == d.failureAt {
		return nil, nil, d.failure
	}
	if d.next < len(d.pairs) {
		pair := d.pairs[d.next]
		if pair.private == nil {
			return nil, nil, errors.New("deny fixture: pair already transferred")
		}
		private := pair.private
		pair.private = nil
		d.next++
		d.issued = append(d.issued, private)
		return private, bytes.Clone(pair.public), nil
	}
	if !d.fallback {
		return nil, nil, errors.New("deny fixture: unexpected candidate draw")
	}
	if len(d.issued) != 1 || d.issued[0].Bytes() == nil {
		return nil, nil, errors.New("deny fixture: reserved control candidate was rejected")
	}
	return d.CryptoProvider.GenerateEphemeral()
}

func (d *denyFixtureDraws) Agree(private *secmem.Buffer, public []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	d.agreements++
	return d.CryptoProvider.Agree(private, public, ctx)
}

func (d *denyFixtureDraws) NoiseDH(private *secmem.Buffer, public []byte) (*secmem.Buffer, error) {
	d.noiseDH++
	return d.CryptoProvider.NoiseDH(private, public)
}

func (d *denyFixtureDraws) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	d.aead++
	return d.CryptoProvider.NewAEAD(key)
}

type denyFixtureRole struct {
	role              e2e.Role
	sender, recipient e2e.Card
	candidates        []*denyFixturePair
	controlCalled     bool
	controlDraws      *denyFixtureDraws
	controlError      error
}

type denyVerdictFixture struct {
	t              *testing.T
	pairs          []*denyFixturePair
	observed       []*secmem.Buffer
	roles          map[*e2e.Identity]*denyFixtureRole
	failingRole    e2e.Role
	candidateError error
	closed         sync.Once
	done           bool
}

func newDenyVerdictFixture(t *testing.T) *denyVerdictFixture {
	t.Helper()
	f := &denyVerdictFixture{t: t, roles: make(map[*e2e.Identity]*denyFixtureRole)}
	t.Cleanup(f.close)
	return f
}

func (f *denyVerdictFixture) releaseOwned() {
	for _, pair := range f.pairs {
		if pair.private != nil {
			pair.private.Release()
			pair.private = nil
		}
	}
}

func (f *denyVerdictFixture) close() {
	f.closed.Do(func() {
		f.done = true
		f.releaseOwned()
		for _, buffer := range f.observed {
			if buffer.Bytes() != nil {
				f.t.Error("deny fixture: transferred key survived its production owner")
			}
		}
	})
}

func (f *denyVerdictFixture) steps() denySteps {
	steps := scenarioSteps
	steps.identities, steps.control = f.identities, f.control
	return steps
}

func (f *denyVerdictFixture) drawPairs(p jcrypto.CryptoProvider, count int) ([]*denyFixturePair, error) {
	pairs := make([]*denyFixturePair, 0, count)
	for range count {
		private, public, err := p.GenerateEphemeral()
		if private != nil {
			pair := &denyFixturePair{private: private, public: bytes.Clone(public)}
			f.pairs = append(f.pairs, pair)
			f.observed = append(f.observed, private)
			pairs = append(pairs, pair)
		}
		if err != nil {
			f.releaseOwned()
			return nil, err
		}
		if private == nil || private.Len() == 0 || len(public) != p.HandshakeInfo().PublicKeySize {
			f.releaseOwned()
			return nil, errors.New("deny fixture: invalid generated pair")
		}
	}
	slices.SortFunc(pairs, func(a, b *denyFixturePair) int { return bytes.Compare(a.public, b.public) })
	for i := 1; i < len(pairs); i++ {
		if bytes.Equal(pairs[i-1].public, pairs[i].public) {
			f.releaseOwned()
			return nil, errors.New("deny fixture: duplicate generated public key")
		}
	}
	return pairs, nil
}

func (f *denyVerdictFixture) identities(p jcrypto.CryptoProvider, role e2e.Role) (*e2e.Identity, *e2e.Identity, error) {
	if f.done || p == nil || p.Suite() != jcrypto.SuiteC25519 && p.Suite() != jcrypto.SuiteGOST || role != e2e.RoleInitiator && role != e2e.RoleResponder {
		return nil, nil, errors.New("deny fixture: unsupported identity request")
	}
	for _, previous := range f.roles {
		if previous.role == role {
			return nil, nil, errors.New("deny fixture: duplicate role request")
		}
	}
	count := 3
	if role == f.failingRole {
		count = 66
		if f.candidateError != nil {
			count = 4
		}
	}
	pairs, err := f.drawPairs(p, count)
	if err != nil {
		return nil, nil, err
	}
	var sender, recipient *denyFixturePair
	var candidates []*denyFixturePair
	if role == f.failingRole {
		if role == e2e.RoleInitiator {
			recipient, sender, candidates = pairs[0], pairs[1], pairs[2:]
		} else {
			recipient, sender, candidates = pairs[count-1], pairs[count-2], pairs[:count-2]
		}
	} else {
		sender, recipient, candidates = pairs[2], pairs[0], pairs[1:2]
		if role == e2e.RoleResponder {
			sender, recipient = pairs[0], pairs[2]
		}
	}
	draws := &denyFixtureDraws{CryptoProvider: p, pairs: []*denyFixturePair{sender, recipient}}
	s, r, err := scenario.Identities(draws, role)
	if err != nil {
		if s != nil {
			s.Close()
		}
		if r != nil {
			r.Close()
		}
		f.releaseOwned()
		return nil, nil, err
	}
	if s == nil || r == nil || draws.requests != 2 || draws.next != 2 {
		if s != nil {
			s.Close()
		}
		if r != nil {
			r.Close()
		}
		f.releaseOwned()
		return nil, nil, errors.New("deny fixture: identities did not consume one actual pair")
	}
	senderCard, recipientCard := s.Card(), r.Card()
	if !bytes.Equal(senderCard.Static, sender.public) || !bytes.Equal(recipientCard.Static, recipient.public) || senderCard.Suite != p.Suite() || recipientCard.Suite != p.Suite() || senderCard.Mailbox != scenario.Mailbox || recipientCard.Mailbox != scenario.Mailbox || senderCard.Queue != [e2e.QueueSize]byte{1} || recipientCard.Queue != [e2e.QueueSize]byte{2} || (bytes.Compare(recipientCard.Static, senderCard.Static) < 0) != (role == e2e.RoleInitiator) {
		s.Close()
		r.Close()
		f.releaseOwned()
		return nil, nil, errors.New("deny fixture: identities changed their actual role or cards")
	}
	f.roles[r] = &denyFixtureRole{role: role, sender: senderCard, recipient: recipientCard, candidates: candidates}
	return s, r, nil
}

func (f *denyVerdictFixture) control(p jcrypto.CryptoProvider, recipient *e2e.Identity, sender e2e.Card, lines []scenario.Line) (*scenario.ControlRun, error) {
	record := f.roles[recipient]
	if f.done || p == nil || record == nil || record.controlCalled || !bytes.Equal(record.sender.Bytes(), sender.Bytes()) || !bytes.Equal(record.recipient.Bytes(), recipient.Card().Bytes()) {
		return nil, errors.New("deny fixture: unexpected control request")
	}
	record.controlCalled = true
	failing := record.role == f.failingRole
	for _, candidate := range record.candidates {
		initiates := bytes.Compare(candidate.public, sender.Static) < 0
		if bytes.Equal(candidate.public, recipient.Card().Static) || bytes.Equal(candidate.public, sender.Static) || (initiates == (record.role == e2e.RoleInitiator)) == failing {
			return nil, errors.New("deny fixture: candidate has the wrong prepared role")
		}
	}
	draws := &denyFixtureDraws{CryptoProvider: p, pairs: record.candidates, fallback: !failing}
	if failing && f.candidateError != nil {
		draws.failure, draws.failureAt = f.candidateError, 2
	}
	record.controlDraws = draws
	run, err := scenario.Control(draws, recipient, sender, lines)
	record.controlError = err
	if failing {
		validError := err != nil && err.Error() == "scenario: no fresh key took the recipient's role"
		want := 64
		if f.candidateError != nil {
			validError, want = errors.Is(err, f.candidateError), 2
		}
		requests := want
		if f.candidateError != nil {
			requests++
		}
		valid := run == nil && validError && !errors.Is(err, scenario.ErrMismatch) && scenario.RefusedAt(err) == -1 && draws.requests == requests && draws.next == want && len(draws.issued) == want && draws.agreements == 0 && draws.noiseDH == 0 && draws.aead == 0
		for _, buffer := range draws.issued {
			valid = valid && buffer.Bytes() == nil
		}
		if run != nil {
			run.Close()
		}
		if !valid {
			return nil, errors.New("deny fixture: bounded control failure did not follow its real path")
		}
		return nil, err
	}
	if err != nil {
		if run != nil {
			run.Close()
		}
		return nil, err
	}
	if run == nil || run.Stand == nil || run.Transcript == nil || run.Evidence == nil || draws.next != 1 || len(draws.issued) != 1 {
		if run != nil {
			run.Close()
		}
		return nil, errors.New("deny fixture: control did not use its single reserved pair")
	}
	stand, own := run.Stand.Card(), recipient.Card()
	if !bytes.Equal(stand.Static, record.candidates[0].public) || stand.Suite != own.Suite || stand.Mailbox != own.Mailbox || stand.Queue != own.Queue || (bytes.Compare(stand.Static, sender.Static) < 0) != (record.role == e2e.RoleInitiator) || !bytes.Equal(run.Transcript.Sender.Bytes(), sender.Bytes()) || !bytes.Equal(run.Transcript.Recipient.Bytes(), stand.Bytes()) {
		run.Close()
		return nil, errors.New("deny fixture: actual control stand or transcript changed")
	}
	if _, err := scenario.Verify(p, run.Stand, run.Evidence, run.Transcript); err != nil {
		run.Close()
		return nil, err
	}
	named := *run.Transcript
	named.Recipient = own
	_, refusal := scenario.Verify(p, recipient, run.Evidence, &named)
	if !errors.Is(refusal, scenario.ErrMismatch) || scenario.RefusedAt(refusal) != 0 || !run.Rejected() || run.RefusedAt() != 0 {
		run.Close()
		return nil, errors.New("deny fixture: control did not fail at the actual recipient record")
	}
	return run, nil
}

type denyFixtureGenerationFailure struct {
	jcrypto.CryptoProvider
	calls int
	cause error
}

func (p *denyFixtureGenerationFailure) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	p.calls++
	if p.calls == 2 {
		return nil, nil, p.cause
	}
	return p.CryptoProvider.GenerateEphemeral()
}

func exercisePreparedDenyControls(t *testing.T) {
	t.Helper()
	for _, name := range []string{"c25519", "gost"} {
		fixture := newDenyVerdictFixture(t)
		dir := t.TempDir()
		var out, errOut bytes.Buffer
		status := deny(fixture.steps(), name, "abc", dir, &out, &errOut)
		fixture.close()
		if status != 0 || errOut.Len() != 0 || len(fixture.roles) != 2 {
			t.Fatalf("prepared %s deny: status %d, stderr %q", name, status, errOut.String())
		}
		names := reports(t, dir)
		if len(names) != 1 {
			t.Fatalf("prepared %s reports %v", name, names)
		}
		raw, err := os.ReadFile(filepath.Join(dir, names[0]))
		if err != nil {
			t.Fatal(err)
		}
		var report denyReport
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		if report.Set != "deny" || report.Suite != name || report.Rev != "abc" || report.Claim != denyClaim || report.Assumption != denyAssumption || len(report.Roles) != 2 || report.Roles[0].RecipientRole != "initiator" || report.Roles[1].RecipientRole != "responder" {
			t.Fatal("prepared deny report lost its actual head or roles")
		}
		for _, row := range report.Roles {
			if err := row.holds(); err != nil || row.ControlRefusedAt != 0 || row.SenderMessagesInGenuine != 2 || row.SenderMessagesInForged != 2 {
				t.Fatalf("prepared %s/%s verdict: %v", name, row.RecipientRole, err)
			}
			checkDenyRecords(t, row)
		}
		for _, role := range []e2e.Role{e2e.RoleInitiator, e2e.RoleResponder} {
			exerciseDenyControlFailure(t, name, role, nil)
		}
		exerciseDenyControlFailure(t, name, e2e.RoleResponder, errors.New("deny fixture: candidate generation failed"))
		chosen, err := suite.Parse(name)
		if err != nil {
			t.Fatal(err)
		}
		base, err := suite.New(chosen)
		if err != nil {
			t.Fatal(err)
		}
		bootstrap := newDenyVerdictFixture(t)
		cause := errors.New("deny fixture: bootstrap generation failed")
		failed := &denyFixtureGenerationFailure{CryptoProvider: base, cause: cause}
		sender, recipient, err := bootstrap.identities(failed, e2e.RoleInitiator)
		if sender != nil || recipient != nil || !errors.Is(err, cause) || failed.calls != 2 || len(bootstrap.observed) != 1 || bootstrap.observed[0].Bytes() != nil {
			if sender != nil {
				sender.Close()
			}
			if recipient != nil {
				recipient.Close()
			}
			t.Fatal("bootstrap failure did not release its partial real draw")
		}
		bootstrap.close()
		unused := newDenyVerdictFixture(t)
		sender, recipient, err = unused.identities(base, e2e.RoleInitiator)
		if err != nil {
			t.Fatal(err)
		}
		reserved := unused.roles[recipient].candidates[0].private
		if reserved == nil || reserved.Bytes() == nil {
			t.Fatal("unused real control reserve was not fixture-owned")
		}
		sender.Close()
		recipient.Close()
		unused.close()
		if reserved.Bytes() != nil {
			t.Fatal("unused real control reserve survived fixture cleanup")
		}
	}
}

func exerciseDenyControlFailure(t *testing.T, name string, role e2e.Role, cause error) {
	t.Helper()
	fixture := newDenyVerdictFixture(t)
	fixture.failingRole, fixture.candidateError = role, cause
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	status := deny(fixture.steps(), name, "abc", dir, &out, &errOut)
	fixture.close()
	wantError := "scenario: no fresh key took the recipient's role"
	if cause != nil {
		wantError = cause.Error()
	}
	wantRoles := 1
	if role == e2e.RoleResponder {
		wantRoles = 2
	}
	if status != 1 || out.Len() != 0 || errOut.String() != fmt.Sprintf("deny: recipient %s: %s\n", role.String(), wantError) || len(reports(t, dir)) != 0 || len(fixture.roles) != wantRoles {
		t.Fatalf("prepared %s/%s setup failure: status %d, stdout %q, stderr %q", name, role, status, out.String(), errOut.String())
	}
	for _, record := range fixture.roles {
		if !record.controlCalled || record.controlDraws == nil {
			t.Fatal("prepared failure skipped its actual control")
		}
		if record.role == role {
			if record.controlError == nil || record.controlError.Error() != wantError {
				t.Fatal("prepared failure replaced its actual control error")
			}
		} else if record.controlError != nil {
			t.Fatal("an earlier genuine control failed before the intended role")
		}
	}
}

func TestDenySetRefusesAnUnknownSuite(t *testing.T) {
	var out, errOut bytes.Buffer
	if status := command([]string{"-set", "deny", "-suite", "rsa", "-out", t.TempDir()}, &out, &errOut); status != 2 {
		t.Fatalf("status %d, stderr %q", status, errOut.String())
	}
}
