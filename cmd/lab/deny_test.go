package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
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
					"control_rejected", "sender_private_key_used", "sender_private_key_seen_in_genuine", "genuine", "forged"} {
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

// no secret of the run, private keys and every derived key alike, appears in
// the report in hex or base64. The public halves of the ephemeral keys do, in
// the handshake records, which shows the search finds what is there
func TestDenyReportHoldsNoKeyBytes(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			base, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			k := &secretKeeper{CryptoProvider: base}
			rep, err := runDeny(k, "abc")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			if len(k.secrets) < 100 {
				t.Fatalf("only %d secrets kept, the provider was bypassed", len(k.secrets))
			}
			for _, sec := range k.secrets {
				for _, enc := range []string{hex.EncodeToString(sec), strings.ToUpper(hex.EncodeToString(sec)), base64.StdEncoding.EncodeToString(sec)} {
					if strings.Contains(text, enc) {
						t.Fatalf("the report holds a secret of %d bytes", len(sec))
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

func TestDenyVerdicts(t *testing.T) {
	good := denyRow{GenuineVerified: true, ForgedVerified: true, StructureEqual: true, ControlRejected: true, SenderKeySeenInGenuine: true}
	if err := good.holds(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(r *denyRow){
		func(r *denyRow) { r.GenuineVerified = false },
		func(r *denyRow) { r.ForgedVerified = false },
		func(r *denyRow) { r.StructureEqual = false },
		func(r *denyRow) { r.ControlRejected = false },
		func(r *denyRow) { r.SenderPrivateKeyUsed = true },
		func(r *denyRow) { r.SenderKeySeenInGenuine = false },
	} {
		r := good
		bad(&r)
		if r.holds() == nil {
			t.Fatalf("%+v holds", r)
		}
	}
}

func TestDenySetRefusesAnUnknownSuite(t *testing.T) {
	var out, errOut bytes.Buffer
	if status := command([]string{"-set", "deny", "-suite", "rsa", "-out", t.TempDir()}, &out, &errOut); status != 2 {
		t.Fatalf("status %d, stderr %q", status, errOut.String())
	}
}
