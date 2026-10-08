package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/lab/scenario"
)

const (
	denyClaim      = "a transcript together with the recipient's private keys does not prove the sender's participation to a third party"
	denyAssumption = "the judge holds no independent trusted record of who transmitted the ciphertexts"
)

// opens with the sender, so as responder the recipient sends the confirming
// dummy first
var denyScript = []scenario.Line{
	{FromSender: true, Body: []byte("the meeting moves to thursday")},
	{Body: []byte("noted")},
	{FromSender: true, Dummy: true},
	{Dummy: true},
	{FromSender: true, Body: []byte("bring the signed copy")},
}

// a demonstration, not a measurement: the verdicts for one suite and both
// roles of the recipient, with the records and no byte of a secret key
type denyReport struct {
	Set        string    `json:"set"`
	Suite      string    `json:"suite"`
	Rev        string    `json:"rev"`
	Claim      string    `json:"claim"`
	Assumption string    `json:"assumption"`
	Roles      []denyRow `json:"roles"`
}

type denyRow struct {
	RecipientRole     string `json:"recipient_role"`
	SenderCardHash    string `json:"sender_card_hash"`
	RecipientCardHash string `json:"recipient_card_hash"`
	GenuineVerified   bool   `json:"genuine_verified"`
	ForgedVerified    bool   `json:"forged_verified"`
	StructureEqual    bool   `json:"structure_equal"`
	ControlRejected   bool   `json:"control_rejected"`
	// whether the sender's private key reached an agreement while forging and
	// while checking both transcripts; the spy that tells shows it did see the
	// key in the genuine conversation
	SenderPrivateKeyUsed    bool         `json:"sender_private_key_used"`
	SenderKeySeenInGenuine  bool         `json:"sender_private_key_seen_in_genuine"`
	GenuineRecords          []denyRecord `json:"genuine"`
	ForgedRecords           []denyRecord `json:"forged"`
	SenderMessagesInGenuine int          `json:"sender_messages_read_from_genuine"`
	SenderMessagesInForged  int          `json:"sender_messages_read_from_forged"`
}

type denyRecord struct {
	From  string `json:"from"`
	Kind  string `json:"kind"`
	Dummy bool   `json:"dummy,omitempty"`
	Size  int    `json:"size"`
	Body  string `json:"body,omitempty"`
	Hex   string `json:"hex"`
}

func (r denyRow) holds() error {
	switch {
	case !r.GenuineVerified:
		return errors.New("the genuine transcript does not verify")
	case !r.ForgedVerified:
		return errors.New("the forged transcript does not verify")
	case !r.StructureEqual:
		return errors.New("the forged transcript is shaped otherwise")
	case !r.ControlRejected:
		return errors.New("a forgery without the recipient's key verified")
	case r.SenderPrivateKeyUsed:
		return errors.New("the sender's private key was used")
	case !r.SenderKeySeenInGenuine:
		return errors.New("the spy did not see the sender's key in the genuine conversation")
	}
	return nil
}

// writes the report even when a verdict fails, and then exits with 1
func deny(suiteName, rev, out string, stdout, stderr io.Writer) int {
	if rev == "unknown" {
		fmt.Fprintln(stderr, "warning: no -rev given, rows cannot be traced to a revision")
	}
	chosen, err := suite.Parse(suiteName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	p, err := suite.New(chosen)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	rep, err := runDeny(p, rev)
	if err != nil {
		fmt.Fprintf(stderr, "deny: %v\n", err)
		return 1
	}
	printDeny(stdout, rep)
	if err := write(stdout, out, "deny-"+rep.Suite+"-"+time.Now().UTC().Format("20060102-150405"), rep); err != nil {
		fmt.Fprintf(stderr, "report: %v\n", err)
		return 1
	}
	status := 0
	for _, r := range rep.Roles {
		if err := r.holds(); err != nil {
			fmt.Fprintf(stderr, "deny: recipient %s: %v\n", r.RecipientRole, err)
			status = 1
		}
	}
	return status
}

func runDeny(p jcrypto.CryptoProvider, rev string) (denyReport, error) {
	rep := denyReport{Set: "deny", Suite: p.Suite().String(), Rev: rev, Claim: denyClaim, Assumption: denyAssumption}
	for _, role := range []e2e.Role{e2e.RoleInitiator, e2e.RoleResponder} {
		row, err := denyRole(p, role)
		if err != nil {
			return rep, fmt.Errorf("recipient %v: %w", role, err)
		}
		rep.Roles = append(rep.Roles, row)
	}
	return rep, nil
}

func denyRole(p jcrypto.CryptoProvider, role e2e.Role) (denyRow, error) {
	spy := scenario.NewSpy(p)
	sender, recipient, err := scenario.Identities(spy, role)
	if err != nil {
		return denyRow{}, err
	}
	defer sender.Close()
	defer recipient.Close()
	senderKey := sender.Card().Static

	spy.Forget()
	genuine, genuineEv, err := scenario.Genuine(spy, sender, recipient, denyScript)
	if err != nil {
		return denyRow{}, err
	}
	defer genuineEv.Release()
	row := denyRow{SenderKeySeenInGenuine: spy.Used(senderKey)}

	// from here on only the recipient's keys and the sender's card
	spy.Forget()
	forged, forgedEv, err := scenario.Forge(spy, recipient, sender.Card(), denyScript)
	if err != nil {
		return denyRow{}, err
	}
	defer forgedEv.Release()
	said, err := scenario.Verify(spy, recipient, genuineEv, genuine)
	row.GenuineVerified, row.SenderMessagesInGenuine = err == nil, len(said)
	if err != nil && !errors.Is(err, scenario.ErrMismatch) {
		return denyRow{}, err
	}
	said, err = scenario.Verify(spy, recipient, forgedEv, forged)
	row.ForgedVerified, row.SenderMessagesInForged = err == nil, len(said)
	if err != nil && !errors.Is(err, scenario.ErrMismatch) {
		return denyRow{}, err
	}
	if row.ControlRejected, err = scenario.Control(spy, recipient, sender.Card(), denyScript); err != nil {
		return denyRow{}, err
	}
	row.SenderPrivateKeyUsed = spy.Used(senderKey)
	row.StructureEqual = scenario.SameShape(genuine, forged)

	row.RecipientRole = e2e.RoleResponder.String()
	if !genuine.Records[0].FromSender {
		row.RecipientRole = e2e.RoleInitiator.String()
	}
	if row.RecipientRole != role.String() {
		return denyRow{}, fmt.Errorf("the recipient took the role %s", row.RecipientRole)
	}
	if row.SenderCardHash, err = cardHash(p, sender.Card()); err != nil {
		return denyRow{}, err
	}
	if row.RecipientCardHash, err = cardHash(p, recipient.Card()); err != nil {
		return denyRow{}, err
	}
	row.GenuineRecords, row.ForgedRecords = denyRecords(genuine), denyRecords(forged)
	return row, nil
}

func cardHash(p jcrypto.CryptoProvider, c e2e.Card) (string, error) {
	h, err := e2e.CardHash(p, c)
	return hex.EncodeToString(h), err
}

func denyRecords(t *scenario.Transcript) []denyRecord {
	kinds := map[byte]string{scenario.KindKK1: "kk1", scenario.KindKK2: "kk2", scenario.KindData: "data"}
	out := make([]denyRecord, len(t.Records))
	for i, r := range t.Records {
		from := "recipient"
		if r.FromSender {
			from = "sender"
		}
		out[i] = denyRecord{From: from, Kind: kinds[r.Kind], Dummy: r.Dummy, Size: len(r.Bytes), Body: string(r.Body), Hex: hex.EncodeToString(r.Bytes)}
	}
	return out
}

func printDeny(w io.Writer, rep denyReport) {
	fmt.Fprintf(w, "deny: suite %s, rev %s\n", rep.Suite, rep.Rev)
	fmt.Fprintf(w, "%-10s %7s %9s %9s %10s %9s %15s\n", "recipient", "records", "genuine", "forged", "same shape", "control", "sender key used")
	verdict := func(ok bool, yes, no string) string {
		if ok {
			return yes
		}
		return no
	}
	for _, r := range rep.Roles {
		fmt.Fprintf(w, "%-10s %7d %9s %9s %10s %9s %15s\n", r.RecipientRole, len(r.GenuineRecords),
			verdict(r.GenuineVerified, "verified", "refused"), verdict(r.ForgedVerified, "verified", "refused"),
			verdict(r.StructureEqual, "yes", "no"), verdict(r.ControlRejected, "rejected", "verified"),
			verdict(r.SenderPrivateKeyUsed, "yes", "no"))
	}
	fmt.Fprintln(w, "control: a forgery made with a fresh key in place of the recipient's")
	fmt.Fprintf(w, "claim: %s\n", rep.Claim)
	fmt.Fprintf(w, "assumption: %s\n", rep.Assumption)
}
