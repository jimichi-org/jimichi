package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
)

// a card of the suite and mailbox asked for, of a new key every time, whose
// hash card-hash prints as e2e.CardHash computes it
func TestKeygenCardAndCardHash(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST, jcrypto.SuiteC25519} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"keygen-card", "-suite", s.String(), "-mailbox", addrOf("relay-5")}, &stdout, &stderr); code != 0 {
			t.Fatalf("keygen-card exit %d: %s", code, stderr.String())
		}
		line := strings.TrimSuffix(stdout.String(), "\n")
		card, err := e2e.ParseCard(line)
		if err != nil || card.Suite != s || card.Mailbox != addrOf("relay-5") {
			t.Fatalf("keygen-card printed %q: %v", line, err)
		}
		if seen[line] {
			t.Fatal("two runs printed the same card")
		}
		seen[line] = true

		stdout.Reset()
		if code := run([]string{"card-hash", line}, &stdout, &stderr); code != 0 {
			t.Fatalf("card-hash exit %d: %s", code, stderr.String())
		}
		want, err := e2e.CardHash(provider(t, s), card)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSuffix(stdout.String(), "\n"); got != hex.EncodeToString(want) {
			t.Fatalf("card-hash printed %q, want %x", got, want)
		}
	}
}

func TestCardCommandLine(t *testing.T) {
	var stdout bytes.Buffer
	if code := run([]string{"keygen-card", "-mailbox", addrOf("relay-5")}, &stdout, io.Discard); code != 0 {
		t.Fatalf("keygen-card exit %d", code)
	}
	card := strings.TrimSuffix(stdout.String(), "\n")
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"keygen-card"}, 1},
		{[]string{"keygen-card", "-mailbox", "Relay-5:9000"}, 1},
		{[]string{"keygen-card", "-mailbox", "relay-5"}, 1},
		{[]string{"keygen-card", "-mailbox", addrOf("relay-5"), "-suite", "rsa"}, 1},
		{[]string{"keygen-card", "-mailbox", addrOf("relay-5"), "extra"}, 1},
		{[]string{"card-hash"}, 1},
		{[]string{"card-hash", card, card}, 1},
		{[]string{"card-hash", "hello"}, 1},
		{[]string{"card-hash", card + "\n"}, 1},
		{[]string{"card-hash", strings.Replace(card, "c25519:", "gost:", 1)}, 1},
		{[]string{"card-hash", card}, 0},
	} {
		if code := run(c.args, io.Discard, io.Discard); code != c.code {
			t.Errorf("jimichi %v: exit %d, want %d", c.args, code, c.code)
		}
	}
}
