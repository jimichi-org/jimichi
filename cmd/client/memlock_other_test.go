//go:build !linux

package main

import (
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

// with no RLIMIT_MEMLOCK to read, a client that must lock its keys refuses at
// the memlock check, before the identity and before any request
func TestPeerWithoutAMemlockBudgetRefusesToStart(t *testing.T) {
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	pr := bed.start(t, "unbounded", nil, "-harden=false", "-keymem", "all")
	code := pr.exit(t, 30*time.Second)
	out := pr.out.String()
	if code != 1 || !strings.Contains(out, " secmem: memlock budget requires linux\n") {
		t.Fatalf("exit code %d, want 1 and the line of the memlock check:\n%s", code, out)
	}
	if strings.Contains(out, "card_hash=") || bed.info.requests.Load() != 0 {
		t.Fatalf("an identity or a request before the check:\n%s", out)
	}
}
