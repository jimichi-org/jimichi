//go:build linux

package main

import (
	"bytes"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/vault"
	"github.com/jimichi-org/jimichi/vault/profile"
)

// a client process started by the tests below runs main under the soft limit
// this names; it is set before main starts, as a pod's limit would be
const asBoundClient = "JIMICHI_TEST_MEMLOCK"

func init() {
	v := os.Getenv(asBoundClient)
	if v == "" {
		return
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		panic(err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		panic(err)
	}
	lim.Cur = min(n, lim.Max)
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		panic(err)
	}
}

// a process that may lock without the bound, with CAP_IPC_LOCK, has nothing
// to measure: one page under a soft limit of one page must not lock twice
func lockingIsBounded(t *testing.T) bool {
	t.Helper()
	var was unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
		t.Fatal(err)
	}
	if was.Max < minPeerMemlock {
		t.Skipf("RLIMIT_MEMLOCK hard limit %d is below the minimum %d", was.Max, minPeerMemlock)
	}
	before := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secmem.SetPolicy(before) }()
	page := uint64(os.Getpagesize())
	lim := unix.Rlimit{Cur: page, Max: was.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
			t.Errorf("RLIMIT_MEMLOCK not restored: %v", err)
		}
	}()
	var taken []*secmem.Buffer
	defer func() {
		for _, b := range taken {
			b.Release()
		}
	}()
	for range 3 {
		b, err := secmem.New(1)
		if err != nil {
			return true
		}
		taken = append(taken, b)
	}
	return false
}

// two clients at the minimum of the binary, each in a process of its own with
// every key memory measure on: both start, are introduced, hold a handshake
// and talk without a page they could not lock
func TestPeersTalkAtTheMemlockMinimum(t *testing.T) {
	if !lockingIsBounded(t) {
		t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
	}
	suites := []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}
	if testing.Short() {
		suites = suites[:1]
	}
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			bed := newPeerBed(t, s)
			env := []string{asBoundClient + "=" + strconv.Itoa(minPeerMemlock)}
			interval := (messageTicks * bed.rate).String()
			a := bed.start(t, "a", env, "-interval", interval, "-count", "3", "-respond")
			b := bed.start(t, "b", env, "-interval", interval, "-count", "3", "-respond")
			bed.introduce(t, a, b)
			bed.wait(t, "three round trips each", bed.legs(handshakeLegs+2)+3*messageTicks, func() bool {
				return roundTrips(a.out.String()) >= 3 && roundTrips(b.out.String()) >= 3
			})
			time.Sleep(200 * time.Millisecond)
			for _, pr := range []*peerProc{a, b} {
				out := pr.out.String()
				if pr.exited() || strings.Contains(out, "secmem: ") || strings.Contains(out, "not locked") {
					t.Fatalf("%s ran short of locked memory:\n%s", pr.name, out)
				}
			}
		})
	}
}

// a limit one byte under the minimum is refused by the check, before the
// identity and before any request
func TestPeerUnderTheMemlockMinimumNamesTheLimit(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max < minPeerMemlock {
		t.Skipf("RLIMIT_MEMLOCK hard limit %d is below the minimum %d", lim.Max, minPeerMemlock)
	}
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	pr := bed.start(t, "under", []string{asBoundClient + "=" + strconv.Itoa(minPeerMemlock-1)})
	select {
	case <-pr.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the client did not exit")
	}
	out := pr.out.String()
	if code := pr.cmd.ProcessState.ExitCode(); code != 1 || !strings.Contains(out, "RLIMIT_MEMLOCK is "+strconv.Itoa(minPeerMemlock-1)+" bytes") {
		t.Fatalf("exit code %d:\n%s", code, out)
	}
	if strings.Contains(out, "card_hash=") || bed.info.requests.Load() != 0 {
		t.Fatalf("an identity or a request before the check:\n%s", out)
	}
}

// a -vault client at the minimum with every key memory measure on: an init
// of two volumes whose second checks its contact as the initiator, a first
// write that fails before the link so that its repeat runs while the
// handshake does, talk, a restart, the unlock and talk again, without a page
// it could not lock
func TestVaultPeerTalksAtTheMemlockMinimum(t *testing.T) {
	if !lockingIsBounded(t) {
		t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
	}
	suites := []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}
	if testing.Short() {
		suites = suites[:1]
	}
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			for attempt := 1; !vaultAtTheMinimum(t, s); attempt++ {
				if attempt == 3 {
					t.Fatal("the second volume never checked its contact as the initiator")
				}
			}
		})
	}
}

// false when the second volume took the responder's side of its check, which
// a key of the decoy that starts with 0xff leaves to about 2^-9
func vaultAtTheMinimum(t *testing.T, s jcrypto.Suite) bool {
	bed := newPeerBed(t, s)
	// a restart recovers in about 4 min at the default stale bound
	stale := max(3*time.Second, 40*bed.rate)
	env := []string{asBoundClient + "=" + strconv.Itoa(minPeerMemlock), staleAfterVar + "=" + stale.String()}
	vaultEnv := append([]string{cheapStretchVar + "=1", failFirstWriteVar + "=1"}, env...)
	talk := []string{"-interval", (messageTicks * bed.rate).String(), "-count", "0", "-respond", "-handshake-timeout", stale.String()}
	path := vaultPath(t)
	decoy := highCard(t, bed.p, bed.addrs[2])
	const decoyPassword = "another password"
	vaultArgs := append([]string{"-vault", path}, talk...)

	a := bed.start(t, "a", vaultEnv, vaultArgs...)
	adminA := a.locked(t)
	mustCall(t, http.MethodPut, adminA+"/vault/init", vaultPassword+"\n\n"+decoyPassword+"\n"+decoy.String()+"\n", http.StatusNoContent)
	cardA := vaultCard(t, adminA)
	b, textB := peerAbove(t, bed, cardA, env, talk)
	if code, text := httpCall(t, http.MethodPut, adminA+"/contact", textB); code != http.StatusInternalServerError || text != notWritten+"write\n" {
		t.Fatalf("the first write: %d %q", code, text)
	}
	// the initiator's handshake starts at the pin and waits for kk2, which b
	// cannot send before its own pin: the repeat of the write now is the peak
	// of a draft
	if st := vaultStatus(t, adminA); st.State != "handshaking" {
		t.Fatalf("the write repeats in the state %s", st.State)
	}
	mustCall(t, http.MethodPut, adminA+"/contact", textB, http.StatusNoContent)
	if st := vaultStatus(t, adminA); st.State != "handshaking" || st.Container != containerWritten {
		t.Fatalf("after the repeat: %+v", st)
	}
	if n := strings.Count(a.out.String(), " vault written\n"); n != 1 {
		t.Fatalf("%d writes:\n%s", n, a.out.String())
	}
	mustCall(t, http.MethodPut, "http://"+b.admin(t)+"/contact", cardA.String(), http.StatusNoContent)
	if !secondChecksAsInitiator(t, bed.p, path, decoyPassword, decoy) {
		a.terminate(t)
		return false
	}

	short := func(pr *peerProc) {
		t.Helper()
		out := pr.out.String()
		if pr.exited() || strings.Contains(out, "secmem: ") || strings.Contains(out, "not locked") || strings.Contains(out, "memory") {
			t.Fatalf("%s ran short of locked memory:\n%s", pr.name, out)
		}
	}
	talked := func(admin string, from int) {
		t.Helper()
		for limit := time.Now().Add(maxWait); ; time.Sleep(50 * time.Millisecond) {
			if vaultStatus(t, admin).RoundTrips >= 3 && roundTrips(b.out.String()) >= from+3 {
				return
			}
			short(a)
			if time.Now().After(limit) {
				t.Fatal("no three round trips each")
			}
		}
	}
	talked(adminA, 0)
	short(a)
	short(b)
	a.terminate(t)

	a = bed.start(t, "a again", vaultEnv, vaultArgs...)
	adminA = a.locked(t)
	mustCall(t, http.MethodPut, adminA+"/vault/unlock", vaultPassword+"\n", http.StatusNoContent)
	talked(adminA, roundTrips(b.out.String()))
	time.Sleep(200 * time.Millisecond)
	short(a)
	short(b)
	return true
}

// a client b whose key is above the one of own, so that own takes the
// initiator's side; each try is even odds
func peerAbove(t *testing.T, bed *peerBed, own e2e.Card, env, args []string) (*peerProc, string) {
	t.Helper()
	for range 24 {
		b := bed.start(t, "b", env, args...)
		text, _ := b.card(t, bed.p)
		card, err := e2e.ParseCard(text)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(own.Static, card.Static) < 0 {
			return b, text
		}
		b.terminate(t)
	}
	t.Fatal("no client with a key above the one of the vault")
	return nil, ""
}

// a card whose key starts with 0xff, so that a volume holding it as its
// contact almost surely checks it as the initiator
func highCard(t *testing.T, p jcrypto.CryptoProvider, mailboxAddr string) e2e.Card {
	t.Helper()
	for range 1 << 13 {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		priv.Release()
		if pub[0] != 0xff {
			continue
		}
		c := newPeerID(t, p, mailboxAddr).card
		c.Static = pub
		return c
	}
	t.Fatal("no key that starts with 0xff")
	return e2e.Card{}
}

// the role of the second volume in the check of its contact, by the order of
// the keys: the initiator's key is the lower
func secondChecksAsInitiator(t *testing.T, p jcrypto.CryptoProvider, path, password string, contact e2e.Card) bool {
	t.Helper()
	pw, err := secmem.NewFrom([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Release()
	v, err := vault.Open(cheapStretch{CryptoProvider: p}, path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	pr, err := profile.Parse(p, v)
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	if !bytes.Equal(pr.Contact.Bytes(), contact.Bytes()) {
		t.Fatal("the second volume holds another contact")
	}
	return bytes.Compare(pr.Card.Static, contact.Static) < 0
}
