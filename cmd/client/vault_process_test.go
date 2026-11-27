package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/vault"
	"github.com/jimichi-org/jimichi/vault/profile"
)

// a client process started by the tests below takes this in place of the
// 90 s after which a silent session is stale, and a third of it for the 30 s
// of the keepalive
const staleAfterVar = "JIMICHI_TEST_STALE_AFTER"

func init() {
	s := os.Getenv(staleAfterVar)
	if s == "" {
		return
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(err)
	}
	staleAfter, keepalive = d, d/3
}

const vaultPassword = "correct horse battery staple 42"

// a -peer client with -vault and the cheap stretch
func (bed *peerBed) startVault(t *testing.T, name, path string, env []string, extra ...string) *peerProc {
	t.Helper()
	env = append([]string{cheapStretchVar + "=1"}, env...)
	return bed.start(t, name, env, append([]string{"-harden=false", "-keymem", "none", "-vault", path}, extra...)...)
}

// the admin listener of a client that came up locked
func (pr *peerProc) locked(t *testing.T) string {
	t.Helper()
	pr.await(t, "the locked state", func(out string) bool { return strings.Contains(out, " vault locked\n") })
	return "http://" + pr.admin(t)
}

func vaultCard(t *testing.T, admin string) e2e.Card {
	t.Helper()
	code, text := httpCall(t, http.MethodGet, admin+"/card", "")
	if code != http.StatusOK {
		t.Fatalf("GET /card = %d %q", code, text)
	}
	c, err := e2e.ParseCard(strings.TrimSuffix(text, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustCall(t *testing.T, method, url, body string, want int) {
	t.Helper()
	if code, text := httpCall(t, method, url, body); code != want {
		t.Fatalf("%s %s = %d %q, want %d", method, url, code, text, want)
	}
}

func vaultStatus(t *testing.T, admin string) statusFields {
	t.Helper()
	code, text := httpCall(t, http.MethodGet, admin+"/status", "")
	if code != http.StatusOK {
		t.Fatalf("GET /status = %d %q", code, text)
	}
	return decodeStatus(t, text)
}

// SIGTERM where there is one; Windows has none to send, so the process is
// killed, which is an exit like any other
func (pr *peerProc) stop(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		pr.terminate(t)
		return
	}
	_ = pr.cmd.Process.Kill()
	pr.exit(t, 30*time.Second)
}

// what no line of a -vault client may hold
func checkVaultOutput(t *testing.T, pr *peerProc, secrets ...string) {
	t.Helper()
	out := pr.out.String()
	for _, s := range append([]string{"card_hash", "role=", "e2e ", "block", "not reachable"}, secrets...) {
		if strings.Contains(out, s) {
			t.Fatalf("%s logged %q:\n%s", pr.name, s, out)
		}
	}
}

var lineTime = regexp.MustCompile(`^\S+ \S+ `)

// the kinds of the lines: no times, numbers or addresses
func lineKinds(out string) []string {
	var kinds []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = lineTime.ReplaceAllString(l, "")
		if strings.HasPrefix(l, "admin listening on ") {
			l = "admin listening on"
		}
		l = regexp.MustCompile(`[0-9]+`).ReplaceAllString(l, "N")
		if !slices.Contains(kinds, l) {
			kinds = append(kinds, l)
		}
	}
	slices.Sort(kinds)
	return kinds
}

func cardSecrets(cards ...e2e.Card) []string {
	var out []string
	for _, c := range cards {
		s := c.String()
		out = append(out, s, s[strings.Index(s, ":")+1:])
		out = append(out, encodings(c.Static)...)
		out = append(out, encodings(c.Queue[:])...)
	}
	return out
}

// a refusal of -vault is code 2 before anything else, a file that is no
// container code 1 before the listener; a leftover tmp goes at the start, and
// a locked client prints no card_hash and ends on SIGTERM with code 0
func TestVaultClientStart(t *testing.T) {
	nodes := strings.Join([]string{"127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"}, ",")
	args := func(path string) []string {
		return []string{"-peer", "-nodes", nodes, "-mailbox", "127.0.0.1:3", "-mode", "fixed", "-auth=false",
			"-harden=false", "-keymem", "none", "-admin", "127.0.0.1:0", "-vault", path}
	}
	dir := t.TempDir()
	for _, c := range []struct {
		name string
		args []string
	}{
		{"-vault without -peer", []string{"-vault", filepath.Join(dir, "client.vault")}},
		{"a directory that does not exist", args(filepath.Join(dir, "none", "client.vault"))},
	} {
		pr := startClient(t, c.name, nil, c.args...)
		if code := pr.exit(t, 30*time.Second); code != exitFlags {
			t.Fatalf("%s: exit code %d:\n%s", c.name, code, pr.out.String())
		}
	}

	short := filepath.Join(dir, "short.vault")
	if err := os.WriteFile(short, make([]byte, vault.FileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	pr := startClient(t, "short", nil, args(short)...)
	if code := pr.exit(t, 30*time.Second); code != 1 || !strings.Contains(pr.out.String(), " "+lineNotVault+"\n") ||
		strings.Contains(pr.out.String(), "admin listening") {
		t.Fatalf("a file of another size: exit code %d:\n%s", code, pr.out.String())
	}

	path := filepath.Join(dir, "client.vault")
	if err := os.WriteFile(path+".tmp", []byte("left"), 0o600); err != nil {
		t.Fatal(err)
	}
	pr = startClient(t, "locked", []string{cheapStretchVar + "=1"}, args(path)...)
	admin := pr.locked(t)
	if exists(path + ".tmp") {
		t.Fatal("the tmp is left")
	}
	mustCall(t, http.MethodGet, admin+"/card", "", http.StatusServiceUnavailable)
	mustCall(t, http.MethodGet, admin+"/status", "", http.StatusServiceUnavailable)
	mustCall(t, http.MethodPut, admin+"/vault/unlock", vaultPassword+"\n", http.StatusConflict)
	out := pr.out.String()
	if strings.Contains(out, "card_hash") || strings.Index(out, "admin listening") > strings.Index(out, "vault locked") {
		t.Fatalf("the start of a locked client:\n%s", out)
	}
	if runtime.GOOS == "windows" {
		return
	}
	pr.terminate(t)
}

// a -vault client talks with a client of RAM only, exits and comes back
// locked; the unlock gives the same card, pins the contact without a PUT, and
// the conversation resumes while the other client sees no other card, and a
// third card stops it. The file is written once and stays as it is, and no
// line names a card, a role, the session or a round trip. Both suites, on the
// cheap stretch
func TestVaultClientResumesAfterARestart(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) { resumesAfterARestart(t, s) })
	}
}

func resumesAfterARestart(t *testing.T, s jcrypto.Suite) {
	bed := newPeerBed(t, s)
	stale := max(3*time.Second, 40*bed.rate)
	env := []string{reportEveryVar + "=" + bed.reportEvery().String(), staleAfterVar + "=" + stale.String()}
	talk := []string{"-interval", (messageTicks * bed.rate).String(), "-count", "0", "-respond", "-handshake-timeout", stale.String()}
	path := vaultPath(t)

	a := bed.startVault(t, "a", path, env, talk...)
	b := bed.start(t, "b", env, append([]string{"-harden=false", "-keymem", "none"}, talk...)...)
	adminA := a.locked(t)
	mustCall(t, http.MethodPut, adminA+"/vault/init", vaultPassword+"\n\n", http.StatusNoContent)
	cardA := vaultCard(t, adminA)
	textB, _ := b.card(t, bed.p)
	cardB, err := e2e.ParseCard(textB)
	if err != nil {
		t.Fatal(err)
	}
	mustCall(t, http.MethodPut, adminA+"/contact", textB, http.StatusNoContent)
	mustCall(t, http.MethodPut, "http://"+b.admin(t)+"/contact", cardA.String(), http.StatusNoContent)
	out := a.out.String()
	if w, p := strings.Index(out, " vault written\n"), strings.Index(out, " contact pinned\n"); w < 0 || p < w {
		t.Fatalf("the write and the pin:\n%s", out)
	}
	written := fileBytes(t, path)

	trips := func(admin string) uint64 { return vaultStatus(t, admin).RoundTrips }
	waitFor := func(what string, done func() bool) {
		t.Helper()
		for limit := time.Now().Add(maxWait); !done(); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(limit) {
				t.Fatalf("no %s in %v", what, maxWait)
			}
		}
	}
	waitFor("round trips both ways", func() bool { return trips(adminA) >= 2 && roundTrips(b.out.String()) >= 2 })
	if st := vaultStatus(t, adminA); st.LastRoundTripMS == nil || st.LastRoundTripAt == nil || st.SilentFor == nil ||
		st.Container != containerWritten || (st.State != "established" && st.State != "confirmed") {
		t.Fatalf("GET /status %+v", st)
	}
	a.stop(t)
	checkVaultOutput(t, a, append(cardSecrets(cardA, cardB), vaultPassword)...)

	again := bed.startVault(t, "a again", path, env, talk...)
	adminA = again.locked(t)
	mustCall(t, http.MethodGet, adminA+"/card", "", http.StatusServiceUnavailable)
	mustCall(t, http.MethodPut, adminA+"/vault/init", vaultPassword+"\n\n", http.StatusConflict)
	mustCall(t, http.MethodPut, adminA+"/vault/unlock", vaultPassword+"\n", http.StatusNoContent)
	if got := vaultCard(t, adminA); !bytes.Equal(got.Bytes(), cardA.Bytes()) {
		t.Fatalf("the card after the restart %s, before it %s", got, cardA)
	}
	if !strings.Contains(again.out.String(), " contact pinned\n") {
		t.Fatalf("no pin from the volume before the answer:\n%s", again.out.String())
	}
	seen := roundTrips(b.out.String())
	waitFor("the conversation after the restart", func() bool {
		return trips(adminA) >= 2 && roundTrips(b.out.String()) >= seen+2
	})
	mustCall(t, http.MethodPut, adminA+"/contact", textB, http.StatusNoContent)
	if !bytes.Equal(fileBytes(t, path), written) {
		t.Fatal("the file changed after the restart and the pins")
	}
	if strings.Contains(b.out.String(), "contact card changed") {
		t.Fatalf("the other client saw another card:\n%s", b.out.String())
	}
	mustCall(t, http.MethodGet, "http://"+b.admin(t)+"/card", "", http.StatusOK)
	// the pin restored by the unlock is the only card: another one stops the
	// client and leaves the file as it is
	foreign := newPeerID(t, bed.p, bed.addrs[2]).card
	mustCall(t, http.MethodPut, adminA+"/contact", foreign.String(), http.StatusConflict)
	again.await(t, "the stop", func(out string) bool { return strings.Contains(out, " contact card changed, refusing\n") })
	mustCall(t, http.MethodGet, adminA+"/status", "", http.StatusConflict)
	if !bytes.Equal(fileBytes(t, path), written) {
		t.Fatal("the file changed after the stop")
	}
	checkVaultOutput(t, again, append(cardSecrets(cardA, cardB, foreign), vaultPassword)...)
	again.stop(t)
}

// an open whose first chain cannot be built answers before the listener goes,
// and the process exits with code 1; the operator reads from the answer that
// no container is on disk
func TestVaultClientNotStarted(t *testing.T) {
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	m := *bed.info.mirror.Load()
	entries, err := pki.ParseMirror(m)
	if err != nil {
		t.Fatal(err)
	}
	short, err := pki.MarshalMirror(entries[:2])
	if err != nil {
		t.Fatal(err)
	}
	bed.info.mirror.Store(&short)
	path := vaultPath(t)
	pr := bed.startVault(t, "no chain", path, nil)
	admin := pr.locked(t)
	code, text := httpCall(t, http.MethodPut, admin+"/vault/init", vaultPassword+"\n\n")
	if want := notStarted + "circuit, " + noContainer + "\n"; code != http.StatusServiceUnavailable || text != want {
		t.Fatalf("the init: %d %q, want %q", code, text, want)
	}
	if code := pr.exit(t, 60*time.Second); code != 1 || exists(path) {
		t.Fatalf("exit code %d, file %v:\n%s", code, exists(path), pr.out.String())
	}
	if out := pr.out.String(); !strings.Contains(out, " refusing to build the circuit: ") || logsAnAddress(out, bed.addrs) {
		t.Fatalf("the line of the chain:\n%s", out)
	}
}

// a SIGTERM ends a locked client and an open that waits for its first chain
// alike with code 0; meanwhile the routes of the running client say the
// volume is opening
func TestVaultClientStopsWhileOpening(t *testing.T) {
	nodes := strings.Join([]string{"127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"}, ",")
	args := func(path string) []string {
		return []string{"-peer", "-nodes", nodes, "-mailbox", "127.0.0.1:3", "-mode", "fixed", "-auth=false",
			"-harden=false", "-keymem", "none", "-admin", "127.0.0.1:0", "-vault", path}
	}
	env := []string{cheapStretchVar + "=1"}
	p := provider(t, jcrypto.SuiteC25519)
	path := vaultPath(t)
	mustCreate(t, cheapStretch{CryptoProvider: p}, path, volumeSpec{vaultPassword, profile.New(p, "127.0.0.1:3", cardOf(t, p, "127.0.0.1:3"))})

	pr := startClient(t, "locked", env, args(path)...)
	pr.locked(t)
	pr.stop(t)

	pr = startClient(t, "opening", env, args(path)...)
	admin := pr.locked(t)
	type answer struct {
		code int
		text string
	}
	result := make(chan answer, 1)
	// a kill on Windows ends the request without an answer
	go func() {
		req, err := http.NewRequest(http.MethodPut, admin+"/vault/unlock", strings.NewReader(vaultPassword+"\n"))
		if err != nil {
			result <- answer{}
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- answer{}
			return
		}
		defer resp.Body.Close()
		text, _ := io.ReadAll(resp.Body)
		result <- answer{resp.StatusCode, string(text)}
	}()
	for limit := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, text := httpCall(t, http.MethodGet, admin+"/card", ""); text == openingText+"\n" {
			break
		}
		if time.Now().After(limit) {
			t.Fatalf("not opening:\n%s", pr.out.String())
		}
	}
	mustCall(t, http.MethodGet, admin+"/status", "", http.StatusServiceUnavailable)
	mustCall(t, http.MethodPut, admin+"/vault/unlock", vaultPassword+"\n", http.StatusTooManyRequests)
	if runtime.GOOS == "windows" {
		return
	}
	pr.terminate(t)
	got := <-result
	if want := notStarted + "shutdown, " + onDisk + "\n"; got.code != http.StatusServiceUnavailable || got.text != want {
		t.Fatalf("the unlock: %d %q, want %q", got.code, got.text, want)
	}
}

// the second volume gives another card and its own contact, and a run with
// it logs the same kinds of lines as a run with the first
func TestVaultClientDecoyLooksTheSame(t *testing.T) {
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	path := vaultPath(t)
	decoy := newPeerID(t, bed.p, bed.addrs[2]).card
	contact := newPeerID(t, bed.p, bed.addrs[2]).card
	const decoyPassword = "a second password of the decoy"

	first := bed.startVault(t, "init", path, nil)
	admin := first.locked(t)
	mustCall(t, http.MethodPut, admin+"/vault/init", vaultPassword+"\n\n"+decoyPassword+"\n"+decoy.String()+"\n", http.StatusNoContent)
	real := vaultCard(t, admin)
	mustCall(t, http.MethodPut, admin+"/contact", contact.String(), http.StatusNoContent)
	first.stop(t)

	var kinds [][]string
	for _, pw := range []string{vaultPassword, decoyPassword} {
		pr := bed.startVault(t, "unlock", path, nil)
		admin := pr.locked(t)
		mustCall(t, http.MethodPut, admin+"/vault/unlock", pw+"\n", http.StatusNoContent)
		card := vaultCard(t, admin)
		if same := bytes.Equal(card.Bytes(), real.Bytes()); same != (pw == vaultPassword) {
			t.Fatalf("the card of %q is the first volume's: %v", pw, same)
		}
		pinned := contact
		if pw == decoyPassword {
			pinned = decoy
		}
		mustCall(t, http.MethodPut, admin+"/contact", pinned.String(), http.StatusNoContent)
		pr.await(t, "the pin", func(out string) bool { return strings.Contains(out, " contact pinned\n") })
		pr.stop(t)
		checkVaultOutput(t, pr, append(cardSecrets(real, card, contact, decoy), vaultPassword, decoyPassword)...)
		kinds = append(kinds, lineKinds(pr.out.String()))
	}
	if !slices.Equal(kinds[0], kinds[1]) {
		t.Fatalf("the kinds of lines differ:\n%q\n%q", kinds[0], kinds[1])
	}
}

// an exit after three refused replies, code 3, comes back locked, and the unlock
// gives the identity of the first run
func TestVaultClientExitComesBackLocked(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	addrs, infoPort, _ := refusingEntry(t, p)
	path := vaultPath(t)
	contact := newPeerID(t, p, addrs[2]).card
	run := func(name, path, body string) e2e.Card {
		pr := startClient(t, name, []string{cheapStretchVar + "=1"},
			"-peer", "-nodes", strings.Join(addrs, ","), "-fixed-chain", "-mailbox", addrs[2], "-hops", "3",
			"-mode", "fixed", "-rate", "50ms", "-info-port", infoPort, "-suite", p.Suite().String(),
			"-auth=false", "-harden=false", "-keymem", "none", "-admin", "127.0.0.1:0", "-vault", path)
		admin := pr.locked(t)
		route := "/vault/unlock"
		if strings.Contains(body, ":") {
			route = "/vault/init"
		}
		mustCall(t, http.MethodPut, admin+route, body, http.StatusNoContent)
		card := vaultCard(t, admin)
		if code := pr.exit(t, time.Minute); code != exitRefused {
			t.Fatalf("%s: exit code %d:\n%s", name, code, pr.out.String())
		}
		if !strings.Contains(pr.out.String(), " contact pinned\n") {
			t.Fatalf("%s: no pin:\n%s", name, pr.out.String())
		}
		return card
	}
	first := run("first", path, vaultPassword+"\n"+contact.String()+"\n")
	if !exists(path) {
		t.Fatal("no container after the first run")
	}
	if again := run("again", path, vaultPassword+"\n"); !bytes.Equal(again.Bytes(), first.Bytes()) {
		t.Fatalf("the card after the exit %s, before it %s", again, first)
	}
}

// the production stretch, once: init, restart and unlock give one card
func TestVaultClientAtProductionCost(t *testing.T) {
	if testing.Short() {
		t.Skip("the production stretch")
	}
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	path := vaultPath(t)
	contact := newPeerID(t, bed.p, bed.addrs[2]).card
	plain := []string{"-harden=false", "-keymem", "none", "-vault", path}
	pr := bed.start(t, "init", nil, plain...)
	admin := pr.locked(t)
	mustCall(t, http.MethodPut, admin+"/vault/init", vaultPassword+"\n"+contact.String()+"\n", http.StatusNoContent)
	card := vaultCard(t, admin)
	pr.stop(t)
	pr = bed.start(t, "unlock", nil, plain...)
	admin = pr.locked(t)
	mustCall(t, http.MethodPut, admin+"/vault/unlock", "another password\n", http.StatusForbidden)
	mustCall(t, http.MethodPut, admin+"/vault/unlock", vaultPassword+"\n", http.StatusNoContent)
	if got := vaultCard(t, admin); !bytes.Equal(got.Bytes(), card.Bytes()) {
		t.Fatalf("the card after unlock %s, after init %s", got, card)
	}
	pr.stop(t)
}
