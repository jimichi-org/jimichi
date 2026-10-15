package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/vault"
)

var vaultSuites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

// no lock and no hardening outside linux, and the tests check the rest
var unprotected = []string{"-keymem", "zero", "-harden=false"}

// the production stretch replaced by a DeriveKey of a hash of the password,
// counted
type cheapStretch struct {
	jcrypto.CryptoProvider
	stretches *atomic.Int32
}

func (c cheapStretch) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	c.stretches.Add(1)
	if password == nil || !jcrypto.ValidPassword(password.Bytes()) {
		return nil, jcrypto.ErrBadPassword
	}
	h, err := secmem.NewFrom(c.Hash(password.Bytes()))
	if err != nil {
		return nil, err
	}
	defer h.Release()
	return c.DeriveKey(h, "test/password", ctx, c.KeySize())
}

func useCheap(t *testing.T) *atomic.Int32 {
	t.Helper()
	n := new(atomic.Int32)
	prev := newProvider
	newProvider = func(s jcrypto.Suite) (jcrypto.CryptoProvider, error) {
		p, err := suite.New(s)
		if err != nil {
			return nil, err
		}
		return cheapStretch{CryptoProvider: p, stretches: n}, nil
	}
	t.Cleanup(func() { newProvider = prev })
	return n
}

type contactOf struct {
	card e2e.Card
	hash string
}

func newContact(t *testing.T, s jcrypto.Suite, addr string) contactOf {
	t.Helper()
	p := provider(t, s)
	var q [e2e.QueueSize]byte
	if _, err := rand.Read(q[:]); err != nil {
		t.Fatal(err)
	}
	q[0] |= 1
	id, err := e2e.NewIdentity(p, addr, q)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Close()
	card := id.Card()
	h, err := e2e.CardHash(p, card)
	if err != nil {
		t.Fatal(err)
	}
	return contactOf{card: card, hash: hex.EncodeToString(h)}
}

func vaultAt(t *testing.T) string { return filepath.Join(t.TempDir(), "client.vault") }

func initArgs(s jcrypto.Suite, path string, extra []string, contacts ...contactOf) []string {
	args := append([]string{"init", "-suite", s.String(), "-mailbox", addrOf("relay-5")}, unprotected...)
	for _, c := range contacts {
		args = append(args, "-contact", c.card.String())
	}
	args = append(args, extra...)
	return append(args, path)
}

func showArgs(s jcrypto.Suite, path string) []string {
	return append(append([]string{"show", "-suite", s.String()}, unprotected...), path)
}

func vaultCmd(stdin string, args []string) (stdout, stderr string, err error) {
	var out, errOut bytes.Buffer
	err = runVault(args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), errOut.String(), err
}

func mustInit(t *testing.T, stdin string, args []string) []string {
	t.Helper()
	out, errOut, err := vaultCmd(stdin, args)
	if err != nil {
		t.Fatalf("vault init: %v\n%s", err, errOut)
	}
	if !strings.HasSuffix(errOut, "created\n") {
		t.Fatalf("no created line in %q", errOut)
	}
	if out == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

type shown struct{ card, cardHash, mailbox, contactHash string }

var shownLines = regexp.MustCompile(`^card=(\S+)\ncard_hash=([0-9a-f]{64})\nmailbox=(\S+)\ncontact_card_hash=([0-9a-f]{64})\n$`)

func mustShow(t *testing.T, s jcrypto.Suite, path, stdin string) shown {
	t.Helper()
	out, errOut, err := vaultCmd(stdin, showArgs(s, path))
	if err != nil {
		t.Fatalf("vault show: %v\n%s", err, errOut)
	}
	m := shownLines.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("vault show printed %q", out)
	}
	return shown{m[1], m[2], m[3], m[4]}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

func noVault(t *testing.T, path string) {
	t.Helper()
	for _, p := range []string{path, path + ".tmp"} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: %v, want no file", p, err)
		}
	}
}

var generated = regexp.MustCompile(`^[A-Z2-7]{26}$`)

// 16 bytes of crypto/rand each, printed once, one a line in the order of
// -contact, and each opens the volume of its contact
func TestVaultInitGeneratesPasswords(t *testing.T) {
	for _, s := range vaultSuites {
		t.Run(s.String(), func(t *testing.T) {
			stretches := useCheap(t)
			for _, n := range []int{1, 2} {
				contacts := []contactOf{newContact(t, s, addrOf("relay-5")), newContact(t, s, addrOf("relay-5"))}[:n]
				path := vaultAt(t)
				stretches.Store(0)
				out, errOut, err := vaultCmd("", initArgs(s, path, nil, contacts...))
				if err != nil {
					t.Fatalf("vault init: %v\n%s", err, errOut)
				}
				if got := stretches.Load(); got != int32(n) {
					t.Fatalf("%d stretches for %d volumes", got, n)
				}
				lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
				if len(lines) != n || !strings.HasSuffix(out, "\n") {
					t.Fatalf("stdout %q, want %d passwords one a line", out, n)
				}
				seen := map[string]bool{}
				for _, pw := range lines {
					raw, err := passwordEncoding.DecodeString(pw)
					if !generated.MatchString(pw) || err != nil || len(raw) != 16 {
						t.Fatalf("password %q is not 128 bits of base32 without padding: %v", pw, err)
					}
					if seen[pw] || strings.Contains(errOut, pw) {
						t.Fatalf("password %q printed twice", pw)
					}
					seen[pw] = true
				}
				if !strings.HasSuffix(errOut, "created\n") {
					t.Fatalf("stderr %q, want created", errOut)
				}
				if size := fileSize(t, path); size != vault.FileSize {
					t.Fatalf("a file of %d bytes", size)
				}
				for i, pw := range lines {
					if got := mustShow(t, s, path, pw+"\n"); got.contactHash != contacts[i].hash {
						t.Fatalf("password %d opens contact %s, want %s", i+1, got.contactHash, contacts[i].hash)
					}
				}
			}
		})
	}
}

func TestVaultInitStdin(t *testing.T) {
	for _, s := range vaultSuites {
		t.Run(s.String(), func(t *testing.T) {
			useCheap(t)
			a, b := newContact(t, s, addrOf("relay-5")), newContact(t, s, addrOf("relay-5"))
			path := vaultAt(t)
			out, errOut, err := vaultCmd("first password\r\nsecond password\n", initArgs(s, path, []string{"-stdin"}, a, b))
			if err != nil {
				t.Fatalf("vault init -stdin: %v\n%s", err, errOut)
			}
			if out != "" {
				t.Fatalf("passwords from stdin printed back: %q", out)
			}
			if !strings.Contains(errOut, "WARNING: the passwords come from stdin") || !strings.Contains(errOut, "claimed only for generated passwords") {
				t.Fatalf("no warning about passwords from stdin in %q", errOut)
			}
			if got := mustShow(t, s, path, "first password\n"); got.contactHash != a.hash {
				t.Fatal("the first password does not open the first contact")
			}
			if got := mustShow(t, s, path, "second password\r\n"); got.contactHash != b.hash {
				t.Fatal("the second password does not open the second contact")
			}

			_, _, err = vaultCmd("only one\n", initArgs(s, vaultAt(t), []string{"-stdin"}, a, b))
			if err == nil || !strings.Contains(err.Error(), "password 2") {
				t.Fatalf("a missing second password: %v", err)
			}
		})
	}
}

// the formal checks of every card, the flags and the file come before the
// first stretch and before any file
func TestVaultInitRefusesBeforeStretch(t *testing.T) {
	stretches := useCheap(t)
	s := jcrypto.SuiteC25519
	good := newContact(t, s, addrOf("relay-5"))
	other := newContact(t, jcrypto.SuiteGOST, addrOf("relay-5"))
	elsewhere := newContact(t, s, addrOf("relay-4"))
	base := func(more ...string) []string {
		args := append([]string{"init", "-suite", s.String(), "-mailbox", addrOf("relay-5")}, unprotected...)
		return append(args, more...)
	}
	cases := []struct {
		name string
		args func(path string) []string
	}{
		{"no -contact", func(path string) []string { return base(path) }},
		{"three -contact", func(path string) []string {
			return base("-contact", good.card.String(), "-contact", good.card.String(), "-contact", good.card.String(), path)
		}},
		{"a card that does not parse", func(path string) []string { return base("-contact", "c25519:not base64", path) }},
		{"a card of another suite", func(path string) []string { return base("-contact", other.card.String(), path) }},
		{"a card of another mailbox", func(path string) []string { return base("-contact", elsewhere.card.String(), path) }},
		{"a good card, then one of another mailbox", func(path string) []string {
			return base("-contact", good.card.String(), "-contact", elsewhere.card.String(), path)
		}},
		{"a -mailbox that is not an address", func(path string) []string {
			return append([]string{"init", "-mailbox", "relay-5", "-contact", good.card.String()}, append(unprotected, path)...)
		}},
		{"an unknown suite", func(path string) []string {
			return append([]string{"init", "-suite", "rsa", "-mailbox", addrOf("relay-5"), "-contact", good.card.String()}, append(unprotected, path)...)
		}},
		{"no file", func(string) []string { return base("-contact", good.card.String()) }},
		{"a flag after the file", func(path string) []string { return base("-contact", good.card.String(), path, "-stdin") }},
	}
	for _, c := range cases {
		path := vaultAt(t)
		stretches.Store(0)
		if _, _, err := vaultCmd("", c.args(path)); err == nil {
			t.Fatalf("%s: init passed", c.name)
		}
		if n := stretches.Load(); n != 0 {
			t.Fatalf("%s: %d stretches before the refusal", c.name, n)
		}
		noVault(t, path)
	}

	path := vaultAt(t)
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	stretches.Store(0)
	_, _, err := vaultCmd("", initArgs(s, path, nil, good))
	if !errors.Is(err, vault.ErrExists) || stretches.Load() != 0 {
		t.Fatalf("an existing file: %v after %d stretches, want ErrExists before any", err, stretches.Load())
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "keep" {
		t.Fatalf("the existing file changed: %q, %v", b, err)
	}

	path = vaultAt(t)
	_, _, err = vaultCmd("same\nsame\n", initArgs(s, path, []string{"-stdin"}, good, newContact(t, s, addrOf("relay-5"))))
	if !errors.Is(err, vault.ErrSamePassword) || stretches.Load() != 0 {
		t.Fatalf("equal passwords: %v after %d stretches, want ErrSamePassword before any", err, stretches.Load())
	}
	noVault(t, path)

	second := newContact(t, s, addrOf("relay-5"))
	sameKey, sameQueue := second, second
	sameKey.card.Static = good.card.Static
	sameQueue.card.Queue = good.card.Queue
	for name, twice := range map[string]contactOf{"the same card": good, "the key of the first": sameKey, "the queue of the first": sameQueue} {
		path := vaultAt(t)
		stretches.Store(0)
		_, _, err := vaultCmd("", initArgs(s, path, nil, good, twice))
		if err == nil || !strings.Contains(err.Error(), "a contact belongs to one volume") || stretches.Load() != 0 {
			t.Fatalf("a second -contact with %s: %v after %d stretches, want a refusal before any", name, err, stretches.Load())
		}
		noVault(t, path)
	}
}

// init stands behind the guard of show: a warning names what is off, and off
// linux locked memory or hardening asked for refuses the run before any
// password exists
func TestVaultInitKeyMemory(t *testing.T) {
	stretches := useCheap(t)
	prev := secmem.CurrentPolicy()
	t.Cleanup(func() { _ = secmem.SetPolicy(prev) })
	s := jcrypto.SuiteC25519
	contact := newContact(t, s, addrOf("relay-5"))
	_, errOut, err := vaultCmd("", initArgs(s, vaultAt(t), nil, contact))
	if err != nil {
		t.Fatalf("vault init: %v", err)
	}
	if !strings.Contains(errOut, "WARNING: the passwords and the keys they give are held without locked memory and process hardening") {
		t.Fatalf("no warning about the unprotected keys in %q", errOut)
	}
	t.Run("refusal", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("linux locks the memory and hardens the process")
		}
		for _, c := range []struct {
			flags []string
			text  string
		}{
			{[]string{"-keymem", "all", "-harden=false"}, "key memory is not locked, refusing to take a password"},
			{[]string{"-keymem", "zero"}, "harden: "},
		} {
			path := vaultAt(t)
			stretches.Store(0)
			args := append([]string{"init", "-suite", s.String(), "-mailbox", addrOf("relay-5"), "-contact", contact.card.String()}, c.flags...)
			out, _, err := vaultCmd("", append(args, path))
			if err == nil || !strings.Contains(err.Error(), c.text) || out != "" || stretches.Load() != 0 {
				t.Fatalf("init %v: %v, %q after %d stretches, want %q before any", c.flags, err, out, stretches.Load(), c.text)
			}
			noVault(t, path)
		}
	})
}

// a creation that fails after its link takes the file away: no password was
// printed for it, so no container is left that nobody can open
func TestVaultInitFailureAfterLink(t *testing.T) {
	useCheap(t)
	injected := errors.New("injected after the link")
	prev := createVault
	createVault = func(p jcrypto.CryptoProvider, path string, volumes ...vault.Contents) error {
		if err := prev(p, path, volumes...); err != nil {
			return err
		}
		return fmt.Errorf("%w, but %w", vault.ErrWritten, injected)
	}
	t.Cleanup(func() { createVault = prev })
	s := jcrypto.SuiteC25519
	path := vaultAt(t)
	out, errOut, err := vaultCmd("", initArgs(s, path, nil, newContact(t, s, addrOf("relay-5"))))
	if !errors.Is(err, vault.ErrWritten) || !errors.Is(err, injected) || !strings.Contains(err.Error(), "the file is removed") {
		t.Fatalf("a failure after the link: %v", err)
	}
	if out != "" || strings.Contains(errOut, "created") {
		t.Fatalf("a failed creation printed %q and %q", out, errOut)
	}
	noVault(t, path)
}

// a key the agreement refuses passes the formal checks; the volume refuses it
// after its stretch, and no file is written
func TestVaultInitRefusesKey(t *testing.T) {
	for _, s := range vaultSuites {
		t.Run(s.String(), func(t *testing.T) {
			stretches := useCheap(t)
			good, bad := newContact(t, s, addrOf("relay-5")), newContact(t, s, addrOf("relay-5"))
			bad.card.Static = make([]byte, len(bad.card.Static))
			for i, contacts := range [][]contactOf{{bad}, {good, bad}} {
				path := vaultAt(t)
				stretches.Store(0)
				out, _, err := vaultCmd("", initArgs(s, path, nil, contacts...))
				if !errors.Is(err, e2e.ErrCard) || !strings.Contains(err.Error(), fmt.Sprintf("-contact %d", i+1)) {
					t.Fatalf("a contact key the agreement refuses: %v", err)
				}
				if out != "" {
					t.Fatalf("passwords printed for a container not created: %q", out)
				}
				if stretches.Load() == 0 {
					t.Fatal("the key was refused before the identity existed")
				}
				noVault(t, path)
			}
		})
	}
}

// show prints the own card, its hash, the mailbox and the hash of the contact,
// and nothing that names an area or the number of volumes
func TestVaultShow(t *testing.T) {
	for _, s := range vaultSuites {
		t.Run(s.String(), func(t *testing.T) {
			useCheap(t)
			p := provider(t, s)
			a, b := newContact(t, s, addrOf("relay-5")), newContact(t, s, addrOf("relay-5"))
			one, two := vaultAt(t), vaultAt(t)
			mustInit(t, "pw\n", initArgs(s, one, []string{"-stdin"}, a))
			mustInit(t, "pw\nother\n", initArgs(s, two, []string{"-stdin"}, a, b))
			for _, path := range []string{one, two} {
				_, errOut, err := vaultCmd("pw\n", showArgs(s, path))
				if err != nil {
					t.Fatalf("vault show: %v", err)
				}
				for _, line := range strings.Split(strings.TrimSuffix(errOut, "\n"), "\n") {
					if !strings.HasPrefix(line, "WARNING: ") || strings.Contains(line, "area") || strings.Contains(line, "volume") {
						t.Fatalf("show wrote %q to stderr", line)
					}
				}
				got := mustShow(t, s, path, "pw\n")
				card, err := e2e.ParseCard(got.card)
				if err != nil || card.Suite != s || card.Mailbox != addrOf("relay-5") || got.mailbox != addrOf("relay-5") {
					t.Fatalf("show printed card %q, mailbox %q: %v", got.card, got.mailbox, err)
				}
				h, err := e2e.CardHash(p, card)
				if err != nil || hex.EncodeToString(h) != got.cardHash {
					t.Fatalf("card_hash %s, want %x: %v", got.cardHash, h, err)
				}
				if got.contactHash != a.hash || bytes.Equal(card.Static, a.card.Static) {
					t.Fatalf("contact %s, want %s", got.contactHash, a.hash)
				}
				if again := mustShow(t, s, path, "pw\n"); again != got {
					t.Fatal("two shows with one password gave two cards")
				}
			}
			if mustShow(t, s, one, "pw\n").card == mustShow(t, s, two, "pw\n").card {
				t.Fatal("a new container under the same password gave the same card")
			}
			if mustShow(t, s, two, "other\n").card == mustShow(t, s, two, "pw\n").card {
				t.Fatal("two volumes with one card")
			}
		})
	}
}

// a third password is refused as the password of a volume that is not there,
// on stdout, stderr and the exit code
func TestVaultShowThirdPassword(t *testing.T) {
	useCheap(t)
	s := jcrypto.SuiteC25519
	a, b := newContact(t, s, addrOf("relay-5")), newContact(t, s, addrOf("relay-5"))
	one, two := vaultAt(t), vaultAt(t)
	mustInit(t, "a\n", initArgs(s, one, []string{"-stdin"}, a))
	mustInit(t, "a\nb\n", initArgs(s, two, []string{"-stdin"}, a, b))
	answer := func(path, pw string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := runIn(append([]string{"vault"}, showArgs(s, path)...), strings.NewReader(pw), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	code3, out3, err3 := answer(two, "c\n")
	codeAbsent, outAbsent, errAbsent := answer(one, "b\n")
	if code3 != 1 || code3 != codeAbsent || out3 != "" || out3 != outAbsent || err3 != errAbsent {
		t.Fatalf("a third password: %d %q %q\nan absent volume: %d %q %q", code3, out3, err3, codeAbsent, outAbsent, errAbsent)
	}
	if !strings.Contains(err3, "jimichi vault show: vault: no volume opens with this password\n") {
		t.Fatalf("stderr %q", err3)
	}
}

func TestVaultShowLineEndings(t *testing.T) {
	useCheap(t)
	s := jcrypto.SuiteC25519
	path := vaultAt(t)
	mustInit(t, "pw\n", initArgs(s, path, []string{"-stdin"}, newContact(t, s, addrOf("relay-5"))))
	lf := mustShow(t, s, path, "pw\n")
	for _, stdin := range []string{"pw\r\n", "pw", "pw\nnext line\n"} {
		if got := mustShow(t, s, path, stdin); got != lf {
			t.Fatalf("password read from %q opened another card", stdin)
		}
	}
	for _, stdin := range []string{"pw\r\r\n", "p\rw\n", "pw \n"} {
		if _, _, err := vaultCmd(stdin, showArgs(s, path)); !errors.Is(err, vault.ErrNoVolume) && !errors.Is(err, jcrypto.ErrBadPassword) {
			t.Fatalf("password read from %q: %v", stdin, err)
		}
	}
}

func TestReadPassword(t *testing.T) {
	long := strings.Repeat("x", jcrypto.PasswordMax)
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"pw\n", "pw", true},
		{"pw\r\n", "pw", true},
		{"pw", "pw", true},
		{long + "\r\n", long, true},
		{long + "x\n", "", false},
		{"", "", false},
		{"\n", "", false},
		{"\r\n", "", false},
		{"p\x00w\n", "", false},
		{"p\rw\n", "", false},
		{"pw\r\r\n", "", false},
	} {
		pw, err := readPassword(strings.NewReader(c.in))
		if c.ok != (err == nil) {
			t.Fatalf("readPassword(%q): %v", c.in, err)
		}
		if err == nil {
			if string(pw.Bytes()) != c.want {
				t.Fatalf("readPassword(%q) = %q", c.in, pw.Bytes())
			}
			pw.Release()
		}
	}
	r := strings.NewReader("first\nsecond\n")
	pw, err := readPassword(r)
	if err != nil || string(pw.Bytes()) != "first" || r.Len() != len("second\n") {
		t.Fatalf("the first line took %d bytes too many: %v", len("second\n")-r.Len(), err)
	}
	pw.Release()
}

// every run removes what a creation killed before its link left
func TestVaultCleansAtStart(t *testing.T) {
	stretches := useCheap(t)
	s := jcrypto.SuiteC25519
	path := vaultAt(t)
	for _, args := range [][]string{
		append(append([]string{"init", "-mailbox", addrOf("relay-5")}, unprotected...), path),
		showArgs(s, path),
	} {
		if err := os.WriteFile(path+".tmp", []byte("left by a creation"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := vaultCmd("pw\n", args); err == nil {
			t.Fatalf("%v passed without a container", args)
		}
		noVault(t, path)
	}
	if stretches.Load() != 0 {
		t.Fatal("a refused run stretched a password")
	}
}

func TestVaultShowErrors(t *testing.T) {
	useCheap(t)
	s := jcrypto.SuiteC25519
	p, err := newProvider(s)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := vaultAt(t)
	err = vault.Create(p, corrupt, vault.Contents{Password: secret(t, "pw"), Fill: func(_ *vault.Identity, buf []byte) (int, error) {
		return copy(buf, []byte{2, 0}), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	short := vaultAt(t)
	if err := os.WriteFile(short, make([]byte, vault.FileSize-1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path, text string
	}{
		{corrupt, "vault: the volume is corrupt"},
		{short, "vault: not a container"},
		{vaultAt(t), "vault: not opened: io: "},
	} {
		_, _, err := vaultCmd("pw\n", showArgs(s, c.path))
		if err == nil || !strings.HasPrefix(err.Error(), c.text) {
			t.Fatalf("%s: %v, want %s", c.path, err, c.text)
		}
	}
	for _, e := range []error{secmem.ErrNotLocked, secmem.ErrNotMapped} {
		if err := unlockError(fmt.Errorf("vault: identity: %w", e)); !strings.HasPrefix(err.Error(), "vault: not opened: memory: ") {
			t.Fatalf("%v: %v", e, err)
		}
	}
}

func secret(t *testing.T, s string) *secmem.Buffer {
	t.Helper()
	b, err := secmem.NewFrom([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Release)
	return b
}

func TestPagingWarning(t *testing.T) {
	w := pagingWarning("windows")
	for _, name := range []string{"pagefile.sys", "hiberfil.sys", "WSL2"} {
		if !strings.Contains(w, name) {
			t.Fatalf("the Windows warning %q does not name %s", w, name)
		}
	}
	if w := pagingWarning("linux"); w != "" {
		t.Fatalf("a paging warning on linux: %q", w)
	}
	useCheap(t)
	s := jcrypto.SuiteC25519
	_, errOut, _ := vaultCmd("pw\n", showArgs(s, vaultAt(t)))
	if got := strings.Contains(errOut, "pagefile.sys"); got != (runtime.GOOS == "windows") {
		t.Fatalf("stderr on %s: %q", runtime.GOOS, errOut)
	}
	if !strings.Contains(errOut, "WARNING: the passwords and the keys they give are held without locked memory and process hardening") {
		t.Fatalf("no warning about the unprotected keys in %q", errOut)
	}
}

func TestVaultCommandLine(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"help"}, &out, io.Discard); code != 0 || !strings.Contains(out.String(), "jimichi vault init") || !strings.Contains(out.String(), "jimichi vault show") {
		t.Fatalf("usage without the vault commands: %q", out.String())
	}
	for _, args := range [][]string{{"vault"}, {"vault", "pin"}} {
		var errOut bytes.Buffer
		if code := runIn(args, strings.NewReader(""), io.Discard, &errOut); code != 1 {
			t.Fatalf("jimichi %v: exit %d, %s", args, code, errOut.String())
		}
	}
}

// one round per suite at the cost a user pays
func TestVaultProduction(t *testing.T) {
	if testing.Short() {
		t.Skip("PasswordKey at production cost")
	}
	for _, s := range vaultSuites {
		t.Run(s.String(), func(t *testing.T) {
			contact := newContact(t, s, addrOf("relay-5"))
			path := vaultAt(t)
			lines := mustInit(t, "", initArgs(s, path, nil, contact))
			if len(lines) != 1 {
				t.Fatalf("%d passwords for one volume", len(lines))
			}
			if got := mustShow(t, s, path, lines[0]+"\n"); got.contactHash != contact.hash {
				t.Fatal("the generated password does not open its contact")
			}
		})
	}
}
