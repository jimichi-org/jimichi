package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/vault"
	"github.com/jimichi-org/jimichi/vault/profile"
)

const passwordBytes = 16

// ASCII, so neither a terminal nor a shell can normalise it into another
var passwordEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// replaced in tests to count the stretches and make them cheap; a command
// never takes a cost from its caller
var newProvider = suite.New

// replaced in tests to fail after the link
var createVault = vault.Create

func runVault(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("want init or show")
	}
	switch args[0] {
	case "init":
		return runVaultInit(args[1:], stdin, stdout, stderr)
	case "show":
		return runVaultShow(args[1:], stdin, stdout, stderr)
	}
	return fmt.Errorf("unknown command %q, want init or show", args[0])
}

type cardList []e2e.Card

func (c *cardList) String() string { return "" }

func (c *cardList) Set(s string) error {
	card, err := e2e.ParseCard(s)
	if err != nil {
		return err
	}
	*c = append(*c, card)
	return nil
}

func runVaultInit(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("vault init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suiteName := fs.String("suite", suite.Default.String(), "primitive suite: gost or c25519")
	mailboxAddr := fs.String("mailbox", "", "host:port of the mailbox the client and its contacts use")
	var contacts cardList
	fs.Var(&contacts, "contact", "card <suite>:<base64> of the contact of one volume; once or twice, a volume each")
	fromStdin := fs.Bool("stdin", false, "read the passwords from stdin, one a line in the order of -contact, instead of generating them")
	keymem, harden := keyMemoryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := vaultFile(fs)
	if err != nil {
		return err
	}
	if err := vault.Clean(path); err != nil {
		return err
	}
	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		return err
	}
	if !pki.ValidAddr(*mailboxAddr) {
		return fmt.Errorf("-mailbox %q: want host:port in printable ASCII, lower case", *mailboxAddr)
	}
	if err := checkContacts(contacts, chosen, *mailboxAddr); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return vault.ErrExists
	}
	p, err := newProvider(chosen)
	if err != nil {
		return err
	}
	if err := protectVaultMemory(*keymem, *harden, stderr); err != nil {
		return err
	}

	passwords := make([]*secmem.Buffer, 0, len(contacts))
	defer func() {
		for _, pw := range passwords {
			pw.Release()
		}
	}()
	if *fromStdin {
		fmt.Fprintln(stderr, "WARNING: the passwords come from stdin: that the password of one volume does not give the other away is claimed only for generated passwords")
	}
	for i := range contacts {
		var pw *secmem.Buffer
		if *fromStdin {
			pw, err = readPassword(stdin)
		} else {
			pw, err = newPassword()
		}
		if err != nil {
			return fmt.Errorf("password %d: %w", i+1, err)
		}
		passwords = append(passwords, pw)
	}
	volumes := make([]vault.Contents, len(contacts))
	for i := range contacts {
		volumes[i] = vault.Contents{Password: passwords[i], Fill: numbered(i, profile.New(p, *mailboxAddr, &contacts[i]))}
	}
	if err := createVault(p, path, volumes...); err != nil {
		return removeLinked(path, err)
	}
	if !*fromStdin {
		for _, pw := range passwords {
			if _, err := stdout.Write(pw.Bytes()); err != nil {
				return err
			}
			if _, err := io.WriteString(stdout, "\n"); err != nil {
				return err
			}
		}
	}
	fmt.Fprintln(stderr, "created")
	return nil
}

// the formal checks of every card come before the first stretch; the key and
// the own card need the identity, which only the stretch gives
func checkContacts(contacts []e2e.Card, s jcrypto.Suite, addr string) error {
	switch {
	case len(contacts) == 0:
		return errors.New("no -contact given: a volume holds the card of its contact")
	case len(contacts) > 2:
		return errors.New("at most two -contact: a container has two areas")
	}
	for i, c := range contacts {
		switch {
		case c.Suite != s:
			return fmt.Errorf("-contact %d: a card of suite %v, not %v", i+1, c.Suite, s)
		case c.Mailbox != addr:
			return fmt.Errorf("-contact %d: the card names mailbox %s, not %s", i+1, c.Mailbox, addr)
		}
	}
	if len(contacts) == 2 && (bytes.Equal(contacts[0].Static, contacts[1].Static) || contacts[0].Queue == contacts[1].Queue) {
		return errors.New("-contact 2: the key or the queue of -contact 1: a contact belongs to one volume")
	}
	return nil
}

// a creation that failed after its link leaves a container whose passwords
// were never printed; it goes, so an error leaves no file
func removeLinked(path string, err error) error {
	if !errors.Is(err, vault.ErrWritten) {
		return err
	}
	if rerr := os.Remove(path); rerr != nil {
		return fmt.Errorf("%w; the file is left: %v", err, rerr)
	}
	return fmt.Errorf("%w; the file is removed", err)
}

// names the -contact a volume refused, never the area it was to take
func numbered(i int, fill vault.Fill) vault.Fill {
	return func(id *vault.Identity, buf []byte) (int, error) {
		n, err := fill(id, buf)
		if err != nil {
			return 0, fmt.Errorf("-contact %d: %w", i+1, err)
		}
		return n, nil
	}
}

func runVaultShow(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("vault show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suiteName := fs.String("suite", suite.Default.String(), "primitive suite of the container: gost or c25519")
	keymem, harden := keyMemoryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := vaultFile(fs)
	if err != nil {
		return err
	}
	if err := vault.Clean(path); err != nil {
		return err
	}
	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		return err
	}
	p, err := newProvider(chosen)
	if err != nil {
		return err
	}
	if err := protectVaultMemory(*keymem, *harden, stderr); err != nil {
		return err
	}
	pw, err := readPassword(stdin)
	if err != nil {
		return fmt.Errorf("password: %w", err)
	}
	v, err := vault.Open(p, path, pw)
	pw.Release()
	if err != nil {
		return unlockError(err)
	}
	pr, err := profile.Parse(p, v)
	v.Close()
	if err != nil {
		return unlockError(err)
	}
	defer pr.Close()
	own, err := e2e.CardHash(p, pr.Card)
	if err != nil {
		return unlockError(err)
	}
	contact, err := e2e.CardHash(p, pr.Contact)
	if err != nil {
		return unlockError(err)
	}
	_, err = fmt.Fprintf(stdout, "card=%s\ncard_hash=%x\nmailbox=%s\ncontact_card_hash=%x\n", pr.Card, own, pr.Card.Mailbox, contact)
	return err
}

// the classes of an unlock: a password that opens nothing, a volume that does
// not read, and a failure that says nothing of the volume
func unlockError(err error) error {
	switch {
	case errors.Is(err, vault.ErrNoVolume):
		return vault.ErrNoVolume
	case errors.Is(err, vault.ErrCorrupt), errors.Is(err, e2e.ErrCard):
		return vault.ErrCorrupt
	case errors.Is(err, vault.ErrNotVault):
		return vault.ErrNotVault
	case errors.Is(err, secmem.ErrNotMapped), errors.Is(err, secmem.ErrNotLocked):
		return fmt.Errorf("vault: not opened: memory: %w", err)
	}
	return fmt.Errorf("vault: not opened: io: %w", err)
}

func vaultFile(fs *flag.FlagSet) (string, error) {
	if fs.NArg() != 1 {
		return "", errors.New("want one argument after the flags, the container file")
	}
	return fs.Arg(0), nil
}

func keyMemoryFlags(fs *flag.FlagSet) (keymem *string, harden *bool) {
	keymem = fs.String("keymem", "all", "key memory measures for the passwords and keys: all, none, or a list of offheap, lock, dontdump, zero")
	harden = fs.Bool("harden", true, "disable core dumps and ptrace access for the process")
	return keymem, harden
}

func protectVaultMemory(keymem string, harden bool, stderr io.Writer) error {
	missing, err := keyMemory(keymem, harden, "refusing to take a password")
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "WARNING: the passwords and the keys they give are held without %s\n", strings.Join(missing, " and "))
	}
	if w := pagingWarning(runtime.GOOS); w != "" {
		fmt.Fprintln(stderr, w)
	}
	return nil
}

// Windows locks none of these pages, and the stretch works on the heap
// whatever the policy
func pagingWarning(goos string) string {
	if goos != "windows" {
		return ""
	}
	return "WARNING: on Windows the password, its stretch and the keys can be paged out to pagefile.sys and written to hiberfil.sys; the locked path is WSL2"
}

func newPassword() (*secmem.Buffer, error) {
	raw, err := secmem.New(passwordBytes)
	if err != nil {
		return nil, err
	}
	defer raw.Release()
	if _, err := rand.Read(raw.Bytes()); err != nil {
		return nil, err
	}
	pw, err := secmem.New(passwordEncoding.EncodedLen(passwordBytes))
	if err != nil {
		return nil, err
	}
	passwordEncoding.Encode(pw.Bytes(), raw.Bytes())
	return pw, nil
}

// one byte a read, straight into locked memory: a buffered reader would leave
// a copy on the heap and take the next password with it. One CR before the
// LF goes, so a line from Windows gives the same password
func readPassword(r io.Reader) (*secmem.Buffer, error) {
	line, err := secmem.New(jcrypto.PasswordMax + 2)
	if err != nil {
		return nil, err
	}
	defer line.Release()
	b := line.Bytes()
	n := 0
	for {
		if n == len(b) {
			return nil, fmt.Errorf("longer than %d bytes", jcrypto.PasswordMax)
		}
		k, err := r.Read(b[n : n+1])
		if k == 1 && b[n] == '\n' {
			break
		}
		n += k
		if errors.Is(err, io.EOF) {
			if n == 0 {
				return nil, errors.New("none on stdin")
			}
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if n > 0 && b[n-1] == '\r' {
		n--
	}
	if !jcrypto.ValidPassword(b[:n]) {
		return nil, fmt.Errorf("%w: want 1 to %d bytes without NUL and CR", jcrypto.ErrBadPassword, jcrypto.PasswordMax)
	}
	pw, err := secmem.New(n)
	if err != nil {
		return nil, err
	}
	copy(pw.Bytes(), b[:n])
	return pw, nil
}
