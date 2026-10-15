package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

const usage = `usage:
  jimichi enroll -suite c25519 -node name=host:port,admin=host:port,info=host:port,identity=hash [-node ...]
      certify every listed relay under a CA that lives for this run only, give
      each the roster of the listed relays and print the anchor, or print
      nothing and exit 1
  jimichi keygen-ca -suite c25519
      print the anchor of a CA key that is thrown away at once
  jimichi keygen-card -suite c25519 -mailbox host:port
      print the contact card of a client key that is thrown away at once
  jimichi card-hash <suite>:<base64>
      print the hash of a contact card, as a client prints it in card_hash=
  jimichi vault init -suite c25519 -mailbox host:port -contact <suite>:<base64> [-contact ...] [-stdin] FILE
      create a client container with one volume per -contact, each under a
      password of its own: generated and printed one a line in the order of
      -contact, or with -stdin read one a line from stdin
  jimichi vault show -suite c25519 FILE
      read the password of a volume from stdin and print the client card it
      derives, its card_hash, the mailbox and the card_hash of the contact
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runIn(args, os.Stdin, stdout, stderr)
}

func runIn(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	name := args[0]
	var err error
	switch args[0] {
	case "enroll":
		err = runEnroll(args[1:], stdout, stderr)
	case "keygen-ca":
		err = runKeygenCA(args[1:], stdout, stderr)
	case "keygen-card":
		err = runKeygenCard(args[1:], stdout, stderr)
	case "card-hash":
		err = runCardHash(args[1:], stdout, stderr)
	case "vault":
		if len(args) > 1 {
			name += " " + args[1]
		}
		err = runVault(args[1:], stdin, stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "jimichi: unknown command %q\n%s", args[0], usage)
		return 2
	}
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		fmt.Fprintf(stderr, "jimichi %s: %v\n", name, err)
		return 1
	}
	return 0
}

func runKeygenCA(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suiteName := fs.String("suite", suite.Default.String(), "primitive suite: gost or c25519")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		return err
	}
	p, err := suite.New(chosen)
	if err != nil {
		return err
	}
	ca, err := pki.NewCA(p)
	if err != nil {
		return err
	}
	anchor := ca.Anchor()
	ca.Close()
	fmt.Fprintln(stdout, anchor.String())
	return nil
}
