package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/pki"
)

// a card of a key that nobody holds: the stand offers it to a client that
// has pinned its contact, which must refuse it
func runKeygenCard(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen-card", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suiteName := fs.String("suite", suite.Default.String(), "primitive suite: gost or c25519")
	mailboxAddr := fs.String("mailbox", "", "host:port of the mailbox the card names")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if !pki.ValidAddr(*mailboxAddr) {
		return fmt.Errorf("-mailbox %q: want host:port in printable ASCII, lower case", *mailboxAddr)
	}
	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		return err
	}
	p, err := suite.New(chosen)
	if err != nil {
		return err
	}
	f, err := secmem.New(mailbox.CapSize)
	if err != nil {
		return err
	}
	defer f.Release()
	if _, err := rand.Read(f.Bytes()); err != nil {
		return err
	}
	// F of zeroes asks for no fetch, so it names no queue
	f.Bytes()[0] |= 1
	queue, err := mailbox.QueueID(p, f.Bytes())
	if err != nil {
		return err
	}
	id, err := e2e.NewIdentity(p, *mailboxAddr, queue)
	if err != nil {
		return err
	}
	card := id.Card()
	id.Close()
	fmt.Fprintln(stdout, card.String())
	return nil
}

// the hash a client prints as card_hash= for the card it hands out
func runCardHash(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("card-hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("want one argument, the card <suite>:<base64>")
	}
	card, err := e2e.ParseCard(fs.Arg(0))
	if err != nil {
		return err
	}
	p, err := suite.New(card.Suite)
	if err != nil {
		return err
	}
	hash, err := e2e.CardHash(p, card)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%x\n", hash)
	return nil
}
