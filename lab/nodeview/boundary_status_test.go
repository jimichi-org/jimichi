package nodeview

import (
	"github.com/jimichi-org/jimichi/mailbox"
	"testing"
)

func TestBoundaryPutFullKeepsIndependentFetchBit(t *testing.T) {
	for _, status := range []byte{mailbox.PutFull, mailbox.PutFull | mailbox.StatusRecord} {
		if !fullMailboxPut(status) {
			t.Fatal("actual full put lost when fetch returned a record")
		}
	}
	for _, status := range []byte{mailbox.PutStored | mailbox.StatusRecord, mailbox.PutRefused | mailbox.StatusRecord, mailbox.StatusBad, mailbox.StatusBad | mailbox.PutFull, mailbox.PutFull | 0x08} {
		if fullMailboxPut(status) {
			t.Fatal("invalid/stored/refused status fabricated a full put")
		}
	}
}
