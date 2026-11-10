package nodeview

import (
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/mailbox"
)

type preflightCircuit interface {
	Send([]byte) error
	Replies() <-chan []byte
}

func authenticatedPreflight(c preflightCircuit, body []byte, peer bool, timeout time.Duration) error {
	defer secmem.Zero(body)
	err := c.Send(body)
	if peer {
		secmem.Zero(body)
	}
	if err != nil {
		return semanticFailure(err, ReasonBroken)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case reply, ok := <-c.Replies():
		defer secmem.Zero(reply)
		if !ok {
			return fail(ReasonSetup)
		}
		if !peer {
			if !equalBytes(reply, body) {
				return fail(ReasonLabel)
			}
			return nil
		}
		parsed, err := mailbox.ParseReply(reply)
		defer clear(parsed.Record[:])
		if err != nil || parsed.Tag != 65535 {
			return fail(ReasonLabel)
		}
		return nil
	case <-timer.C:
		return fail(ReasonSetup)
	}
}
