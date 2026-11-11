package nodeview

import (
	"bytes"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
)

var (
	mailboxControlContractError   error = failure{ReasonContract}
	mailboxControlLabelError      error = failure{ReasonLabel}
	mailboxControlIncompleteError error = failure{ReasonIncomplete}
)

func peerReadinessRole(own, peer e2e.Card) (e2e.Role, error) {
	size := 0
	switch own.Suite {
	case jcrypto.SuiteC25519:
		size = 32
	case jcrypto.SuiteGOST:
		size = 64
	}
	if size == 0 || own.Suite != peer.Suite || len(own.Static) != size || len(peer.Static) != size {
		return 0, mailboxControlContractError
	}
	switch bytes.Compare(own.Static, peer.Static) {
	case -1:
		return e2e.RoleInitiator, nil
	case 1:
		return e2e.RoleResponder, nil
	default:
		return 0, mailboxControlContractError
	}
}

func peerSessionReady(role e2e.Role, paired bool, state e2e.State) bool {
	return paired && (role == e2e.RoleInitiator && state == e2e.StateEstablished || role == e2e.RoleResponder && state == e2e.StateConfirmed)
}

func readyAcceptanceError(cancelled bool, now, until time.Time) error {
	if cancelled {
		return fail(ReasonCancelled)
	}
	if !now.Before(until) {
		return fail(ReasonIPC)
	}
	return nil
}
