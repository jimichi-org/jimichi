//go:build !race

package lab

import (
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestMarkLiveGOSTSixFlowsOptimized(t *testing.T) {
	testMarkLiveSuite(t, jcrypto.SuiteGOST, 6)
}
