package nodeview

import (
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"testing"
)

func TestFullTaskMetadataCardinality(t *testing.T) {
	for _, row := range []struct {
		set   Set
		phase Phase
		suite jcrypto.Suite
		want  int
	}{
		{Compromise, Structural, jcrypto.SuiteC25519, 33}, {Compromise, Primary, jcrypto.SuiteC25519, 321},
		{Collude, Structural, jcrypto.SuiteC25519, 99}, {Collude, Pilot, jcrypto.SuiteC25519, 45},
		{Collude, Primary, jcrypto.SuiteGOST, 27}, {Mailbox, Structural, jcrypto.SuiteC25519, 21},
		{Mailbox, Train, jcrypto.SuiteC25519, 20}, {Mailbox, Pilot, jcrypto.SuiteC25519, 20}, {Mailbox, Primary, jcrypto.SuiteGOST, 20},
	} {
		c := Config{Set: row.set, Phase: row.phase, Suite: row.suite}
		n, e := plannedTaskCount(c, Plan{Configurations: canonicalCoordinates(row.set)})
		if e != nil || n != row.want {
			t.Fatalf("task cardinality %s/%s: got%d want%d", row.set, row.phase, n, row.want)
		}
	}
}
