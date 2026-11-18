//go:build linux && amd64

package nodeview

import (
	"reflect"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

func TestOutputAdmissionFollowsActualSourceWitnessAndCleanup(t *testing.T) {
	c := Config{Set: Collude, Phase: Structural, Suite: jcrypto.SuiteC25519, Seed: 117}
	task := executionTask{coordinate: Coordinate{ID: "node-F5-L0", Controlled: []int{0, 2}, Settings: echoSettings(0)}}
	truth := privateTruth{setups: append(outcomeTestGroup(0, [3]uint8{0, 1, 2}, 100), outcomeTestGroup(1, [3]uint8{0, 1, 2}, 300)...)}
	views := viewSet{nodes: []nodeView{{position: 0, setups: []setupView{{circuit: 100}, {circuit: 300}}}, {position: 2, setups: []setupView{{circuit: 102}, {circuit: 302}}}}}
	m := predictedMethod{method: "setup"}
	for _, s := range metrics.SetupLagScores([]time.Duration{100, 310}, []time.Duration{300, 315}, nil) {
		m.values = append(m.values, pairValue{s.Entry, s.Exit, s.Value})
	}
	raw := &memoryBudget{limit: controllerArenaBytes}
	output := &memoryBudget{limit: controllerArenaBytes}
	charge := &resultCharge{budget: raw}
	seed := nodeSeed(c, coordinateID(task.coordinate.ID), 0, 0, lab.StreamNodeBootstrap)
	method, audit, e := summarizeMethod(m, evaluationInput{budget: raw, resultCharge: charge, truth: truth, views: views}, task.coordinate.ID, 0, seed)
	if e != nil {
		t.Fatal(e)
	}
	row := RunResult{Configuration: task.coordinate.ID, Phase: c.Phase, Seed: nodeSeed(c, coordinateID(task.coordinate.ID), 0, 0, lab.StreamNodeMain), Methods: []MethodResult{method}}
	c.outputBudget = output
	if e := admitTaskOutput(c, task, row, []RankAudit{audit}, charge); reasonOf(e) != ReasonContract || raw.used == 0 || output.used != 0 {
		t.Fatal("output admitted before raw cleanup")
	}
	charge.cleaned()
	if e := charge.hold(runResultBacking(row)); e != nil {
		t.Fatal(e)
	}
	if e := admitTaskOutput(c, task, row, []RankAudit{audit}, charge); e != nil || raw.used != 0 || output.used == 0 {
		t.Fatal("clean witness did not transfer exactly once")
	}
	before := make([][]RankBucket, len(audit.Groups))
	for i := range before {
		before[i] = append([]RankBucket(nil), audit.Groups[i]...)
	}
	for i := range m.values {
		m.values[i] = pairValue{}
	}
	clear(truth.setups)
	clear(views.nodes)
	if !reflect.DeepEqual(before, audit.Groups) {
		t.Fatal("released output aliases raw observation backing")
	}
	bad := c
	bad.Seed++
	if e := admitTaskOutput(bad, task, row, []RankAudit{audit}, &resultCharge{clean: true}); e == nil {
		t.Fatal("different seed released same witness")
	}
}

func TestGOSTDescriptiveTaskMultiplicity(t *testing.T) {
	c := Config{Set: Collude, Phase: Primary, Suite: jcrypto.SuiteGOST, Seed: 117}
	tasks := registeredTasks(c, Plan{Configurations: canonicalCoordinates(Collude)})
	if len(tasks) != 27 {
		t.Fatal("GOST descriptive coordinates changed")
	}
	seen := map[string]bool{}
	for _, task := range tasks {
		if task.repeat != 0 || seen[task.coordinate.ID] {
			t.Fatal("GOST descriptive run duplicated")
		}
		seen[task.coordinate.ID] = true
	}
}
