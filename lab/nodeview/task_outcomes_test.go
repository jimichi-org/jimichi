package nodeview

import (
	"reflect"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestUnavailableTaskRetainsRequestedPublicSlot(t *testing.T) {
	c := Config{Set: Mailbox, Phase: Primary, Suite: jcrypto.SuiteC25519, Seed: 11704}
	task := executionTask{coordinate: Coordinate{ID: "mail-P0-C0", Controlled: []int{4}}, plannedSides: 16, repeat: 7}
	row := unavailableTask(c, task, ReasonCancelled)
	// independent fixed-arity splitmix calculation: coordinate 13052019413353184713, phase 2465846427759072857
	if row.Configuration != "mail-P0-C0" || row.Repeat != 7 || row.Phase != Primary || row.Seed != 828828449571435933 {
		t.Fatal("unstarted slot lost its public configuration, repeat, phase or seed")
	}
	if row.Counts != (Counts{Planned: 16, Missing: 16}) || len(row.Flags) != 1 || row.Flags[0] != ReasonCancelled {
		t.Fatal("unstarted participants became attempts, successes or unplanned slots")
	}
	for _, value := range []Number{row.QueueJoined, row.PutQ, row.PutBaseline, row.RequestLDA, row.RecordLDA} {
		if value.Value != nil || value.Reason != ReasonCancelled {
			t.Fatal("unstarted slot fabricated a measurement")
		}
	}
	if row.Methods != nil || row.LinkingTimes != nil || row.RouteHistogram != nil || row.MaxRSS != 0 || row.ClockResolutionNS != 0 || row.CostsNS != ([7]int64{}) || row.Capture != (CaptureSummary{}) || row.ModelComplete {
		t.Fatal("unstarted slot fabricated observations, censoring or resource evidence")
	}
}

func TestUnavailableTaskKeepsRouteLessPeerInventoryAndMembershipScope(t *testing.T) {
	c := Config{Set: Compromise, Phase: Structural, Suite: jcrypto.SuiteGOST, Peer: true}
	for _, name := range []string{"H1", "H2", "M1", "M2"} {
		task := executionTask{coordinate: Coordinate{ID: name, Topology: "peer"}, plannedSides: 12, structural: true}
		row := unavailableTask(c, task, ReasonNone)
		if row.Configuration != name || row.Phase != Structural || row.Counts.Planned != 12 || row.Counts.Missing != 12 || len(row.Flags) != 1 || row.Flags[0] != ReasonIncomplete || row.RequestLDA.Reason != ReasonIncomplete {
			t.Fatal("route-less structural peer slot lost its chosen public inventory")
		}
	}
	task := executionTask{coordinate: Coordinate{ID: "unlisted-own-ca"}, membership: true, plannedSides: 32, routes: [][3]uint8{{0, 1, 4}, {2, 3, 4}}}
	row := unavailableTask(c, task, ReasonChild)
	if row.Counts != (Counts{Planned: 1, Missing: 1}) || row.MembershipChecks != 0 || row.MembershipRejected != 0 {
		t.Fatal("unstarted membership probe fabricated a check or expanded its unit")
	}
}

func TestUnavailableTaskDoesNotMutateTaskOrAliasResults(t *testing.T) {
	c := Config{Set: Collude, Phase: Primary, Suite: jcrypto.SuiteC25519, Seed: 117}
	task := executionTask{coordinate: Coordinate{ID: "node-F5-L0", Controlled: []int{0, 4}, ForeignPositions: []int{2}}, routes: [][3]uint8{{0, 1, 4}, {0, 3, 4}}, plannedSides: 5, foreign: []int{2}, repeat: 2}
	before := task
	before.coordinate.Controlled = append([]int(nil), task.coordinate.Controlled...)
	before.coordinate.ForeignPositions = append([]int(nil), task.coordinate.ForeignPositions...)
	before.routes = append([][3]uint8(nil), task.routes...)
	before.foreign = append([]int(nil), task.foreign...)
	row := unavailableTask(c, task, ReasonLimit)
	other := unavailableTask(c, task, ReasonLimit)
	row.Flags[0] = ReasonBroken
	if !reflect.DeepEqual(task, before) || other.Flags[0] != ReasonLimit {
		t.Fatal("unstarted result aliases a task or another result")
	}
	if other.Counts.Planned != 5 || other.Counts.Missing != 5 {
		t.Fatal("partial private route material replaced the requested participant count")
	}
}
