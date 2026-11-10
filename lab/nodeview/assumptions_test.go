package nodeview

import "testing"

func TestObservedSetupOverlapUsesCapturedIntervals(t *testing.T) {
	route := [3]uint8{0, 1, 2}
	in := evaluationInput{truth: privateTruth{setups: append(outcomeTestGroup(0, route, 100), outcomeTestGroup(1, route, 300)...)}, views: viewSet{nodes: []nodeView{{position: 0, setups: []setupView{{circuit: 100, hop: 1, opened: 100}, {circuit: 300, hop: 3, opened: 310}}}, {position: 2, setups: []setupView{{circuit: 102, hop: 2, opened: 300}, {circuit: 302, hop: 4, opened: 320}}}}}}
	if n, e := observedSetupOverlap(in); e != nil || n != 0 {
		t.Fatal("strict serial intervals rejected")
	}
	in.views.nodes[0].setups[1].opened = 300
	if n, e := observedSetupOverlap(in); e != nil || n != 1 {
		t.Fatal("equal boundary accepted as strict serial")
	}
	in.views.nodes[0].setups[1].opened = 250
	if n, e := observedSetupOverlap(in); e != nil || n != 1 {
		t.Fatal("actual overlap not counted")
	}
	in.views.nodes[0].setups[0].opened = 0
	if _, e := observedSetupOverlap(in); reasonOf(e) != ReasonClock {
		t.Fatal("missing callback clock became measured zero")
	}
}

func TestBindingRejectsHistoricalTupleReuse(t *testing.T) {
	node := bindingTestView()
	duplicate := node.connections[1]
	duplicate.generation = 99
	node.connections = append(node.connections, duplicate)
	if validateViewBindings(node, map[uint16]int{1000: 0, 1001: 1}) == nil {
		t.Fatal("tuple reuse escaped generation checks")
	}
}
