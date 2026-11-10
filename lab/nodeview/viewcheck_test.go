package nodeview

import "testing"

func bindingTestView() nodeView {
	return nodeView{position: 0, connections: []connectionView{{generation: 1, localPort: 1000, remotePort: 3000, peer: 255, authenticated: true}, {generation: 2, localPort: 4000, remotePort: 1001, peer: 1, initiator: true, authenticated: true}}, setups: []setupView{{generation: 3, hop: 4, connection: 1, outConnection: 2, index: 0, nextPort: 1001, nextCircuit: 19}}}
}
func TestExplicitSetupSuccessorBinding(t *testing.T) {
	roster := map[uint16]int{1000: 0, 1001: 1}
	v := bindingTestView()
	if e := validateViewBindings(v, roster); e != nil {
		t.Fatal(e)
	}
	v.setups[0].outConnection = 0
	v.cells = []cellView{{kind: 3, dir: 1, circuit: 19, counter: 1, connection: 2, stages: stageWritten}}
	if _, ok := outgoing(v, v.setups[0]); ok {
		t.Fatal("header inferred an absent binding")
	}
	if e := validateViewBindings(v, roster); e != nil {
		t.Fatal("explicit unbound state is not contradictory")
	}
}
func TestExplicitSetupRejectsContradictoryReferences(t *testing.T) {
	for name, mutate := range map[string]func(*nodeView){"dangling": func(v *nodeView) { v.setups[0].outConnection = 9 }, "incoming": func(v *nodeView) { v.setups[0].outConnection = 1 }, "wrong-namespace": func(v *nodeView) { v.setups[0].outConnection = 4 }, "direction": func(v *nodeView) { v.connections[1].initiator = false }, "auth": func(v *nodeView) { v.connections[1].authenticated = false }, "port": func(v *nodeView) { v.connections[1].remotePort = 1002 }, "peer": func(v *nodeView) { v.connections[1].peer = 0 }, "duplicate": func(v *nodeView) { v.connections = append(v.connections, v.connections[1]) }, "shared-owner": func(v *nodeView) {
		s := v.setups[0]
		s.generation = 5
		s.hop = 6
		s.connection = 0
		v.setups = append(v.setups, s)
	}, "exit": func(v *nodeView) { v.setups[0].index = 2; v.setups[0].nextPort = 0 }} {
		t.Run(name, func(t *testing.T) {
			v := bindingTestView()
			mutate(&v)
			if e := validateViewBindings(v, map[uint16]int{1000: 0, 1001: 1}); e == nil {
				t.Fatal("contradictory binding accepted")
			}
		})
	}
}
