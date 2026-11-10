package nodeview

import "testing"

func TestRequiredInitialCaptureRejectsLostSelectedView(t *testing.T) {
	in, counts := outcomeTestInput(t, 0, 2)
	for ni := range in.views.nodes {
		for si := range in.views.nodes[ni].setups {
			in.views.nodes[ni].setups[si].opened = 1
		}
	}
	setup, local, err := requiredInitialCapture(in)
	if err != nil || !setup || !local {
		t.Fatal("actual complete selected initial views were rejected")
	}
	in.views.nodes[0].setups = nil
	setup, local, err = requiredInitialCapture(in)
	if err != nil || setup || local {
		t.Fatal("empty retained view certified known missing initial capture")
	}
	outcome, err := firstChainOutcomes(predictions{}, in, counts, true)
	if err != nil || outcome.ModelComplete {
		t.Fatal("capture certificate disagreed with missing required outcome evidence")
	}
}

func TestRequiredInitialCaptureKeepsCompleteOffPathAbsence(t *testing.T) {
	in, _ := outcomeTestInput(t, 3, 4)
	setup, local, err := requiredInitialCapture(in)
	if err != nil || !setup || !local {
		t.Fatal("genuine complete off-path absence became lost acquisition")
	}
	in.views.nodes = in.views.nodes[1:]
	setup, local, err = requiredInitialCapture(in)
	if err != nil || setup || local {
		t.Fatal("missing selected node became certified off-path absence")
	}
}

func TestRequiredInitialCaptureSeparatesSetupAndLocalHop(t *testing.T) {
	in, _ := outcomeTestInput(t, 0, 2)
	for ni := range in.views.nodes {
		for si := range in.views.nodes[ni].setups {
			in.views.nodes[ni].setups[si].opened = 1
		}
	}
	in.views.nodes[0].setups[0].hop = 0
	in.views.nodes[0].setups[0].stages = stageInput
	setup, local, err := requiredInitialCapture(in)
	if err != nil || !setup || local {
		t.Fatal("actual setup Open was conflated with missing local-hop creation")
	}
	in.truth.setups = in.truth.setups[:2]
	if _, _, err := requiredInitialCapture(in); err == nil {
		t.Fatal("established initial group used incomplete private construction evidence")
	}
}
