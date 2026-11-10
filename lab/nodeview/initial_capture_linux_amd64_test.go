//go:build linux && amd64

package nodeview

import "testing"

func TestAcquisitionMissingRequiredInitialViewIsUnavailable(t *testing.T) {
	t.Run("setup", func(t *testing.T) {
		testAcquisitionMissingRequiredInitialView(t, false)
	})
	t.Run("node", func(t *testing.T) {
		testAcquisitionMissingRequiredInitialView(t, true)
	})
}

func testAcquisitionMissingRequiredInitialView(t *testing.T, missingNode bool) {
	t.Helper()
	in, _ := outcomeTestInput(t, 0, 2)
	in.views.nodes[1].setups[0].opened = 1
	if missingNode {
		in.views.nodes = in.views.nodes[1:]
	} else {
		in.views.nodes[0].setups = nil
	}
	proof := captureLinkingAcquisition(in, true)
	pred := predictions{layout: &predictionLayout{first: 0, second: 1, linking: true}}
	defer pred.wipe()
	if err := completePredictionMethods(&pred); err != nil {
		t.Fatal(err)
	}
	var methods []MethodResult
	for _, method := range pred.methods {
		methods = append(methods, MethodResult{Method: method.method, WindowNS: method.windowNS, TopOne: Number{Reason: ReasonNoPartner}})
	}
	got, err := linkingTimes(methods, proof)
	if err != nil || len(got) != 2 || proof.Setup {
		t.Fatal("missing required view retained a setup certificate")
	}
	for _, link := range got {
		if link.Seconds.Value != nil || link.Censored || link.Seconds.Reason == ReasonNone || link.Seconds.Reason == ReasonCensored {
			t.Fatal("missing required capture became observed no-link censoring")
		}
	}
}
