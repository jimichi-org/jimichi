//go:build linux && amd64

package nodeview

import "testing"

func TestEmptyPredictionMethodsRemainExplicitWithoutFakeScores(t *testing.T) {
	p := predictions{layout: &predictionLayout{linking: true, classifiers: [2]bool{true, true}, mailWindow: 30000000000}}
	if e := completePredictionMethods(&p); e != nil || len(p.methods) != 16 {
		t.Fatal("empty registry positions disappeared")
	}
	for _, m := range p.methods {
		if len(m.values) != 0 || len(m.matches) != 0 {
			t.Fatal("empty evidence became scores or links")
		}
	}
	if e := validatePredictions(p); e != nil {
		t.Fatal("explicit empty methods failed zero tuple coverage")
	}
}
