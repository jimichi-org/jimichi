package nodeview

import (
	"bytes"
	"testing"
)

func TestNestedNumericReasonsCannotCarryRawText(t *testing.T) {
	for _, mutate := range []func(*Report){
		func(r *Report) { r.ModelInference[0].Point.Reason = "raw-numeric-sentinel" },
		func(r *Report) {
			r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Phase: Structural, PutQ: Number{Reason: "raw-numeric-sentinel"}}}
		},
		func(r *Report) {
			r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Phase: Structural, Methods: []MethodResult{{Method: "cells", AUC: Number{Reason: "raw-numeric-sentinel"}}}}}
		},
	} {
		r := testNodeviewReport()
		mutate(&r)
		var out bytes.Buffer
		if WriteReport(&out, r) == nil || out.Len() != 0 {
			t.Fatal("nested raw reason escaped")
		}
	}
}
