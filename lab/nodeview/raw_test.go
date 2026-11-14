package nodeview

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestRawRecordsRejectEveryFormatterAndJSON(t *testing.T) {
	for _, value := range []any{sourceReplayScratch{}, clientTruthCapacity{}, arenaRef{}, connectionView{}, setupView{}, cellView{}, cellSample{}, reassembler{}, transportView{}, frameView{}, contentFragment{}, releaseView{}, actualSetup{}, actualMessage{}, actualSeal{}, actualRequest{}, workloadPlan{}, pairValue{}, predictedMethod{}, setupOwnership{}, &collector{}, &privateCapture{}, &observedConn{}} {
		if _, e := json.Marshal(value); e == nil {
			t.Fatalf("private type %T serialized", value)
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "nodeview: private" {
				t.Fatalf("private type %T exposed fields", value)
			}
		}
	}
}
