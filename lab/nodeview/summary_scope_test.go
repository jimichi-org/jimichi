package nodeview

import "testing"

func TestStagePresenceRetainsLateAssociationWithoutCounterPromotion(t *testing.T) {
	for _, seal := range []int64{190, 210} {
		v := cellView{hop: 1, kind: 1, counter: 7, outputCounter: 12, inputTime: 110, localTime: 120, sealTime: seal, writeTime: 220, stages: stageInput | stageLocal | stageSealed | stagePartial | stageWritten, terminal: terminalForwarded}
		s, e := selectedCaptureSummary(viewSet{nodes: []nodeView{{cells: []cellView{v}, setups: []setupView{{hop: 1, nextPort: 1001}}}}}, 100, 200)
		if e != nil || s.Stages != [5]uint64{1, 1, 1, 1, 1} || s.Lifecycle[terminalForwarded] != 1 {
			t.Fatal("retained lifecycle presence was mistaken for per-callback membership")
		}
		// Seal190 is measured, while Seal210 and both Write220 callbacks are outside [100,200).
		matched := uint64(0)
		if seal < 200 {
			matched = 1
		}
		if s.Counters.Matched != matched || s.Counters.Samples != 1 {
			t.Fatal("late association changed counter measurement")
		}
	}
}
