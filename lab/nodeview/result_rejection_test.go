package nodeview

import (
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab"
)

func TestRejectedTaskClearsOwnedMeasurementsBeforeFallback(t *testing.T) {
	for _, path := range []string{"raw-hold", "output-admission", "fallback-admission", "invalid-counts"} {
		t.Run(path, func(t *testing.T) {
			c := Config{Phase: Structural, Seed: -117}
			task := executionTask{coordinate: Coordinate{ID: "node-1", Controlled: []int{0, 4}}, plannedSides: 4}
			row := unavailableTask(c, task, ReasonBroken)
			row.Counts = Counts{Planned: 4, Attempted: 3, Established: 1, PreflightOK: 1, MessageBearing: 1, Refused: 1, SetupFailed: 1, Rebuilt: 3, Unanswered: 2}
			row.Methods = make([]MethodResult, 1, 16)
			row.Methods[0] = MethodResult{Method: "setup", Candidates: 2, Partners: 1, Made: 1, AUC: number(1, ReasonNone), TPR: number(1, ReasonNone), TopOne: number(1, ReasonNone)}
			row.Methods[:cap(row.Methods)][1].AUC = number(.7, ReasonNone)
			row.LinkingTimes = []LinkingTime{{Method: "cells", Seconds: number(2, ReasonNone)}}
			row.RouteHistogram = []uint64{1, 2, 3}
			row.QueueJoined = number(.5, ReasonNone)
			row.CostsNS[0], row.MaxRSS, row.Capture.Calls = 99, 100, 9
			audit := RankAudit{Configuration: row.Configuration, Repeat: row.Repeat, Method: "setup", Seed: nodeSeed(c, coordinateID(row.Configuration), uint64(row.Repeat), 0, lab.StreamNodeBootstrap), Groups: [][]RankBucket{{{Rank: 1, Negative: 1}, {Rank: 2, Positive: 1, Category: 1}}}, TopOne: [][2]int{{1, 1}}, Made: 1}
			if err := validateRankRelease(row.Methods[0], audit); err != nil {
				t.Fatal(err)
			}
			methods := row.Methods[:cap(row.Methods)]
			times, histogram := row.LinkingTimes, row.RouteHistogram
			metric, ghost, linked := row.Methods[0].AUC.Value, row.Methods[:cap(row.Methods)][1].AUC.Value, row.QueueJoined.Value
			buckets, top := audit.Groups[0], audit.TopOne
			raw := &memoryBudget{limit: 1 << 20}
			charge := &resultCharge{budget: raw, bytes: rankAuditBacking(audit), clean: true, proofs: 1}
			raw.used = charge.bytes
			c.outputBudget = &memoryBudget{limit: runResultBacking(RunResult{}) + 128}
			if runResultBacking(row)+charge.bytes <= c.outputBudget.limit {
				t.Fatal("fixture does not distinguish nested result from failure descriptor")
			}
			switch path {
			case "raw-hold":
				raw.limit = raw.used
			case "fallback-admission":
				c.outputBudget.limit = 0
			case "invalid-counts":
				row.Counts.Established = 4
			}
			prior := RunResult{Configuration: "prior", Methods: []MethodResult{{Method: "setup", AUC: number(.75, ReasonNone)}}}
			report := Report{Runs: make([]RunResult, 1, 2)}
			report.Runs[0] = prior
			priorBytes := uint64(cap(report.Runs))*uint64(unsafe.Sizeof(RunResult{})) + runResultBacking(prior)
			c.outputBudget.used = priorBytes
			c.outputBudget.limit += priorBytes
			stub, returned, err := finalizeTaskOutput(c, task, row, []RankAudit{audit}, charge)
			if err == nil || len(returned) != 0 || raw.used != 0 || charge.bytes != 0 || !charge.discarded {
				t.Fatal("rejection left its raw result charge live after known cleanup")
			}
			if *metric != 0 || *ghost != 0 || *linked != 0 || !reflect.DeepEqual(methods, make([]MethodResult, len(methods))) || !reflect.DeepEqual(times, make([]LinkingTime, len(times))) || !reflect.DeepEqual(histogram, make([]uint64, len(histogram))) || !reflect.DeepEqual(buckets, make([]RankBucket, len(buckets))) || !reflect.DeepEqual(top, make([][2]int, len(top))) {
				t.Fatal("rejected owned backing survived admission failure")
			}
			if path == "fallback-admission" || path == "invalid-counts" {
				if stub.Configuration != "" {
					t.Fatal("unadmitted or untrustworthy descriptor was retained")
				}
				return
			}
			if stub.Configuration != task.coordinate.ID || stub.Counts.Planned != 4 || stub.Counts.Attempted != 3 || stub.Counts.Established != 1 || stub.Counts.Refused != 1 || stub.Counts.SetupFailed != 1 || stub.Counts.Rebuilt != 3 || stub.Counts.Unanswered != 2 || stub.Counts.Missing != 4 || !slices.Contains(stub.Flags, ReasonIncomplete) || !slices.Contains(stub.Flags, ReasonLimit) {
				t.Fatal("failed descriptor lost known execution or admission causes")
			}
			if len(stub.Methods) != 0 || len(stub.RouteHistogram) != 0 || len(stub.LinkingTimes) != 0 || stub.QueueJoined.Value != nil || stub.CostsNS != [7]int64{} || stub.MaxRSS != 0 || stub.Capture != (CaptureSummary{}) {
				t.Fatal("failure descriptor retained unadmitted measurements")
			}
			if err := appendTaskOutput(&report, c.outputBudget, stub, nil); err != nil || !reflect.DeepEqual(report.Runs[0], prior) {
				t.Fatal("bounded failure append changed prior admitted output")
			}
		})
	}
}
