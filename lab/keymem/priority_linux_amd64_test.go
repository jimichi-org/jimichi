//go:build linux && amd64

package keymem

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type priorityLowerEvidence struct {
	name  string
	apply func(*trialEvidence)
}

func priorityLowerCases() []priorityLowerEvidence {
	return []priorityLowerEvidence{
		{"oracle_invalid", func(e *trialEvidence) { e.oracle = oracleResult{Err: errOracleInvalid, Independent: true} }},
		{"capture_limit", func(e *trialEvidence) { e.parser.err = errCaptureLimit }},
		{"parse_invalid", func(e *trialEvidence) { e.parser.err = errParseInvalid }},
		{"control_failed", func(e *trialEvidence) { e.parser.err = errControlFailed }},
	}
}

func priorityTerminalStatuses(t *testing.T) (statusResult, statusResult) {
	t.Helper()
	c := ipcTestConfig()
	failed := readTestStatuses(statusTestFrame(t, &c.Nonce, 1, "failed", failedData{LastOK: "entry", ErrorClass: "workload_failed"}), c)
	cleaned := readTestStatuses(statusTestPrefix(t, c, 4), c)
	if failed.Err != nil || !failed.EOF || failed.Failed == nil || cleaned.Err != nil || !cleaned.EOF || cleaned.Cleaned == nil {
		t.Fatal("priority fixtures did not validate their terminal schemas and EOF")
	}
	return failed, cleaned
}

func TestPriorityTerminalExitContradictionsMixedEvidence(t *testing.T) {
	failed, cleaned := priorityTerminalStatuses(t)
	var rows []Trial
	for _, terminal := range []struct {
		name     string
		status   statusResult
		exitCode int
	}{
		{"failed-exit-0", failed, 0},
		{"cleaned-exit-1", cleaned, 1},
	} {
		for _, lower := range priorityLowerCases() {
			t.Run(terminal.name+"/"+lower.name, func(t *testing.T) {
				e := trialEvidence{status: terminal.status, exitCode: terminal.exitCode}
				lower.apply(&e)
				if got := resolve(e); got != "protocol_invalid" {
					t.Fatalf("terminal contradiction plus %s resolved as %s", lower.name, got)
				}
				row := aggregateTestRow("evaluated", true, [3]uint64{9, 8, 7})
				row.ID = uint64(len(rows) + 1)
				for _, member := range aggregateMembers() {
					member.set(&row, pointer(uint64(10000)))
				}
				row.terminal(resolve(e))
				if row.AnyMatch != nil || row.ErrorClass == nil || *row.ErrorClass != "protocol_invalid" {
					t.Fatal("terminal contradiction retained a primary outcome")
				}
				for _, key := range row.Keys {
					if key.Matches != nil {
						t.Fatal("terminal contradiction retained seeded key counts")
					}
				}
				raw, err := json.Marshal(row)
				if err != nil || strings.Count(string(raw), `"matches":null`) != 3 || !strings.Contains(string(raw), `"any_match":null`) {
					t.Fatal("serialized excluded row did not preserve null outcomes")
				}
				rows = append(rows, row)
			})
		}
	}
	if len(rows) != 8 {
		t.Fatal("mixed-contradiction table did not exercise exactly eight rows")
	}
	result, err := aggregate(rows)
	if err != nil {
		t.Fatal(err)
	}
	s := result["c25519/none/active"]
	// two terminal contradictions times four lower-priority classes gives eight started exclusions and no evaluated denominator
	if len(result) != 1 || s.Planned != 8 || s.Started != 8 || s.Excluded != 8 || s.Evaluated != 0 || s.NotStarted != 0 || s.TrialsWithAnyMatch != 0 || s.AnyMatchProportion != nil {
		t.Fatal("mixed contradictions changed the evaluated population")
	}
	if !reflect.DeepEqual(s.ExcludedByStatus, map[string]uint64{"protocol_invalid": 8}) {
		t.Fatal("mixed contradictions published lower-priority exclusion classes")
	}
	for _, h := range s.Hops {
		if h.TrialsWithMatch != 0 || h.Proportion != nil || h.TotalOccurrences != 0 || h.MinOccurrences != nil || h.MaxOccurrences != nil || len(h.OccurrenceHistogram) != 0 {
			t.Fatal("excluded seeded key outcomes entered a hop population")
		}
	}
	for _, population := range []map[string]Statistics{s.Coverage, s.Timing} {
		for _, statistics := range population {
			assertStatistics(t, statistics, nil, nil, 0, 0)
		}
	}
}

func TestPriorityProvisionalStatusDoesNotEstablishTerminalContradiction(t *testing.T) {
	failed, cleaned := priorityTerminalStatuses(t)
	for _, terminal := range []struct {
		name     string
		status   statusResult
		exitCode int
	}{
		{"failed-exit-0", failed, 0},
		{"cleaned-exit-1", cleaned, 1},
	} {
		for _, provisional := range []string{"missing-status-eof", "status-read-error"} {
			t.Run(terminal.name+"/"+provisional, func(t *testing.T) {
				status := terminal.status
				if provisional == "missing-status-eof" {
					status.EOF = false
				} else {
					status.Err = errProtocolInvalid
				}
				e := trialEvidence{status: status, exitCode: terminal.exitCode}
				if got := resolve(e); got != "target_failed" {
					t.Fatalf("unvalidated terminal contradiction resolved as %s", got)
				}
				for _, lower := range priorityLowerCases() {
					mixed := e
					lower.apply(&mixed)
					if got := resolve(mixed); got != lower.name {
						t.Fatalf("provisional status hid independent %s as %s", lower.name, got)
					}
				}
			})
		}
	}
}

func TestPriorityValidatedReportedCauseAndAbnormalExits(t *testing.T) {
	failed, cleaned := priorityTerminalStatuses(t)
	reported := trialEvidence{
		status:     failed,
		exitCode:   1,
		oracle:     oracleResult{Err: errOracleInvalid},
		parser:     parserEvidence{err: errCaptureIncomplete},
		cleanup:    pointer("fixture_cleanup_failed"),
		deadline:   true,
		controller: true,
	}
	if got := resolve(reported); got != "workload_failed" {
		t.Fatalf("validated cause was replaced by its short-stream or cleanup consequences: %s", got)
	}
	for _, lower := range priorityLowerCases() {
		e := reported
		lower.apply(&e)
		if got := resolve(e); got != lower.name {
			t.Fatalf("reported cause improperly outranked independent %s as %s", lower.name, got)
		}
	}
	for _, tt := range []struct {
		name     string
		evidence trialEvidence
		want     string
	}{
		{"failed-other-exit", trialEvidence{status: failed, exitCode: 7}, "target_failed"},
		{"failed-bootstrap-exit", trialEvidence{status: failed, exitCode: 2}, "target_failed"},
		{"failed-signal", trialEvidence{status: failed, exitCode: -1}, "target_failed"},
		{"cleaned-other-exit", trialEvidence{status: cleaned, exitCode: 7}, "target_failed"},
		{"cleaned-signal", trialEvidence{status: cleaned, exitCode: -1}, "target_failed"},
		{"unexplained-exit", trialEvidence{exitCode: 7}, "target_failed"},
		{"unexplained-signal", trialEvidence{exitCode: -1}, "target_failed"},
		{"premature-success", trialEvidence{exitCode: 0}, "target_failed"},
		{"bootstrap-no-status", trialEvidence{exitCode: 2}, "protocol_invalid"},
		{"deadline-owned-kill", trialEvidence{exitCode: -1, deadline: true}, "capture_timeout"},
		{"caller-owned-kill", trialEvidence{exitCode: -1, cancelled: true}, "controller_failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolve(tt.evidence); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}
