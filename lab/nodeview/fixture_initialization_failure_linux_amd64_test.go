//go:build linux && amd64

package nodeview

import "testing"

func TestFixtureInitializationFailurePreservesBoundEvidenceAndCleanup(t *testing.T) {
	operationBound := attachBound(fail(ReasonLimit), boundDetail{boundBudget, boundBytes, 16, 1, 16, 16})
	cleanupBound := recordBound(boundViewMailbox, maxTruthRecords, 1, maxTruthRecords)
	for _, entry := range []struct {
		name      string
		operation error
		reader    error
		child     bool
		want      Reason
		example   error
	}{
		{"operation-example", operationBound, nil, true, ReasonLimit, operationBound},
		{"cleanup-example-through-ipc", fail(ReasonIPC), cleanupBound, false, ReasonIPC, cleanupBound},
		{"first-example-wins", operationBound, cleanupBound, true, ReasonLimit, operationBound},
		{"plain-priority", fail(ReasonSetup), nil, true, ReasonChild, nil},
		{"clean-teardown", operationBound, nil, false, ReasonLimit, operationBound},
	} {
		t.Run(entry.name, func(t *testing.T) {
			f, child := readerCauseTestFixture(t, false)
			if entry.child {
				child.flags = append(child.flags, ReasonChild)
			}
			if entry.reader != nil {
				child.viewDone <- entry.reader
			}
			cancelled := false
			f.cancel = func() { cancelled = true }
			result, err := f.failInitialization(entry.operation)
			if result != nil || reasonOf(err) != entry.want || err.Error() != fail(entry.want).Error() {
				t.Fatal("initialization failure changed its fixed reason or returned a fixture")
			}
			got, present := boundEvidence(err)
			want, expected := boundEvidence(entry.example)
			if present != expected || got != want {
				t.Fatal("initialization cleanup discarded or replaced its first guard example")
			}
			if !f.closed || !cancelled || !child.reaped || f.quarantined || f.arena.buffer != nil || f.budget.used != 0 {
				t.Fatal("initialization failure skipped actual owned cleanup")
			}
		})
	}
}
