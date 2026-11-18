//go:build linux && amd64

package nodeview

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCloseTrainingRolePreservesOperationResourceAndCleanupPriority(t *testing.T) {
	const sentinel = "private-training-cleanup-sentinel"
	for _, entry := range []struct {
		name      string
		operation error
		resource  error
		cleanup   bool
		want      Reason
	}{
		{"operation-ipc", fail(ReasonIPC), nil, true, ReasonIPC},
		{"operation-limit", fail(ReasonLimit), fail(ReasonChild), true, ReasonLimit},
		{"resource-clock", fail(ReasonSetup), fail(ReasonClock), true, ReasonClock},
		{"resource-only", nil, fail(ReasonLimit), false, ReasonLimit},
		{"cleanup-only", nil, nil, true, ReasonChild},
		{"clean", nil, nil, false, ReasonNone},
	} {
		t.Run(entry.name, func(t *testing.T) {
			budget := &memoryBudget{limit: 4096}
			arena, err := newBudgetedArena(64, 64, budget)
			if err != nil {
				t.Fatal(err)
			}
			child := &ownedChild{reaped: true}
			if entry.cleanup {
				child.waitErr = errors.New(sentinel)
			}
			cancelled := false
			f := &fixture{ctx: context.Background(), cancel: func() { cancelled = true }, budget: budget, arena: arena, children: []*ownedChild{child}}
			t.Cleanup(func() { _ = f.close() })
			got := closeTrainingRole(f, entry.operation, entry.resource)
			if reasonOf(got) != entry.want || !f.closed || !cancelled || f.quarantined || f.arena.buffer != nil || budget.used != 0 {
				t.Fatal("training finalization lost failure priority or skipped actual cleanup")
			}
			if got != nil && strings.Contains(got.Error(), sentinel) {
				t.Fatal("training cleanup leaked an ordinary error into the fixed result")
			}
		})
	}
}
