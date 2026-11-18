//go:build linux && amd64

package nodeview

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func readerCauseTestFixture(t *testing.T, held bool) (*fixture, *ownedChild) {
	t.Helper()
	budget := &memoryBudget{limit: controllerArenaBytes}
	arena, e := newBudgetedArena(4096, 4096, budget)
	if e != nil {
		t.Fatal(e)
	}
	child := &ownedChild{writer: &protocolWriter{w: io.Discard, limit: 1 << 20}, exited: make(chan error, 1), watchDone: make(chan struct{}), status: make(chan statusFrame, 8), viewDone: make(chan error, 1), truthDone: make(chan error, 1)}
	if !held {
		child.exited <- nil
	}
	f := &fixture{ctx: context.Background(), cancel: func() {}, budget: budget, arena: arena, children: []*ownedChild{child}}
	t.Cleanup(func() {
		select {
		case child.exited <- nil:
		default:
		}
		if child.readersStarted {
			for _, done := range []chan struct{}{child.statusJoined, child.viewJoined, child.truthJoined} {
				if done != nil {
					select {
					case <-done:
					default:
						close(done)
					}
				}
			}
		}
		_ = f.close()
		until := time.Now().Add(5 * time.Second)
		for quarantinedFixtures.Load() != 0 && time.Now().Before(until) {
			time.Sleep(time.Millisecond)
		}
		if quarantinedFixtures.Load() != 0 {
			t.Error("reader-cause test left unresolved quarantine")
			return
		}
		f.closeMu.Lock()
		defer f.closeMu.Unlock()
		if f.arena.buffer != nil || f.budget.used != 0 {
			t.Error("reader-cause test did not release its owned arena")
		}
	})
	return f, child
}

func TestCloseCapturesCanonicalReaderCausesBeforeAbort(t *testing.T) {
	const sentinel = "private-reader-sentinel"
	for _, entry := range []struct {
		name string
		err  error
		want Reason
	}{
		{"limit", fail(ReasonLimit), ReasonLimit},
		{"clock", fail(ReasonClock), ReasonClock},
		{"ipc", fail(ReasonIPC), ReasonIPC},
		{"contract", fail(ReasonContract), ReasonContract},
		{"label", fail(ReasonLabel), ReasonLabel},
		{"unsupported", ErrUnsupported, ReasonUnsupported},
		{"wrapped-unsupported", fmt.Errorf("%s: %w", sentinel, ErrUnsupported), ReasonUnsupported},
		{"empty-structured", fail(ReasonNone), ReasonChild},
		{"invalid-structured", fail(Reason(sentinel)), ReasonChild},
		{"ordinary", errors.New(sentinel), ReasonChild},
	} {
		t.Run(entry.name, func(t *testing.T) {
			f, child := readerCauseTestFixture(t, false)
			child.flags = []Reason{ReasonIPC}
			child.viewDone <- entry.err
			child.truthDone <- nil
			expected := appendRuntimeReason([]Reason{ReasonIPC}, entry.want)
			f.cancel = func() {
				if !reflect.DeepEqual(child.flags, expected) {
					t.Error("reader cause was not captured before cancel")
				}
				child.viewDone <- fail(ReasonPower)
				child.truthDone <- fail(ReasonBroken)
			}
			row := RunResult{}
			var result error
			closeTaskFixture(f, &row, &result)
			if reasonOf(result) != ReasonIPC || !reflect.DeepEqual(row.Flags, expected) || strings.Contains(result.Error(), sentinel) || strings.Contains(fmt.Sprint(row.Flags), sentinel) {
				t.Fatal("reader cause escaped its canonical boundary or lost existing priority")
			}
			if len(child.viewDone) != 1 || len(child.truthDone) != 1 || slices.Contains(row.Flags, ReasonPower) || slices.Contains(row.Flags, ReasonBroken) {
				t.Fatal("abort-generated reader result was resnapshotted")
			}
			before := f.causeSnapshot()
			if reasonOf(f.close()) != ReasonIPC || !reflect.DeepEqual(before, f.causeSnapshot()) || len(child.viewDone) != 1 || len(child.truthDone) != 1 {
				t.Fatal("repeated close consumed later reader results or changed its immutable cause set")
			}
		})
	}
}

func TestCloseIgnoresUnavailableCleanAndConsumedReaderResults(t *testing.T) {
	for _, kind := range []string{"nil-channels", "empty-channels", "clean", "closed", "closed-clean", "consumed"} {
		t.Run(kind, func(t *testing.T) {
			f, child := readerCauseTestFixture(t, false)
			want := ReasonNone
			switch kind {
			case "nil-channels":
				child.viewDone, child.truthDone = nil, nil
			case "clean":
				child.viewDone <- nil
				child.truthDone <- nil
			case "closed":
				close(child.viewDone)
				close(child.truthDone)
			case "closed-clean":
				child.viewDone <- nil
				child.truthDone <- nil
				close(child.viewDone)
				close(child.truthDone)
			case "consumed":
				child.viewDone <- fail(ReasonLimit)
				<-child.viewDone
				child.truthDone <- nil
				<-child.truthDone
				child.flags = []Reason{ReasonLimit}
				want = ReasonLimit
			}
			finished := make(chan error, 1)
			go func() { finished <- f.close() }()
			select {
			case e := <-finished:
				if reasonOf(e) != want {
					t.Fatal("clean or consumed reader result invented a new failure")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("close waited for an unavailable reader result")
			}
			if want == ReasonNone && len(f.causeSnapshot()) != 0 || want != ReasonNone && !reflect.DeepEqual(f.causeSnapshot(), []Reason{want}) {
				t.Fatal("existing known causes were lost or duplicated")
			}
		})
	}
}

func TestCloseKeepsBothReadyReaderCauses(t *testing.T) {
	f, child := readerCauseTestFixture(t, false)
	child.viewDone <- fail(ReasonLimit)
	child.truthDone <- fail(ReasonClock)
	want := []Reason{ReasonLimit, ReasonClock}
	f.cancel = func() {
		if !reflect.DeepEqual(child.flags, want) {
			t.Error("both reader results were not known before abort")
		}
	}
	if reasonOf(f.close()) != ReasonLimit || !reflect.DeepEqual(f.causeSnapshot(), want) {
		t.Fatal("view/truth causes were lost or their existing priority changed")
	}
}

func TestReaderCauseSnapshotRetainsQuarantineUntilWaitAndReaders(t *testing.T) {
	f, child := readerCauseTestFixture(t, true)
	child.readersStarted = true
	child.statusJoined, child.viewJoined, child.truthJoined = make(chan struct{}), make(chan struct{}), make(chan struct{})
	child.viewDone <- fail(ReasonLimit)
	child.truthDone <- nil
	f.shutdownUntil = time.Now().Add(20 * time.Millisecond)
	f.emergencyUntil = f.shutdownUntil.Add(20 * time.Millisecond)
	row := RunResult{}
	var result error
	closeTaskFixture(f, &row, &result)
	if reasonOf(result) != ReasonLimit || !slices.Contains(row.Flags, ReasonLimit) || !slices.Contains(row.Flags, ReasonChild) || !f.quarantined || f.arena.buffer == nil || f.budget.used != 4096 {
		t.Fatal("known reader error caused an early ownership release or was hidden")
	}
	rowBefore := append([]Reason(nil), row.Flags...)
	causesBefore := f.causeSnapshot()
	child.viewDone <- fail(ReasonClock)
	child.exited <- nil
	close(child.statusJoined)
	close(child.viewJoined)
	if f.arena.buffer == nil || f.budget.used != 4096 {
		t.Fatal("definitive Wait released raw state before the last reader joined")
	}
	close(child.truthJoined)
	until := time.Now().Add(5 * time.Second)
	for quarantinedFixtures.Load() != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if quarantinedFixtures.Load() != 0 {
		t.Fatal("existing Wait and reader joins did not release quarantine")
	}
	f.closeMu.Lock()
	released := !f.quarantined && f.arena.buffer == nil && f.budget.used == 0
	f.closeMu.Unlock()
	if !released || !reflect.DeepEqual(row.Flags, rowBefore) || !reflect.DeepEqual(f.causeSnapshot(), causesBefore) || len(child.viewDone) != 1 {
		t.Fatal("late cleanup changed the returned cause snapshot or released ownership twice")
	}
	if reasonOf(f.close()) != ReasonLimit || len(child.viewDone) != 1 {
		t.Fatal("late reader cause altered repeated cleanup")
	}
}
