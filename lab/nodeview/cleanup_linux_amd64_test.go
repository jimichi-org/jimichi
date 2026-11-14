//go:build linux && amd64

package nodeview

import (
	"context"
	"io"
	"os/exec"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestUnreapedChildRetainsArenaReservationAndBlocksCohorts(t *testing.T) {
	buffer, e := secmem.New(4096)
	if e != nil {
		t.Fatal(e)
	}
	ch := &ownedChild{cmd: &exec.Cmd{}, writer: &protocolWriter{w: io.Discard, limit: 1 << 20}, exited: make(chan error, 1), watchDone: make(chan struct{})}
	f := &fixture{ctx: context.Background(), cancel: func() {}, children: []*ownedChild{ch}, arena: &lockedArena{buffer: buffer}, budget: &memoryBudget{used: 8192, limit: controllerArenaBytes}, scorerReservation: 8192}
	f.shutdownUntil = time.Now().Add(20 * time.Millisecond)
	f.emergencyUntil = f.shutdownUntil.Add(20 * time.Millisecond)
	result := RunResult{}
	var resultErr error
	closeTaskFixture(f, &result, &resultErr)
	if reasonOf(resultErr) != ReasonChild || len(result.Flags) != 1 || result.Flags[0] != ReasonChild || ch.reaped || !f.quarantined || f.arena.buffer == nil || f.scorerReservation != 8192 || f.budget.used != 8192 {
		t.Fatal("unreaped ownership was released or hidden")
	}
	if _, e := newFixture(context.Background(), 0, Settings{}, 0, nil, nil, "", 0, fixtureResources{}); reasonOf(e) != ReasonChild {
		t.Fatal("quarantined series allocated another cohort")
	}
	if reasonOf(f.close()) != ReasonChild {
		t.Fatal("repeated cleanup cleared quarantine")
	}
	ch.exited <- nil
	until := time.Now().Add(time.Second)
	for quarantinedFixtures.Load() != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if quarantinedFixtures.Load() != 0 {
		t.Fatal("definitive Wait did not release quarantine")
	}
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if !ch.reaped || f.arena.buffer != nil || f.scorerReservation != 0 || f.budget.used != 0 {
		t.Fatal("definitive Wait did not wipe retained storage")
	}
}
