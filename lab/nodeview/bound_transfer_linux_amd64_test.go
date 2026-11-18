//go:build linux && amd64

package nodeview

import (
	"reflect"
	"testing"
	"time"
)

func boundViewPacket(kind byte) encoder {
	w := encoder{}
	w.u8(kind)
	w.u16(1)
	switch kind {
	case 1:
		w.u32(1)
		w.i64(0)
		w.u32(1)
		w.u8(0)
		w.u16(123)
		w.u16(456)
		w.u8(255)
		w.u16(0)
		w.bool(true)
	case 2:
		w.u32(1)
		w.i64(1)
		w.u32(0)
		w.u32(1)
		w.u32(0)
		w.u8(2)
		w.u64(5)
		w.u64(0)
		w.u64(0)
		w.u16(0)
		w.u16(0)
		w.i64(0)
		w.u32(0)
	case 3:
		encodeCell(&w, cellView{generation: 1, kind: 1, inputTime: 1, localTime: 1, stages: stageInput | stageLocal, terminal: terminalNoWrite})
	case 4:
		w.u32(1)
		w.i64(1)
		w.u32(1)
		w.u16(0)
		w.u32(0)
		w.u32(0)
		w.u32(0)
		w.bool(false)
		w.bytes(nil, 392)
		w.u8(0)
		w.u32(0)
		w.u8(0)
		w.i64(0)
		w.bool(true)
	case 5:
		w.u32(1)
		w.i64(1)
		w.u32(1)
		w.u32(0)
		w.u8(1)
		w.bool(false)
		w.bool(false)
	}
	return w
}

func TestBoundViewInventoriesExactThenOneDeficit(t *testing.T) {
	for kind := byte(1); kind <= 5; kind++ {
		for _, minimal := range []bool{false, true} {
			if kind != 3 && minimal {
				continue
			}
			t.Run(boundOriginName(boundOrigin(kind))+map[bool]string{false: "-full", true: "-minimal"}[minimal], func(t *testing.T) {
				v := nodeView{scorerProjection: minimal}
				limit := 0
				switch kind {
				case 1:
					limit = maxConnections
					v.connections = make([]connectionView, limit-1, limit)
				case 2:
					limit = maxContexts
					v.setups = make([]setupView, limit-1, limit)
				case 3:
					limit = maxLifecycles * 3
					if minimal {
						v.samples = make([]cellSample, limit-1, limit)
					} else {
						v.cells = make([]cellView, limit-1, limit)
					}
				case 4:
					limit = maxTruthRecords
					v.mailbox = make([]mailboxObservation, limit-1, limit)
				case 5:
					limit = maxLifecycles
					v.releases = make([]releaseView, limit-1, limit)
				}
				defer v.wipe()
				w := boundViewPacket(kind)
				defer w.wipe()
				if e := receiveView(&decoder{b: w.b}, &v); e != nil {
					t.Fatal("exact view inventory boundary rejected")
				}
				err := receiveView(&decoder{b: w.b}, &v)
				want := boundDetail{boundOrigin(kind), boundRecords, uint64(limit), 1, uint64(limit), uint64(limit)}
				if d, ok := boundEvidence(err); !ok || d != want || reasonOf(err) != ReasonLimit {
					t.Fatal("view limit was relabelled or lost its exact inventory")
				}
			})
		}
	}
}

func boundTruthPacket(kind byte) encoder {
	w := encoder{}
	w.u8(kind)
	w.u16(1)
	switch kind {
	case 1:
		w.u16(0)
		w.raw(make([]byte, 128))
		w.bool(false)
		w.bool(false)
	case 2:
		w.u16(0)
		w.u8(2)
		w.u64(0)
		w.u8(2)
	case 3:
		w.u16(0)
		w.u32(1)
		w.raw(make([]byte, 392))
		w.bool(false)
	case 4:
		w.u16(0)
		w.u32(1)
		w.u16(0)
		w.bytes(nil, 392)
		w.u8(1)
		w.bool(false)
	case 5:
		w.u32(1)
		w.u8(1)
		w.bytes(make([]byte, 128), 512)
	}
	return w
}

func TestBoundTruthInventoriesExactThenOneDeficit(t *testing.T) {
	for kind := byte(1); kind <= 5; kind++ {
		t.Run(boundOriginName(boundTruthMessages+boundOrigin(kind-1)), func(t *testing.T) {
			truth := privateTruth{arena: logicalChunkArena(t, 4096, 4096, 4096, nil)}
			defer truth.wipeMetadata()
			limit := 0
			switch kind {
			case 1:
				limit = maxMessages
				truth.messages = make([]actualMessage, limit-1, limit)
			case 2:
				limit = maxTruthRecords
				truth.setups = make([]actualSetup, limit-1, limit)
			case 3:
				limit = maxTruthRecords
				truth.seals = make([]actualSeal, limit-1, limit)
			case 4:
				limit = maxTruthRecords
				truth.requests = make([]actualRequest, limit-1, limit)
			case 5:
				limit = maxSelectedCells
				truth.fragments = make([]contentFragment, limit-1, limit)
			}
			w := boundTruthPacket(kind)
			defer w.wipe()
			if e := receiveTruth(&decoder{b: w.b}, &truth); e != nil {
				t.Fatal("exact per-source truth inventory rejected")
			}
			err := receiveTruth(&decoder{b: w.b}, &truth)
			want := boundDetail{boundTruthMessages + boundOrigin(kind-1), boundRecords, uint64(limit), 1, uint64(limit), uint64(limit)}
			if d, ok := boundEvidence(err); !ok || d != want || reasonOf(err) != ReasonLimit {
				t.Fatal("per-source and cohort bounds were conflated or lost")
			}
		})
	}
}

func TestBoundCheckedArenaPreservesViewLimitAndTruthIPC(t *testing.T) {
	fullArena := func() *lockedArena {
		a := logicalChunkArena(t, 392, 392, 392, nil)
		if _, ok := a.copy(make([]byte, 392)); !ok {
			t.Fatal("arena fill")
		}
		return a
	}
	view := nodeView{arena: fullArena()}
	defer view.wipe()
	w := encoder{}
	w.u8(4)
	w.u16(1)
	w.u32(1)
	w.i64(1)
	w.u32(1)
	w.u16(1)
	w.u32(1)
	w.u32(0)
	w.u32(1)
	w.bool(true)
	record := make([]byte, 392)
	record[0] = 3
	w.bytes(record, 392)
	w.u8(3)
	w.u32(0)
	w.u8(0)
	w.i64(0)
	w.bool(true)
	viewErr := receiveView(&decoder{b: w.b}, &view)
	if d, ok := boundEvidence(viewErr); !ok || d.origin != boundArenaSpace || reasonOf(viewErr) != ReasonLimit || viewErr.Error() != fail(ReasonLimit).Error() {
		t.Fatal("view arena-copy bool failure changed canonical Limit")
	}
	truth := privateTruth{arena: fullArena()}
	defer truth.wipeMetadata()
	tw := boundTruthPacket(1)
	truthErr := receiveTruth(&decoder{b: tw.b}, &truth)
	if d, ok := boundEvidence(truthErr); !ok || d.origin != boundArenaSpace || reasonOf(truthErr) != ReasonIPC || truthErr.Error() != fail(ReasonIPC).Error() {
		t.Fatal("truth copyRaw/decoder.bad no longer preserves IPC")
	}
	if view.arena.used != 392 || truth.arena.used != 392 || record[0] != 3 {
		t.Fatal("failed copies changed prior arena or borrowed record")
	}
}

func TestBoundHostDenialUsesSameProbeAndArenaKeepsInnerExample(t *testing.T) {
	for _, need := range []uint64{10, 11} {
		calls := 0
		err := currentHostGrowth(need, func() (uint64, error) { calls++; return 10, nil })
		if calls != 1 {
			t.Fatal("headroom evidence probed twice")
		}
		if need == 10 {
			if err != nil {
				t.Fatal("exact headroom equality rejected")
			}
			continue
		}
		if d, ok := boundEvidence(err); !ok || d.origin != boundHostHeadroom || d.need != 11 || d.limit != 10 || d.have != 0 || d.high != 0 {
			t.Fatal("headroom denial was reconstructed from a different sample")
		}
	}
	probeErr := fail(ReasonClock)
	if got := currentHostGrowth(1, func() (uint64, error) { return 0, probeErr }); got != probeErr {
		t.Fatal("non-Limit probe failure changed")
	}
	b := &memoryBudget{used: 8, high: 8, limit: 16}
	a := logicalChunkArena(t, 16, 8, 8, b)
	a.copy(make([]byte, 8))
	calls := 0
	b.beforeAllocation = func(n uint64) error { return currentHostGrowth(n, func() (uint64, error) { calls++; return 7, nil }) }
	_, err := a.copyChecked([]byte{1})
	if d, ok := boundEvidence(err); !ok || d.origin != boundHostHeadroom || d.need != 8 || d.limit != 7 || calls != 1 || b.used != 8 || a.used != 8 || a.allocated != 8 {
		t.Fatal("arena replaced inner physical denial or changed rollback")
	}
}

func TestBoundReadySnapshotCarriesOneImmutableExampleThroughIPC(t *testing.T) {
	f, child := readerCauseTestFixture(t, false)
	first := recordBound(boundViewMailbox, maxTruthRecords, 1, maxTruthRecords)
	second := recordBound(boundTruthFragments, maxSelectedCells, 1, maxSelectedCells)
	child.flags = []Reason{ReasonIPC}
	child.viewDone <- first
	child.truthDone <- second
	f.cancel = func() { child.viewDone <- recordBound(boundViewConnections, maxConnections, 1, maxConnections) }
	row := RunResult{}
	result := fail(ReasonIPC)
	closeTaskFixture(f, &row, &result)
	want, _ := boundEvidence(first)
	if d, ok := boundEvidence(result); !ok || d != want || reasonOf(result) != ReasonIPC || result.Error() != fail(ReasonIPC).Error() {
		t.Fatal("snapshot/close merge lost the first valid example or changed priority")
	}
	if d, ok := boundEvidence(carryBoundReason(result, ReasonIPC)); !ok || d != want {
		t.Fatal("outer reason fold discarded evidence")
	}
	if d, ok := boundEvidence(f.close()); !ok || d != want || len(child.viewDone) != 1 {
		t.Fatal("repeated cleanup replaced evidence with a later error")
	}
}

func TestBoundQuarantineDoesNotReplaceFrozenReaderExample(t *testing.T) {
	f, child := readerCauseTestFixture(t, true)
	child.readersStarted = true
	child.statusJoined, child.viewJoined, child.truthJoined = make(chan struct{}), make(chan struct{}), make(chan struct{})
	first := recordBound(boundTruthSeals, maxTruthRecords, 1, maxTruthRecords)
	child.viewDone <- first
	f.shutdownUntil = time.Now().Add(20 * time.Millisecond)
	f.emergencyUntil = f.shutdownUntil.Add(20 * time.Millisecond)
	row := RunResult{}
	var result error
	closeTaskFixture(f, &row, &result)
	want, _ := boundEvidence(first)
	flags := append([]Reason(nil), row.Flags...)
	if d, ok := boundEvidence(result); !ok || d != want || !f.quarantined || f.arena.buffer == nil || f.budget.used != 4096 {
		t.Fatal("known bound evidence released unresolved ownership")
	}
	child.viewDone <- recordBound(boundViewCells, maxLifecycles*3, 1, maxLifecycles*3)
	child.exited <- nil
	close(child.statusJoined)
	close(child.viewJoined)
	close(child.truthJoined)
	until := time.Now().Add(5 * time.Second)
	for quarantinedFixtures.Load() != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if quarantinedFixtures.Load() != 0 {
		t.Fatal("existing Wait/joins did not finish cleanup")
	}
	if d, ok := boundEvidence(f.close()); !ok || d != want || !reflect.DeepEqual(row.Flags, flags) || len(child.viewDone) != 1 {
		t.Fatal("late quarantine completion changed frozen evidence")
	}
}
