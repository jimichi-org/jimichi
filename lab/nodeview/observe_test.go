package nodeview

import (
	"encoding/binary"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestArenaExtentIncludesFragmentation(t *testing.T) {
	b, e := secmem.New(32)
	if e != nil {
		t.Fatal(e)
	}
	a := lockedArena{buffer: b}
	defer a.close()
	r, ok := a.copy(make([]byte, 12))
	if !ok {
		t.Fatal("initial allocation")
	}
	a.erase(&r)
	if _, ok = a.copy(make([]byte, 16)); !ok {
		t.Fatal("second allocation")
	}
	// a 12-byte hole cannot fit 16 bytes, so occupied extent is 28 while live size is 16
	if a.high != 28 || a.live != 16 {
		t.Fatalf("extent %d live %d", a.high, a.live)
	}
	if _, ok = a.copy(make([]byte, 5)); !ok {
		t.Fatal("hole not reused")
	}
	if _, ok = a.copy(make([]byte, 10)); ok {
		t.Fatal("fragmented capacity exceeded")
	}
}

func TestObservedCounterKnownAnswer(t *testing.T) {
	// inputs 7,8 and outputs 12,13 give two advances and one repeated shift of 5
	c := collector{start: 1, cutoff: 100, view: nodeView{cells: []cellView{{hop: 1, kind: 1, counter: 7, outputCounter: 12, localTime: 2, sealTime: 3, writeTime: 3, stages: stageInput | stageLocal | stageSealed | stageWritten}, {hop: 1, kind: 1, counter: 8, outputCounter: 13, localTime: 4, sealTime: 5, writeTime: 5, stages: stageInput | stageLocal | stageSealed | stageWritten}}}}
	c.checkCounters()
	got := c.summary.Counters
	if got.Samples != 2 || got.Transitions != 2 || got.Advanced != 2 || got.Matched != 2 || got.ShiftChecks != 1 || got.ShiftOK != 1 {
		t.Fatalf("counter witness %+v", got)
	}
	c = collector{start: 1, cutoff: 100, view: nodeView{cells: []cellView{{hop: 1, kind: 1, counter: (1 << 62) - 1, localTime: 2}, {hop: 1, kind: 1, counter: 0, localTime: 3}, {hop: 1, kind: 1, counter: 1 << 62, localTime: 4}}}}
	c.checkCounters()
	if c.summary.Counters.Advanced != 1 || c.summary.Counters.Invalid != 1 {
		t.Fatal("wrap and overflow conflated")
	}
}

func TestNonceSuiteLayoutsAndOverflow(t *testing.T) {
	var n [24]byte
	n[0] = 1
	binary.BigEndian.PutUint64(n[1:9], 37)
	binary.BigEndian.PutUint64(n[9:17], 19)
	id, count, dir, ok := decodeNonce(n[:])
	if !ok || id != 37 || count != 19 || dir != 1 {
		t.Fatal("extended nonce layout")
	}
	binary.BigEndian.PutUint64(n[9:17], 1<<62)
	if _, _, _, ok = decodeNonce(n[:]); ok {
		t.Fatal("counter overflow accepted")
	}
	var mgm [16]byte
	binary.BigEndian.PutUint64(mgm[:8], uint64(1)<<62|19)
	binary.BigEndian.PutUint64(mgm[8:], 37)
	id, count, dir, ok = decodeNonce(mgm[:])
	if !ok || id != 37 || count != 19 || dir != 1 {
		t.Fatal("MGM nonce layout")
	}
	mgm[0] |= 0x80
	if _, _, _, ok = decodeNonce(mgm[:]); ok {
		t.Fatal("MGM high bit accepted")
	}
}

func TestCounterRelationsDoNotInventExitBackwardInput(t *testing.T) {
	c := collector{start: 1, cutoff: 100, view: nodeView{setups: []setupView{{hop: 1, index: 2, nextPort: 0}}, cells: []cellView{{hop: 1, kind: 1, dir: 1, counter: 9, outputCounter: 9, localTime: 2, stages: stageInput | stageLocal}, {hop: 1, kind: 1, dir: 1, counter: 10, outputCounter: 10, localTime: 3, stages: stageInput | stageLocal}}}}
	c.checkCounters()
	if c.summary.Counters.Matched != 0 || c.summary.Counters.ShiftChecks != 0 || c.summary.Counters.Missing != 2 || c.summary.Counters.Advanced != 1 {
		t.Fatal("exit reply manufactured an incoming counter")
	}
}

func TestExitFirstUsesActualPreflightSample(t *testing.T) {
	c := collector{start: 100, cutoff: 200, view: nodeView{setups: []setupView{{hop: 1, index: 2, nextPort: 0, first: 7}}, cells: []cellView{{hop: 1, kind: 1, counter: 7, localTime: 2, stages: stageInput | stageLocal}, {hop: 1, kind: 1, counter: 8, localTime: 101, stages: stageInput | stageLocal}}}}
	c.checkCounters()
	if c.summary.Counters.FirstChecked != 1 || c.summary.Counters.FirstOK != 1 || c.summary.Counters.FirstFailed != 0 || c.summary.Counters.Samples != 1 {
		t.Fatal("preflight First and measured samples mixed")
	}
}
