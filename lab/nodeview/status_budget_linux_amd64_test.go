//go:build linux && amd64

package nodeview

import (
	"context"
	"testing"
	"time"
)

func TestStatusCloneReservesBeforeCopyAndSurvivesUntilConsumption(t *testing.T) {
	source := []byte{1, 2, 3}
	b := &memoryBudget{limit: 2}
	if body, n, e := copyStatusBody(&decoder{b: source}, b); reasonOf(e) != ReasonLimit || body != nil || n != 0 || b.used != 0 {
		t.Fatal("over-budget status was copied")
	}
	b.limit = 8
	first, n, e := copyStatusBody(&decoder{b: source}, b)
	if e != nil || n != 3 || cap(first) != 3 || b.used != 3 {
		t.Fatal("exact status backing not charged")
	}
	child := &ownedChild{status: make(chan statusFrame, 2), statusBudget: b}
	child.status <- statusFrame{op: opBoot, body: first, charged: n}
	r, e := child.expect(context.Background(), opBoot, time.Now().Add(time.Second))
	if e != nil || r.u8() != 1 || b.used != 3 {
		t.Fatal("status released while borrowed decoder is live")
	}
	next, n, e := copyStatusBody(&decoder{b: []byte{4}}, b)
	if e != nil {
		t.Fatal(e)
	}
	child.status <- statusFrame{op: opReady, body: next, charged: n}
	if _, e := child.expect(context.Background(), opReady, time.Now().Add(time.Second)); e != nil || b.used != 1 {
		t.Fatal("previous status ownership not released")
	}
	for _, v := range first {
		if v != 0 {
			t.Fatal("previous status body not wiped")
		}
	}
	child.releaseStatusBody()
	if b.used != 0 || next[0] != 0 {
		t.Fatal("last status body not wiped and released")
	}
}
