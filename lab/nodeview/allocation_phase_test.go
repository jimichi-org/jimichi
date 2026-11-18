package nodeview

import (
	"testing"
	"unsafe"
)

func TestTrainingAndMetricWorkingSetKnownAnswers(t *testing.T) {
	if unsafe.Sizeof(encodedTrainingRow{}) != 42 {
		t.Fatal("training backing layout changed")
	}
	// Two 131072-row pools occupy 2*131072*42 = 11010048 bytes.
	pools := uint64(2*maxTrainingRows) * uint64(unsafe.Sizeof(encodedTrainingRow{}))
	if pools != 11010048 || pools+(64<<20)+(8<<20) != 86507520 {
		t.Fatal("simultaneous training pools were omitted")
	}
	// Unequal groups may repeat the larger group: K=2*3=6, exceeding N=4.
	n, e := metricScratchBytes(4, 2, 3)
	if e != nil || n != 2100352 {
		t.Fatal("unequal bootstrap groups undercounted")
	}
	if _, e := metricScratchBytes(4, 129, 3); e == nil {
		t.Fatal("group cap missing")
	}
	if _, e := metricScratchBytes(4, 2, 5); e == nil {
		t.Fatal("group length exceeded all observations")
	}
}

func TestSourceCapacityFixedControllerOverlapKnownAnswer(t *testing.T) {
	// 37 retained application descriptors can coexist with the later scorer descriptor
	controls := uint64(38*88 + 32*8 + 32*4 + 8*256)
	owner, e := sourceReplayBackingBytes()
	if e != nil {
		t.Fatal(e)
	}
	// the 3584-byte scan backing needs its header/class, while bounded locals occupy at most 1024 bytes
	cold := owner + 4096 + 1024
	if controls != 5776 || controls > 16384 || cold != 15984 || cold > 16384 || 8002256+16384+16384 != 8035024 || (8<<20)-8035024 != 353584 {
		t.Fatal("source-capacity controls do not fit the existing fixed reservation")
	}
}

func TestMethodRejectsScratchBeforeAnnotation(t *testing.T) {
	b := &memoryBudget{limit: 1}
	_, _, e := summarizeMethod(predictedMethod{values: []pairValue{{}}}, evaluationInput{budget: b}, "x", 0, 0)
	if reasonOf(e) != ReasonLimit || b.used != 0 {
		t.Fatal("scratch allocation preceded reservation")
	}
	b = &memoryBudget{limit: 4096}
	release, e := scratchReservation(b, 4096)
	if e != nil || b.used != 4096 {
		t.Fatal("scratch reservation")
	}
	if _, e := scratchReservation(b, 1); e == nil {
		t.Fatal("overlapping scratch escaped cap")
	}
	release()
	if b.used != 0 {
		t.Fatal("scratch release")
	}
}

func TestMailboxExtractionChecksOwnedPopulationBounds(t *testing.T) {
	for _, node := range []nodeView{
		{position: 0, mailbox: []mailboxObservation{{Circuit: 1}}},
		{position: 4, mailbox: []mailboxObservation{{}}},
	} {
		if _, e := boundedMailboxRows(node, 35000000); reasonOf(e) != ReasonContract {
			t.Fatal("unowned mailbox population")
		}
	}
	node := nodeView{position: 4}
	for i := 0; i < 33; i++ {
		node.mailbox = append(node.mailbox, mailboxObservation{Circuit: 1, FetchQueue: uint32(i + 1)})
	}
	if _, e := boundedMailboxRows(node, 35000000); reasonOf(e) != ReasonContract {
		t.Fatal("more than32 owned capabilities reached extractor maps")
	}
}
