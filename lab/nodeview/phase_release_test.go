package nodeview

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"
)

func TestEvaluatedParentReleasePreservesRemainingConsumers(t *testing.T) {
	budget := &memoryBudget{used: 4096, limit: 1 << 20}
	arena := logicalChunkArena(t, 4096, 4096, 4096, budget)
	ref, ok := arena.copy([]byte{1, 2, 3, 4})
	if !ok {
		t.Fatal("arena setup")
	}
	view := nodeView{budget: budget, arena: arena, cells: make([]cellView, 1, 2), mailbox: []mailboxObservation{{Circuit: 3, record: ref}}, setups: []setupView{{circuit: 9}}}
	view.cells[0].counter = 81
	view.cells[:cap(view.cells)][1].counter = 91
	truth := privateTruth{budget: budget, arena: arena, messages: []actualMessage{{side: 2, body: ref}}}
	pred := predictions{layout: &predictionLayout{first: 1, total: 0}, methods: []predictedMethod{{method: "cells", values: []pairValue{{0, 0, .75}}}}}
	retained := predictionBackingBytes(pred)
	budget.used += uint64(cap(view.cells))*uint64(unsafe.Sizeof(cellView{})) + uint64(cap(truth.messages))*uint64(unsafe.Sizeof(actualMessage{})) + retained
	cells, messages, values := view.cells[:cap(view.cells)], truth.messages, pred.methods[0].values
	witness := RankAudit{Groups: [][]RankBucket{{{Rank: 1, Positive: 1}}}}
	training := []encodedTrainingRow{{Positive: true, Conversation: 3}}
	training[0].Values[2] = 42
	if got := clearEvaluatedOwner(&view, &truth, &pred); got != retained || budget.used != 4096+retained {
		t.Fatal("phase release double charged or released prediction ownership prematurely")
	}
	budget.release(retained)
	if !reflect.DeepEqual(cells, make([]cellView, len(cells))) || !reflect.DeepEqual(messages, make([]actualMessage, len(messages))) || !reflect.DeepEqual(values, make([]pairValue, len(values))) || len(view.cells) != 0 || truth.messages != nil || pred.layout != nil {
		t.Fatal("last-consumer raw backing survived release")
	}
	if !bytes.Equal(arena.bytes(ref), []byte{1, 2, 3, 4}) || view.mailbox[0].record != ref || view.setups[0].circuit != 9 || witness.Groups[0][0].Positive != 1 || training[0].Values[2] != 42 || budget.used != 4096 {
		t.Fatal("phase release changed arena, classifier, witness or returned training material")
	}
}
