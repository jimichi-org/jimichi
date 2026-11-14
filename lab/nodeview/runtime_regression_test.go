package nodeview

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/mailbox"
)

type preflightTestCircuit struct {
	send    func([]byte) error
	replies func() <-chan []byte
}

func (c preflightTestCircuit) Send(body []byte) error { return c.send(body) }
func (c preflightTestCircuit) Replies() <-chan []byte { return c.replies() }

func TestPreflightOwnedBuffersErasedOnEveryExit(t *testing.T) {
	for _, name := range []string{"send", "eof", "malformed", "tag", "timeout", "success"} {
		t.Run(name, func(t *testing.T) {
			fetch, err := secmem.New(mailbox.CapSize)
			if err != nil {
				t.Fatal(err)
			}
			defer fetch.Release()
			for i := range fetch.Bytes() {
				fetch.Bytes()[i] = byte(i + 1)
			}
			original := bytes.Clone(fetch.Bytes())
			defer clear(original)
			request := mailbox.Request{Tag: 65535}
			copy(request.Fetch[:], fetch.Bytes())
			body := request.Bytes()
			clear(request.Fetch[:])
			reply := (mailbox.Reply{Tag: 65535}).Bytes()
			responses := make(chan []byte, 1)
			want := ReasonNone
			switch name {
			case "send":
				want = ReasonClock
			case "eof":
				close(responses)
				want = ReasonSetup
			case "malformed":
				reply[0] = 0
				responses <- reply
				want = ReasonLabel
			case "tag":
				reply[1] = 0
				responses <- reply
				want = ReasonLabel
			case "timeout":
				want = ReasonSetup
			default:
				responses <- reply
			}
			circuit := preflightTestCircuit{send: func(sent []byte) error {
				if !bytes.Equal(sent[3:3+mailbox.CapSize], original) {
					t.Fatal("authenticated request lost its original fetch capability")
				}
				if name == "send" {
					return fail(ReasonClock)
				}
				return nil
			}, replies: func() <-chan []byte {
				if !bytes.Equal(body, make([]byte, len(body))) {
					t.Fatal("peer request survived into reply waiting")
				}
				return responses
			}}
			if got := reasonOf(authenticatedPreflight(circuit, body, true, time.Millisecond)); got != want {
				t.Fatalf("reason %s, want %s", got, want)
			}
			if !bytes.Equal(body, make([]byte, len(body))) || !bytes.Equal(fetch.Bytes(), original) {
				t.Fatal("request copy not erased or original owner was changed")
			}
			if name == "malformed" || name == "tag" || name == "success" {
				if !bytes.Equal(reply, make([]byte, len(reply))) {
					t.Fatal("received reply backing not erased")
				}
			}
		})
	}
}

func TestEchoPreflightRetainsBodyThroughComparisonThenErases(t *testing.T) {
	for _, equal := range []bool{false, true} {
		body := []byte{1, 2, 3, 4}
		reply := bytes.Clone(body)
		if !equal {
			reply[3]++
		}
		responses := make(chan []byte, 1)
		responses <- reply
		circuit := preflightTestCircuit{send: func([]byte) error { return nil }, replies: func() <-chan []byte {
			if !bytes.Equal(body, []byte{1, 2, 3, 4}) {
				t.Fatal("echo body erased before comparison")
			}
			return responses
		}}
		want := ReasonLabel
		if equal {
			want = ReasonNone
		}
		if got := reasonOf(authenticatedPreflight(circuit, body, false, time.Second)); got != want || !bytes.Equal(body, make([]byte, 4)) || !bytes.Equal(reply, make([]byte, 4)) {
			t.Fatal("echo comparison or all-path ownership changed")
		}
	}
}

func TestObserverBarrierHoldsReleaseAndConsumesWorkOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan struct{})
	work := make(chan error, 1)
	read := make(chan struct{})
	var cancels, closes atomic.Int32
	barrier := &observerLifetime{cancel: func() { cancels.Add(1); cancel() }, close: func() { closes.Add(1); close(closed) }, workDone: work, readDone: read}
	finished := make(chan error, 1)
	var released atomic.Bool
	go func() {
		err := barrier.join()
		released.Store(true)
		finished <- err
	}()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("barrier did not cancel")
	}
	<-closed
	if released.Load() {
		t.Fatal("release preceded observer joins")
	}
	close(read)
	if released.Load() {
		t.Fatal("release preceded workload completion")
	}
	work <- fail(ReasonLimit)
	select {
	case err := <-finished:
		if reasonOf(err) != ReasonLimit {
			t.Fatal("workload cause lost")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("barrier did not finish after both joins")
	}
	if reasonOf(barrier.join()) != ReasonLimit || reasonOf(barrier.join()) != ReasonLimit || cancels.Load() != 1 || closes.Load() != 1 {
		t.Fatal("repeated cleanup consumed work or closed twice")
	}
}

func TestPublicQueueInventoryPrecedesPrivateEligibility(t *testing.T) {
	observed := []mailboxObservation{
		{Circuit: 101, CallNS: 100, Complete: true, HasPut: true, PutQueue: 9, FetchQueue: 7, RecordKind: 1},
		{Circuit: 102, CallNS: 110, Complete: true, FetchQueue: 9},
		{Circuit: 103, CallNS: 120, Complete: true, FetchQueue: 11},
		{Circuit: 104, CallNS: 130, Complete: true, HasPut: true, PutQueue: 11, RecordKind: 3, RecordNumber: 12},
		{Circuit: 104, CallNS: 140, Complete: true, HasPut: true, PutQueue: 11, RecordKind: 3, RecordNumber: 12},
		{Circuit: 105, CallNS: 150, Complete: false, FetchQueue: 9},
		{Circuit: 106, CallNS: 200, Complete: true, FetchQueue: 9},
	}
	view, err := queueInventory(observed, 100, 200)
	if err != nil || len(view) != 4 || !reflect.DeepEqual(queueCandidates(view), []queuePair{{0, 1}, {2, 3}}) {
		t.Fatal("public handshake, one-way alias, stale put or cutoff inventory changed")
	}
	node := nodeView{position: 4}
	truth := privateTruth{}
	for i, side := range []uint16{0, 1, 2, 4} {
		circuit := uint64(i + 1)
		node.setups = append(node.setups, setupView{hop: uint32(101 + i), circuit: circuit})
		truth.ownership = append(truth.ownership, setupOwnerEntry{setupIdentity{circuit, 4}, setupOwnership{side: side, group: 1, complete: true}})
	}
	joined, falsePairs, err := evaluateQueues(node, view, truth, 3)
	// one joined original conversation and one cross-conversation edge, silent originals remain in the denominator
	if err != nil || joined.Value == nil || *joined.Value != 1.0/3 || falsePairs != 1 {
		t.Fatal("public candidate evaluation changed original-conversation denominator")
	}
	for i := range observed {
		observed[i].RecordKind = 2
		observed[i].RecordNumber = 999
		observed[i].RecordAlias = uint32(50 + i)
	}
	truth.requests = []actualRequest{{eligibility: 0, success: false}}
	truth.seals = []actualSeal{{real: false}}
	changed, err := queueInventory(observed, 100, 200)
	if err != nil || !reflect.DeepEqual(view, changed) {
		t.Fatal("private class or eligibility changed public candidates")
	}
	again, falseAgain, err := evaluateQueues(node, changed, truth, 3)
	if err != nil || again.Value == nil || *again.Value != *joined.Value || falseAgain != falsePairs {
		t.Fatal("private class or eligibility changed queue metric")
	}
	observed = append(observed, mailboxObservation{Circuit: 101, CallNS: 160, Complete: true, HasPut: true, PutQueue: 10})
	if partial, err := queueInventory(observed, 100, 200); reasonOf(err) != ReasonContract || partial != nil {
		t.Fatal("ambiguous public queue retained a partial result")
	}
}

func TestOwnedGenerationOutputClearedOnlyOnFailure(t *testing.T) {
	setups := []actualSetup{setupRecord(0, 2, 1), setupRecord(0, 1, 2), setupRecord(0, 0, 3)}
	owners := make(setupOwnershipIndex, len(setups))
	if err := parseSetupOwnershipInto(setups, owners); err != nil || len(owners) != 3 {
		t.Fatal("returned owner map erased on success")
	}
	saved := append(setupOwnershipIndex(nil), owners...)
	if _, ok := ownerOf(privateTruth{ownership: owners}, 1, 2); !ok || !reflect.DeepEqual(owners, saved) {
		t.Fatal("borrowed owner map erased by consumer")
	}
	setups = append(setups, setupRecord(0, 1, 4))
	failed := make(setupOwnershipIndex, len(setups))
	if reasonOf(parseSetupOwnershipInto(setups, failed)) != ReasonLabel || !reflect.DeepEqual(failed, make(setupOwnershipIndex, len(failed))) {
		t.Fatal("failed parser retained partial caller-owned crosswalk")
	}
}

func TestSourceBodyErasesRandomScratchOnEveryExit(t *testing.T) {
	for _, name := range []string{"read", "short", "uniform", "duplicate", "limit", "success"} {
		t.Run(name, func(t *testing.T) {
			arena := logicalChunkArena(t, 256, 256, 256, &memoryBudget{used: 256, limit: 256})
			var input [128]byte
			for i := range input {
				input[i] = byte(i + 1)
			}
			if name == "uniform" {
				for i := range input {
					input[i] = 7
				}
			}
			var declared []arenaRef
			if name == "duplicate" {
				ref, _ := arena.copy(input[:])
				declared = append(declared, ref)
			}
			if name == "limit" {
				if _, ok := arena.copy(make([]byte, 256)); !ok {
					t.Fatal("setup arena fill")
				}
			}
			var scratch [128]byte
			ref, err := declareSourceBody(arena, declared, func(target []byte) (int, error) {
				copy(target, input[:])
				switch name {
				case "read":
					return 31, errors.New("entropy read")
				case "short":
					return 127, nil
				}
				return 128, nil
			}, &scratch)
			if scratch != [128]byte{} {
				t.Fatal("random scratch backing survived return")
			}
			want := map[string]Reason{"read": ReasonChild, "short": ReasonChild, "uniform": ReasonLabel, "duplicate": ReasonLabel, "limit": ReasonLimit, "success": ReasonNone}[name]
			if reasonOf(err) != want {
				t.Fatal("body failure reason changed")
			}
			if name == "success" && !bytes.Equal(arena.bytes(ref), input[:]) {
				t.Fatal("successful owned arena body erased with scratch")
			}
			if name == "duplicate" && !bytes.Equal(arena.bytes(declared[0]), input[:]) {
				t.Fatal("borrowed declared body changed")
			}
		})
	}
}

func TestStructuredRuntimeCausesSurviveSemanticFallbacks(t *testing.T) {
	for _, cause := range []Reason{ReasonContract, ReasonIPC, ReasonClock, ReasonLabel, ReasonLimit} {
		for _, fallback := range []Reason{ReasonChild, ReasonSetup, ReasonBroken, ReasonIncomplete, ReasonRefused} {
			if got := reasonOf(semanticFailure(fail(cause), fallback)); got != cause {
				t.Fatalf("cause %s replaced by %s", cause, got)
			}
			if got := reasonOf(mergeRuntimeFailure(fail(fallback), fail(cause))); got != cause {
				t.Fatal("capture failure lost precedence")
			}
			flags := appendRuntimeReason([]Reason{fallback}, cause)
			flags = appendRuntimeReason(flags, cause)
			if !reflect.DeepEqual(flags, []Reason{fallback, cause}) {
				t.Fatal("applicable flags lost or duplicated")
			}
		}
	}
	if reasonOf(semanticFailure(errors.New("send"), ReasonBroken)) != ReasonBroken || reasonOf(semanticFailure(ErrUnsupported, ReasonBroken)) != ReasonUnsupported {
		t.Fatal("ordinary Send or unsupported semantics changed")
	}
}

func TestSegmentGapDerivationIncludesFixedTrailingZeros(t *testing.T) {
	for _, segment := range []int64{0, 20_000_000_000} {
		got := newGapRand(-117, segment)
		want := rand.New(rand.NewSource(lab.Derive(-117, uint64(segment), 0, 0, 0)))
		legacy := rand.New(rand.NewSource(lab.Derive(-117, uint64(segment))))
		different := false
		for range 10 {
			x := got.Int63()
			if x != want.Int63() {
				t.Fatal("fixed-width segment seed contract changed")
			}
			different = different || x != legacy.Int63()
		}
		if !different {
			t.Fatal("variable-width derivation unexpectedly reused")
		}
	}
}

func TestLogicalCellBinsRequireActualSetupHop(t *testing.T) {
	for _, minimal := range []bool{false, true} {
		first := nodeView{position: 0, setups: []setupView{{connection: 1, opened: 1, index: 0}}}
		second := nodeView{position: 4, setups: []setupView{{connection: 2, opened: 2, index: 2}}}
		for i := range 3 {
			stamp := int64(100_000_001 + i*100_000_000)
			if minimal {
				first.samples = append(first.samples, cellSample{connection: 1, time: stamp, kind: 1, stages: stageInput})
				second.samples = append(second.samples, cellSample{connection: 2, time: stamp, kind: 1, stages: stageInput})
			} else {
				first.cells = append(first.cells, cellView{connection: 1, inputTime: stamp, kind: 1, stages: stageInput})
				second.cells = append(second.cells, cellView{connection: 2, inputTime: stamp, kind: 1, stages: stageInput})
			}
		}
		prediction, err := predict(viewSet{nodes: []nodeView{first, second}}, publicConfig{n: 5, h: 3, epochNS: 1, cutoffNS: 20_000_000_001, binNS: 100_000_000, windowsNS: linkingGrid[:]}, frozenTraining{})
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, method := range prediction.methods {
			if method.method == "cells" || method.method == "frames" {
				seen++
				if len(method.values) != 1 {
					t.Fatal("candidate population changed")
				}
				want := -2.0
				if method.method == "frames" {
					want = 1
				}
				if method.values[0].value != want {
					t.Fatalf("minimal %t %s value %g, want %g", minimal, method.method, method.values[0].value, want)
				}
			}
		}
		if seen != 10 {
			t.Fatal("window inventory changed")
		}
		prediction.wipe()
	}
}
