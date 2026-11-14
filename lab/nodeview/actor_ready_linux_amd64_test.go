//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestActorReadyOwnerRejectsMalformedAndFailedRounds(t *testing.T) {
	for _, kind := range []byte{1, 2, 3} {
		for _, state := range []string{"success", "wrong-kind", "bad-bool", "trailing", "failure-eof", "failure-none", "failure-refused", "failure-clock"} {
			var wire bytes.Buffer
			token := [16]byte{kind, 11, 17}
			writer := protocolWriter{w: &wire, token: token, limit: 1024}
			body := encoder{}
			actualKind := kind
			if state == "wrong-kind" {
				actualKind = kind + 1
			}
			body.u8(actualKind)
			if state == "bad-bool" {
				body.u8(2)
			} else {
				body.bool(state == "success" || state == "wrong-kind" || state == "trailing")
			}
			if state == "trailing" {
				body.u8(1)
			}
			if e := writer.send(opReady, body); e != nil {
				t.Fatal(e)
			}
			want := ReasonIPC
			if state == "success" {
				want = ReasonNone
			}
			if state == "failure-none" || state == "failure-refused" || state == "failure-clock" {
				reason := ReasonNone
				if state == "failure-refused" {
					reason, want = ReasonRefused, ReasonRefused
				} else if state == "failure-clock" {
					reason, want = ReasonClock, ReasonClock
				}
				body := encoder{}
				body.u8(reasonByte(reason))
				if e := writer.send(opError, body); e != nil {
					t.Fatal(e)
				}
			}
			reader, e := newProtocolReader(bytes.NewReader(wire.Bytes()), token, 1024)
			if e != nil {
				t.Fatal(e)
			}
			budget := &memoryBudget{limit: 1024}
			child := &ownedChild{status: make(chan statusFrame, 3), statusBudget: budget}
			var held [][]byte
			for {
				opcode, r, e := reader.next()
				if e != nil {
					if e != io.EOF {
						t.Fatal(e)
					}
					child.status <- statusFrame{err: e}
					break
				}
				copy, charge, e := copyStatusBody(r, budget)
				if e != nil {
					t.Fatal(e)
				}
				held = append(held, copy)
				child.status <- statusFrame{op: opcode, body: copy, charged: charge}
			}
			reader.close()
			if e := child.expectReady(context.Background(), kind, time.Now().Add(5*time.Second)); reasonOf(e) != want {
				t.Fatalf("ready %d/%s: %v, want %s", kind, state, e, want)
			}
			if want == ReasonRefused || want == ReasonClock {
				if len(child.flags) != 1 || child.flags[0] != want {
					t.Fatal("failed ready round lost its structured participant error")
				}
			} else if len(child.flags) != 0 {
				t.Fatal("invalid ready round created a semantic refusal")
			}
			child.releaseStatusBody()
			if budget.used != 0 {
				t.Fatal("ready round retained its owned status loan")
			}
			for _, body := range held {
				for _, b := range body {
					if b != 0 {
						t.Fatal("ready round did not erase a consumed status body")
					}
				}
			}
		}
	}
}

func queuedPeerReady(t *testing.T, state string) (*ownedChild, *bytes.Buffer, func()) {
	t.Helper()
	budget := &memoryBudget{limit: 256}
	commands := &bytes.Buffer{}
	child := &ownedChild{role: roleClient, status: make(chan statusFrame, 3), statusBudget: budget, writer: &protocolWriter{w: commands, limit: 1024}}
	var held [][]byte
	add := func(op byte, body []byte) {
		copy, charged, e := copyStatusBody(&decoder{b: body}, budget)
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, copy)
		child.status <- statusFrame{op: op, body: copy, charged: charged}
	}
	switch state {
	case "success":
		add(opReady, []byte{3, 1})
	case "false":
		add(opReady, []byte{3, 0})
		add(opError, []byte{reasonByte(ReasonClock)})
	case "malformed":
		add(opReady, []byte{3, 2})
	case "missing":
	default:
		t.Fatal("unknown owned readiness fixture")
	}
	return child, commands, func() {
		child.releaseStatusBody()
		for len(child.status) > 0 {
			frame := <-child.status
			clear(frame.body)
			budget.release(frame.charged)
		}
		if budget.used != 0 {
			t.Fatal("readiness failure retained a status loan")
		}
		for _, body := range held {
			for _, b := range body {
				if b != 0 {
					t.Fatal("readiness failure did not clear owned status backing")
				}
			}
		}
	}
}

func TestPeerReadyBarrierRequiresBothParticipants(t *testing.T) {
	for _, row := range []struct {
		state string
		want  Reason
	}{{"success", ReasonNone}, {"missing", ReasonIPC}, {"false", ReasonClock}, {"malformed", ReasonIPC}} {
		t.Run(row.state, func(t *testing.T) {
			a, aw, releaseA := queuedPeerReady(t, "success")
			defer releaseA()
			b, bw, releaseB := queuedPeerReady(t, row.state)
			defer releaseB()
			f := &fixture{ctx: context.Background(), settings: peerSettings(false, 0), children: []*ownedChild{a, b}}
			until := time.Now().Add(20 * time.Millisecond)
			e := f.awaitClientsReady(f.children, false, &until)
			if reasonOf(e) != row.want || a.statusConsumed != 1 {
				t.Fatal("one actual kind3 or failed second round passed the cohort barrier")
			}
			if e == nil {
				if e := f.begin(monotonicNS() + int64(time.Second)); e != nil {
					t.Fatal(e)
				}
			}
			if row.want != ReasonNone && (aw.Len() != 0 || bw.Len() != 0) {
				t.Fatal("ordinary Begin preceded the complete paired barrier")
			}
			if row.state == "missing" && time.Now().Before(until) {
				t.Fatal("missing peer did not retain the shared deadline")
			}
			if row.state == "success" && (aw.Len() == 0 || bw.Len() == 0) {
				t.Fatal("complete paired barrier did not permit ordinary Begin")
			}
		})
	}
}

func TestPeerReadyDeadlineRejectsQueuedSuccess(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		for range 16 {
			child, _, release := queuedPeerReady(t, "success")
			ctx, cancel := context.WithCancel(context.Background())
			if cancelled {
				cancel()
			}
			want := ReasonIPC
			if cancelled {
				want = ReasonCancelled
			}
			if reasonOf(child.expectReady(ctx, 3, time.Now().Add(-time.Nanosecond))) != want {
				t.Fatal("queued kind3 bypassed expiry or cancellation")
			}
			cancel()
			release()
		}
	}
	child, _, release := queuedPeerReady(t, "success")
	defer release()
	f := &fixture{ctx: context.Background()}
	child.orphan = true
	until := time.Now().Add(-time.Nanosecond)
	if reasonOf(f.awaitClientsReady([]*ownedChild{child}, false, &until)) != ReasonIPC {
		t.Fatal("final aggregate guard accepted an expired exempt cohort")
	}
	child.orphan = false
	if reasonOf(f.awaitClientsReady([]*ownedChild{child}, true, &until)) != ReasonIPC {
		t.Fatal("delayed exception reset the parent deadline")
	}
	f.settings = Settings{ControlProfile: 5, DurationNS: 1}
	if reasonOf(f.begin(monotonicNS()-1)) != ReasonIPC {
		t.Fatal("actual delayed Begin accepted an expired monotonic cutoff")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.ctx = ctx
	f.settings.DurationNS = int64(time.Second)
	if reasonOf(f.begin(monotonicNS()+int64(time.Second))) != ReasonCancelled {
		t.Fatal("actual delayed Begin lost cancellation")
	}
}
