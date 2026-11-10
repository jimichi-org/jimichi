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
