//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func lifecyclePacket(t *testing.T, token [16]byte, op byte) []byte {
	t.Helper()
	var output bytes.Buffer
	w := protocolWriter{w: &output, token: token, limit: 1 << 20}
	body := encoder{}
	body.u8(3)
	if err := w.send(op, body); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestProtocolReaderRejectsEveryTruncatedFrame(t *testing.T) {
	token := [16]byte{1, 3, 5, 7}
	packet := lifecyclePacket(t, token, opReady)
	for cut := 1; cut < len(packet); cut++ {
		t.Run(strconv.Itoa(cut), func(t *testing.T) {
			r, err := newProtocolReader(bytes.NewReader(packet[:cut]), token, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer r.close()
			if _, _, err = r.next(); reasonOf(err) != ReasonIPC {
				t.Fatal("truncated frame did not fail IPC validation")
			}
			if r.sequence != 0 || r.frames != 0 || r.bytes != 0 {
				t.Fatal("truncated frame advanced stream counters")
			}
		})
	}
}

func TestProtocolReaderRejectsForeignAndNoncanonicalFrames(t *testing.T) {
	token := [16]byte{2, 4, 6, 8}
	packet := lifecyclePacket(t, token, opReady)
	for _, name := range []string{"short-length", "long-length", "version-zero", "version-two", "opcode-zero", "opcode-unknown", "sequence", "token", "byte-limit", "frame-limit", "sequence-limit"} {
		t.Run(name, func(t *testing.T) {
			input := bytes.Clone(packet)
			limit := uint64(1 << 20)
			switch name {
			case "short-length":
				binary.BigEndian.PutUint32(input[:4], 25)
			case "long-length":
				binary.BigEndian.PutUint32(input[:4], 65533)
			case "version-zero":
				input[4] = 0
			case "version-two":
				input[4] = 2
			case "opcode-zero":
				input[5] = 0
			case "opcode-unknown":
				input[5] = 23
			case "sequence":
				binary.BigEndian.PutUint64(input[6:14], 1)
			case "token":
				input[14] ^= 1
			case "byte-limit":
				limit = uint64(len(input) - 1)
			}
			r, err := newProtocolReader(bytes.NewReader(input), token, limit)
			if err != nil {
				t.Fatal(err)
			}
			defer r.close()
			if name == "frame-limit" {
				r.frames = maxIPCMessages
			}
			if name == "sequence-limit" {
				r.sequence = math.MaxUint64
			}
			sequence, frames := r.sequence, r.frames
			if _, _, err = r.next(); reasonOf(err) != ReasonIPC {
				t.Fatal("invalid frame was accepted")
			}
			if r.sequence != sequence || r.frames != frames || r.bytes != 0 {
				t.Fatal("invalid frame advanced stream counters")
			}
		})
	}
}

func TestProtocolReaderRejectsReplayAfterAcceptedFrame(t *testing.T) {
	token := [16]byte{9, 8, 7, 6}
	packet := lifecyclePacket(t, token, opReady)
	input := append(bytes.Clone(packet), packet...)
	r, err := newProtocolReader(bytes.NewReader(input), token, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	op, body, err := r.next()
	if err != nil || op != opReady || body.u8() != 3 || body.end() != nil {
		t.Fatal("canonical frame was rejected")
	}
	if _, _, err = r.next(); reasonOf(err) != ReasonIPC || r.sequence != 1 || r.frames != 1 || r.bytes != uint64(len(packet)) {
		t.Fatal("replayed sequence was committed")
	}
}

type lifecycleFailureWriter struct {
	calls, failAt int
	zero          bool
}

func (w *lifecycleFailureWriter) Write(b []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		if w.zero {
			return 0, nil
		}
		return len(b) / 2, io.ErrClosedPipe
	}
	return len(b), nil
}

func TestProtocolWriterErasesBodyWithoutCommittingFailedFrame(t *testing.T) {
	for _, name := range []string{"bad-body", "bad-opcode", "byte-limit", "frame-limit", "sequence-limit", "header-write", "body-write", "zero-write"} {
		t.Run(name, func(t *testing.T) {
			output := &lifecycleFailureWriter{}
			w := protocolWriter{w: output, limit: 1 << 20}
			body := encoder{b: []byte{91, 92, 93, 94}}
			op, want := byte(opReady), ReasonIPC
			switch name {
			case "bad-body":
				body.bad = true
			case "bad-opcode":
				op = 23
			case "byte-limit":
				w.limit, want = 33, ReasonLimit
			case "frame-limit":
				w.frames = maxIPCMessages
			case "sequence-limit":
				w.sequence = math.MaxUint64
			case "header-write":
				output.failAt = 1
			case "body-write":
				output.failAt = 2
			case "zero-write":
				output.failAt, output.zero = 1, true
			}
			sequence, frames := w.sequence, w.frames
			if err := w.send(op, body); reasonOf(err) != want {
				t.Fatal("failed frame returned the wrong reason")
			}
			if w.sequence != sequence || w.frames != frames || w.bytes != 0 || !bytes.Equal(body.b, make([]byte, len(body.b))) {
				t.Fatal("failed frame committed counters or retained its body")
			}
		})
	}
}

func TestProtocolWriterDeadlineBoundsHeldOpenPipe(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	raw, err := write.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var capacity int
	var capacityErr error
	err = raw.Control(func(fd uintptr) {
		capacity, capacityErr = unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0)
	})
	if err != nil || capacityErr != nil || capacity <= 0 || capacity > 1<<20 {
		t.Fatal("pipe capacity is unavailable or outside the test bound")
	}
	if err = write.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := write.Write(make([]byte, capacity)); err != nil || n != capacity {
		t.Fatal("could not fill the owned test pipe")
	}
	w := protocolWriter{w: write, limit: 1 << 20, timeout: 20 * time.Millisecond}
	body := encoder{b: []byte{51, 52, 53}}
	done := make(chan error, 1)
	go func() { done <- w.send(opReady, body) }()
	select {
	case err := <-done:
		if reasonOf(err) != ReasonIPC || w.sequence != 0 || w.frames != 0 || w.bytes != 0 || !bytes.Equal(body.b, []byte{0, 0, 0}) {
			t.Fatal("held-open pipe committed a frame or retained its body")
		}
	case <-time.After(2 * time.Second):
		write.Close()
		t.Fatal("owned pipe write ignored its deadline")
	}
}

func TestOwnedChildExpectRejectsWrongStateAndEarlyExit(t *testing.T) {
	for _, name := range []string{"wrong-opcode", "early-eof", "error-none", "error-trailing", "cancelled", "cancelled-eof", "deadline"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			child := &ownedChild{status: make(chan statusFrame, 1)}
			deadline, want := time.Now().Add(time.Second), ReasonIPC
			switch name {
			case "wrong-opcode":
				child.status <- statusFrame{op: opCleaned}
			case "early-eof":
				child.status <- statusFrame{err: io.EOF}
			case "error-none":
				child.status <- statusFrame{op: opError, body: []byte{reasonByte(ReasonNone)}}
			case "error-trailing":
				child.status <- statusFrame{op: opError, body: []byte{reasonByte(ReasonClock), 0}}
			case "cancelled":
				cancel()
				want = ReasonCancelled
			case "cancelled-eof":
				child.status <- statusFrame{err: io.EOF}
				cancel()
				want = ReasonCancelled
			case "deadline":
				deadline = time.Now().Add(-time.Millisecond)
			}
			if _, err := child.expect(ctx, opReady, deadline); reasonOf(err) != want || len(child.flags) != 0 {
				t.Fatal("invalid child state was accepted or became a reported observation")
			}
		})
	}
}

func TestOwnedChildExpectPreservesErrorBeforeTerminal(t *testing.T) {
	child := &ownedChild{status: make(chan statusFrame, 2)}
	child.status <- statusFrame{op: opError, body: []byte{reasonByte(ReasonClock)}}
	child.status <- statusFrame{op: opEnd, body: []byte{19}}
	r, err := child.expect(context.Background(), opEnd, time.Now().Add(time.Second))
	if err != nil || r.u8() != 19 || r.end() != nil || child.statusConsumed != 2 || len(child.flags) != 1 || child.flags[0] != ReasonClock {
		t.Fatal("terminal consumption lost the preceding error or packet count")
	}
}

func TestWaitFramesRejectsExcessAndHonorsCancellation(t *testing.T) {
	var current atomic.Uint64
	current.Store(2)
	if err := waitFrames(context.Background(), &current, 1, nil, time.Now().Add(time.Second)); reasonOf(err) != ReasonIPC {
		t.Fatal("excess packets were accepted")
	}
	current.Store(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitFrames(ctx, &current, 1, nil, time.Now().Add(time.Second)); reasonOf(err) != ReasonCancelled {
		t.Fatal("missing packet wait ignored cancellation")
	}
	if err := waitFrames(context.Background(), &current, 1, nil, time.Now().Add(-time.Millisecond)); reasonOf(err) != ReasonIPC {
		t.Fatal("missing packet wait ignored its deadline")
	}
}

func TestTerminalRecordCountCannotSubstituteForPacketCount(t *testing.T) {
	for _, stream := range []string{"view", "truth"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output bytes.Buffer
			role := byte(roleRelay)
			if stream == "truth" {
				role = roleClient
			}
			child := &ownedChild{role: role, status: make(chan statusFrame), writer: &protocolWriter{w: &output, limit: 1 << 20}}
			views, truths := uint64(0), uint64(0)
			if stream == "view" {
				child.viewFrames.Store(1)
				views = 256
			} else {
				child.truthFrames.Store(1)
				truths = 256
			}
			body := encoder{}
			body.u8(0)
			body.u8(reasonByte(ReasonNone))
			body.u64(1)
			body.u64(views)
			body.u64(truths)
			encodeCounts(&body, Counts{})
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				select {
				case child.status <- statusFrame{op: opEnd, body: body.b}:
					cancel()
				case <-ctx.Done():
				}
			}()
			f := fixture{ctx: ctx}
			err := f.finishOne(child)
			cancel()
			<-sent
			if reasonOf(err) != ReasonCancelled || child.statusConsumed != 1 || output.Len() != 0 || child.reaped {
				t.Fatal("terminal record count reached acknowledgment before packet reconciliation")
			}
		})
	}
}

func TestFixtureReapRequiresEOFAndAllOutputCompletion(t *testing.T) {
	for _, name := range []string{"extra-status", "truncated-status", "held-status", "view-error", "truth-error", "missing-exit", "failed-exit"} {
		t.Run(name, func(t *testing.T) {
			child := &ownedChild{status: make(chan statusFrame, 1), viewDone: make(chan error, 1), truthDone: make(chan error, 1), exited: make(chan error, 1), watchDone: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			until := time.Now().Add(5 * time.Second)
			var staged chan struct{}
			want, reaped := ReasonIPC, false
			switch name {
			case "extra-status":
				child.status <- statusFrame{op: opEnd}
			case "truncated-status":
				child.status <- statusFrame{err: io.ErrUnexpectedEOF}
			case "held-status":
				until = time.Now().Add(-time.Millisecond)
			case "view-error":
				child.status <- statusFrame{err: io.EOF}
				child.viewDone <- fail(ReasonIPC)
			case "truth-error":
				child.status <- statusFrame{err: io.EOF}
				child.viewDone <- nil
				child.truthDone <- fail(ReasonLabel)
				want = ReasonLabel
			case "missing-exit":
				child.status = make(chan statusFrame)
				child.viewDone = make(chan error)
				child.truthDone = make(chan error)
				staged = make(chan struct{})
				want = ReasonCancelled
				go func() {
					defer close(staged)
					select {
					case child.status <- statusFrame{err: io.EOF}:
					case <-ctx.Done():
						return
					}
					select {
					case child.viewDone <- nil:
					case <-ctx.Done():
						return
					}
					select {
					case child.truthDone <- nil:
						cancel()
					case <-ctx.Done():
					}
				}()
			case "failed-exit":
				child.status <- statusFrame{err: io.EOF}
				child.viewDone <- nil
				child.truthDone <- nil
				want = ReasonChild
				child.exited <- io.ErrClosedPipe
				reaped = true
			}
			f := fixture{ctx: ctx}
			err := f.reap(child, until)
			cancel()
			if staged != nil {
				<-staged
			}
			if reasonOf(err) != want || child.reaped != reaped {
				t.Fatal("reap accepted incomplete output or misreported child ownership")
			}
		})
	}
}
