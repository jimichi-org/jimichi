//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestEncoderClearsReplacedAndFinalBacking(t *testing.T) {
	w := encoder{}
	w.raw(bytes.Repeat([]byte{7}, 64))
	old := w.b[:cap(w.b)]
	w.u64(0x0102030405060708)
	if !bytes.Equal(old, make([]byte, len(old))) || !bytes.Equal(w.b[:64], bytes.Repeat([]byte{7}, 64)) || !bytes.Equal(w.b[64:], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("encoder replacement lost bytes or retained old prefix")
	}
	current := w.b[:cap(w.b)]
	writer := &protocolWriter{w: &lifecycleFailureWriter{failAt: 1}, limit: 1 << 20}
	if reasonOf(writer.send(opClientPlan, w)) != ReasonIPC || !bytes.Equal(current, make([]byte, len(current))) {
		t.Fatal("failed final write retained encoder backing")
	}
	bad := encoder{}
	bad.raw([]byte{1, 2, 3})
	alias := bad.b[:cap(bad.b)]
	bad.raw(make([]byte, 65507))
	if reasonOf((&protocolWriter{w: io.Discard, limit: 1 << 20}).send(opTrain, bad)) != ReasonIPC || !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatal("bad encoder prefix survived rejection")
	}
}

func TestEncoderDeniedGrowthPreservesCauseAndBorrowedInput(t *testing.T) {
	calls := 0
	budget := &memoryBudget{beforeAllocation: func(n uint64) error {
		calls++
		if calls == 2 {
			return fail(ReasonClock)
		}
		return nil
	}}
	w := encoder{budget: budget}
	input := bytes.Repeat([]byte{19}, 64)
	w.raw(input)
	owned := w.b[:cap(w.b)]
	w.u8(1)
	var output bytes.Buffer
	if reasonOf((&protocolWriter{w: &output, limit: 1 << 20}).send(opClientPlan, w)) != ReasonClock || calls != 2 || output.Len() != 0 || !bytes.Equal(owned, make([]byte, len(owned))) || !bytes.Equal(input, bytes.Repeat([]byte{19}, 64)) {
		t.Fatal("denied growth wrote a frame, lost its cause or erased borrowed input")
	}
}

func TestPredictionPreparedStorageCommitsWholeBatchWithoutGrowth(t *testing.T) {
	p := predictions{layout: &predictionLayout{first: 1, second: 2, total: 28}}
	preparePredictionStorage(&p)
	defer p.wipe()
	values := p.methods[0].values[:cap(p.methods[0].values)]
	matches := p.methods[0].matches[:cap(p.methods[0].matches)]
	batch := func(duplicateMatch bool) encoder {
		w := encoder{}
		w.u16(2)
		for second := range 2 {
			w.u8(1)
			w.u8(0)
			w.u16(0)
			w.u16(uint16(second))
			w.f64(float64(second) + .25)
			w.bool(second == 1 || duplicateMatch)
		}
		return w
	}
	invalid := batch(true)
	if reasonOf(receivePrediction(&decoder{b: invalid.b}, &p)) != ReasonIPC || p.received != 0 || p.lastBatch != 0 || p.seen[0] != 0 || len(p.methods[0].values) != 0 || len(p.methods[0].matches) != 0 {
		t.Fatal("capacity-invalid matched batch partially committed")
	}
	good := batch(false)
	if err := receivePrediction(&decoder{b: good.b}, &p); err != nil {
		t.Fatal(err)
	}
	if &p.methods[0].values[:cap(p.methods[0].values)][0] != &values[0] || &p.methods[0].matches[:cap(p.methods[0].matches)][0] != &matches[0] || !reflect.DeepEqual(p.methods[0].values, []pairValue{{0, 0, .25}, {0, 1, 1.25}}) {
		t.Fatal("valid predictions grew or changed retained storage")
	}
	oldMethods := p.methods[:cap(p.methods)]
	if err := completePredictionMethods(&p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldMethods, make([]predictedMethod, len(oldMethods))) || len(p.methods[0].values) != 2 || p.methods[0].values[1].value != 1.25 {
		t.Fatal("metadata transfer erased live values or retained old headers")
	}
}

func TestPredictionLayoutCountsAllocateNothing(t *testing.T) {
	views := viewSet{nodes: []nodeView{{setups: make([]setupView, 16)}, {setups: make([]setupView, 32)}}}
	var result predictionLayoutCounts
	allocations := testing.AllocsPerRun(10, func() {
		var err error
		result, err = countPredictionLayout(views, publicConfig{}, frozenTraining{})
		if err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 || result.total != 14*16*32 {
		t.Fatal("layout counting allocated raw index storage before admission")
	}
}

func TestPreflightRefusalRequiresExactFailureGrammar(t *testing.T) {
	for _, entry := range []struct {
		body    []byte
		want    Reason
		refused bool
	}{
		{[]byte{reasonByte(ReasonRefused)}, ReasonNone, true},
		{[]byte{reasonByte(ReasonRefused), 1}, ReasonIPC, false},
		{[]byte{reasonByte(ReasonSetup), 1}, ReasonIPC, false},
		{[]byte{reasonByte(ReasonClock)}, ReasonClock, false},
		{nil, ReasonIPC, false},
	} {
		child := &ownedChild{}
		if reasonOf(child.preflightFailure(&decoder{b: entry.body})) != entry.want || (child.reason == ReasonRefused) != entry.refused {
			t.Fatal("malformed refusal acquired semantic refusal/orphan permission")
		}
	}
}

func TestEvaluatedInputRequiresOwnedWaitAndAllReaderJoins(t *testing.T) {
	budget := &memoryBudget{limit: 1 << 20, used: 160}
	child := &ownedChild{view: nodeView{budget: budget, cells: []cellView{{counter: 19}}}, readersStarted: true, statusJoined: make(chan struct{}), viewJoined: make(chan struct{}), truthJoined: make(chan struct{})}
	views := viewSet{nodes: []nodeView{child.view}}
	pred := predictions{}
	f := &fixture{children: []*ownedChild{child}, budget: budget}
	if reasonOf(f.releaseEvaluatedInput(&views, &pred)) != ReasonChild || child.view.cells[0].counter != 19 || budget.used != 160 {
		t.Fatal("early phase release preceded definitive Wait")
	}
	child.reaped = true
	close(child.statusJoined)
	close(child.viewJoined)
	if reasonOf(f.releaseEvaluatedInput(&views, &pred)) != ReasonChild || child.view.cells[0].counter != 19 {
		t.Fatal("early phase release preceded last reader join")
	}
	close(child.truthJoined)
	if err := f.releaseEvaluatedInput(&views, &pred); err != nil || views.nodes[0].cells != nil || child.view.cells != nil || budget.used != 0 {
		t.Fatal("complete last-consumer release failed to clear both aliases exactly once")
	}
}

func TestInitialClientObserverCauseSurvivesReadyAndTerminal(t *testing.T) {
	for _, cause := range []Reason{ReasonContract, ReasonLabel, ReasonLimit, ReasonClock} {
		p := &privateCapture{err: cause}
		_, _, actual := p.completedSince(constructionMark{})
		var command, status, truth bytes.Buffer
		commands := &protocolWriter{w: &command, limit: 1 << 20}
		stop := encoder{}
		stop.u8(1)
		if err := commands.send(opStop, stop); err != nil {
			t.Fatal(err)
		}
		ack := encoder{}
		ack.u8(0)
		if err := commands.send(opAck, ack); err != nil {
			t.Fatal(err)
		}
		reader, err := newProtocolReader(&command, [16]byte{}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.close()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
		defer r.Close()
		c := &childIO{command: reader, status: &protocolWriter{w: &status, limit: 1 << 20}, view: &protocolWriter{w: io.Discard, limit: 1 << 20}, truth: &protocolWriter{w: &truth, limit: 1 << 20}}
		c.files[0] = r
		cleaned := false
		if err := initialClientFailure(c, p, Counts{Planned: 1, Attempted: 1}, func() { cleaned = true }, actual); err != nil || !cleaned {
			t.Fatal("failed initial construction did not clean through its real failure handler")
		}
		replies, err := newProtocolReader(&status, [16]byte{}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		defer replies.close()
		op, row, err := replies.next()
		if err != nil || op != opReady || row.u8() != 2 || row.bool() || row.end() != nil {
			t.Fatal("initial failure invented readiness")
		}
		op, row, err = replies.next()
		if err != nil || op != opError || decodeReason(row) != cause || row.end() != nil {
			t.Fatal("initial observer cause became setup failure")
		}
		op, row, err = replies.next()
		if err != nil || op != opEnd || row.u8() != 1 || decodeReason(row) != cause {
			t.Fatal("terminal discarded the observer cause")
		}
		row.u64()
		row.u64()
		row.u64()
		counts := decodeCounts(row)
		if row.end() != nil || counts.Planned != 1 || counts.Attempted != 1 || counts.SetupFailed != 1 || counts.Refused != 0 || counts.Established != 0 {
			t.Fatal("observer failure changed actual setup counts")
		}
	}
}

func TestQuarantineReturnsImmutableKnownCauseSnapshot(t *testing.T) {
	a := logicalChunkArena(t, 4096, 4096, 4096, &memoryBudget{limit: 4096, used: 4096})
	child := &ownedChild{writer: &protocolWriter{w: io.Discard, limit: 1 << 20}, exited: make(chan error, 1), watchDone: make(chan struct{}), status: make(chan statusFrame, 8), readersStarted: true, statusJoined: make(chan struct{}), viewJoined: make(chan struct{}), truthJoined: make(chan struct{})}
	known := encoder{}
	known.u8(reasonByte(ReasonLimit))
	child.status <- statusFrame{op: opError, body: known.b}
	f := &fixture{ctx: context.Background(), cancel: func() {}, arena: a, children: []*ownedChild{child}, shutdownUntil: time.Now().Add(10 * time.Millisecond)}
	f.emergencyUntil = f.shutdownUntil.Add(10 * time.Millisecond)
	row := RunResult{}
	var result error
	closeTaskFixture(f, &row, &result)
	if reasonOf(result) != ReasonLimit || !slices.Contains(row.Flags, ReasonLimit) || !slices.Contains(row.Flags, ReasonChild) || a.buffer == nil {
		t.Fatal("known deadline cause was lost or ownership released")
	}
	snapshot := append([]Reason(nil), row.Flags...)
	late := encoder{}
	late.u8(reasonByte(ReasonClock))
	child.status <- statusFrame{op: opError, body: late.b}
	child.exited <- errors.New("late owned exit")
	close(child.statusJoined)
	close(child.viewJoined)
	close(child.truthJoined)
	deadline := time.Now().Add(5 * time.Second)
	for quarantinedFixtures.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if quarantinedFixtures.Load() != 0 || !reflect.DeepEqual(row.Flags, snapshot) || slices.Contains(f.causeSnapshot(), ReasonClock) {
		t.Fatal("late cleanup raced or changed the returned cause snapshot")
	}
}
