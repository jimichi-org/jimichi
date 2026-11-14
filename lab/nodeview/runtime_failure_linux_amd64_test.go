//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

func TestFixtureShutdownUsesOneCohortDeadline(t *testing.T) {
	f := &fixture{}
	before := time.Now()
	normal, emergency := f.shutdownDeadlines()
	after := time.Now()
	if normal.Before(before.Add(10*time.Second)) || normal.After(after.Add(10*time.Second)) || emergency.Sub(normal) != 2*time.Second {
		t.Fatal("shutdown grace changed")
	}
	if again, last := f.shutdownDeadlines(); again != normal || last != emergency {
		t.Fatal("cleanup renewed cohort deadlines")
	}
}

func TestClientTruthReceivedMessageOwnResourceRefusal(t *testing.T) {
	for _, resource := range []string{"stream", "frames", "scalar", "arena", "sticky"} {
		t.Run(resource, func(t *testing.T) {
			p := capacityTestCapture(t)
			storage := p.truth.messages
			defer func() { p.truth.messages = storage[:len(p.truth.messages)] }()
			blockMessageResource(p, resource)
			want := ReasonLimit
			if resource == "sticky" {
				p.err, want = ReasonContract, ReasonContract
			}
			body := bytes.Repeat([]byte{7}, 128)
			before := capturePrefix(p)
			markPeerReply(p, body)
			if p.err != want || !bytes.Equal(body, bytes.Repeat([]byte{7}, 128)) {
				t.Fatal("receive refusal changed the borrowed body or precise sticky cause")
			}
			assertCapturePrefix(t, p, before)
			p.truth.messages = storage[:0]
			p.truth.setups = p.truth.setups[:0]
			p.truth.capacity = clientTruthCapacity{}
			p.truth.arena.used = 0
			after := capturePrefix(p)
			markPeerReply(p, body)
			if p.err != want {
				t.Fatal("later receive replaced its first failure")
			}
			assertCapturePrefix(t, p, after)
		})
	}
}

func TestClientTruthReceivedMessageRejectsMalformedWidthBeforeRetention(t *testing.T) {
	for _, width := range []int{0, 127, 129} {
		p := capacityTestCapture(t)
		body := bytes.Repeat([]byte{7}, width)
		before := capturePrefix(p)
		markPeerReply(p, body)
		if p.err != ReasonLabel || !bytes.Equal(body, bytes.Repeat([]byte{7}, width)) {
			t.Fatal("malformed received width was treated as a capacity refusal or changed its input")
		}
		assertCapturePrefix(t, p, before)
		markPeerReply(p, bytes.Repeat([]byte{8}, 128))
		if p.err != ReasonLabel {
			t.Fatal("valid later receive replaced the malformed-width cause")
		}
		assertCapturePrefix(t, p, before)
	}
}

func TestClientTruthReceivedMessageExactArenaFitCopiesOnce(t *testing.T) {
	p := capacityTestCapture(t)
	p.side = 3
	p.truth.arena.used = clientArenaBytes - 128
	body := bytes.Repeat([]byte{7}, 128)
	markPeerReply(p, body)
	if p.err != ReasonNone || len(p.truth.messages) != 1 || p.truth.arena.used != clientArenaBytes || p.truth.capacity.messages != 1 || p.truth.capacity.wireBytes != 165 || p.truth.capacity.frames != 1 {
		t.Fatal("received body did not use its exact final arena extent")
	}
	m := p.truth.messages[0]
	if m.side != 3 || m.sent || !m.replied || m.body.offset != clientArenaBytes-128 || m.body.size != 128 || !bytes.Equal(p.truth.arena.bytes(m.body), body) || &p.truth.arena.bytes(m.body)[0] == &body[0] {
		t.Fatal("received row lost ownership, reply facts or its separate protected copy")
	}
	clear(body)
	if !bytes.Equal(p.truth.arena.bytes(m.body), bytes.Repeat([]byte{7}, 128)) {
		t.Fatal("received protected body retained a borrowed caller alias")
	}
}

func TestClientTruthLiveConstructorUsesProtectedPrepayment(t *testing.T) {
	p, e := newPrivateCapture(3)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if p.side != 3 || !p.truth.client || p.truth.arena == nil || p.truth.arena.buffer == nil || !p.truth.arena.buffer.Locked() || p.truth.arena.buffer.Len() != clientArenaBytes || ([4]int{cap(p.truth.messages), cap(p.truth.setups), cap(p.truth.seals), cap(p.truth.requests)}) != ([4]int{6355, 8192, 2628, 32768}) || len(p.truth.clientPacket) != 65506 || cap(p.truth.clientPacket) != 65506 || p.truth.capacity != (clientTruthCapacity{}) {
		t.Fatal("live capture constructor bypassed protection or prepaid owners")
	}
	buffer := p.truth.arena.buffer
	p.close()
	if buffer.Len() != 0 || p.truth.arena != nil || p.truth.client || p.truth.clientPacket != nil {
		t.Fatal("live capture construction retained its actual protected startup owners")
	}
}

func TestFixtureAll37WaitsAndReaderRetainQuarantine(t *testing.T) {
	buffer, err := secmem.New(4096)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{ctx: context.Background(), cancel: func() {}, arena: &lockedArena{buffer: buffer}, budget: &memoryBudget{used: 8192, limit: controllerArenaBytes}, scorerReservation: 8192}
	f.shutdownUntil = time.Now().Add(25 * time.Millisecond)
	f.emergencyUntil = f.shutdownUntil.Add(25 * time.Millisecond)
	for range maxClients + 5 {
		f.children = append(f.children, &ownedChild{writer: &protocolWriter{w: io.Discard, limit: 1 << 20}, exited: make(chan error, 1), watchDone: make(chan struct{})})
	}
	held := f.children[len(f.children)-1]
	held.readersStarted = true
	held.statusJoined, held.viewJoined, held.truthJoined = make(chan struct{}), make(chan struct{}), make(chan struct{})
	var released bool
	defer func() {
		if !released {
			for _, child := range f.children {
				select {
				case child.exited <- nil:
				default:
				}
			}
			close(held.statusJoined)
			close(held.viewJoined)
			close(held.truthJoined)
		}
	}()
	started := time.Now()
	if reasonOf(f.close()) != ReasonChild || time.Since(started) > time.Second {
		t.Fatal("all-child cleanup renewed a serial deadline")
	}
	if !f.quarantined || quarantinedFixtures.Load() == 0 || f.arena.buffer == nil || f.budget.used != 8192 || f.scorerReservation != 8192 {
		t.Fatal("unreaped cohort lost retained raw ownership")
	}
	for _, child := range f.children {
		if child.reaped || !child.stopSent {
			t.Fatal("held Wait became definitive or Stop was not attempted")
		}
		child.exited <- nil
	}
	if _, err := newFixture(context.Background(), 0, Settings{}, 0, nil, nil, "", 0, fixtureResources{}); reasonOf(err) != ReasonChild {
		t.Fatal("another cohort started during quarantine")
	}
	close(held.statusJoined)
	close(held.viewJoined)
	// even after every owned Wait, the last reader still owns the raw backing
	if !f.quarantined || f.arena.buffer == nil {
		t.Fatal("reader join was omitted from retained quarantine")
	}
	close(held.truthJoined)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for quarantinedFixtures.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if quarantinedFixtures.Load() != 0 || f.quarantined || f.arena.buffer != nil || f.budget.used != 0 || f.scorerReservation != 0 {
		t.Fatal("definitive Wait and joins did not release ownership once")
	}
}

func TestFixtureCleanupRetainsNonzeroOwnedWait(t *testing.T) {
	a, err := newArena(4096)
	if err != nil {
		t.Fatal(err)
	}
	child := &ownedChild{writer: &protocolWriter{w: io.Discard, limit: 1 << 20}, exited: make(chan error, 1), watchDone: make(chan struct{})}
	child.exited <- errors.New("owned execution failure")
	f := &fixture{ctx: context.Background(), cancel: func() {}, arena: a, children: []*ownedChild{child}}
	row := RunResult{Flags: []Reason{ReasonClock}}
	result := fail(ReasonClock)
	closeTaskFixture(f, &row, &result)
	if !child.reaped || reasonOf(result) != ReasonClock || !reflect.DeepEqual(row.Flags, []Reason{ReasonClock, ReasonChild}) || reasonOf(f.close()) != ReasonChild {
		t.Fatal("cleanup hid owned Wait failure or overrode capture priority")
	}
}

func TestFreshHostGrowthUsesCurrentProspectiveIncrement(t *testing.T) {
	available := uint64(100)
	calls := 0
	probe := func() (uint64, error) { calls++; return available, nil }
	if err := currentHostGrowth(100, probe); err != nil {
		t.Fatal("exact current headroom rejected")
	}
	available = 0
	if reasonOf(currentHostGrowth(1, probe)) != ReasonLimit || calls != 2 {
		t.Fatal("growth reused stale host headroom")
	}
	if err := currentHostGrowth(0, probe); err != nil {
		t.Fatal("already-resident allocation was charged again")
	}
	if reasonOf(currentHostGrowth(0, func() (uint64, error) { return 0, fail(ReasonUnsupported) })) != ReasonUnsupported {
		t.Fatal("fresh host probe failure was hidden")
	}
}

func TestScorerProspectiveHostFailurePrecedesOwnedStart(t *testing.T) {
	calls := 0
	budget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: func(n uint64) error {
		calls++
		if n == 0 {
			t.Fatal("scorer allocation was not prospective")
		}
		return fail(ReasonLimit)
	}}
	f := &fixture{ctx: context.Background(), budget: budget}
	_, err := f.score(viewSet{}, publicConfig{n: 5, h: 3, binNS: 100000000}, frozenTraining{})
	if reasonOf(err) != ReasonLimit || calls != 1 || budget.used != 0 || f.scorerReservation != 0 || len(f.children) != 0 {
		t.Fatal("scorer started or retained reservation after fresh-host rejection")
	}
}

func TestFitterProspectiveHostFailureRollsBackOnlyNewReservation(t *testing.T) {
	const retained = uint64(123)
	calls := 0
	budget := &memoryBudget{used: retained, limit: controllerArenaBytes, beforeAllocation: func(n uint64) error {
		calls++
		if n != 3*512+8<<20 {
			t.Fatal("fit prospective allocation changed")
		}
		return fail(ReasonLimit)
	}}
	f := &fixture{ctx: context.Background(), budget: budget}
	_, err := f.train(make([]encodedTrainingRow, 3), true, true)
	if reasonOf(err) != ReasonLimit || calls != 1 || budget.used != retained || f.scorerReservation != 0 || len(f.children) != 0 {
		t.Fatal("fitter started, double charged retained pools or leaked a rejected reservation")
	}
}

func TestStatusReadFailurePreservesEveryStructuredCause(t *testing.T) {
	for _, cause := range []Reason{ReasonContract, ReasonIPC, ReasonLabel, ReasonClock, ReasonLimit} {
		ctx, cancel := context.WithCancel(context.Background())
		status := make(chan statusFrame, 1)
		status <- statusFrame{err: fail(cause)}
		child := &ownedChild{status: status}
		_, err := child.expect(ctx, opReady, time.Now().Add(time.Second))
		cancel()
		if reasonOf(err) != cause {
			t.Fatal("structured status-read error became a semantic child failure")
		}
	}
}

func TestChildRuntimeFailureKeepsBothFlagsAndPriority(t *testing.T) {
	var stream bytes.Buffer
	c := &childIO{status: &protocolWriter{w: &stream, limit: 1 << 20}}
	err := mergeChildFailure(c, fail(ReasonBroken), fail(ReasonLimit))
	if reasonOf(err) != ReasonLimit {
		t.Fatal("capture failure lost precedence")
	}
	reader, err := newProtocolReader(&stream, [16]byte{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.close()
	for _, want := range []Reason{ReasonBroken, ReasonLimit} {
		op, row, err := reader.next()
		if err != nil || op != opError || decodeReason(row) != want || row.end() != nil {
			t.Fatal("one applicable runtime flag was discarded")
		}
	}
}

func TestPredictionValidationPreservesBorrowedInputsOnAllExits(t *testing.T) {
	for _, valid := range []bool{false, true} {
		method := predictedMethod{method: "cells", values: []pairValue{{0, 0, .25}, {0, 1, .5}}, matches: []metrics.ViewEdge{{First: 0, Second: 1}}}
		if !valid {
			method.matches[0].Second = 0
		}
		values := append([]pairValue(nil), method.values...)
		matches := append([]metrics.ViewEdge(nil), method.matches...)
		err := validatePredictionMethod(predictions{layout: &predictionLayout{first: 1}}, method)
		if (err == nil) != valid || !reflect.DeepEqual(method.values, values) || !reflect.DeepEqual(method.matches, matches) {
			t.Fatal("validation changed borrowed prediction backing")
		}
	}
}

func TestUnstartedAppendKeepsRequestedInventoryAndPriorRows(t *testing.T) {
	c := Config{Phase: Train, Seed: -117, outputBudget: &memoryBudget{limit: 1 << 20}}
	prior := RunResult{Configuration: "mailbox-1", Repeat: 0, Counts: Counts{Planned: 4, Attempted: 4}, Flags: []Reason{ReasonRefused}, Methods: []MethodResult{{Method: "setup", AUC: number(.75, ReasonNone)}}}
	report := Report{Runs: []RunResult{prior}}
	tasks := []executionTask{
		{coordinate: Coordinate{ID: "mailbox-1"}, repeat: 0, plannedSides: 4},
		{coordinate: Coordinate{ID: "mailbox-1"}, repeat: 1, plannedSides: 4},
		{coordinate: Coordinate{ID: "mailbox-structural-peer"}, repeat: 0, plannedSides: 2},
	}
	if err := appendMissingTrainingTasks(&report, c, tasks, ReasonCancelled); err != nil {
		t.Fatal(err)
	}
	if len(report.Runs) != 3 || !reflect.DeepEqual(report.Runs[0], prior) || report.Runs[1].Repeat != 1 || report.Runs[2].Configuration != tasks[2].coordinate.ID {
		t.Fatal("earlier admitted row changed or requested subset was lost")
	}
	for _, row := range report.Runs[1:] {
		if row.Counts.Attempted != 0 || row.Counts.Established != 0 || row.Counts.Missing != row.Counts.Planned || !reflect.DeepEqual(row.Flags, []Reason{ReasonCancelled}) || len(row.Methods) != 0 || len(row.LinkingTimes) != 0 {
			t.Fatal("unstarted requested slot fabricated acquired evidence")
		}
	}
}

func TestLinkingAcquisitionUsesVerifiedWindowEvidence(t *testing.T) {
	route := [3]uint8{0, 1, 2}
	input := evaluationInput{
		public:      publicConfig{n: 5, h: 3, controlled: []int{0, 1}, epochNS: 1, cutoffNS: 30_000_000_001},
		plans:       []workloadPlan{{side: 0, route: route}},
		truth:       privateTruth{setups: outcomeTestGroup(0, route, 100)},
		established: map[uint16]bool{0: true},
	}
	for position := range 2 {
		node := outcomeTestNode(uint8(position), uint8(position), 0, 100, uint32(position)+1)
		node.setups[0].opened = 1
		input.views.nodes = append(input.views.nodes, node)
	}
	one := input
	one.public.controlled, one.views.nodes = []int{0}, input.views.nodes[:1]
	unrequested := captureLinkingAcquisition(one, true)
	if unrequested.Requested || unrequested.Setup || unrequested.Windows != [2][5]bool{} {
		t.Fatal("a single selected node requested a two-node linking certificate")
	}
	unknown := captureLinkingAcquisition(input, false)
	if !unknown.Requested || unknown.Setup || unknown.Windows != [2][5]bool{} {
		t.Fatal("unfinished capture was certified")
	}
	known := captureLinkingAcquisition(input, true)
	if !known.Setup || known.Windows != [2][5]bool{{true, true, true, true, true}, {true, true, true, true, true}} {
		t.Fatal("verified empty windows were lost")
	}
	savedSetup := input.views.nodes[0].setups[0]
	input.views.nodes[0].setups[0].hop = 0
	input.views.nodes[0].setups[0].stages = stageInput
	missingLocal := captureLinkingAcquisition(input, true)
	if !missingLocal.Setup || missingLocal.Windows[0] != [5]bool{} || missingLocal.Windows[1] != [5]bool{true, true, true, true, true} {
		t.Fatal("verified setup Open was conflated with missing local-hop acquisition")
	}
	for window := range 5 {
		if missingLocal.Reasons[0][window] != ReasonIncomplete || missingLocal.Reasons[1][window] != ReasonNone {
			t.Fatal("missing logical acquisition changed the independently acquired frame windows")
		}
	}
	input.views.nodes[0].setups[0] = savedSetup
	input.views.nodes[0].cells = []cellView{{hop: 1, kind: 1, dir: 0, localTime: 7_000_000_001, inputTime: 7_000_000_001, stages: stageInput}}
	proof := captureLinkingAcquisition(input, true)
	if !proof.Windows[0][2] || proof.Windows[0][3] || proof.Windows[0][4] || !proof.Windows[1][4] || proof.Reasons[0][4] != ReasonProvenance {
		t.Fatal("one incomplete logical observation did not preserve actual window availability")
	}
	input.views.nodes[0].connections[0].authenticated = false
	proof = captureLinkingAcquisition(input, true)
	if proof.Setup || proof.Windows != [2][5]bool{} {
		t.Fatal("unproven tuple became a setup certificate")
	}
}
