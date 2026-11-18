//go:build linux && amd64

package nodeview

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"golang.org/x/sys/unix"
)

func TestFitLateResultOwnedActor(t *testing.T) {
	if os.Getenv("JIMICHI_FIT_LATE_TEST") != "1" {
		t.Skip("owned subprocess helper")
	}
	if protectProcess(controllerArenaBytes) != nil {
		t.Fatal("owned late-result actor protection failed")
	}
	role := byte(roleTrainer)
	if os.Getenv("JIMICHI_FIT_LATE_ROLE") == "auditor" {
		role = roleFitAuditor
	}
	c := &childIO{role: role, suite: jcrypto.SuiteC25519}
	for i := range c.files {
		if unix.SetNonblock(3+i, true) != nil {
			t.Fatal("owned inherited pipe nonblocking setup failed")
		}
		c.files[i] = os.NewFile(uintptr(3+i), "fit-owned-pipe")
		if c.files[i] == nil || validatePipe(c.files[i], i != 0) != nil {
			t.Fatal("owned inherited pipe validation failed")
		}
		defer c.files[i].Close()
	}
	var err error
	c.command, err = newProtocolReader(c.files[0], [16]byte{}, 1<<20)
	if err != nil {
		t.Fatal("owned late-result command reader failed")
	}
	defer c.command.close()
	c.status = &protocolWriter{w: c.files[1], limit: 1 << 20}
	c.view = &protocolWriter{w: c.files[2], limit: 1 << 20}
	c.truth = &protocolWriter{w: c.files[3], limit: 1 << 20}
	w := encoder{}
	w.u8(role)
	w.u8(byte(c.suite))
	w.u16(0)
	w.u8(1)
	if c.status.send(opBoot, w) != nil {
		t.Fatal("owned actor boot failed")
	}
	s, err := acquireFitCertificate(func(n uint64) error { return currentHostGrowth(n, availableHostMemory) })
	if err != nil {
		t.Fatal("owned actor fit admission failed")
	}
	defer s.close()
	rows := mailboxTrainingFixture()
	defer clear(rows)
	training := trainMailbox(rows, featureVersion, true, true, s)
	defer wipeMailboxTraining(&training)
	if !training.Releasable || sendFitActorResult(c, &training) != nil {
		t.Fatal("owned actor first result failed")
	}
	if c.terminal(Counts{}, ReasonNone) != nil {
		t.Fatal("owned actor real End/Ack failed")
	}
	if os.Getenv("JIMICHI_FIT_LATE_EXTRA") == "1" && sendFitActorResult(c, &training) != nil {
		t.Fatal("owned actor late duplicate send failed")
	}
	s.close()
	wipeMailboxTraining(&training)
	clear(rows)
	c.command.close()
	if c.cleaned() != nil {
		t.Fatal("owned actor Cleaned/EOF failed")
	}
}

func TestFitLateAfterAckRetainsOwnerThroughWait(t *testing.T) {
	for _, role := range []byte{roleTrainer, roleFitAuditor} {
		for _, extra := range []bool{false, true} {
			name := roleNames[role] + "/positive"
			if extra {
				name = roleNames[role] + "/late"
			}
			t.Run(name, func(t *testing.T) { fitLateAfterAckCase(t, role, extra) })
		}
	}
}

func sendFitActorResult(c *childIO, training *MailboxTraining) error {
	if c.role == roleTrainer {
		return c.view.send(opTrained, encodeTraining(*training))
	}
	w := encoder{}
	w.u8(2)
	w.bool(training.Releasable)
	w.u8(reasonByte(Reason(training.Reason)))
	w.u32(uint32(training.Support.Rows[0] + training.Support.Rows[1]))
	return c.view.send(opFitCheck, w)
}

type fitLateStatusTrace struct {
	frames, cleaned uint64
	canonical, eof  bool
}

func fitLateAfterAckCase(t *testing.T, role byte, extra bool) {
	budget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: (&hostCapacity{}).checkGrowth}
	parentCharge := uint64(8 << 20)
	reservation := uint64(128*512 + 8<<20)
	if budget.reserve(parentCharge+reservation) != nil {
		t.Fatal("late-result whole-overlap admission failed")
	}
	if budget.checkAllocation(parentCharge+reservation) != nil {
		budget.release(parentCharge + reservation)
		t.Fatal("late-result whole-overlap admission failed")
	}
	defer budget.release(parentCharge)
	fitLateAfterAckCaseAdmitted(t, role, extra, budget, reservation)
}

func fitLateAfterAckCaseAdmitted(t *testing.T, role byte, extra bool, budget *memoryBudget, reservation uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	f := &fixture{ctx: ctx, cancel: cancel, budget: budget, scorerReservation: reservation, resources: &resourceUsage{}}
	var err error
	f.arena, err = newBudgetedArena(4096, 4096, budget)
	if err != nil {
		cancel()
		budget.release(reservation)
		t.Fatal("late-result arena unavailable")
	}
	defer func() { _ = f.close() }()
	child := &ownedChild{role: role, fitExpected: fitTestExpectation(128, true, ReasonNone), status: make(chan statusFrame, 8), statusBudget: budget, viewDone: make(chan error, 1), truthDone: make(chan error, 1), exited: make(chan error, 1), viewProgress: make(chan struct{}, 1), truthProgress: make(chan struct{}, 1), statusJoined: make(chan struct{}), viewJoined: make(chan struct{}), truthJoined: make(chan struct{}), watchDone: make(chan struct{})}
	var parent, inherited [4]*os.File
	for i := range 4 {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal("late-result owned pipe unavailable")
		}
		if i == 0 {
			parent[i], inherited[i] = w, r
		} else {
			parent[i], inherited[i] = r, w
		}
		defer inherited[i].Close()
		defer parent[i].Close()
	}
	child.command, child.statusFile, child.viewFile, child.truthFile = parent[0], parent[1], parent[2], parent[3]
	child.writer = &protocolWriter{w: parent[0], limit: 1 << 20}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("owned actor executable unavailable")
	}
	cmd := exec.Command(exe, "-test.run=^TestFitLateResultOwnedActor$")
	roleName := "trainer"
	if role == roleFitAuditor {
		roleName = "auditor"
	}
	extraName := "0"
	if extra {
		extraName = "1"
	}
	cmd.Env = []string{"JIMICHI_FIT_LATE_TEST=1", "JIMICHI_FIT_LATE_ROLE=" + roleName, "JIMICHI_FIT_LATE_EXTRA=" + extraName}
	cmd.ExtraFiles = inherited[:]
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	child.cmd = cmd
	if budget.checkAllocation(reservation) != nil {
		t.Fatal("late-result current spawn headroom failed")
	}
	if cmd.Start() != nil {
		child.reaped = true
		t.Fatal("owned late-result actor did not start")
	}
	child.resource = f.resources.start()
	f.children = append(f.children, child)
	for _, file := range inherited {
		file.Close()
	}
	go func() {
		e := cmd.Wait()
		child.maxRSS, child.usageErr = waitRSS(cmd.ProcessState)
		child.resource.record(child.maxRSS, child.usageErr)
		child.exited <- e
	}()
	if budget.checkAllocation(65536) != nil {
		t.Fatal("late-result status reader admission failed")
	}
	status, e := newProtocolReader(parent[1], [16]byte{}, 1<<20)
	if e != nil {
		t.Fatal("protected actor status unavailable")
	}
	if budget.checkAllocation(65536) != nil {
		t.Fatal("late-result view reader admission failed")
	}
	view, e := newProtocolReader(parent[2], [16]byte{}, 1<<20)
	if e != nil {
		status.close()
		t.Fatal("protected actor view unavailable")
	}
	if budget.checkAllocation(65536) != nil {
		t.Fatal("late-result truth reader admission failed")
	}
	truth, e := newProtocolReader(parent[3], [16]byte{}, 1<<20)
	if e != nil {
		status.close()
		view.close()
		t.Fatal("protected actor truth unavailable")
	}
	child.readersStarted = true
	if unsafe.Sizeof(fitLateStatusTrace{}) != 24 || unsafe.Sizeof(decoder{}) != 40 || unsafe.Sizeof(error(nil)) != 16 || unsafe.Sizeof((chan error)(nil)) != 8 {
		t.Fatal("late-result observer control layout changed")
	}
	if budget.checkAllocation(768) != nil {
		t.Fatal("late-result observer controls admission failed")
	}
	viewObserved := make(chan error, 1)
	statusTrace := fitLateStatusTrace{canonical: true}
	go func() {
		defer close(child.statusJoined)
		defer status.close()
		for {
			op, r, e := status.next()
			if e != nil {
				statusTrace.eof = e == io.EOF
				if !statusTrace.eof {
					statusTrace.canonical = false
				}
				child.status <- statusFrame{err: e}
				return
			}
			statusTrace.frames++
			want := byte(0)
			switch statusTrace.frames {
			case 1:
				want = opBoot
			case 2:
				want = opEnd
			case 3:
				want = opCleaned
			}
			if op != want {
				statusTrace.canonical = false
			}
			if op == opCleaned {
				statusTrace.cleaned++
				check := decoder{b: r.b}
				if !check.bool() || !check.bool() || check.end() != nil {
					statusTrace.canonical = false
				}
			}
			body, charge, e := copyStatusBody(r, budget)
			if e != nil {
				child.status <- statusFrame{err: e}
				return
			}
			child.status <- statusFrame{op: op, body: body, charged: charge}
		}
	}()
	type aliases struct {
		witness *MailboxFitWitness
		weights []float64
	}
	first := make(chan aliases, 1)
	var decodes atomic.Uint32
	go func() {
		defer close(child.viewJoined)
		defer view.close()
		op := byte(opTrained)
		if role == roleFitAuditor {
			op = opFitCheck
		}
		e := readOutput(view, op, func(r *decoder) error {
			e := acceptFitRoleResult(child, r, func(d *decoder) (MailboxTraining, error) { decodes.Add(1); return decodeTraining(d) })
			if e != nil {
				return e
			}
			if role == roleTrainer {
				first <- aliases{child.training.Witness, child.training.Model.Weights}
			} else {
				first <- aliases{}
			}
			child.viewFrames.Add(1)
			select {
			case child.viewProgress <- struct{}{}:
			default:
			}
			return nil
		})
		viewObserved <- e
		child.viewDone <- e
	}()
	go func() {
		defer close(child.truthJoined)
		defer truth.close()
		child.truthDone <- readOutput(truth, opTruth, func(*decoder) error { return fail(ReasonIPC) })
	}()
	boot, e := child.expect(ctx, opBoot, time.Now().Add(30*time.Second))
	if e != nil || boot.u8() != role || boot.u8() != byte(jcrypto.SuiteC25519) || boot.u16() != 0 || boot.u8() != 1 || boot.end() != nil {
		t.Fatal("owned late-result boot grammar failed")
	}
	var retained aliases
	select {
	case retained = <-first:
	case <-ctx.Done():
		t.Fatal("owned actor first result missing")
	}
	finishErr := f.finishOne(child)
	wantDecodes := uint32(1)
	if role == roleFitAuditor {
		wantDecodes = 0
	}
	if extra && reasonOf(finishErr) != ReasonIPC || !extra && finishErr != nil || child.writer.frames != 1 || decodes.Load() != wantDecodes || role == roleTrainer && retained.witness.Count != 128 || budget.used < reservation || f.scorerReservation != reservation || child.resource == nil {
		t.Fatal("late-after-Ack result escaped singleton/retained ownership")
	}
	if extra && child.fitReason&128 == 0 || child.fitExpected != fitTestExpectation(128, true, ReasonNone) {
		t.Fatal("late rejection was not sticky or changed bound expectation")
	}

	_ = f.close()
	if !child.reaped || !child.joinReaders(time.Now().Add(time.Second)) || f.scorerReservation != 0 || f.quarantined || retained.witness != nil && retained.witness.Count != 0 || child.training.Model != nil || child.training.Witness != nil {
		t.Fatal("late-after-Ack rejection released before owned Wait/readers or missed rollback")
	}
	if child.waitErr != nil || child.usageErr != nil || child.cmd == nil || child.cmd.ProcessState == nil || !child.cmd.ProcessState.Success() || child.cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("late-result evidence requires a normal exit-zero actor and valid owned usage")
	}
	if !statusTrace.canonical || !statusTrace.eof || statusTrace.frames != 3 || statusTrace.cleaned != 1 || child.statusConsumed != 3 {
		t.Fatal("late-result evidence lacks actual canonical Cleaned/status EOF")
	}
	select {
	case actualViewError := <-viewObserved:
		if extra && (actualViewError == nil || reasonOf(actualViewError) != ReasonIPC) || !extra && actualViewError != nil {
			t.Fatal("late-result rejection did not originate from the actual view reader")
		}
	default:
		t.Fatal("late-result view reader outcome was not observed after its join")
	}
	assertFitBackingZero(t, retained.weights)
	if child.fitSeen || child.fitCommitted || child.fitOK || child.fitReason != 0 || child.fitCount != 0 || child.fitExpected != 0 {
		t.Fatal("late-result cleanup retained fixed private result state")
	}
	point := f.resources.snapshot(0, nil)
	if point.Reason != ReasonNone || point.MaxRSS == nil {
		t.Fatal("owned late-result process resource ticket was not finalized")
	}
}
