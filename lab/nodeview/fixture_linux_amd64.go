//go:build linux && amd64

package nodeview

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

type statusFrame struct {
	op      byte
	body    []byte
	err     error
	charged uint64
}
type ownedChild struct {
	resource                              *resourceTicket
	usageErr                              error
	stopSent                              bool
	waitErr                               error
	statusBudget                          *memoryBudget
	statusBody                            []byte
	statusCharge                          uint64
	dataMu                                sync.Mutex
	orphan                                bool
	flags                                 []Reason
	processSummary                        processSummary
	hasSummary                            bool
	maxRSS                                uint64
	statusConsumed                        uint64
	watchDone                             chan struct{}
	watchOnce                             sync.Once
	statusJoined, viewJoined, truthJoined chan struct{}
	readersStarted                        bool
	cmd                                   *exec.Cmd
	command                               *os.File
	statusFile, viewFile, truthFile       *os.File
	writer                                *protocolWriter
	status                                chan statusFrame
	viewDone, truthDone                   chan error
	exited                                chan error
	viewFrames, truthFrames               atomic.Uint64
	viewProgress, truthProgress           chan struct{}
	view                                  nodeView
	truth                                 privateTruth
	role                                  byte
	selected                              bool
	port                                  uint16
	bundle                                []byte
	counts                                Counts
	reason                                Reason
	reaped                                bool
	predictions                           predictions
	training                              MailboxTraining
	fitOK                                 bool
}

type fixture struct {
	captureValidated              bool
	resources                     *resourceUsage
	shutdownUntil, emergencyUntil time.Time
	enrollmentDeadline            time.Time
	quarantined                   bool
	inventory                     cohortInventory
	scorerReservation             uint64
	budget                        *memoryBudget
	resultCharge                  *resultCharge
	allowOrphan                   bool
	binaryDigest                  string
	closeMu                       sync.Mutex
	ctx                           context.Context
	cancel                        context.CancelFunc
	suite                         jcrypto.Suite
	arena                         *lockedArena
	mu                            sync.Mutex
	children                      []*ownedChild
	relays                        []*ownedChild
	roster                        []publicRelay
	anchor                        pki.Anchor
	settings                      Settings
	topology                      byte
	mailbox                       uint8
	missing                       uint8
	closed                        bool
	closedCauses                  []Reason
	closedBound                   boundDetail
}

type fixtureResources struct {
	retained uint64
	usage    *resourceUsage
	host     *hostCapacity
}

var quarantinedFixtures atomic.Int64

func newFixture(ctx context.Context, s jcrypto.Suite, settings Settings, topology byte, controlled, foreign []int, binaryDigest string, missing uint8, resources fixtureResources) (*fixture, error) {
	if quarantinedFixtures.Load() != 0 {
		return nil, fail(ReasonChild)
	}
	if settings.validate(topology == 2) != nil || missing > 2 || settings.ControlProfile != 0 && missing != 2 {
		return nil, ErrInvalid
	}
	base := uint64(8 << 20)
	if resources.retained > controllerArenaBytes-base {
		return nil, fail(ReasonLimit)
	}
	base += resources.retained
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	f := &fixture{ctx: ctx, cancel: cancel, suite: s, settings: settings, topology: topology, mailbox: 255, missing: missing, resources: resources.usage}
	f.binaryDigest = binaryDigest
	if topology == 2 {
		f.mailbox = 4
	}
	f.budget = &memoryBudget{limit: controllerArenaBytes, used: base, high: base, beforeAllocation: resources.host.checkGrowth}
	a, e := newBudgetedArena(controllerArenaBytes/2, 8<<20, f.budget)
	if e != nil {
		cancel()
		return nil, e
	}
	f.arena = a
	failure := f.failInitialization
	p, _ := suite.New(s)
	caA, e := pki.NewCA(p)
	if e != nil {
		return failure(fail(ReasonEnrollment))
	}
	defer caA.Close()
	caB, e := pki.NewCA(p)
	if e != nil {
		return failure(fail(ReasonEnrollment))
	}
	defer caB.Close()
	f.anchor = caA.Anchor()
	start := time.Now()
	until := start.Add(30 * time.Second)
	f.enrollmentDeadline = until
	for i := range 5 {
		selected := containsInt(controlled, i)
		child, e := f.spawn(roleRelay, selected)
		if e != nil {
			return failure(e)
		}
		f.relays = append(f.relays, child)
		child.view.position = uint8(i)
		boot, e := child.expect(f.ctx, opBoot, until)
		if e != nil {
			return failure(e)
		}
		if boot.u8() != roleRelay || jcrypto.Suite(boot.u8()) != s {
			return failure(fail(ReasonIPC))
		}
		child.port = boot.u16()
		if boot.u8() != 1 || boot.end() != nil || child.port == 0 {
			return failure(fail(ReasonIPC))
		}
		ca := caA
		if containsInt(foreign, i) {
			ca = caB
		}
		name := "node" + decimal(i+1)
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return failure(fail(ReasonEnrollment))
		}
		w := encoder{budget: f.budget}
		w.ascii(name, 32)
		w.u16(child.port)
		w.raw(nonce[:])
		w.ascii(ca.Anchor().String(), 256)
		w.i64(start.Add(-time.Minute).Unix())
		w.i64(start.Add(time.Hour).Unix())
		w.i64(int64(10 * time.Minute))
		if e := child.writer.send(opChallenge, w); e != nil {
			return failure(e)
		}
		r, e := child.expect(f.ctx, opRequest, until)
		if e != nil {
			return failure(e)
		}
		request, e := decodeEnrollmentRequest(r, p, nonce, name, loopback(child.port))
		if e != nil {
			return failure(e)
		}
		clear(nonce[:])
		cert, e := ca.Issue(request, start.Add(-time.Minute), start.Add(time.Hour))
		if e != nil {
			return failure(fail(ReasonEnrollment))
		}
		w = encoder{budget: f.budget}
		w.bytes(cert.Marshal(), 2048)
		if e := child.writer.send(opCertificate, w); e != nil {
			return failure(e)
		}
		r, e = child.expect(f.ctx, opBundle, until)
		if e != nil {
			return failure(e)
		}
		bundle := append([]byte(nil), r.bytes(4096)...)
		if r.end() != nil {
			return failure(fail(ReasonIPC))
		}
		if _, e = pki.Verify(p, policy(ca.Anchor()), loopback(child.port), bundle, start); e != nil {
			return failure(fail(ReasonEnrollment))
		}
		child.bundle = bundle
		f.roster = append(f.roster, publicRelay{child.port, bundle})
	}
	for i, child := range f.relays {
		anchor := caA.Anchor()
		if containsInt(foreign, i) {
			anchor = caB.Anchor()
		}
		cfg := applicationConfig{s, topology, true, missing, anchor, f.roster, f.mailbox, child.selected, settings}
		if e := child.writer.send(opConfigure, encodeApplication(cfg, f.budget)); e != nil {
			return failure(e)
		}
	}
	for _, child := range f.relays {
		if e := child.expectReady(f.ctx, 1, until); e != nil {
			return failure(e)
		}
	}
	return f, nil
}

func (f *fixture) failInitialization(err error) (*fixture, error) {
	return nil, mergeRuntimeFailure(err, f.close())
}

func containsInt(a []int, n int) bool {
	for _, v := range a {
		if v == n {
			return true
		}
	}
	return false
}

func (f *fixture) spawn(role byte, selected bool) (*ownedChild, error) {
	if role < roleRelay || role > roleFitAuditor {
		return nil, ErrInvalid
	}
	active := 0
	for _, c := range f.children {
		if !c.reaped {
			active++
		}
	}
	if role <= roleClient && active >= maxClients+5 || role >= roleScorer && active != 0 {
		return nil, fail(ReasonLimit)
	}
	exe, e := os.Executable()
	if e != nil {
		return nil, fail(ReasonChild)
	}
	binaryBytes, e := os.ReadFile(exe)
	if e != nil {
		return nil, fail(ReasonChild)
	}
	digest := publicHash(binaryBytes)
	if f.binaryDigest == "" {
		f.binaryDigest = digest
	} else if digest != f.binaryDigest {
		return nil, fail(ReasonContract)
	}
	var token [16]byte
	if _, e = rand.Read(token[:]); e != nil {
		return nil, fail(ReasonChild)
	}
	child := &ownedChild{role: role, selected: selected, status: make(chan statusFrame, 8), viewDone: make(chan error, 1), truthDone: make(chan error, 1), exited: make(chan error, 1), viewProgress: make(chan struct{}, 1), truthProgress: make(chan struct{}, 1), truth: privateTruth{arena: f.arena}, watchDone: make(chan struct{}), statusJoined: make(chan struct{}), viewJoined: make(chan struct{}), truthJoined: make(chan struct{})}
	var parent [4]*os.File
	var inherited [4]*os.File
	for i := range 4 {
		read, write, e := os.Pipe()
		if e != nil {
			for _, p := range parent {
				if p != nil {
					p.Close()
				}
			}
			for _, p := range inherited {
				if p != nil {
					p.Close()
				}
			}
			return nil, fail(ReasonChild)
		}
		if i == 0 {
			inherited[i], parent[i] = read, write
		} else {
			parent[i], inherited[i] = read, write
		}
	}
	cmd := exec.Command(exe, "--nodeview-child-v1="+roleNames[role])
	cmd.Env = envToken(token, f.suite)
	cmd.ExtraFiles = inherited[:]
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		for _, p := range parent {
			p.Close()
		}
		for _, p := range inherited {
			p.Close()
		}
		return nil, fail(ReasonChild)
	}
	for _, p := range inherited {
		p.Close()
	}
	child.cmd = cmd
	child.resource = f.resources.start()
	child.command, child.statusFile, child.viewFile, child.truthFile = parent[0], parent[1], parent[2], parent[3]
	child.writer = &protocolWriter{w: child.command, token: token, limit: controllerArenaBytes, budget: f.budget}
	f.children = append(f.children, child)
	child.view.arena = f.arena
	child.view.budget = f.budget
	child.truth.budget = f.budget
	child.statusBudget = f.budget
	go func() {
		executionErr := cmd.Wait()
		child.maxRSS, child.usageErr = waitRSS(cmd.ProcessState)
		child.resource.record(child.maxRSS, child.usageErr)
		child.exited <- executionErr
	}()
	go func() {
		select {
		case <-f.ctx.Done():
			child.command.Close()
		case <-child.watchDone:
		}
	}()
	status, e := newProtocolReader(parent[1], token, 1<<20)
	if e != nil {
		return nil, e
	}
	view, e := newProtocolReader(parent[2], token, relayArenaBytes)
	if e != nil {
		status.close()
		return nil, e
	}
	truthLimit := uint64(clientArenaBytes)
	if role == roleRelay {
		truthLimit = relayArenaBytes
	}
	truth, e := newProtocolReader(parent[3], token, truthLimit)
	if e != nil {
		status.close()
		view.close()
		return nil, e
	}
	go func() {
		defer close(child.statusJoined)
		defer status.close()
		for {
			op, r, e := status.next()
			if e != nil {
				select {
				case child.status <- statusFrame{err: e}:
				case <-f.ctx.Done():
				}
				return
			}
			body, charge, e := copyStatusBody(r, child.statusBudget)
			if e != nil {
				select {
				case child.status <- statusFrame{err: e}:
				case <-f.ctx.Done():
				}
				return
			}
			select {
			case child.status <- statusFrame{op: op, body: body, charged: charge}:
			case <-f.ctx.Done():
				clear(body)
				child.statusBudget.release(charge)
				return
			}
		}
	}()
	viewOp := byte(opView)
	if role == roleScorer {
		viewOp = opPredictions
	} else if role == roleTrainer {
		viewOp = opTrained
	} else if role == roleFitAuditor {
		viewOp = opFitCheck
	}
	child.readersStarted = true
	go func() {
		defer close(child.viewJoined)
		e := readOutput(view, viewOp, func(r *decoder) error {
			var e error
			switch role {
			case roleRelay:
				f.mu.Lock()
				if f.closed {
					f.mu.Unlock()
					return fail(ReasonCancelled)
				}
				if len(r.b) > 0 && r.b[0] == 6 {
					if child.hasSummary {
						e = fail(ReasonIPC)
					} else {
						child.processSummary, e = decodeProcessSummary(r)
						if e == nil {
							child.hasSummary = true
						}
					}
				} else if !selected {
					e = fail(ReasonIPC)
				} else {
					e = receiveView(r, &child.view)
				}
				f.mu.Unlock()
			case roleScorer:
				child.dataMu.Lock()
				e = receivePrediction(r, &child.predictions)
				child.dataMu.Unlock()
			case roleTrainer:
				child.training, e = decodeTraining(r)
			case roleFitAuditor:
				if r.u8() != 2 {
					return fail(ReasonIPC)
				}
				child.fitOK = r.bool()
				_ = decodeReason(r)
				_ = r.u32()
				e = r.end()
			default:
				return fail(ReasonIPC)
			}
			if e != nil {
				return e
			}
			child.viewFrames.Add(1)
			select {
			case child.viewProgress <- struct{}{}:
			default:
			}
			return nil
		})
		child.viewDone <- e
	}()
	go func() {
		defer close(child.truthJoined)
		e := readOutput(truth, opTruth, func(r *decoder) error {
			if role != roleClient && (role != roleRelay || !selected) {
				return fail(ReasonIPC)
			}
			f.mu.Lock()
			if f.closed {
				f.mu.Unlock()
				return fail(ReasonCancelled)
			}
			if len(r.b) < 3 {
				f.mu.Unlock()
				return fail(ReasonIPC)
			}
			if e := f.inventory.reserveTruth(r.b[0], int(r.b[1])<<8|int(r.b[2])); e != nil {
				f.mu.Unlock()
				return e
			}
			e := receiveTruth(r, &child.truth)
			f.mu.Unlock()
			if e != nil {
				return e
			}
			child.truthFrames.Add(1)
			select {
			case child.truthProgress <- struct{}{}:
			default:
			}
			return nil
		})
		child.truthDone <- e
	}()
	return child, nil
}

func (c *ownedChild) expect(ctx context.Context, want byte, deadline time.Time) (*decoder, error) {
	c.releaseStatusBody()
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fail(ReasonCancelled)
		case <-t.C:
			return nil, fail(ReasonIPC)
		case frame := <-c.status:
			if frame.err != nil {
				var structured failure
				if errors.As(frame.err, &structured) || errors.Is(frame.err, ErrUnsupported) {
					return nil, frame.err
				}
				if ctx.Err() != nil {
					return nil, fail(ReasonCancelled)
				}
				if frame.err == io.EOF {
					return nil, fail(ReasonIPC)
				}
				return nil, semanticFailure(frame.err, ReasonChild)
			}
			c.releaseStatusBody()
			c.statusBody, c.statusCharge = frame.body, frame.charged
			c.statusConsumed++
			if frame.op == opError && want != opError {
				r := &decoder{b: frame.body}
				reason := decodeReason(r)
				if r.end() != nil || reason == ReasonNone {
					return nil, fail(ReasonIPC)
				}
				c.flags = append(c.flags, reason)
				if want == opEnd {
					continue
				}
				return nil, fail(reason)
			}
			if frame.op != want {
				return nil, fail(ReasonIPC)
			}
			return &decoder{b: frame.body}, nil
		}
	}
}

func (c *ownedChild) releaseStatusBody() {
	clear(c.statusBody)
	c.statusBudget.release(c.statusCharge)
	c.statusBody = nil
	c.statusCharge = 0
}

func copyStatusBody(r *decoder, b *memoryBudget) ([]byte, uint64, error) {
	n := uint64(len(r.b))
	if e := b.reserve(n); e != nil {
		return nil, 0, e
	}
	if e := b.checkAllocation(n); e != nil {
		b.release(n)
		return nil, 0, e
	}
	body := make([]byte, len(r.b))
	copy(body, r.b)
	return body, n, nil
}

func (f *fixture) addClients(plans []workloadPlan, serial bool) ([]*ownedChild, error) {
	profile, boundary := boundaryProfileFor(f.settings.ControlProfile)
	if len(plans) > 32 || cohortCapacity(f.settings, len(plans)) != nil {
		return nil, fail(ReasonLimit)
	}
	clients := make([]*ownedChild, 0, len(plans))
	var cards [][]byte
	until := f.enrollmentDeadline
	if until.IsZero() {
		return nil, fail(ReasonContract)
	}
	for range plans {
		ch, e := f.spawn(roleClient, false)
		if e != nil {
			return clients, e
		}
		clients = append(clients, ch)
		r, e := ch.expect(f.ctx, opBoot, until)
		if e != nil {
			return clients, e
		}
		if r.u8() != roleClient || jcrypto.Suite(r.u8()) != f.suite || r.u16() != 0 || r.u8() != 1 || r.end() != nil {
			return clients, fail(ReasonIPC)
		}
		cfg := applicationConfig{f.suite, f.topology, true, f.missing, f.anchor, f.roster, f.mailbox, false, f.settings}
		if e := ch.writer.send(opConfigure, encodeApplication(cfg, f.budget)); e != nil {
			return clients, e
		}
		if e = ch.expectReady(f.ctx, 1, until); e != nil {
			return clients, e
		}
	}
	if f.topology == 2 {
		cards = make([][]byte, len(clients))
		for i, ch := range clients {
			r, e := ch.expect(f.ctx, opContact, until)
			if e != nil {
				return clients, e
			}
			if r.u16() != 1 {
				return clients, fail(ReasonIPC)
			}
			cards[i] = append([]byte(nil), r.bytes(2048)...)
			if r.end() != nil {
				return clients, fail(ReasonIPC)
			}
		}
		for i := range plans {
			if i^1 >= len(plans) {
				return clients, ErrInvalid
			}
			plans[i].contact = nil
		}
	}
	dispatch := 16
	if serial {
		dispatch = 1
	}
	sem := make(chan struct{}, dispatch)
	var wg sync.WaitGroup
	errors := make(chan error, len(clients))
	preflightUntil := f.enrollmentDeadline.Add(time.Duration(len(plans)) * 5 * time.Second)
	for i, ch := range clients {
		wg.Add(1)
		go func(i int, ch *ownedChild) {
			defer wg.Done()
			reportError := func(e error) {
				ch.flags = appendRuntimeReason(ch.flags, reasonOf(e))
				errors <- e
			}
			select {
			case sem <- struct{}{}:
			case <-f.ctx.Done():
				reportError(fail(ReasonCancelled))
				return
			}
			defer func() { <-sem }()
			if e := ch.writer.send(opClientPlan, encodeWorkload(plans[i], f.budget)); e != nil {
				reportError(e)
				return
			}
			r, e := ch.expect(f.ctx, opReady, preflightUntil)
			if e != nil {
				reportError(e)
				return
			}
			if r.u8() != 2 {
				reportError(fail(ReasonIPC))
				return
			}
			success := r.bool()
			if r.end() != nil {
				reportError(fail(ReasonIPC))
				return
			}
			if !success {
				r, e := ch.expect(f.ctx, opError, time.Now().Add(30*time.Second))
				if e != nil {
					reportError(e)
					return
				}
				if e := ch.preflightFailure(r); e != nil {
					reportError(e)
					return
				}
				return
			}
		}(i, ch)
	}
	wg.Wait()
	close(errors)
	var preflightErr error
	for e := range errors {
		preflightErr = mergeRuntimeFailure(preflightErr, e)
	}
	if preflightErr != nil {
		return clients, preflightErr
	}
	if f.topology == 2 {
		readyUntil := time.Now().Add(30 * time.Second)
		for i, ch := range clients {
			if ch.reason != ReasonNone {
				continue
			}
			peer := i ^ 1
			if peer >= len(clients) {
				return clients, fail(ReasonIPC)
			}
			w := encoder{budget: f.budget}
			if clients[peer].reason == ReasonNone {
				w.u16(1)
				w.bytes(cards[peer], 2048)
			} else if f.allowOrphan && i == 3 && peer == 2 && clients[peer].reason == ReasonRefused {
				w.u16(0)
				ch.orphan = true
			} else {
				return clients, fail(ReasonNoPartner)
			}
			if e := ch.writer.send(opContact, w); e != nil {
				return clients, e
			}
		}
		if e := f.awaitClientsReady(clients, boundary && !profile.pairedBeforeBegin, &readyUntil); e != nil {
			return clients, e
		}
	}
	return clients, nil
}

func (f *fixture) awaitClientsReady(clients []*ownedChild, delayed bool, until *time.Time) error {
	for _, ch := range clients {
		if ch.reason != ReasonNone || ch.orphan || delayed {
			continue
		}
		if e := ch.expectReady(f.ctx, 3, *until); e != nil {
			return e
		}
	}
	return readyAcceptanceError(f.ctx.Err() != nil, time.Now(), *until)
}

func (f *fixture) begin(epoch int64) error {
	w := encoder{budget: f.budget}
	defer w.wipe()
	w.i64(epoch)
	w.i64(f.settings.DurationNS)
	w.i64(epoch + f.settings.DurationNS)
	for _, ch := range f.children {
		copyBody := encoder{budget: f.budget}
		copyBody.raw(w.b)
		if e := ch.writer.send(opBegin, copyBody); e != nil {
			return e
		}
	}
	if f.settings.ControlProfile == 5 {
		now := monotonicNS()
		if now <= 0 || epoch <= 0 || f.settings.DurationNS <= 0 || epoch > math.MaxInt64-f.settings.DurationNS {
			return fail(ReasonClock)
		}
		cutoff := epoch + f.settings.DurationNS
		if f.ctx.Err() != nil {
			return fail(ReasonCancelled)
		}
		if now >= cutoff {
			return fail(ReasonIPC)
		}
		until := time.Now().Add(time.Duration(cutoff - now))
		for _, ch := range f.children {
			if ch.role != roleClient {
				continue
			}
			if e := ch.expectReady(f.ctx, 3, until); e != nil {
				return e
			}
		}
		if f.ctx.Err() != nil {
			return fail(ReasonCancelled)
		}
		now = monotonicNS()
		if now <= 0 {
			return fail(ReasonClock)
		}
		if now >= cutoff {
			return fail(ReasonIPC)
		}
	}
	return nil
}
func (f *fixture) stop(reason byte) error {
	until, _ := f.shutdownDeadlines()
	for _, ch := range f.children {
		if e := f.sendStop(ch, reason, until); e != nil {
			return e
		}
	}
	return nil
}

func waitFrames(ctx context.Context, current *atomic.Uint64, want uint64, progress <-chan struct{}, deadline time.Time) error {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	for {
		n := current.Load()
		if n > want {
			return fail(ReasonIPC)
		}
		if n == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fail(ReasonCancelled)
		case <-t.C:
			return fail(ReasonIPC)
		case <-progress:
		}
	}
}

func (f *fixture) finish() error {
	until, _ := f.shutdownDeadlines()
	for _, ch := range f.children {
		r, e := ch.expect(f.ctx, opEnd, until)
		if e != nil {
			return e
		}
		status := r.u8()
		reason := decodeReason(r)
		statusFrames := r.u64()
		views, truths := r.u64(), r.u64()
		ch.counts = decodeCounts(r)
		if r.end() != nil || statusFrames != ch.statusConsumed || status > 3 && status != 130 || status == 0 && reason != ReasonNone || status != 0 && reason == ReasonNone {
			return fail(ReasonIPC)
		}
		ch.reason = reason
		if e = waitFrames(f.ctx, &ch.viewFrames, views, ch.viewProgress, until); e != nil {
			return e
		}
		if e = waitFrames(f.ctx, &ch.truthFrames, truths, ch.truthProgress, until); e != nil {
			return e
		}
		if ch.role == roleRelay && !ch.hasSummary {
			return fail(ReasonIncomplete)
		}
		if ch.role == roleRelay && ch.selected {
			roster := map[uint16]int{}
			for i, node := range f.roster {
				roster[node.port] = i
			}
			if e = validateViewBindings(ch.view, roster); e != nil {
				return e
			}
		}
		w := encoder{}
		w.u8(0)
		if e := ch.writer.send(opAck, w); e != nil {
			return e
		}
		ch.command.Close()
	}
	for _, ch := range f.children {
		r, e := ch.expect(f.ctx, opCleaned, until)
		if e != nil {
			return e
		}
		if !r.bool() || !r.bool() || r.end() != nil {
			return fail(ReasonIPC)
		}
		if e = f.reap(ch, until); e != nil {
			return e
		}
	}
	f.captureValidated = true
	return nil
}

func (f *fixture) reap(ch *ownedChild, until time.Time) error {
	deadline := time.NewTimer(time.Until(until))
	defer deadline.Stop()
	select {
	case frame := <-ch.status:
		if frame.err != io.EOF {
			return fail(ReasonIPC)
		}
	case <-f.ctx.Done():
		return fail(ReasonCancelled)
	case <-deadline.C:
		return fail(ReasonIPC)
	}
	select {
	case e := <-ch.viewDone:
		if e != nil {
			return e
		}
	case <-f.ctx.Done():
		return fail(ReasonCancelled)
	case <-deadline.C:
		return fail(ReasonIPC)
	}
	select {
	case e := <-ch.truthDone:
		if e != nil {
			return e
		}
	case <-f.ctx.Done():
		return fail(ReasonCancelled)
	case <-deadline.C:
		return fail(ReasonIPC)
	}
	select {
	case e := <-ch.exited:
		ch.waitErr = e
		ch.reaped = true
		ch.watchOnce.Do(func() { close(ch.watchDone) })
		if e != nil {
			return fail(ReasonChild)
		}
		if ch.usageErr != nil {
			return ch.usageErr
		}
		if ch.hasSummary && ch.maxRSS < ch.processSummary.values[23] {
			return fail(ReasonContract)
		}
	case <-f.ctx.Done():
		return fail(ReasonCancelled)
	case <-deadline.C:
		return fail(ReasonChild)
	}
	ch.statusFile.Close()
	ch.viewFile.Close()
	ch.truthFile.Close()
	if !ch.joinReaders(until) {
		return fail(ReasonChild)
	}
	return nil
}

func (f *fixture) releaseEvaluatedInput(views *viewSet, pred *predictions) error {
	var retained uint64
	for _, ch := range f.children {
		if !ch.reaped || !ch.joinReaders(time.Time{}) {
			return fail(ReasonChild)
		}
		retained += predictionBackingBytes(ch.predictions)
	}
	if retained > f.scorerReservation {
		return fail(ReasonContract)
	}
	for _, ch := range f.children {
		clearEvaluatedOwner(&ch.view, &ch.truth, &ch.predictions)
	}
	for i := range views.nodes {
		views.nodes[i].cells = nil
	}
	*pred = predictions{}
	f.budget.release(retained)
	f.scorerReservation -= retained
	return nil
}

func (f *fixture) close() error {
	if f == nil {
		return nil
	}
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return f.closedFailure()
	}
	f.captureReadyReaderCauses()
	f.closed = true
	f.mu.Unlock()
	normalUntil, emergencyUntil := f.shutdownDeadlines()
	for _, ch := range f.children {
		_ = f.sendStop(ch, 1, normalUntil)
		ch.command.Close()
	}
	f.cancel()
	waitsComplete := f.collectWaits(normalUntil)
	f.closeOutputs()
	readersComplete := false
	if waitsComplete {
		readersComplete = f.joinReaders(normalUntil)
	}
	if !waitsComplete || !readersComplete {
		for _, ch := range f.children {
			if !ch.reaped && ch.cmd != nil && ch.cmd.Process != nil {
				_ = ch.cmd.Process.Kill()
			}
		}
		waitsComplete = f.collectWaits(emergencyUntil)
		readersComplete = f.joinReaders(emergencyUntil)
	}
	if !waitsComplete || !readersComplete {
		f.quarantined = true
		f.freezeCauses(ReasonChild)
		quarantinedFixtures.Add(1)
		go f.awaitQuarantined()
		return f.closedFailure()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.freezeCauses(ReasonNone)
	f.releaseRetained()
	return f.closedFailure()
}

func closeTaskFixture(f *fixture, r *RunResult, result *error) {
	if e := f.close(); e != nil {
		r.Flags = appendRuntimeReason(r.Flags, reasonOf(e))
		*result = mergeRuntimeFailure(*result, e)
	}
	for _, reason := range f.causeSnapshot() {
		r.Flags = appendRuntimeReason(r.Flags, reason)
		*result = mergeRuntimeFailure(*result, fail(reason))
	}
}

func (f *fixture) releaseRetained() {
	for _, ch := range f.children {
		ch.releaseStatusBody()
	drainStatus:
		for {
			select {
			case frame, ok := <-ch.status:
				if !ok {
					break drainStatus
				}
				clear(frame.body)
				ch.statusBudget.release(frame.charged)
			default:
				break drainStatus
			}
		}
		ch.view.wipe()
		ch.truth.wipeMetadata()
		ch.predictions.wipe()
		clear(ch.bundle)
		ch.bundle = nil
		if ch.writer != nil {
			ch.writer.token = [16]byte{}
		}
		if ch.cmd != nil {
			clear(ch.cmd.Env)
			ch.cmd.Env = nil
		}
		ch.port = 0
	}
	for i := range f.roster {
		clear(f.roster[i].bundle)
		f.roster[i].bundle = nil
		f.roster[i].port = 0
	}
	f.roster = nil
	f.arena.close()
	f.budget.release(f.scorerReservation)
	f.scorerReservation = 0
	f.resultCharge.cleaned()
}

func (f *fixture) awaitQuarantined() {
	for _, ch := range f.children {
		if !ch.reaped {
			ch.waitErr = <-ch.exited
			ch.reaped = true
			ch.watchOnce.Do(func() { close(ch.watchDone) })
		}
	}
	f.joinReadersFinally()
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseRetained()
	f.quarantined = false
	quarantinedFixtures.Add(-1)
}

func randomTokenText() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
