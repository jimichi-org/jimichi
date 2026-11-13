//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func fitTestExpectation(rows int, released bool, reason Reason) uint64 {
	return uint64(rows) | uint64(boolInt(released))<<32 | uint64(reasonByte(reason))<<33 | uint64(1)<<63
}

func TestFitRoleResultFramedSingletonAndRollback(t *testing.T) {
	for _, name := range []string{"trainer-duplicate", "trainer-partial", "duplicate-after-rejection", "auditor-valid", "auditor-reader-error", "auditor-sensitive", "auditor-duplicate", "auditor-wrong-count", "auditor-oversized", "auditor-reason", "auditor-empty-reason"} {
		t.Run(name, func(t *testing.T) {
			budget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: (&hostCapacity{}).checkGrowth}
			if budget.reserve(8<<20) != nil || budget.checkAllocation(8<<20) != nil {
				t.Fatal("bounded result-parser admission failed")
			}
			defer budget.release(8 << 20)
			s := testFitCertificate(t)
			defer s.close()
			rows := mailboxTrainingFixture()
			defer clear(rows)
			training := trainMailbox(rows, featureVersion, true, true, s)
			defer wipeMailboxTraining(&training)
			if !training.Releasable {
				t.Fatal("parser baseline did not actually fit")
			}
			role := byte(roleFitAuditor)
			if len(name) >= 7 && name[:7] == "trainer" || name == "duplicate-after-rejection" {
				role = roleTrainer
			}
			child := &ownedChild{role: role, fitExpected: fitTestExpectation(128, true, ReasonNone)}
			if name == "auditor-sensitive" || name == "auditor-empty-reason" {
				child.fitExpected = fitTestExpectation(128, false, ReasonFitSensitive)
			}
			wire := fitCorpusWire{b: make([]byte, 65536)}
			defer clear(wire.b)
			writer := protocolWriter{w: &wire, limit: 65536}
			frames := 1
			if name == "trainer-duplicate" || name == "auditor-duplicate" || name == "duplicate-after-rejection" {
				frames = 2
			}
			for i := 0; i < frames; i++ {
				body := encoder{}
				if role == roleTrainer {
					body = encodeTraining(training)
					if i == 0 && (name == "trainer-partial" || name == "duplicate-after-rejection") {
						body.b = body.b[:len(body.b)-2]
					}
				} else {
					ok, reason, count := true, ReasonNone, uint32(128)
					if name == "auditor-sensitive" {
						ok, reason = false, ReasonFitSensitive
					}
					if name == "auditor-wrong-count" {
						count = 127
					}
					if name == "auditor-oversized" {
						count = maxTrainingRows + 1
					}
					if name == "auditor-reason" {
						reason = ReasonFitSensitive
					}
					if name == "auditor-empty-reason" {
						ok = false
					}
					body.u8(2)
					body.bool(ok)
					body.u8(reasonByte(reason))
					body.u32(count)
				}
				op := byte(opFitCheck)
				if role == roleTrainer {
					op = opTrained
				}
				if writer.send(op, body) != nil {
					t.Fatal("typed result frame construction failed")
				}
			}
			if budget.checkAllocation(65536) != nil {
				t.Fatal("result-reader physical admission failed")
			}
			reader, err := newProtocolReader(bytes.NewReader(wire.b[:wire.used]), [16]byte{}, 65536)
			if err != nil {
				t.Fatal("protected result reader unavailable")
			}
			defer reader.close()
			entries := 0
			var first, partial *MailboxFitWitness
			var partialModel *metrics.Discriminant
			var firstWeights, partialWeights []float64
			var firstWeight float64
			decode := func(r *decoder) (MailboxTraining, error) {
				entries++
				value, err := decodeTraining(r)
				if err != nil {
					partial = value.Witness
					partialModel = value.Model
					if value.Model != nil {
						partialWeights = value.Model.Weights
					}
				}
				return value, err
			}
			op := byte(opFitCheck)
			if role == roleTrainer {
				op = opTrained
			}
			err = readOutput(reader, op, func(r *decoder) error {
				err := acceptFitRoleResult(child, r, decode)
				if err == nil && role == roleTrainer && first == nil {
					first = child.training.Witness
					firstWeights = child.training.Model.Weights
					firstWeight = firstWeights[0]
				}
				return err
			})
			valid := name == "auditor-valid" || name == "auditor-reader-error" || name == "auditor-sensitive"
			if valid && err != nil || !valid && reasonOf(err) != ReasonIPC {
				t.Fatal("framed result parser accepted an inconsistent or repeated owner")
			}
			if role == roleTrainer && entries != 1 {
				t.Fatal("duplicate result reached a second decode/allocation")
			}
			if first != nil && (child.training.Witness != first || first.Count != 128 || len(firstWeights) != 18 || child.training.Model.Weights[0] != firstWeight || firstWeights[0] != firstWeight || firstWeight == 0) {
				t.Fatal("duplicate replaced or wiped the first committed owner")
			}
			if name == "trainer-duplicate" || name == "auditor-duplicate" {
				if child.fitReason&128 == 0 || validCommittedFitResult(child) {
					t.Fatal("observed duplicate remained admissible at the synchronized checkpoint")
				}
				assertFitObservedRejectBeforeAck(t, child, budget)
			}
			if name == "auditor-reader-error" {
				child.truthDone = make(chan error, 1)
				child.truthDone <- fail(ReasonIPC)
				assertFitObservedRejectBeforeAck(t, child, budget)
				select {
				case retained := <-child.truthDone:
					if reasonOf(retained) != ReasonIPC {
						t.Fatal("observed reader error changed")
					}
					child.truthDone <- retained
				default:
					t.Fatal("pre-Ack polling discarded a published reader error")
				}
			}
			if partial != nil && (partial.Count != 0 || partial.Kept != nil || partial.Unused != nil) {
				t.Fatal("transactional rejected partial witness retained private fields")
			}
			assertFitBackingZero(t, partialWeights)
			assertFitWitnessZero(t, partial)
			assertFitModelZero(t, partialModel)
			if name == "duplicate-after-rejection" {
				if budget.checkAllocation(65536) != nil {
					t.Fatal("rejected-session follow-up reader admission failed")
				}
				follow, e := newProtocolReader(reader.r, reader.token, reader.limit)
				if e != nil {
					t.Fatal("protected rejected-session follow-up reader unavailable")
				}
				defer follow.close()
				follow.sequence, follow.frames, follow.bytes = reader.sequence, reader.frames, reader.bytes
				op, r, e := follow.next()
				if e != nil || op != opTrained || acceptFitRoleResult(child, r, decode) == nil || entries != 1 || child.fitCommitted || child.training.Model != nil || child.training.Witness != nil {
					t.Fatal("rejected first result allowed a later decode")
				}
			}
			arena, e := newBudgetedArena(4096, 4096, budget)
			if e != nil {
				t.Fatal("result rollback arena unavailable")
			}
			fixture := &fixture{children: []*ownedChild{child}, budget: budget, arena: arena}
			fixture.releaseRetained()
			assertFitBackingZero(t, firstWeights)
			if first != nil && first.Count != 0 || child.training.Model != nil || child.training.Witness != nil {
				t.Fatal("real retained-result finalizer did not wipe the first owner")
			}
		})
	}
}

func assertFitObservedRejectBeforeAck(t *testing.T, child *ownedChild, budget *memoryBudget) {
	t.Helper()
	if budget.checkAllocation(65536) != nil {
		t.Fatal("observed rejection status admission failed")
	}
	wire := fitCorpusWire{b: make([]byte, 65536)}
	defer clear(wire.b)
	w := encoder{}
	w.u8(0)
	w.u8(reasonByte(ReasonNone))
	w.u64(1)
	w.u64(1)
	w.u64(0)
	encodeCounts(&w, Counts{})
	if (&protocolWriter{w: &wire, limit: 65536}).send(opEnd, w) != nil {
		t.Fatal("observed rejection End encoding failed")
	}
	if budget.checkAllocation(65536) != nil {
		t.Fatal("observed rejection protected reader admission failed")
	}
	r, err := newProtocolReader(bytes.NewReader(wire.b[:wire.used]), [16]byte{}, 65536)
	if err != nil {
		t.Fatal("observed rejection status reader unavailable")
	}
	defer r.close()
	op, body, err := r.next()
	if err != nil {
		t.Fatal("observed rejection End framing failed")
	}
	copyBody, charge, err := copyStatusBody(body, budget)
	if err != nil {
		t.Fatal("observed rejection status copy admission failed")
	}
	child.status = make(chan statusFrame, 1)
	child.statusBudget = budget
	child.status <- statusFrame{op: op, body: copyBody, charged: charge}
	child.viewFrames.Store(1)
	ack := &lifecycleFailureWriter{failAt: 1}
	child.writer = &protocolWriter{w: ack, limit: 65536}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f := &fixture{ctx: ctx, budget: budget}
	if reasonOf(f.finishOne(child)) != ReasonIPC || ack.calls != 0 {
		t.Fatal("already observed rejection crossed the real Ack checkpoint")
	}
	child.releaseStatusBody()
}

func TestFitResultEndGrammarBeforeAck(t *testing.T) {
	for _, entry := range []struct {
		name          string
		views, truths uint64
		counted       bool
	}{{"missing", 0, 0, false}, {"extra", 2, 0, false}, {"truth", 1, 1, false}, {"counts", 1, 0, true}, {"uncommitted", 1, 0, false}} {
		t.Run(entry.name, func(t *testing.T) {
			budget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: (&hostCapacity{}).checkGrowth}
			if budget.reserve(1<<20) != nil || budget.checkAllocation(1<<20) != nil {
				t.Fatal("terminal grammar admission failed")
			}
			defer budget.release(1 << 20)
			wire := fitCorpusWire{b: make([]byte, 65536)}
			defer clear(wire.b)
			writer := protocolWriter{w: &wire, limit: 65536}
			body := encoder{}
			body.u8(0)
			body.u8(reasonByte(ReasonNone))
			body.u64(1)
			body.u64(entry.views)
			body.u64(entry.truths)
			counts := Counts{}
			if entry.counted {
				counts.Attempted = 1
			}
			encodeCounts(&body, counts)
			if writer.send(opEnd, body) != nil {
				t.Fatal("real terminal frame encode failed")
			}
			reader, err := newProtocolReader(bytes.NewReader(wire.b[:wire.used]), [16]byte{}, 65536)
			if err != nil {
				t.Fatal("protected terminal parser unavailable")
			}
			defer reader.close()
			op, r, err := reader.next()
			if err != nil {
				t.Fatal("real terminal frame parse failed")
			}
			copyBody, charge, err := copyStatusBody(r, budget)
			if err != nil {
				t.Fatal("terminal body admission failed")
			}
			ack := &lifecycleFailureWriter{}
			child := &ownedChild{role: roleTrainer, fitExpected: fitTestExpectation(128, false, ReasonNone), status: make(chan statusFrame, 1), statusBudget: budget, writer: &protocolWriter{w: ack, limit: 65536}, viewProgress: make(chan struct{}, 1), truthProgress: make(chan struct{}, 1)}
			child.viewFrames.Store(entry.views)
			child.truthFrames.Store(entry.truths)
			child.status <- statusFrame{op: op, body: copyBody, charged: charge}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			f := &fixture{ctx: ctx, budget: budget}
			if reasonOf(f.finishOne(child)) != ReasonIPC || ack.calls != 0 {
				t.Fatal("incomplete fit role crossed the Ack boundary")
			}
			child.releaseStatusBody()
		})
	}
}

func TestFitRolePrivateDescriptorLayout(t *testing.T) {
	if unsafe.Sizeof(ownedChild{}) != 1400 || unsafe.Offsetof(ownedChild{}.fitOK) != 1384 || unsafe.Offsetof(ownedChild{}.fitSeen) != 1385 || unsafe.Offsetof(ownedChild{}.fitCommitted) != 1386 || unsafe.Offsetof(ownedChild{}.fitReason) != 1387 || unsafe.Offsetof(ownedChild{}.fitCount) != 1388 || unsafe.Offsetof(ownedChild{}.fitExpected) != 1392 {
		t.Fatal("private result state lost its packed descriptor layout")
	}
	a := &outputArithmetic{}
	if outputRoundObject(1392, a) != 1408 || outputRoundObject(1400, a) != 1408 || 38*8 != 304 {
		t.Fatal("retained descriptor class or logical delta changed")
	}
}
