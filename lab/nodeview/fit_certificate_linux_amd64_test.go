//go:build linux && amd64

package nodeview

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/mailbox"
)

func fitCertificateBody(namespace, side, event int) [128]byte {
	var out [128]byte
	binary.BigEndian.PutUint32(out[:4], uint32(namespace))
	binary.BigEndian.PutUint16(out[4:6], uint16(side))
	binary.BigEndian.PutUint16(out[6:8], uint16(event))
	for j := 8; j < len(out); j++ {
		out[j] = byte(j + 17*side + 31*event + namespace)
	}
	return out
}

func fitCertificateRecord(namespace, side, event int) [392]byte {
	var out [392]byte
	out[0] = 3
	binary.BigEndian.PutUint32(out[1:5], uint32(event))
	binary.BigEndian.PutUint32(out[5:9], uint32(namespace))
	binary.BigEndian.PutUint16(out[9:11], uint16(side))
	binary.BigEndian.PutUint16(out[11:13], uint16(event))
	for j := 13; j < len(out); j++ {
		out[j] = byte(j + 17*side + 31*event + namespace)
	}
	return out
}

func fitCertificateExpectedRow(side, event, m, p, d int, hasPut bool, previous int) encodedMailboxRow {
	var row encodedMailboxRow
	if hasPut {
		row[0], row[1] = 1, 3
		row[4] = int16(boolInt(event > 0))
	}
	row[5] = int16(boolInt(event == m-1))
	if event > 0 {
		row[6], row[7], row[10], row[11] = int16(7+p), 1, int16(5*p), 1
	}
	if previous >= 0 {
		row[8], row[9] = int16((7+p)*(event-previous)), 1
	}
	if hasPut && side%2 == 1 {
		row[15], row[16] = int16((event+1)*(35+5*p)/10), 1
	}
	row[17] = int16(100 + 100*boolInt(event >= m/2) + 10*p + d)
	return row
}

func fitCertificateCorpus(t *testing.T, coordinate Coordinate, evaluation bool, budget *memoryBudget, frozen frozenTraining) (request, record []encodedTrainingRow, closeCorpus func()) {
	t.Helper()
	p, b, d, m := 0, int(boolInt(coordinate.Settings.CoverPuts)), int(boolInt(evaluation)), 16
	if strings.Contains(coordinate.ID, "33250000") {
		p = 1
	}
	if evaluation {
		m = 8
	}
	namespace := 1 + 2*(2*p+b) + d
	epoch, gap := int64(1000000000+1000000000*d), int64(35000000+5000000*p)
	corpus, err := newFitCorpusOwner(budget, availableHostMemory, allocatePrivateCapture)
	if err != nil {
		t.Fatal("typed corpus constructor admission failed")
	}
	t.Cleanup(corpus.close)
	if err = budget.checkAllocation(262144); err != nil {
		t.Fatal("typed corpus metadata admission failed")
	}
	in := &evaluationInput{budget: budget, resultCharge: &resultCharge{budget: budget}, public: publicConfig{n: 5, h: 3, binNS: 100000000, controlled: []int{4}, settings: coordinate.Settings, population: "peer", epochNS: epoch, cutoffNS: epoch + 30000000000}, established: make(map[uint16]bool, 16), portToRoster: map[uint16]int{2000: 0, 2001: 1, 2002: 2, 2003: 3, 2004: 4}}
	arena, err := newBudgetedArena(1<<20, 1<<20, budget)
	if err != nil {
		t.Fatal("protected typed corpus unavailable")
	}
	in.truth = privateTruth{arena: arena, budget: budget}
	in.views.nodes = []nodeView{{position: 4, arena: arena, budget: budget}}
	closed := false
	closeCorpus = func() {
		if closed {
			return
		}
		closed = true
		clear(request[:cap(request)])
		clear(record[:cap(record)])
		in.resultCharge.cleaned()
		in.resultCharge.discard()
		in.views.nodes[0].wipe()
		in.truth.close()
		clear(in.plans[:cap(in.plans)])
		releaseCapacity(in.plans, budget)
		in.plans = nil
		clear(in.established)
		clear(in.portToRoster)
		corpus.close()
	}
	t.Cleanup(closeCorpus)
	if err = preallocateFitCorpusAggregate(in); err != nil {
		t.Fatal("aggregate prepayment/preallocation failed")
	}
	prepaid := fitCorpusAggregatePointers(in)
	defer clear(prepaid[:])
	if !validFitCorpusAggregateCaps(in) {
		t.Fatal("aggregate caps differ from the predeclared bounds")
	}
	for _, pointer := range prepaid {
		if pointer == nil {
			t.Fatal("aggregate preallocation supplied an empty backing")
		}
	}
	for side := range 16 {
		if budget.checkAllocation(4096) != nil {
			t.Fatal("typed side helper admission failed")
		}
		route := replayRoute(coordinate, side)
		base := uint64(100000*namespace + 100*side + 1000)
		if corpus.reset(uint16(side), route) != nil {
			t.Fatal("typed reusable capture reset failed")
		}
		capture := corpus.capture
		for _, hop := range []uint8{2, 1, 0} {
			replaySetup(t, capture, true, hop, base+uint64(hop))
		}
		for event := range m / 2 {
			body := fitCertificateBody(namespace, side, event)
			replaySource(t, capture, true, body[:], true)
			clear(body[:])
		}
		for event := range m {
			real := event < m/2
			hasPut := real || b == 1 || event%2 == 0 || event == m-1
			originalEvent := event
			if event == m-1 {
				originalEvent--
			}
			raw := fitCertificateRecord(namespace, side, originalEvent)
			var payload []byte
			if hasPut {
				payload = raw[:]
				if event != m-1 {
					replaySeal(t, capture, true, payload, real, event)
				}
			}
			replayTypedRequest(t, capture, true, 1, uint16(event), payload, 2, true)
			observation := mailboxObservation{Circuit: uint32(1000*namespace + 3*side + 3), Order: uint32(m*side + event + 1), Tag: uint16(event), CallNS: epoch + int64(m*side+event+1)*gap, Complete: true, FetchQueue: uint32(10000*namespace + 1000 + side), HasPut: hasPut}
			observation.ReturnNS = observation.CallNS + int64(10000*(100+100*boolInt(!real)+10*p+d))
			if hasPut {
				observation.PutQueue = uint32(10000*namespace + 1000 + (side ^ 1))
				observation.RecordAlias = uint32(1 + 4096*namespace + 32*side + originalEvent)
				observation.RecordKind, observation.RecordNumber, observation.ReplyStatus = 3, uint32(originalEvent), mailbox.PutStored
				observation.record = replayCopy(t, arena, raw[:])
			}
			if len(in.views.nodes[0].mailbox) == cap(in.views.nodes[0].mailbox) {
				t.Fatal("prepaid observation bound exceeded")
			}
			in.views.nodes[0].mailbox, err = appendPrivate(in.views.nodes[0].mailbox, observation, budget)
			if err != nil {
				t.Fatal("typed observation growth admission failed")
			}
			clear(raw[:])
		}
		if size, e := truthStreamSize(capture.truth); e != nil || !evaluation && b == 1 && (size.bytes != 13970 || size.frames != 13) {
			t.Fatal("independent complete-wire size changed")
		}
		if corpus.transfer(&in.truth) != nil {
			t.Fatal("typed reusable encode/decode failed")
		}
		for role, position := range route {
			if position == 4 {
				piece := replayViewPiece(side, route, uint8(role), base, uint32(1000*namespace+3*side+role+1))
				piece.setups[0].generation = piece.setups[0].hop*10 + 2
				if len(in.views.nodes[0].connections)+len(piece.connections) > cap(in.views.nodes[0].connections) || len(in.views.nodes[0].setups)+len(piece.setups) > cap(in.views.nodes[0].setups) {
					t.Fatal("prepaid view metadata bound exceeded")
				}
				for _, connection := range piece.connections {
					in.views.nodes[0].connections, err = appendPrivate(in.views.nodes[0].connections, connection, budget)
					if err != nil {
						t.Fatal("typed connection admission failed")
					}
				}
				for _, setup := range piece.setups {
					in.views.nodes[0].setups, err = appendPrivate(in.views.nodes[0].setups, setup, budget)
					if err != nil {
						t.Fatal("typed setup admission failed")
					}
				}
				clear(piece.connections[:cap(piece.connections)])
				clear(piece.setups[:cap(piece.setups)])
			}
		}
		if len(in.plans) != side || len(in.plans) == cap(in.plans) {
			t.Fatal("prepaid plan order or bound changed")
		}
		in.plans, err = appendPrivate(in.plans, workloadPlan{side: uint16(side), route: route}, budget)
		if err != nil {
			t.Fatal("prepaid plan append failed")
		}
		in.established[uint16(side)] = true
	}
	if !validFitCorpusAggregateCaps(in) || fitCorpusAggregatePointers(in) != prepaid {
		t.Fatal("real aggregate codec growth replaced a prepaid backing")
	}
	if budget.checkAllocation(262144) != nil {
		t.Fatal("typed ownership/map admission failed")
	}
	in.truth.ownership, err = parseSetupOwnership(in.truth.setups)
	if err != nil || validateViewBindings(in.views.nodes[0], in.portToRoster) != nil {
		t.Fatal("typed corpus setup ownership or actual view binding failed")
	}
	features, err := boundedMailboxRows(in.views.nodes[0], coordinate.Settings.RateNS)
	if err != nil {
		t.Fatal("typed corpus feature extraction failed")
	}
	defer clear(features[:cap(features)])
	for side := range 16 {
		previous := -1
		for event := range m {
			o := in.views.nodes[0].mailbox[m*side+event]
			want := fitCertificateExpectedRow(side, event, m, p, d, o.HasPut, previous)
			positive, eligible, owner, ok := mailboxLabel(in.views.nodes[0], o, in.truth)
			if !ok || !eligible || owner != uint16(side) || positive != (event < m/2) || features[m*side+event] != want || !validEncodedMailboxRow(want) {
				t.Fatal("independent 18-column identity/eligibility/order oracle failed")
			}
			if o.HasPut {
				previous = event
			}
		}
	}
	var falsePairs uint64
	in.queueFalsePairs = &falsePairs
	q, _, joined, request, record, err := mailboxEvaluation(*in)
	if err != nil || joined.Value == nil || *joined.Value != 1 || falsePairs != 0 || q.Value == nil {
		t.Fatal("typed corpus honest queue join or extraction failed")
	}
	wantQ := 0.
	if b == 0 {
		wantQ = .375
		if evaluation {
			wantQ = .25
		}
	}
	if *q.Value != wantQ || len(request) != 16*m || len(record) != 16*m-16*(m/4-1)*int(boolInt(b == 0)) {
		t.Fatal("nonvacuous request/record filtering or no-put fraction changed")
	}
	for population, rows := range [][]encodedTrainingRow{request, record} {
		var counts, originals [2]int
		var conversations [2][8]int
		for _, row := range rows {
			class := int(boolInt(row.Positive))
			counts[class]++
			originals[class] += int(boolInt(row.OriginalSeal))
			conversations[class][row.Conversation]++
		}
		wantNegative, wantPositive := 8*m, 8*m
		wantOriginal := [2]int{16 * (m/2 - 1), wantPositive}
		if b == 0 {
			wantOriginal[0] = 4 * m
			if population == 1 {
				wantNegative = 16 * (m/4 + 1)
			}
		}
		if counts != [2]int{wantNegative, wantPositive} || originals != wantOriginal {
			t.Fatal("predetermined class or original-seal support changed")
		}
		for class := range 2 {
			for _, n := range conversations[class] {
				if n != counts[class]/8 {
					t.Fatal("predetermined eight-conversation support changed")
				}
			}
		}
	}
	if evaluation {
		predicted, err := predict(in.views, in.public, frozen)
		defer predicted.wipe()
		if err != nil || len(predicted.methods) != 1 {
			t.Fatal("matching frozen evaluation prediction path failed")
		}
		scores, labels, groups, err := annotateMethod(predicted.methods[0], *in)
		defer clear(scores[:cap(scores)])
		defer clear(labels)
		want := request
		if frozen.record != nil {
			want = record
		}
		if err != nil || groups != 8 || len(scores) != len(want) {
			t.Fatal("disjoint fixed evaluation labels or population changed")
		}
		for i, score := range scores {
			if score.True != want[i].Positive {
				t.Fatal("frozen prediction acquired evaluation-dependent labels")
			}
		}
	}
	return request, record, closeCorpus
}

func fitCertificateProcess(t *testing.T, suite jcrypto.Suite, rows []encodedTrainingRow, budget *memoryBudget) MailboxTraining {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	f := &fixture{ctx: ctx, cancel: cancel, suite: suite, budget: budget, resources: &resourceUsage{}}
	var err error
	f.arena, err = newBudgetedArena(4096, 4096, budget)
	if err != nil {
		cancel()
		t.Fatal("fitter protocol arena admission failed")
	}
	before := budget.used - 4096
	t.Cleanup(func() {
		if err := f.close(); err != nil {
			t.Error("fitter process cleanup failed")
		}
	})
	trained, err := f.train(rows, true, true)
	if err != nil || !validateMailboxTraining(trained) || len(f.children) != 2 {
		t.Fatal("independent framed trainer/auditor failed")
	}
	for i, child := range f.children {
		if child.role != []byte{roleTrainer, roleFitAuditor}[i] || !child.reaped || child.waitErr != nil || child.usageErr != nil || child.reason != ReasonNone || trained.Releasable && i == 1 && !child.fitOK {
			t.Fatal("fitter role did not reach definitive Wait and clean readers")
		}
	}
	if err = f.close(); err != nil || budget.used != before || f.scorerReservation != 0 || quarantinedFixtures.Load() != 0 {
		t.Fatal("fitter released input ownership or retained completed role loans")
	}
	return trained
}

func TestMailboxFitCertificateOptimized(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("optimized protected fit certification")
	}
	if err := protectProcess(controllerArenaBytes); err != nil {
		t.Fatal("protected certificate controller unavailable")
	}
	for _, suite := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(suite.String(), func(t *testing.T) {
			budget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: (&hostCapacity{}).checkGrowth}
			bundle := newFitFrozenOwner(t, budget, suite)
			defer bundle.close()
			for _, coordinate := range bundle.plan.Configurations {
				if coordinate.Population != "classifier" {
					continue
				}
				t.Run(coordinate.ID, func(t *testing.T) {
					for population, name := range []string{"request", "record"} {
						t.Run(name, func(t *testing.T) {
							if budget.reserve(8<<20) != nil || budget.checkAllocation(8<<20) != nil {
								t.Fatal("retained leaf replay/serialization history admission failed")
							}
							t.Cleanup(func() { budget.release(8 << 20) })
							request, record, closeTraining := fitCertificateCorpus(t, coordinate, false, budget, frozenTraining{})
							rows := request
							if population == 1 {
								rows = record
							}
							trained := fitCertificateProcess(t, suite, rows, budget)
							defer wipeMailboxTraining(&trained)
							if !trained.Releasable || trained.Model == nil || trained.Witness == nil || !trained.Support.RAMConformance || !trained.Support.Stable {
								t.Fatal("distinct extracted family did not release a genuine model")
							}
							train, truth := fitTestInputs(t, rows)
							point, ok := metrics.FitDiscriminant(train, truth)
							if !ok || !sameMailboxModel(point, *trained.Model) {
								t.Fatal("process model differs from original production bits")
							}
							wipeMailboxModel(&point)
							released := bundle.leaf(t, trained, coordinate.ID, name)
							defer wipeMailboxTraining(&released.Training)
							closeTraining()
							frozen := frozenTraining{request: released.Training.Model}
							if population == 1 {
								frozen = frozenTraining{record: released.Training.Model}
							}
							evalRequest, evalRecord, closeEvaluation := fitCertificateCorpus(t, coordinate, true, budget, frozen)
							evaluation := evalRequest
							if population == 1 {
								evaluation = evalRecord
							}
							values, _ := fitTestInputs(t, evaluation)
							scores := released.Training.Model.Scores(values)
							if len(scores) != len(evaluation) || len(scores) == 0 {
								t.Fatal("disjoint evaluation did not use its matching frozen model")
							}
							clear(scores[:cap(scores)])
							closeEvaluation()
							if coordinate.ID == "mail-P0-C0" && population == 0 {
								var histories uint64
								defer func() { budget.release(histories) }()
								for _, name := range []string{"large-dependent", "general-68572", "general-68574", "cutoff-full-row"} {
									n := 65536
									if name == "general-68572" {
										n = 68572
									}
									if name == "general-68574" {
										n = 68574
									}
									if name == "cutoff-full-row" {
										n = 108784
									}
									charge := uint64(n) * uint64(unsafe.Sizeof(encodedTrainingRow{}))
									if budget.reserve(charge) != nil || budget.checkAllocation(charge) != nil {
										t.Fatal("large protected KAT pool admission failed")
									}
									histories += charge
									large := fitKnownRows(t, name)
									result := fitCertificateProcess(t, suite, large, budget)
									if name == "cutoff-full-row" {
										if result.Reason != string(ReasonFitSensitive) || !result.Support.RAMConformance {
											t.Fatal("protected genuine cutoff did not withhold")
										}
										assertFitSuppressed(t, result)
										exerciseFitAuditorMismatch(t, suite, budget, large, &result)
									} else if !result.Releasable {
										t.Fatal("mandatory large numerical process path did not release")
									}
									wipeMailboxTraining(&result)
									clear(large[:cap(large)])
								}
								exerciseFitCertificateProcessEOF(t, suite, budget)
							}
							bundle.take(t, &released)
						})
					}
				})
			}
			bundle.finish(t)
		})
	}
}

func exerciseFitAuditorMismatch(t *testing.T, suite jcrypto.Suite, budget *memoryBudget, rows []encodedTrainingRow, trainer *MailboxTraining) {
	t.Helper()
	if trainer.Releasable || trainer.Reason != string(ReasonFitSensitive) || !trainer.Support.RAMConformance {
		t.Fatal("malformed-result lifecycle lacks a genuine withheld trainer predecessor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	f := &fixture{ctx: ctx, cancel: cancel, suite: suite, budget: budget, resources: &resourceUsage{}}
	var err error
	f.arena, err = newBudgetedArena(4096, 4096, budget)
	if err != nil {
		cancel()
		t.Fatal("malformed-result arena admission failed")
	}
	defer func() { _ = f.close() }()
	reservation := uint64(len(rows))*512 + 8<<20
	if budget.reserve(reservation) != nil || budget.checkAllocation(reservation) != nil {
		t.Fatal("malformed-result full role admission failed")
	}
	f.scorerReservation += reservation
	child, err := f.spawnFit(roleFitAuditor, len(rows), trainer.Releasable, Reason(trainer.Reason))
	if err != nil {
		t.Fatal("real malformed-result auditor spawn failed")
	}
	boot, err := child.expect(ctx, opBoot, time.Now().Add(30*time.Second))
	if err != nil || boot.u8() != roleFitAuditor || boot.u8() != byte(suite) || boot.u16() != 0 || boot.u8() != 1 || boot.end() != nil {
		t.Fatal("real malformed-result auditor boot failed")
	}
	w := encoder{budget: budget}
	w.u8(2)
	w.u8(0)
	w.bool(true)
	w.bool(true)
	if child.writer.send(opTrain, w) != nil {
		t.Fatal("malformed-result header failed")
	}
	// a truncated submitted stream contradicts the bound complete trainer count and reason
	w = encoder{budget: budget}
	w.u8(2)
	w.u8(1)
	w.u16(128)
	for _, row := range rows[:128] {
		for _, v := range row.Values {
			w.u16(uint16(v))
		}
		w.bool(row.Positive)
		w.u16(row.Conversation)
		w.bool(row.OriginalSeal)
	}
	if child.writer.send(opTrain, w) != nil {
		t.Fatal("malformed-result truncated row stream failed")
	}
	w = encoder{budget: budget}
	w.u8(2)
	w.u8(255)
	if child.writer.send(opTrain, w) != nil {
		t.Fatal("malformed-result final command failed")
	}
	if reasonOf(f.finishOne(child)) != ReasonIPC || child.writer.frames != 3 || f.scorerReservation != reservation || budget.used < reservation || child.reaped {
		t.Fatal("inconsistent real auditor result crossed Ack or released ownership")
	}
	_ = f.close()
	if !child.reaped || !child.joinReaders(time.Now().Add(time.Second)) || f.scorerReservation != 0 || f.quarantined || child.training.Model != nil || child.training.Witness != nil {
		t.Fatal("real malformed-result lifecycle failed definitive Wait/reader rollback")
	}
}

func exerciseFitCertificateProcessEOF(t *testing.T, suite jcrypto.Suite, budget *memoryBudget) {
	t.Helper()
	pool := uint64(128) * uint64(unsafe.Sizeof(encodedTrainingRow{}))
	if budget.reserve(pool) != nil || budget.checkAllocation(pool) != nil {
		t.Fatal("held-EOF input admission failed")
	}
	rows := mailboxTrainingFixture()
	defer func() { clear(rows[:cap(rows)]); budget.release(pool) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	f := &fixture{ctx: ctx, cancel: cancel, suite: suite, budget: budget, resources: &resourceUsage{}}
	var err error
	f.arena, err = newBudgetedArena(4096, 4096, budget)
	if err != nil {
		cancel()
		t.Fatal("held-EOF arena unavailable")
	}
	defer func() {
		if f.close() != nil {
			t.Error("held-EOF fixture cleanup failed")
		}
	}()
	reservation := uint64(len(rows))*512 + 8<<20
	if budget.reserve(reservation) != nil || budget.checkAllocation(reservation) != nil {
		t.Fatal("held-EOF full fitter admission failed")
	}
	f.scorerReservation += reservation
	child, err := f.spawnFit(roleTrainer, len(rows), false, ReasonNone)
	if err != nil {
		t.Fatal("actual held-EOF trainer spawn failed")
	}
	until := time.Now().Add(30 * time.Second)
	boot, err := child.expect(ctx, opBoot, until)
	if err != nil || boot.u8() != roleTrainer || boot.u8() != byte(suite) || boot.u16() != 0 || boot.u8() != 1 || boot.end() != nil {
		t.Fatal("held-EOF real boot failed")
	}
	w := encoder{budget: budget}
	w.u8(2)
	w.u8(0)
	w.bool(true)
	w.bool(true)
	if child.writer.send(opTrain, w) != nil {
		t.Fatal("held-EOF training header failed")
	}
	w = encoder{budget: budget}
	w.u8(2)
	w.u8(1)
	w.u16(uint16(len(rows)))
	for _, row := range rows {
		for _, v := range row.Values {
			w.u16(uint16(v))
		}
		w.bool(row.Positive)
		w.u16(row.Conversation)
		w.bool(row.OriginalSeal)
	}
	if child.writer.send(opTrain, w) != nil {
		t.Fatal("held-EOF real row transfer failed")
	}
	w = encoder{budget: budget}
	w.u8(2)
	w.u8(255)
	if child.writer.send(opTrain, w) != nil {
		t.Fatal("held-EOF final train command failed")
	}
	end, err := child.expect(ctx, opEnd, until)
	if err != nil || end.u8() != 0 || decodeReason(end) != ReasonNone || end.u64() != child.statusConsumed {
		t.Fatal("held-EOF real terminal failed")
	}
	views, truths := end.u64(), end.u64()
	decodeCounts(end)
	if end.end() != nil || views != 1 || truths != 0 || waitFrames(ctx, &child.viewFrames, views, child.viewProgress, until) != nil {
		t.Fatal("held-EOF output readers failed")
	}
	w = encoder{budget: budget}
	w.u8(0)
	if child.writer.send(opAck, w) != nil {
		t.Fatal("held-EOF real acknowledgement failed")
	}
	cleaned, err := child.expect(ctx, opCleaned, until)
	if err != nil || !cleaned.bool() || !cleaned.bool() || cleaned.end() != nil || !child.training.Releasable {
		t.Fatal("held-EOF real cleanup receipt failed")
	}
	if f.scorerReservation != reservation || budget.used < reservation+pool || child.reaped {
		t.Fatal("Cleaned released the full fitter lease before Wait")
	}
	select {
	case <-child.exited:
		t.Fatal("trainer exited before held command EOF")
	default:
	}
	child.command.Close()
	if f.reap(child, until) != nil {
		t.Fatal("held-EOF definitive Wait or reader join failed")
	}
	wipeMailboxTraining(&child.training)
	budget.release(reservation)
	f.scorerReservation -= reservation
}

func fitCertificateDenseRows(t *testing.T) []encodedTrainingRow {
	t.Helper()
	rows := make([]encodedTrainingRow, maxTrainingRows)
	t.Cleanup(func() { clear(rows[:cap(rows)]) })
	for i := range rows {
		h := i >> 12 & 1
		r := &rows[i]
		r.Positive, r.Conversation, r.OriginalSeal = h != 0, uint16(i%4), h == 0
		r.Values = encodedMailboxRow{int16(h), int16(3 * h), int16(h * (i % 4096)), int16(h * (i >> 7 & 1) * (i % 4096)), int16(h * (i >> 7 & 1)), int16(h * (i >> 8 & 1)), int16((i >> 9 & 1) * (i % 4096)), int16(i >> 9 & 1), int16((i >> 10 & 1) * (i % 4096)), int16(i >> 10 & 1), int16((i >> 9 & 1) * ((i % 8191) - 4095)), 0, 0, 0, 0, int16(h * (i >> 11 & 1) * (i % 3001)), int16(h * (i >> 11 & 1)), int16(i % 4096)}
		if i%5 != 0 {
			r.Values[10+i%5] = 1
		}
		if !validEncodedMailboxRow(r.Values) {
			t.Fatal("dense fixed row violates schema")
		}
	}
	return rows
}

func TestMailboxFitCertificateMaxRowsOptimized(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("optimized maximum-row fit certification")
	}
	if protectProcess(controllerArenaBytes) != nil {
		t.Fatal("protected maximum-row controller unavailable")
	}
	for _, suite := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(suite.String(), func(t *testing.T) {
			budget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: (&hostCapacity{}).checkGrowth}
			charge := uint64(maxTrainingRows) * uint64(unsafe.Sizeof(encodedTrainingRow{}))
			if budget.reserve(charge) != nil || budget.checkAllocation(charge) != nil {
				t.Fatal("maximum-row pool admission failed")
			}
			rows := fitCertificateDenseRows(t)
			defer func() { clear(rows[:cap(rows)]); budget.release(charge) }()
			pureHistory := uint64(maxTrainingRows)*169 + 8<<20
			if budget.reserve(pureHistory) != nil || budget.checkAllocation(pureHistory) != nil {
				t.Fatal("retained independent replay history admission failed")
			}
			defer budget.release(pureHistory)
			train, truth := fitTestInputs(t, rows)
			point, ok := metrics.FitDiscriminant(train, truth)
			if !ok {
				t.Fatal("dense cost qualification short-circuited at the production fitter")
			}
			wipeMailboxModel(&point)
			s := testFitCertificate(t)
			witness := mailboxMoments(rows)
			replayed, _, ok := checkMailboxFit(train, truth, &witness, s)
			defer wipeMailboxModel(&replayed)
			defer wipeMailboxWitness(&witness)
			if !ok || s.scalars[33] != maxTrainingRows || s.scalars[32] != 22413312 {
				t.Fatal("maximum-row certificate did not finish all dense row updates")
			}
			trained := fitCertificateProcess(t, suite, rows, budget)
			defer wipeMailboxTraining(&trained)
			if !trained.Support.RAMConformance || trained.Reason != "" && trained.Reason != string(ReasonFitSensitive) {
				t.Fatal("maximum-row real deadline qualification did not complete conformance")
			}
		})
	}
}

type fitCertificateRetainedWriter struct {
	w      io.Writer
	body   []byte
	header bool
	fail   bool
}

func (w *fitCertificateRetainedWriter) Write(b []byte) (int, error) {
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	if !w.header {
		w.header = true
	} else {
		w.body = b
	}
	return w.w.Write(b)
}

func TestFitCertificateCleanedPrecedesCommandEOF(t *testing.T) {
	if protectProcess(controllerArenaBytes) != nil {
		t.Fatal("protected cleanup controller unavailable")
	}
	for _, role := range []byte{roleTrainer, roleFitAuditor} {
		for _, name := range []string{"success", "sensitive", "send-failure", "terminal-failure"} {
			t.Run(roleNames[role]+"/"+name, func(t *testing.T) {
				fixture := "small-dependent"
				if name == "sensitive" {
					fixture = "cutoff-full-row"
				}
				n := 16384
				if name == "sensitive" {
					n = 108784
				}
				budget := &memoryBudget{limit: controllerArenaBytes, beforeAllocation: (&hostCapacity{}).checkGrowth}
				charge := uint64(n)*(42+512) + (8 << 20) + (4 << 16)
				if budget.reserve(charge) != nil || budget.checkAllocation(charge) != nil {
					t.Fatal("complete direct-fit/IO prospective admission failed")
				}
				defer budget.release(charge)
				rows := fitKnownRows(t, fixture)
				s, err := acquireFitCertificate(func(n uint64) error { return currentHostGrowth(n, availableHostMemory) })
				if err != nil {
					t.Fatal("protected cleanup proof admission failed")
				}
				defer s.close()
				training := trainMailbox(rows, featureVersion, true, true, s)
				if !training.Support.RAMConformance || name != "sensitive" && !training.Releasable || name == "sensitive" && training.Reason != string(ReasonFitSensitive) {
					t.Fatal("cleanup did not start from an actual completed fit")
				}
				var weights, centers []float64
				var kept, unused []int
				witness := training.Witness
				if training.Model != nil {
					weights, centers, kept, unused = training.Model.Weights, training.Model.Center, training.Model.Kept, training.Model.Unused
				}
				s.padding[0], s.padding[len(s.padding)-1], s.words[7][71] = 0xa5, 0xa5, 0xa5
				commandRead, commandWrite, err := os.Pipe()
				if err != nil {
					t.Fatal("owned command pipe unavailable")
				}
				defer commandRead.Close()
				defer commandWrite.Close()
				statusRead, statusWrite, err := os.Pipe()
				if err != nil {
					t.Fatal("owned status pipe unavailable")
				}
				defer statusRead.Close()
				defer statusWrite.Close()
				viewRead, viewWrite, err := os.Pipe()
				if err != nil {
					t.Fatal("owned view pipe unavailable")
				}
				truthRead, truthWrite, err := os.Pipe()
				if err != nil {
					t.Fatal("owned truth pipe unavailable")
				}
				defer truthRead.Close()
				defer truthWrite.Close()
				defer viewRead.Close()
				defer viewWrite.Close()
				if budget.checkAllocation(65536) != nil {
					t.Fatal("direct-fit command reader admission failed")
				}
				command, err := newProtocolReader(commandRead, [16]byte{}, 1<<20)
				if err != nil {
					t.Fatal("protected command reader unavailable")
				}
				defer command.close()
				if budget.checkAllocation(65536) != nil {
					t.Fatal("direct-fit status reader admission failed")
				}
				status, err := newProtocolReader(statusRead, [16]byte{}, 1<<20)
				if err != nil {
					t.Fatal("protected status reader unavailable")
				}
				defer status.close()
				if budget.checkAllocation(65536) != nil {
					t.Fatal("direct-fit view reader admission failed")
				}
				view, err := newProtocolReader(viewRead, [16]byte{}, 1<<20)
				if err != nil {
					t.Fatal("protected view reader unavailable")
				}
				defer view.close()
				retained := &fitCertificateRetainedWriter{w: viewWrite, fail: name == "send-failure"}
				child := &childIO{command: command, files: [4]*os.File{commandRead, statusWrite, viewWrite, truthWrite}, role: role, truth: &protocolWriter{w: truthWrite, limit: clientArenaBytes}, status: &protocolWriter{w: statusWrite, limit: 1 << 20}, view: &protocolWriter{w: retained, limit: 1 << 20}}
				expectedReason := reasonByte(Reason(training.Reason))
				done := make(chan error, 1)
				go func() { done <- finishTrainingCommand(child, rows, &training, s) }()
				if name != "send-failure" {
					op, frame, err := view.next()
					if err != nil {
						t.Fatal("actual role output failed")
					}
					if role == roleTrainer {
						decoded, err := decodeTraining(frame)
						if op != opTrained || err != nil || !validateMailboxTraining(decoded) {
							t.Fatal("actual trainer output framing failed")
						}
						wipeMailboxTraining(&decoded)
					} else if op != opFitCheck || frame.u8() != 2 || frame.bool() != (name != "sensitive") || frame.u8() != expectedReason || int(frame.u32()) != len(rows) || frame.end() != nil {
						t.Fatal("actual auditor output framing failed")
					}
					op, frame, err = status.next()
					if err != nil || op != opEnd || frame.u8() != 0 || decodeReason(frame) != ReasonNone || frame.u64() != 1 || frame.u64() != 1 || frame.u64() != 0 {
						t.Fatal("actual terminal frame failed")
					}
					decodeCounts(frame)
					if frame.end() != nil {
						t.Fatal("terminal counts framing failed")
					}
					if name == "terminal-failure" {
						commandWrite.Close()
					} else {
						ack := encoder{}
						ack.u8(0)
						if (&protocolWriter{w: commandWrite, limit: 1 << 20}).send(opAck, ack) != nil {
							t.Fatal("actual terminal acknowledgement failed")
						}
						op, frame, err = status.next()
						if err != nil || op != opCleaned || !frame.bool() || !frame.bool() || frame.end() != nil {
							t.Fatal("actual cleanup acknowledgement failed")
						}
						select {
						case <-done:
							t.Fatal("cleanup returned before owned command EOF")
						default:
						}
					}
				}
				if name == "send-failure" || name == "terminal-failure" {
					select {
					case err = <-done:
						if err == nil {
							t.Fatal("real send or terminal failure was accepted")
						}
					case <-time.After(5 * time.Second):
						t.Fatal("failed final command did not join")
					}
				}
				if child.truth.frames != 0 || child.truth.bytes != 0 {
					t.Fatal("empty real truth writer emitted data")
				}
				truthWrite.Close()
				var truthByte [1]byte
				if n, e := truthRead.Read(truthByte[:]); n != 0 || e != io.EOF {
					t.Fatal("empty owned truth pipe did not reach real EOF")
				}
				for _, x := range unsafe.Slice((*byte)(unsafe.Pointer(s)), 65536) {
					if x != 0 {
						t.Fatal("positive Cleaned preceded full proof/body/padding erasure")
					}
				}
				for _, row := range rows[:cap(rows)] {
					if row != (encodedTrainingRow{}) {
						t.Fatal("cleanup retained a private row")
					}
				}
				for _, data := range [][]float64{weights, centers} {
					for _, x := range data[:cap(data)] {
						if x != 0 {
							t.Fatal("cleanup retained model backing")
						}
					}
				}
				for _, data := range [][]int{kept, unused} {
					for _, x := range data[:cap(data)] {
						if x != 0 {
							t.Fatal("cleanup retained column backing")
						}
					}
				}
				if witness != nil && (witness.Count != 0 || witness.Kept != nil || witness.Unused != nil) || training.Model != nil || training.Witness != nil || s.flags[0] != 0 || command.scratch != nil {
					t.Fatal("cleanup retained owned witnesses or live aliases")
				}
				for _, x := range retained.body[:cap(retained.body)] {
					if x != 0 {
						t.Fatal("cleanup retained sent encoder capacity")
					}
				}
				if name != "send-failure" && name != "terminal-failure" {
					commandWrite.Close()
					select {
					case err = <-done:
						if err != nil {
							t.Fatal("owned command EOF failed")
						}
					case <-time.After(5 * time.Second):
						t.Fatal("owned final command did not join")
					}
				}
			})
		}
	}
}

func TestFitCertificateFailedChildSerializationSuppression(t *testing.T) {
	s := testFitCertificate(t)
	failed := trainMailbox(mailboxTrainingFixture(), featureVersion, false, true, s)
	w := encodeTraining(failed)
	defer w.wipe()
	if w.bad || w.err != nil {
		t.Fatal("fixed failed training could not encode")
	}
	decoded, err := decodeTraining(&decoder{b: w.b})
	if err != nil || decoded.Releasable || decoded.Model != nil || decoded.Witness != nil {
		t.Fatal("failed training child frame attached private fitting state")
	}
	w.u8(1)
	if _, err = decodeTraining(&decoder{b: w.b}); err == nil {
		t.Fatal("failed training accepted a trailing model attachment")
	}
	failed.Model = &metrics.Discriminant{Weights: []float64{1}}
	forbidden := encodeTraining(failed)
	defer forbidden.wipe()
	if !forbidden.bad || len(forbidden.b) != 0 {
		t.Fatal("failed training serializer accepted a model attachment")
	}
	wipeMailboxModel(failed.Model)
	failed.Model = nil
	failed.Witness = &MailboxFitWitness{Count: 1}
	forbidden = encodeTraining(failed)
	if !forbidden.bad || len(forbidden.b) != 0 {
		t.Fatal("failed training serializer accepted a witness attachment")
	}
	wipeMailboxWitness(failed.Witness)
}
