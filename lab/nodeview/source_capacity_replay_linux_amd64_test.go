//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"reflect"
	"testing"

	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/mailbox"
)

const replayBootstrapSeed = int64(1171601)
const replayPowerSeed = int64(1171610)
const replayEpoch = int64(1000000000)

func replayBits(t *testing.T, path string, left, right any) {
	t.Helper()
	aliases, reverse := make(map[uintptr]uintptr), make(map[uintptr]uintptr)
	var compare func(string, reflect.Value, reflect.Value)
	compare = func(path string, a, b reflect.Value) {
		if a.IsValid() != b.IsValid() {
			t.Fatalf("fixed replay validity differs at %s", path)
		}
		if !a.IsValid() {
			return
		}
		if a.Type() != b.Type() {
			t.Fatalf("fixed replay type differs at %s", path)
		}
		bad := false
		switch a.Kind() {
		case reflect.Bool:
			bad = a.Bool() != b.Bool()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			bad = a.Int() != b.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			bad = a.Uint() != b.Uint()
		case reflect.String:
			bad = a.String() != b.String()
		case reflect.Float64:
			bad = math.Float64bits(a.Float()) != math.Float64bits(b.Float())
		case reflect.Float32:
			bad = math.Float32bits(float32(a.Float())) != math.Float32bits(float32(b.Float()))
		case reflect.Interface, reflect.Pointer:
			if a.IsNil() != b.IsNil() {
				bad = true
			} else if !a.IsNil() {
				if a.Kind() == reflect.Pointer {
					x, y := a.Pointer(), b.Pointer()
					if old, ok := aliases[x]; ok && old != y {
						bad = true
						break
					}
					if old, ok := reverse[y]; ok && old != x {
						bad = true
						break
					}
					aliases[x], reverse[y] = y, x
				}
				compare(path+".value", a.Elem(), b.Elem())
			}
		case reflect.Slice:
			if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
				bad = true
				break
			}
			for i := 0; i < a.Len(); i++ {
				compare(path+"["+decimal(i)+"]", a.Index(i), b.Index(i))
			}
		case reflect.Array:
			for i := 0; i < a.Len(); i++ {
				compare(path+"["+decimal(i)+"]", a.Index(i), b.Index(i))
			}
		case reflect.Struct:
			for i := 0; i < a.NumField(); i++ {
				compare(path+"."+a.Type().Field(i).Name, a.Field(i), b.Field(i))
			}
		case reflect.Map:
			if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
				bad = true
				break
			}
			for _, key := range a.MapKeys() {
				compare(path+".entry", a.MapIndex(key), b.MapIndex(key))
			}
		default:
			t.Fatalf("unsupported fixed replay kind at %s", path)
		}
		if bad {
			t.Fatalf("fixed replay differs at %s", path)
		}
	}
	compare(path, reflect.ValueOf(left), reflect.ValueOf(right))
}

func replayArena(t *testing.T) *lockedArena {
	t.Helper()
	a, e := newArena(clientArenaBytes)
	if e != nil {
		t.Fatal("protected replay arena unavailable")
	}
	t.Cleanup(a.close)
	return a
}

func replayCopy(t *testing.T, a *lockedArena, b []byte) arenaRef {
	t.Helper()
	r, ok := a.copy(b)
	if !ok {
		t.Fatal("bounded replay payload did not fit")
	}
	return r
}

func replayCapture(t *testing.T, current bool, side uint16, route [3]uint8) *privateCapture {
	t.Helper()
	var p *privateCapture
	if current {
		p = capacityTestCapture(t)
	} else {
		p = &privateCapture{truth: privateTruth{arena: replayArena(t)}, nextSetupHop: 255}
		t.Cleanup(p.close)
	}
	p.side, p.route = side, route
	return p
}

func replaySetup(t *testing.T, p *privateCapture, current bool, hop uint8, id uint64) {
	t.Helper()
	if current {
		appendSetupSeal(p, hop, id)
	} else {
		if hop == 2 {
			p.generation++
			p.nextSetupHop = 1
		} else if hop == 1 {
			p.nextSetupHop = 0
		} else {
			p.nextSetupHop = 255
			p.completeGeneration = p.generation
		}
		p.truth.setups = append(p.truth.setups, actualSetup{p.side, hop, id, p.route[hop]})
	}
	if p.err != ReasonNone {
		t.Fatal("fixed setup retention failed")
	}
}

func replaySource(t *testing.T, p *privateCapture, current bool, body []byte, sent bool) {
	t.Helper()
	ref := replayCopy(t, p.truth.arena, body)
	index := len(p.truth.messages)
	if current {
		var e error
		index, e = p.sourceMessage(ref)
		if e != nil {
			t.Fatal("fixed source retention failed")
		}
	} else {
		p.truth.messages = append(p.truth.messages, actualMessage{side: p.side, body: ref})
	}
	p.truth.messages[index].sent = sent
}

func replayReceipt(t *testing.T, p *privateCapture, current bool, body []byte) {
	t.Helper()
	if current {
		markPeerReply(p, body)
	} else {
		ref := replayCopy(t, p.truth.arena, body)
		p.truth.messages = append(p.truth.messages, actualMessage{side: p.side, body: ref, replied: true})
	}
	if p.err != ReasonNone {
		t.Fatal("fixed received-body retention failed")
	}
}

func replayRecord(side, event int) [392]byte {
	var out [392]byte
	out[0] = 3
	binary.BigEndian.PutUint32(out[1:5], uint32(event))
	for i := 5; i < len(out); i++ {
		out[i] = byte(i + side*17 + event*31)
	}
	return out
}

func replaySeal(t *testing.T, p *privateCapture, current bool, record []byte, real bool, event int) {
	t.Helper()
	if current {
		var plain [371]byte
		if !real {
			plain[0] = 1
		}
		tag := keyTag{purpose: "e2e/step/key"}
		binary.BigEndian.PutUint32(tag.context[:4], uint32(event+1))
		p.beforeSeal(tag, nil, plain[:], []byte{3, 0, 0, 0, 0})
		p.afterSeal(tag, nil, record, nil)
		clear(plain[:])
	} else {
		ref := replayCopy(t, p.truth.arena, record)
		p.truth.seals = append(p.truth.seals, actualSeal{p.side, p.generation, ref, real})
	}
	if p.err != ReasonNone {
		t.Fatal("fixed data-seal retention failed")
	}
}

func replayTypedRequest(t *testing.T, p *privateCapture, current bool, generation uint32, tag uint16, record []byte, eligibility uint8, success bool) {
	t.Helper()
	next := p.truth.capacity
	if current {
		var e error
		next, e = p.truth.nextClient(4, len(record), len(record))
		if e != nil {
			t.Fatal("fixed typed request admission failed")
		}
	}
	ref := arenaRef{}
	if len(record) != 0 {
		ref = replayCopy(t, p.truth.arena, record)
	}
	p.truth.requests = append(p.truth.requests, actualRequest{p.side, generation, tag, ref, eligibility, success})
	if current {
		p.truth.capacity = next
	}
}

func replayWire(t *testing.T, p *privateCapture) []byte {
	t.Helper()
	p.frozen = true
	var wire bytes.Buffer
	writer := &protocolWriter{w: &wire, limit: clientArenaBytes}
	if e := sendTruth(&childIO{truth: writer}, &p.truth); e != nil {
		t.Fatal("fixed private freeze/encode failed")
	}
	out := bytes.Clone(wire.Bytes())
	clear(wire.Bytes()[:wire.Cap()])
	t.Cleanup(func() { clear(out[:cap(out)]) })
	return out
}

func replayDecode(t *testing.T, wire []byte, truth *privateTruth) {
	t.Helper()
	reader, e := newProtocolReader(bytes.NewReader(wire), [16]byte{}, clientArenaBytes)
	if e != nil {
		t.Fatal("protected replay reader unavailable")
	}
	defer reader.close()
	for {
		op, r, e := reader.next()
		if e == io.EOF {
			return
		}
		if e != nil || op != opTruth {
			t.Fatal("fixed private stream decode failed")
		}
		if e = receiveTruth(r, truth); e != nil {
			t.Fatal("fixed private record decode failed")
		}
	}
}

func replayTruthBits(t *testing.T, left, right privateTruth) {
	t.Helper()
	replayBits(t, "truth.setups", left.setups, right.setups)
	if len(left.messages) != len(right.messages) || len(left.seals) != len(right.seals) || len(left.requests) != len(right.requests) {
		t.Fatal("fixed private row counts differ")
	}
	for i, a := range left.messages {
		b := right.messages[i]
		replayBits(t, "truth.message.facts", [3]uint64{uint64(a.side), uint64(boolInt(a.sent)), uint64(boolInt(a.replied))}, [3]uint64{uint64(b.side), uint64(boolInt(b.sent)), uint64(boolInt(b.replied))})
		replayBits(t, "truth.message.body", left.arena.bytes(a.body), right.arena.bytes(b.body))
	}
	for i, a := range left.seals {
		b := right.seals[i]
		replayBits(t, "truth.seal.facts", [3]uint64{uint64(a.side), uint64(a.generation), uint64(boolInt(a.real))}, [3]uint64{uint64(b.side), uint64(b.generation), uint64(boolInt(b.real))})
		replayBits(t, "truth.seal.record", left.arena.bytes(a.record), right.arena.bytes(b.record))
	}
	for i, a := range left.requests {
		b := right.requests[i]
		replayBits(t, "truth.request.facts", [5]uint64{uint64(a.side), uint64(a.generation), uint64(a.tag), uint64(a.eligibility), uint64(boolInt(a.success))}, [5]uint64{uint64(b.side), uint64(b.generation), uint64(b.tag), uint64(b.eligibility), uint64(boolInt(b.success))})
		replayBits(t, "truth.request.record", left.arena.bytes(a.record), right.arena.bytes(b.record))
	}
}

func replayProducerBridge(t *testing.T) {
	parents := [2]privateTruth{{arena: replayArena(t)}, {arena: replayArena(t)}}
	defer parents[0].close()
	defer parents[1].close()
	var wires [2][]byte
	for branch := range 2 {
		current := branch == 1
		p := replayCapture(t, current, 0, [3]uint8{0, 1, 4})
		for i, hop := range []uint8{2, 1, 0} {
			replaySetup(t, p, current, hop, uint64(100+2-i))
		}
		body := outcomeTestBody(1)
		replaySource(t, p, current, body, true)
		replayReceipt(t, p, current, body)
		clear(body)
		body = outcomeTestBody(2)
		replaySource(t, p, current, body, false)
		clear(body)
		record := replayRecord(0, 0)
		replaySeal(t, p, current, record[:], true, 0)
		request := mailboxRequestForReplay(1, record[:])
		payload := request.Bytes()
		if current {
			gate := make(chan struct{})
			close(gate)
			conv := &conversation.Conversation{}
			delegate := &capacityCircuit{}
			observed := observedCircuit{Circuit: delegate, private: p, gate: gate, conversation: &conv, generation: 1}
			if e := observed.Send(payload); e != nil || delegate.calls != 1 || &delegate.body[0] != &payload[0] {
				t.Fatal("fixed callback changed its successful delegation")
			}
			if p.truth.requests[0].eligibility != 1 {
				t.Fatal("zero Conversation supplied an invented established label")
			}
		} else {
			replayTypedRequest(t, p, false, 1, 1, record[:], 1, true)
		}
		clear(payload)
		clear(request.Record[:])
		clear(record[:])
		for _, hop := range []uint8{2, 1, 2, 1, 0} {
			replaySetup(t, p, current, hop, uint64(200+len(p.truth.setups)))
		}
		wires[branch] = replayWire(t, p)
		replayDecode(t, wires[branch], &parents[branch])
		p.close()
	}
	replayBits(t, "producer.wire", wires[0], wires[1])
	replayTruthBits(t, parents[0], parents[1])
	replayBits(t, "producer.unanswered", parents[0].resolveMessageReceipts(), parents[1].resolveMessageReceipts())
}

type replayCorpus struct {
	in     evaluationInput
	counts Counts
}

type replayResult struct {
	run             RunResult
	audit           []RankAudit
	request, record []encodedTrainingRow
	pred            predictions
	annotations     []replayAnnotation
	features        [][]encodedMailboxRow
	labels          [][4]uint64
}

type replayAnnotation struct {
	scores []metrics.Score
	truth  map[int]int
	groups int
}

func (r *replayResult) close() {
	for i := range r.audit {
		wipeRankAudit(&r.audit[i])
	}
	for i := range r.request {
		r.request[i].wipe()
	}
	for i := range r.record {
		r.record[i].wipe()
	}
	r.pred.wipe()
	for i := range r.annotations {
		clear(r.annotations[i].scores)
		clear(r.annotations[i].truth)
	}
	for i := range r.features {
		clear(r.features[i][:cap(r.features[i])])
	}
	clear(r.labels)
	clear(r.run.RouteHistogram)
	clear(r.run.Methods)
	clear(r.run.LinkingTimes)
	*r = replayResult{}
}

func mailboxRequestForReplay(tag uint16, record []byte) mailbox.Request {
	request := mailbox.Request{Tag: tag, Fetch: [16]byte{1}}
	if len(record) != 0 {
		request.Put[0] = 1
		copy(request.Record[:], record)
	}
	return request
}

func replayRoute(coordinate Coordinate, side int) [3]uint8 {
	if coordinate.Population == "link" {
		return [3]uint8{0, uint8(2 + side%3), 1}
	}
	routes := allRoutes(coordinate.Topology == "peer", 4)
	defer clear(routes)
	return routes[side%len(routes)]
}

func replayViewPiece(side int, route [3]uint8, role uint8, base uint64, hop uint32) nodeView {
	position := route[role]
	node := outcomeTestNode(position, role, uint16(side), base, hop)
	in := &node.connections[0]
	in.localPort = 2000 + uint16(position)
	if role > 0 {
		in.remotePort = 4000 + uint16(side*10+int(role)-1)
		in.selectorPort = 2000 + uint16(route[role-1])
		in.peer = route[role-1]
	}
	if role < 2 {
		out := &node.connections[1]
		out.localPort = 4000 + uint16(side*10+int(role))
		out.remotePort = 2000 + uint16(route[role+1])
		out.peer = route[role+1]
		node.setups[0].nextPort = out.remotePort
		node.setups[0].nextCircuit = base + uint64(role+1)
	}
	s := &node.setups[0]
	s.opened = replayEpoch - 500000000 + int64(side)*1000000 + int64(role)*100000
	s.released = replayEpoch + 19000000000 + int64(side)*1000
	if side == 0 {
		s.released = 0
	}
	s.first = 1
	return node
}

func appendReplayPiece(node *nodeView, piece nodeView, side int, epoch int64, traces bool) {
	node.connections = append(node.connections, piece.connections...)
	node.setups = append(node.setups, piece.setups...)
	if !traces {
		return
	}
	s := piece.setups[0]
	for event := range 4 {
		stamp := epoch + int64((side%4)*2+event*5+1)*100000000
		node.cells = append(node.cells, cellView{connection: s.connection, hop: s.hop, circuit: s.circuit, index: s.index, kind: 1, dir: 0, stages: stageInput | stageLocal, counter: uint64(event + 1), inputTime: stamp, localTime: stamp})
		// raw boundaries deliberately carry a different fixed histogram from logical cells
		rawStamp := epoch + int64((side%2)*3+event*4+1)*100000000
		node.cells = append(node.cells, cellView{connection: s.connection, kind: 1, dir: 0, stages: stageInput, inputTime: rawStamp, localTime: rawStamp})
	}
}

func buildReplayCorpus(t *testing.T, coordinate Coordinate, units int, mail, training bool, edge string) [2]replayCorpus {
	t.Helper()
	var pair [2]replayCorpus
	for branch := range 2 {
		truth := privateTruth{arena: replayArena(t)}
		pair[branch].in = evaluationInput{truth: truth, plans: make([]workloadPlan, units), established: make(map[uint16]bool, units), nkEndpoints: make(map[uint32]int, units), portToRoster: map[uint16]int{2000: 0, 2001: 1, 2002: 2, 2003: 3, 2004: 4}, public: publicConfig{n: 5, h: 3, binNS: 100000000, controlled: append([]int(nil), coordinate.Controlled...), settings: coordinate.Settings, windowsNS: append([]int64(nil), linkingGrid[:]...), population: coordinate.Topology, epochNS: replayEpoch, cutoffNS: replayEpoch + coordinate.Settings.DurationNS}}
		for _, position := range coordinate.Controlled {
			pair[branch].in.views.nodes = append(pair[branch].in.views.nodes, nodeView{position: uint8(position), arena: truth.arena})
		}
		pair[branch].counts = inferenceTestCounts(units)
		index := branch
		t.Cleanup(func() {
			in := &pair[index].in
			for i := range in.views.nodes {
				in.views.nodes[i].wipe()
			}
			in.truth.close()
			clear(in.plans)
			clear(in.established)
			clear(in.nkEndpoints)
			clear(in.portToRoster)
			clear(in.fragmentSource)
		})
	}
	for side := range units {
		route := replayRoute(coordinate, side)
		base := uint64(1000 + side*100)
		var wires [2][]byte
		for branch := range 2 {
			current := branch == 1
			p := replayCapture(t, current, uint16(side), route)
			for _, hop := range []uint8{2, 1, 0} {
				replaySetup(t, p, current, hop, base+uint64(hop))
			}
			body := outcomeTestBody(byte(side + 1))
			if mail {
				for event := range 4 {
					message := outcomeTestBody(byte(side*4 + event + 1))
					replaySource(t, p, current, message, true)
					clear(message)
				}
			} else {
				replaySource(t, p, current, body, true)
			}
			if edge == "rebuilt" && side == 0 {
				replayReceipt(t, p, current, body)
				unsent := outcomeTestBody(250)
				replaySource(t, p, current, unsent, false)
				clear(unsent)
			}
			clear(body)
			if mail {
				for event := range 8 {
					real := event < 4
					if edge == "missing-class" {
						real = true
					}
					hasPut := training || coordinate.Settings.CoverPuts || real || event%2 == 0
					record := replayRecord(side, event)
					var payload []byte
					if hasPut {
						replaySeal(t, p, current, record[:], real, event)
						payload = record[:]
					}
					eligibility := uint8(2)
					if edge == "empty" && side >= units-2 {
						eligibility = 1
					}
					replayTypedRequest(t, p, current, 1, uint16(event), payload, eligibility, true)
					clear(record[:])
				}
			}
			if edge == "rebuilt" && side == 0 {
				for i, hop := range []uint8{2, 1, 2, 1, 0} {
					replaySetup(t, p, current, hop, base+50+uint64(i))
				}
				if mail {
					record := replayRecord(side, 6)
					replayTypedRequest(t, p, current, 3, 0, record[:], 2, true)
					clear(record[:])
				}
			}
			wires[branch] = replayWire(t, p)
			replayDecode(t, wires[branch], &pair[branch].in.truth)
			p.close()
		}
		replayBits(t, "corpus.private.wire", wires[0], wires[1])
		for branch := range 2 {
			in := &pair[branch].in
			in.plans[side] = workloadPlan{side: uint16(side), route: route}
			in.established[uint16(side)] = true
			for ni := range in.views.nodes {
				node := &in.views.nodes[ni]
				for role, position := range route {
					if position != node.position {
						continue
					}
					piece := replayViewPiece(side, route, uint8(role), base, uint32(side*3+role+1))
					if edge == "rebuilt" && side == 0 {
						piece.setups[0].stages &^= stageLocal
					}
					appendReplayPiece(node, piece, side, replayEpoch, !mail)
					if role == 0 {
						in.nkEndpoints[uint32(piece.connections[0].localPort)<<16|uint32(piece.connections[0].remotePort)] = 5 + side
					}
					if role == 2 && coordinate.Topology == "echo" && side%2 == 0 {
						body := outcomeTestBody(byte(side + 1))
						ref := replayCopy(t, in.truth.arena, body)
						clear(body)
						in.truth.fragments = append(in.truth.fragments, contentFragment{hop: piece.setups[0].hop, kind: 1, data: ref})
						in.fragmentSource = append(in.fragmentSource, fragmentSourceEntry{ref, node.position})
					}
					if edge == "rebuilt" && side == 0 {
						later := replayViewPiece(side, route, uint8(role), base+52-2, uint32(500+role))
						later.setups[0].circuit = base + 52 + uint64(2-role)
						if role < 2 {
							later.setups[0].nextCircuit = base + 53 - uint64(role)
						}
						appendReplayPiece(node, later, side, replayEpoch, false)
					}
				}
			}
		}
	}
	if mail {
		for branch := range 2 {
			in := &pair[branch].in
			for side := range units {
				for event := range 8 {
					real := event < 4
					if edge == "missing-class" {
						real = true
					}
					hasPut := training || coordinate.Settings.CoverPuts || real || event%2 == 0
					record := replayRecord(side, event)
					for ni := range in.views.nodes {
						node := &in.views.nodes[ni]
						if node.position != 4 {
							continue
						}
						stamp := replayEpoch + int64(side*8+event+1)*35000000
						duration := int64(1000000)
						if !real && (training || !coordinate.Settings.CoverPuts) {
							duration = 2000000
						}
						o := mailboxObservation{Circuit: uint32(side*3 + 3), Order: uint32(side*8 + event + 1), Tag: uint16(event), CallNS: stamp, ReturnNS: stamp + duration, Complete: true, FetchQueue: uint32(1000 + side), HasPut: hasPut}
						if hasPut {
							o.PutQueue = uint32(1000 + (side ^ 1))
							o.RecordAlias = uint32(side*8 + event + 1)
							o.RecordKind = 3
							o.RecordNumber = uint32(event)
							o.record = replayCopy(t, in.truth.arena, record[:])
							o.ReplyStatus = mailbox.PutStored
						}
						node.mailbox = append(node.mailbox, o)
					}
					clear(record[:])
				}
			}
			if edge == "rebuilt" {
				for ni := range in.views.nodes {
					node := &in.views.nodes[ni]
					if node.position == 4 {
						record := replayRecord(0, 6)
						node.mailbox = append(node.mailbox, mailboxObservation{Circuit: 502, Order: uint32(units*8 + 1), Tag: 0, CallNS: replayEpoch + 8000000000, ReturnNS: replayEpoch + 8001000000, Complete: true, FetchQueue: 1000, PutQueue: 1001, HasPut: true, RecordAlias: 7, RecordKind: 3, RecordNumber: 6, record: replayCopy(t, in.truth.arena, record[:]), ReplyStatus: mailbox.PutStored})
						clear(record[:])
					}
				}
			}
		}
	}
	for branch := range 2 {
		in := &pair[branch].in
		pair[branch].counts.Unanswered = in.truth.resolveMessageReceipts()
		var e error
		in.truth.ownership, e = parseSetupOwnership(in.truth.setups)
		if e != nil {
			t.Fatal("fixed setup ownership failed")
		}
		if edge == "ties" {
			for ni := range in.views.nodes {
				for si := range in.views.nodes[ni].setups {
					in.views.nodes[ni].setups[si].opened = replayEpoch - 1
				}
			}
		}
		if edge == "degenerate" {
			for ni := range in.views.nodes {
				cells := in.views.nodes[ni].cells
				for i := 1; i < len(cells); i += 2 {
					cells[i].inputTime, cells[i].localTime = cells[i-1].inputTime, cells[i-1].localTime
				}
			}
		}
	}
	replayTruthBits(t, pair[0].in.truth, pair[1].in.truth)
	replayBits(t, "corpus.counts", pair[0].counts, pair[1].counts)
	return pair
}

func replayMath(t *testing.T, corpus replayCorpus, coordinate Coordinate, frozen frozenTraining, summarize, clean bool) replayResult {
	t.Helper()
	in := corpus.in
	out := replayResult{}
	t.Cleanup(out.close)
	var e error
	out.pred, e = predict(in.views, in.public, frozen)
	if e != nil {
		t.Fatal("fixed prediction failed")
	}
	out.run, e = firstChainOutcomes(out.pred, in, corpus.counts, clean)
	if e != nil {
		t.Fatal("fixed initial outcome failed")
	}
	out.run.Counts = corpus.counts
	if !out.run.ModelComplete {
		out.run.Flags = appendRuntimeReason(out.run.Flags, ReasonIncomplete)
	}
	out.run.Configuration, out.run.Phase = coordinate.ID, Primary
	if !clean {
		out.run.Flags = []Reason{ReasonIncomplete}
	}
	selected, e := selectedCaptureSummary(in.views, in.public.epochNS, in.public.cutoffNS)
	if e != nil {
		t.Fatal("fixed counter summary failed")
	}
	selected.Roles = out.run.Capture.Roles
	out.run.Capture = selected
	proof := captureLinkingAcquisition(in, clean)
	if summarize {
		previous := cryptorand.Reader
		// this public test stream fixes anonymous order before any score or label is inspected
		cryptorand.Reader = bytes.NewReader(make([]byte, 1<<16))
		defer func() { cryptorand.Reader = previous }()
		for index, method := range out.pred.methods {
			scores, truth, groups, e := annotateMethod(method, in)
			if e != nil {
				t.Fatal("fixed label annotation failed")
			}
			out.annotations = append(out.annotations, replayAnnotation{scores, truth, groups})
			if groups < 0 {
				t.Fatal("invalid fixed group inventory")
			}
			m, a, e := summarizeMethod(method, in, coordinate.ID, 0, replayBootstrapSeed+int64(index))
			if e != nil {
				t.Fatal("fixed metric/bootstrap/rank release failed")
			}
			out.run.Methods = append(out.run.Methods, m)
			out.audit = append(out.audit, a)
			if method.method == "request" {
				out.run.RequestLDA = m.AUC
			}
			if method.method == "record" {
				out.run.RecordLDA = m.AUC
			}
		}
		out.run.LinkingTimes, e = linkingTimes(out.run.Methods, proof)
		if e != nil {
			t.Fatal("fixed acquisition time failed")
		}
	}
	if coordinate.Topology == "peer" && coordinate.Population == "classifier" {
		for _, node := range in.views.nodes {
			if len(node.mailbox) == 0 {
				continue
			}
			rows, e := boundedMailboxRows(node, in.public.settings.RateNS)
			if e != nil {
				t.Fatal("fixed feature extraction failed")
			}
			out.features = append(out.features, rows)
			for _, o := range node.mailbox {
				positive, eligible, side, ok := mailboxLabel(node, o, in.truth)
				out.labels = append(out.labels, [4]uint64{uint64(boolInt(positive)), uint64(boolInt(eligible)), uint64(side), uint64(boolInt(ok))})
			}
		}
		population, excluded, classes, e := mailboxPopulation(in)
		if e != nil {
			t.Fatal("fixed mailbox population failed")
		}
		out.run.Counts.Eligible, out.run.Counts.Positive, out.run.Counts.Negative, out.run.Counts.Unknown = population.Eligible, population.Positive, population.Negative, population.Unknown
		out.run.RequestExclusions, out.run.RecordClasses = excluded, classes
		var falsePairs uint64
		in.queueFalsePairs = &falsePairs
		out.run.PutQ, out.run.PutBaseline, out.run.QueueJoined, out.request, out.record, e = mailboxEvaluation(in)
		if e != nil {
			t.Fatal("fixed mailbox join/feature evaluation failed")
		}
		out.run.QueueFalsePairs = falsePairs
	}
	return out
}

func replayPairMath(t *testing.T, pair [2]replayCorpus, coordinate Coordinate, frozen frozenTraining, summarize, clean bool) [2]replayResult {
	t.Helper()
	var results [2]replayResult
	for i := range 2 {
		results[i] = replayMath(t, pair[i], coordinate, frozen, summarize, clean)
	}
	replayBits(t, "math.predictions", results[0].pred, results[1].pred)
	replayBits(t, "math.annotation", results[0].annotations, results[1].annotations)
	replayBits(t, "math.features", results[0].features, results[1].features)
	replayBits(t, "math.labels", results[0].labels, results[1].labels)
	replayBits(t, "math.run", results[0].run, results[1].run)
	replayBits(t, "math.rank", results[0].audit, results[1].audit)
	replayBits(t, "math.training.request", results[0].request, results[1].request)
	replayBits(t, "math.training.record", results[0].record, results[1].record)
	return results
}

func replayClearTraining(fit *MailboxTraining) {
	if fit.Model != nil {
		clear(fit.Model.Weights)
		clear(fit.Model.Center)
		clear(fit.Model.Kept)
		clear(fit.Model.Unused)
		*fit.Model = metrics.Discriminant{}
	}
	if fit.Witness != nil {
		clear(fit.Witness.Kept)
		clear(fit.Witness.Unused)
		*fit.Witness = MailboxFitWitness{}
	}
	*fit = MailboxTraining{}
}

func replayFits(t *testing.T, results [2]replayResult, release bool) [2][2]MailboxTraining {
	scratch := testFitCertificate(t)
	t.Helper()
	var fits [2][2]MailboxTraining
	for branch := range 2 {
		for population, rows := range [][]encodedTrainingRow{results[branch].request, results[branch].record} {
			fits[branch][population] = trainMailbox(rows, featureVersion, true, true, scratch)
			b, p := branch, population
			t.Cleanup(func() { replayClearTraining(&fits[b][p]) })
			if release && (!fits[branch][population].Releasable || fits[branch][population].Model == nil || fits[branch][population].Witness == nil) {
				t.Fatal("ordinary fixed returned-row fit did not release a model and witness")
			}
		}
	}
	replayBits(t, "fit.request", fits[0][0], fits[1][0])
	replayBits(t, "fit.record", fits[0][1], fits[1][1])
	return fits
}

func replayAUC(t *testing.T, n Number) float64 {
	t.Helper()
	if n.Value == nil || n.Reason != ReasonNone {
		t.Fatal("ordinary replay lacks a required defined AUC")
	}
	return *n.Value
}

func replayCloneRun(input RunResult) RunResult {
	out := input
	pointers := make(map[*float64]*float64)
	clone := func(n Number) Number {
		if n.Value != nil {
			p, ok := pointers[n.Value]
			if !ok {
				v := *n.Value
				p = &v
				pointers[n.Value] = p
			}
			n.Value = p
		}
		return n
	}
	out.Flags = append([]Reason(nil), input.Flags...)
	out.RouteHistogram = append([]uint64(nil), input.RouteHistogram...)
	out.Methods = append([]MethodResult(nil), input.Methods...)
	for i := range out.Methods {
		m := &out.Methods[i]
		m.AUC, m.TopOne, m.TPR, m.BootstrapLow, m.BootstrapHigh = clone(m.AUC), clone(m.TopOne), clone(m.TPR), clone(m.BootstrapLow), clone(m.BootstrapHigh)
	}
	out.LinkingTimes = append([]LinkingTime(nil), input.LinkingTimes...)
	for i := range out.LinkingTimes {
		out.LinkingTimes[i].Seconds = clone(out.LinkingTimes[i].Seconds)
	}
	out.QueueJoined, out.PutQ, out.PutBaseline, out.RequestLDA, out.RecordLDA = clone(input.QueueJoined), clone(input.PutQ), clone(input.PutBaseline), clone(input.RequestLDA), clone(input.RecordLDA)
	clear(pointers)
	return out
}

func replayWipeRun(run *RunResult) {
	wipe := func(n Number) {
		if n.Value != nil {
			*n.Value = 0
		}
	}
	for _, m := range run.Methods {
		wipe(m.AUC)
		wipe(m.TopOne)
		wipe(m.TPR)
		wipe(m.BootstrapLow)
		wipe(m.BootstrapHigh)
	}
	for _, point := range run.LinkingTimes {
		wipe(point.Seconds)
	}
	wipe(run.QueueJoined)
	wipe(run.PutQ)
	wipe(run.PutBaseline)
	wipe(run.RequestLDA)
	wipe(run.RecordLDA)
	clear(run.Flags)
	clear(run.RouteHistogram)
	clear(run.Methods)
	clear(run.LinkingTimes)
	*run = RunResult{}
}

func replayOrdinary(t *testing.T) ([2][]RunResult, [2][]RunResult, [2][]RunResult) {
	t.Helper()
	mailCoordinates := canonicalCoordinates(Mailbox)
	trainingCoordinate := mailCoordinates[0]
	trainingCoordinate.Settings.CoverPuts = true
	training := buildReplayCorpus(t, trainingCoordinate, 16, true, true, "")
	trainingResults := replayPairMath(t, training, trainingCoordinate, frozenTraining{}, false, true)
	fits := replayFits(t, trainingResults, true)
	frozen := frozenTraining{request: fits[0][0].Model, record: fits[0][1].Model}
	var link, mail, model [2][]RunResult
	for _, coordinate := range canonicalCoordinates(Collude)[:9] {
		pair := buildReplayCorpus(t, coordinate, coordinate.Flows, false, false, "")
		results := replayPairMath(t, pair, coordinate, frozenTraining{}, true, true)
		undefined, ruledOut, tied, nonconstant := false, false, false, false
		for _, method := range results[0].pred.methods {
			seen := make(map[uint64]int)
			for _, value := range method.values {
				bits := math.Float64bits(value.value)
				seen[bits]++
				undefined = undefined || value.value == -2
				ruledOut = ruledOut || value.value == -3
				tied = tied || seen[bits] > 1
			}
			nonconstant = nonconstant || len(seen) > 1
			clear(seen)
		}
		if !undefined || !ruledOut || !tied || !nonconstant {
			t.Fatal("ordinary linking did not exercise sentinel, exact tie and nonconstant scores")
		}
		for branch := range 2 {
			link[branch] = append(link[branch], replayCloneRun(results[branch].run))
		}
	}
	for _, coordinate := range mailCoordinates {
		if coordinate.Population != "classifier" {
			continue
		}
		pair := buildReplayCorpus(t, coordinate, 16, true, false, "")
		results := replayPairMath(t, pair, coordinate, frozen, true, true)
		for branch := range 2 {
			if results[branch].run.RecordClasses[0] == 0 || results[branch].run.RecordClasses[1] == 0 {
				t.Fatal("ordinary record corpus lacks a class")
			}
			replayAUC(t, results[branch].run.RequestLDA)
			replayAUC(t, results[branch].run.RecordLDA)
			mail[branch] = append(mail[branch], replayCloneRun(results[branch].run))
		}
	}
	for _, coordinate := range canonicalCoordinates(Compromise)[:6] {
		pair := buildReplayCorpus(t, coordinate, 32, false, false, "")
		results := replayPairMath(t, pair, coordinate, frozenTraining{}, false, true)
		for branch := range 2 {
			if !results[branch].run.ModelComplete {
				t.Fatal("ordinary fixed first-chain corpus is incomplete")
			}
			model[branch] = append(model[branch], replayCloneRun(results[branch].run))
		}
	}
	replayBits(t, "frozen.input.after.request", fits[0][0], fits[1][0])
	replayBits(t, "frozen.input.after.record", fits[0][1], fits[1][1])
	return link, mail, model
}

func replayRegisteredMath(t *testing.T, link, mail, model [2][]RunResult) {
	t.Helper()
	ctx := context.Background()
	var modelPlans [2][]ModelSamplePlan
	var modelResults, commonResults [2][]Inference
	var powerPlans [2][]PairedPowerPlan
	var calculations [2][]SampleCalculation
	var masked [2][][]Inference
	edgeCoordinate := canonicalCoordinates(Collude)[0]
	failed := replayPairMath(t, buildReplayCorpus(t, edgeCoordinate, 5, false, false, "unavailable"), edgeCoordinate, frozenTraining{}, true, false)
	degenerate := replayPairMath(t, buildReplayCorpus(t, edgeCoordinate, 5, false, false, "degenerate"), edgeCoordinate, frozenTraining{}, true, true)
	for branch := range 2 {
		var e error
		modelPlans[branch], e = PlanModelSlots(ctx)
		if e != nil {
			t.Fatal("fixed exact model planning failed")
		}
		plan := inferenceTestPlan(Compromise)
		calculations[branch], e = modelSampleCalculations(ctx, plan, modelPlans[branch])
		if e != nil || len(calculations[branch]) != 13 {
			t.Fatal("fixed full model power calculations failed")
		}
		var runs []RunResult
		for _, template := range model[branch] {
			for _, coordinate := range plan.Configurations {
				if coordinate.ID != template.Configuration {
					continue
				}
				for repeat := range coordinate.Slots / 32 {
					run := template
					run.Repeat = repeat
					runs = append(runs, run)
				}
			}
		}
		modelResults[branch], _, e = summarizeInferences(plan, runs)
		if e != nil {
			t.Fatal("fixed full model family failed")
		}
		if len(modelResults[branch]) != 13 {
			t.Fatal("fixed model family lost a position")
		}
		for _, result := range modelResults[branch] {
			if !result.Defined || result.Usable != 2048 {
				t.Fatal("fixed model claim remained unavailable")
			}
		}
		clear(runs)
		runs = runs[:0]
		plan = inferenceTestPlan(Collude)
		plan.Powers = nil
		for position, id := range differenceIDs() {
			var a, b float64
			if position < 9 {
				var usable bool
				a, b, usable, e = inferenceLinkPair(link[branch][position])
				if e != nil || !usable {
					t.Fatal("fixed linking template cannot supply its paired input")
				}
			} else {
				period := (position - 9) / 2
				off, on := mail[branch][2*period], mail[branch][2*period+1]
				if (position-9)%2 == 0 {
					a, b = replayAUC(t, on.RequestLDA), replayAUC(t, off.RequestLDA)
				} else {
					a, b = replayAUC(t, on.RecordLDA), replayAUC(t, off.RecordLDA)
				}
			}
			x, y := []float64{a, a, a, a, a}, []float64{b, b, b, b, b}
			seed := replayPowerSeed + int64(position)
			search, e := PlanPairedPower(ctx, x, y, seed)
			if e != nil || search.SelectedN == 0 {
				t.Fatal("fixed full paired-power search failed")
			}
			powerPlans[branch] = append(powerPlans[branch], search)
			point, e := PairedPowerAtN(ctx, x, y, seed, search.SelectedN)
			if e != nil {
				t.Fatal("fixed registered power recheck failed")
			}
			plan.Powers = append(plan.Powers, powerCalculation(PowerCalculation{ID: id, Seed: seed, PilotX: x, PilotY: y}, point))
		}
		counts := make(map[string]int)
		for _, power := range plan.Powers {
			counts[power.ID] = power.N
		}
		for i := range plan.Configurations {
			if n, ok := configurationIncidentCount(plan.Configurations[i], counts); ok {
				plan.Configurations[i].Main = n
			}
		}
		for _, template := range append(append([]RunResult(nil), link[branch]...), mail[branch]...) {
			n := counts[template.Configuration]
			if n == 0 {
				for _, coordinate := range canonicalCoordinates(Mailbox) {
					if coordinate.ID == template.Configuration {
						n = max(counts["mail-P"+decimal(int(coordinate.Settings.RelayPeriodNS))+"-request"], counts["mail-P"+decimal(int(coordinate.Settings.RelayPeriodNS))+"-record"])
					}
				}
			}
			if n == 0 {
				t.Fatal("fixed template has no registered incident count")
			}
			for repeat := range n {
				run := template
				run.Repeat = repeat
				runs = append(runs, run)
			}
		}
		for index, run := range runs {
			if run.Phase != Primary || run.Configuration == "" || run.Repeat < 0 {
				t.Fatalf("fixed common slot %d has invalid phase/coordinate/repeat metadata", index)
			}
		}
		_, commonResults[branch], e = summarizeInferences(plan, runs)
		if e != nil {
			if e == ErrInvalid {
				t.Fatal("fixed common family rejected typed input metadata")
			}
			t.Fatalf("fixed common family returned status %s", reasonOf(e))
		}
		if len(commonResults[branch]) != 13 {
			t.Fatal("fixed common family returned an invalid position count")
		}
		defined := 0
		for _, result := range commonResults[branch] {
			if !result.Defined {
				t.Fatal("fixed common comparison remained unavailable")
			}
			if result.P.Value != nil && result.AdjustedP.Value != nil {
				defined++
			}
		}
		if defined == 0 {
			t.Fatal("fixed common family exercised no nondegenerate Holm comparison")
		}
		_, missing, e := summarizeInferences(plan, runs[1:])
		if e != nil || len(missing) != 13 {
			t.Fatal("fixed unstarted mask failed")
		}
		for _, item := range missing {
			if item.AdjustedP.Value != nil {
				t.Fatal("unstarted slot published a reduced Holm family")
			}
		}
		masked[branch] = append(masked[branch], missing)
		failedRuns := append([]RunResult(nil), runs...)
		failedRuns[0] = failed[branch].run
		_, partial, e := summarizeInferences(plan, failedRuns)
		if e != nil || partial[0].Defined || partial[0].Failures != 1 {
			t.Fatal("failed pipeline slot lost its complete mask")
		}
		masked[branch] = append(masked[branch], partial)
		for i := range failedRuns {
			if failedRuns[i].Configuration == edgeCoordinate.ID {
				repeat := failedRuns[i].Repeat
				failedRuns[i] = degenerate[branch].run
				failedRuns[i].Repeat = repeat
			}
		}
		_, zero, e := summarizeInferences(plan, failedRuns)
		if e != nil || !zero[0].Defined || zero[0].Method != "degenerate" || zero[0].AdjustedP.Value != nil {
			t.Fatal("computed degenerate pipeline input lost its registered position")
		}
		masked[branch] = append(masked[branch], zero)
		clear(failedRuns)
		clear(runs)
		clear(counts)
	}
	replayBits(t, "registered.model.plans", modelPlans[0], modelPlans[1])
	replayBits(t, "registered.model.calculations", calculations[0], calculations[1])
	replayBits(t, "registered.model.family", modelResults[0], modelResults[1])
	replayBits(t, "registered.power.search", powerPlans[0], powerPlans[1])
	replayBits(t, "registered.common.family", commonResults[0], commonResults[1])
	replayBits(t, "registered.masks", masked[0], masked[1])
}

func TestSourceCapacityFixedInputReplay(t *testing.T) {
	t.Run("producer-codec", replayProducerBridge)
	var link, mail, model [2][]RunResult
	t.Cleanup(func() {
		for branch := range 2 {
			for _, runs := range [][]RunResult{link[branch], mail[branch], model[branch]} {
				for i := range runs {
					replayWipeRun(&runs[i])
				}
				clear(runs)
			}
		}
	})
	t.Run("typed-pipeline", func(t *testing.T) { link, mail, model = replayOrdinary(t) })
	t.Run("registered-mathematics", func(t *testing.T) { replayRegisteredMath(t, link, mail, model) })
	t.Run("edge-inputs", replayEdges)
}

func replayEdges(t *testing.T) {
	coordinate := canonicalCoordinates(Mailbox)[0]
	training := replayPairMath(t, buildReplayCorpus(t, coordinate, 16, true, true, ""), coordinate, frozenTraining{}, false, true)
	fits := replayFits(t, training, true)
	frozen := frozenTraining{request: fits[0][0].Model, record: fits[0][1].Model}
	for _, edge := range []string{"empty", "missing-class", "rebuilt"} {
		t.Run(edge, func(t *testing.T) {
			pair := buildReplayCorpus(t, coordinate, 16, true, false, edge)
			results := replayPairMath(t, pair, coordinate, frozen, true, true)
			if edge == "empty" {
				found := false
				for _, a := range results[0].audit {
					for _, g := range a.Groups {
						found = found || len(g) == 0
					}
				}
				if !found {
					t.Fatal("empty anonymous group was not exercised")
				}
			}
			if edge == "missing-class" && results[0].run.RecordLDA.Value != nil {
				t.Fatal("missing class became a numeric AUC")
			}
			if edge == "rebuilt" {
				if results[0].run.ModelComplete || pair[0].counts.Unanswered >= 64 {
					t.Fatal("partial/unsent/receipt context was not retained")
				}
				sticky := false
				for _, row := range results[0].record {
					sticky = sticky || !row.OriginalSeal
				}
				if !sticky {
					t.Fatal("rebuilt sticky record was not exercised")
				}
			}
			failed := replayFits(t, results, false)
			if edge == "missing-class" && failed[0][0].Releasable {
				t.Fatal("missing class released fitting material")
			}
		})
	}
	linkCoordinate := canonicalCoordinates(Collude)[0]
	var summaries [2][]RunResult
	for _, edge := range []string{"", "ties", "unavailable"} {
		pair := buildReplayCorpus(t, linkCoordinate, 5, false, false, edge)
		results := replayPairMath(t, pair, linkCoordinate, frozenTraining{}, true, edge != "unavailable")
		for branch := range 2 {
			summaries[branch] = append(summaries[branch], replayCloneRun(results[branch].run))
		}
	}
	defer func() {
		for branch := range 2 {
			for i := range summaries[branch] {
				replayWipeRun(&summaries[branch][i])
			}
		}
	}()
	for branch := range 2 {
		if summaries[branch][0].LinkingTimes[0].Seconds.Value == nil || !summaries[branch][1].LinkingTimes[0].Censored || summaries[branch][2].LinkingTimes[0].Seconds.Value != nil || summaries[branch][2].LinkingTimes[0].Censored {
			t.Fatal("defined/censored/unavailable time cases were not exercised")
		}
	}
	plan := inferenceTestPlan(Collude)
	replayBits(t, "edge.summary", descriptiveSummaries(Report{Plan: plan, Runs: summaries[0]}), descriptiveSummaries(Report{Plan: plan, Runs: summaries[1]}))
}
