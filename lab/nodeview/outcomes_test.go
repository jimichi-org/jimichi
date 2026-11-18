package nodeview

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

func outcomeTestArena(t *testing.T) *lockedArena {
	t.Helper()
	b, e := secmem.New(65536)
	if e != nil {
		t.Fatal(e)
	}
	a := &lockedArena{buffer: b}
	t.Cleanup(a.close)
	return a
}

func outcomeTestCopy(t *testing.T, a *lockedArena, data []byte) arenaRef {
	t.Helper()
	r, ok := a.copy(data)
	if !ok {
		t.Fatal("test arena exhausted")
	}
	return r
}

func outcomeTestBody(seed byte) []byte {
	body := make([]byte, 128)
	for i := range body {
		body[i] = byte(i) + seed
	}
	return body
}

func outcomeTestGroup(side uint16, route [3]uint8, base uint64) []actualSetup {
	return []actualSetup{{side: side, hop: 2, circuit: base + 2, roster: route[2]}, {side: side, hop: 1, circuit: base + 1, roster: route[1]}, {side: side, hop: 0, circuit: base, roster: route[0]}}
}

func outcomeTestNode(position, role uint8, side uint16, base uint64, hop uint32) nodeView {
	in := connectionView{generation: hop * 10, localPort: 2000 + uint16(position), remotePort: uint16(2000 + int(role) - 1), peer: role - 1, authenticated: true}
	if role == 0 {
		in.remotePort, in.peer = 1000+side, 255
	} else {
		in.selectorPort = 1999 + uint16(role)
	}
	s := setupView{generation: hop * 10, hop: hop, connection: in.generation, index: role, circuit: base + uint64(role), stages: stageInput | stageLocal}
	node := nodeView{position: position, connections: []connectionView{in}, setups: []setupView{s}}
	if role < 2 {
		out := connectionView{generation: hop*10 + 1, remotePort: 2001 + uint16(role), peer: role + 1, authenticated: true, initiator: true}
		node.connections = append(node.connections, out)
		node.setups[0].outConnection = out.generation
		node.setups[0].nextCircuit = base + 10 + uint64(role)
		node.setups[0].nextPort = out.remotePort
	}
	return node
}

func outcomeTestInput(t *testing.T, selected ...uint8) (evaluationInput, Counts) {
	t.Helper()
	a := outcomeTestArena(t)
	route := [3]uint8{0, 1, 2}
	in := evaluationInput{
		truth:        privateTruth{arena: a, setups: outcomeTestGroup(0, route, 100)},
		plans:        []workloadPlan{{side: 0, route: route}},
		public:       publicConfig{n: 5, h: 3, population: "echo"},
		portToRoster: map[uint16]int{2000: 0, 2001: 1, 2002: 2},
		nkEndpoints:  map[uint32]int{uint32(2000)<<16 | 1000: 5},
		established:  map[uint16]bool{0: true},
	}
	for _, position := range selected {
		in.public.controlled = append(in.public.controlled, int(position))
		if position < 3 {
			in.views.nodes = append(in.views.nodes, outcomeTestNode(position, position, 0, 100, uint32(position)+1))
		} else {
			in.views.nodes = append(in.views.nodes, nodeView{position: position})
		}
	}
	in.truth.messages = []actualMessage{{side: 0, body: outcomeTestCopy(t, a, outcomeTestBody(1)), sent: true}}
	counts := Counts{Planned: 1, Attempted: 1, Established: 1, PreflightOK: 1, MessageBearing: 1}
	return in, counts
}

func outcomeTestFragment(t *testing.T, in *evaluationInput, position uint8, hop uint32, data []byte) {
	t.Helper()
	r := outcomeTestCopy(t, in.truth.arena, data)
	in.truth.fragments = append(in.truth.fragments, contentFragment{hop: hop, kind: 1, data: r})
	in.fragmentSource = append(in.fragmentSource, fragmentSourceEntry{r, position})
}

func outcomeTestSecondSide(t *testing.T, in *evaluationInput, counts *Counts) {
	t.Helper()
	route := [3]uint8{0, 1, 2}
	in.plans = append(in.plans, workloadPlan{side: 1, route: route})
	in.truth.setups = append(in.truth.setups, outcomeTestGroup(1, route, 300)...)
	in.truth.messages = append(in.truth.messages, actualMessage{side: 1, body: outcomeTestCopy(t, in.truth.arena, outcomeTestBody(2)), sent: true})
	in.established[1] = true
	in.nkEndpoints[uint32(2000)<<16|1001] = 6
	for i := range in.views.nodes {
		node := &in.views.nodes[i]
		later := outcomeTestNode(node.position, node.position, 1, 300, 100+uint32(node.position))
		node.setups = append(node.setups, later.setups...)
		node.connections = append(node.connections, later.connections...)
	}
	counts.Planned, counts.Attempted, counts.Established, counts.PreflightOK, counts.MessageBearing = 2, 2, 2, 2, 2
}

func TestFirstChainRoleKnownAnswers(t *testing.T) {
	// echo claims know 3/4, 3/4, 2/4; excluding the public peer mailbox gives 1, 2/3, 1/3
	for _, population := range []string{"echo", "peer"} {
		for role := uint8(0); role < 3; role++ {
			t.Run(population+decimal(int(role)), func(t *testing.T) {
				in, counts := outcomeTestInput(t, role)
				in.public.population = population
				got, e := firstChainOutcomes(predictions{}, in, counts, true)
				want := []int{3, 3, 2}[role]
				width := 5
				if population == "peer" {
					want, width = []int{3, 2, 1}[role], 4
				}
				if e != nil || len(got.RouteHistogram) != width || got.RouteHistogram[want] != 1 || !got.ModelComplete || got.Touched != 1 || got.Ends != 0 || got.Capture.Roles[role] != 1 {
					t.Fatalf("outcome %+v, error %v", got, e)
				}
				claim, available, e := firstChainClaim(in.views.nodes[0], in.views.nodes[0].setups[0], in)
				var mask uint8
				for i, occupant := range claim {
					if occupant >= 0 {
						mask |= 1 << i
					}
				}
				wantMask := [3]uint8{0b0111, 0b1110, 0b1100}[role]
				if population == "peer" {
					wantMask = [3]uint8{0b111, 0b110, 0b100}[role]
				}
				if e != nil || !available || mask != wantMask {
					t.Fatal("required observed claim mask differs")
				}
				if got.Counts != (Counts{}) || got.Configuration != "" || got.Methods != nil || got.Flags != nil {
					t.Fatal("producer returned fields outside its public subset")
				}
			})
		}
	}
}

func TestFirstChainMixedLinksAndEnds(t *testing.T) {
	in, counts := outcomeTestInput(t, 0, 2)
	pred := predictions{methods: []predictedMethod{{method: "mixed", matches: []metrics.ViewEdge{{First: 0, Second: 0}}}}}
	got, e := firstChainOutcomes(pred, in, counts, true)
	// first knows positions 0,1,2 and exit knows 2,3; only their predicted link permits all four
	if e != nil || got.RouteHistogram[4] != 1 || got.Touched != 1 || got.Ends != 1 || got.Capture.Roles != ([3]uint64{1, 0, 1}) || !got.ModelComplete {
		t.Fatalf("linked outcome %+v, %v", got, e)
	}
	got, e = firstChainOutcomes(predictions{}, in, counts, true)
	if e != nil || got.RouteHistogram[3] != 1 || got.Ends != 1 {
		t.Fatal("unlinked views pooled or ends derived from R")
	}
}

func TestFirstChainMissingAndOffPathCoverage(t *testing.T) {
	for _, position := range []uint8{0, 4} {
		in, counts := outcomeTestInput(t, position)
		in.views.nodes[0].setups = nil
		got, e := firstChainOutcomes(predictions{}, in, counts, true)
		zero := uint64(0)
		if position == 4 {
			zero = 1
		}
		if e != nil || got.RouteHistogram[0] != zero || got.Touched != 0 || got.ModelComplete != (position == 4) {
			t.Fatalf("position %d: %+v, %v", position, got, e)
		}
	}
	in, counts := outcomeTestInput(t, 0)
	in.views.nodes[0].setups[0].hop = 0
	in.views.nodes[0].setups[0].stages = stageInput
	got, e := firstChainOutcomes(predictions{}, in, counts, true)
	if e != nil || got.ModelComplete {
		t.Fatal("opened-only layer established complete initial coverage")
	}
}

func TestFirstChainLaterEvidenceCannotRepairInitial(t *testing.T) {
	for _, onlyLater := range []bool{false, true} {
		in, counts := outcomeTestInput(t, 0, 2)
		in.truth.setups = append(in.truth.setups, outcomeTestGroup(0, [3]uint8{0, 1, 2}, 200)...)
		in.views.nodes[1] = outcomeTestNode(2, 2, 0, 200, 9)
		if onlyLater {
			in.views.nodes[0] = outcomeTestNode(0, 0, 0, 200, 8)
		}
		outcomeTestFragment(t, &in, 2, 9, outcomeTestBody(1))
		pred := predictions{methods: []predictedMethod{{method: "mixed", matches: []metrics.ViewEdge{{First: 0, Second: 0}}}}}
		got, e := firstChainOutcomes(pred, in, counts, true)
		touched := uint64(1)
		if onlyLater {
			touched = 0
		}
		if e != nil || got.ModelComplete || !reflect.DeepEqual(got.RouteHistogram, []uint64{0, 0, 0, 0, 0}) || got.Touched != touched || got.Ends != 0 || got.ContentFound != 0 || got.ContentMessages != 0 || got.Capture.Roles[2] != 0 {
			t.Fatalf("later-only %v: %+v, %v", onlyLater, got, e)
		}
	}
}

func TestFirstChainContentFullBodiesKnownAnswer(t *testing.T) {
	for _, population := range []string{"echo", "peer"} {
		in, counts := outcomeTestInput(t, 0)
		in.public.population = population
		for _, seed := range []byte{2, 3} {
			in.truth.messages = append(in.truth.messages, actualMessage{side: 0, body: outcomeTestCopy(t, in.truth.arena, outcomeTestBody(seed)), sent: true})
		}
		outcomeTestFragment(t, &in, 0, 1, append([]byte{7, 8}, outcomeTestBody(1)...))
		outcomeTestFragment(t, &in, 0, 1, outcomeTestBody(2))
		outcomeTestFragment(t, &in, 0, 1, outcomeTestBody(3)[:127])
		// two full matches plus a 127-byte prefix yield 2/3 messages, one found-any chain
		got, e := firstChainOutcomes(predictions{}, in, counts, true)
		if e != nil || got.ContentFound != 1 || got.ContentMessages != 2 || got.MeasuredMessages != 3 || !got.ModelComplete {
			t.Fatalf("%s: %+v, %v", population, got, e)
		}
	}
}

func TestFirstChainRetainsPlannedInitialDenominator(t *testing.T) {
	in, counts := outcomeTestInput(t, 0)
	in.plans = append(in.plans, workloadPlan{side: 1, route: [3]uint8{3, 1, 2}})
	counts.Planned, counts.Attempted, counts.SetupFailed = 2, 2, 1
	got, e := firstChainOutcomes(predictions{}, in, counts, true)
	// the failed slot remains planned but unavailable, never a measured R0 or a survivor replacement
	if e != nil || got.ModelComplete || !reflect.DeepEqual(got.RouteHistogram, []uint64{0, 0, 0, 1, 0}) || got.Touched != 1 || got.MeasuredMessages != 1 {
		t.Fatalf("failed slot lost: %+v, %v", got, e)
	}
	in.truth.setups = append(in.truth.setups, actualSetup{side: 1, hop: 2, circuit: 302, roster: 2})
	got, e = firstChainOutcomes(predictions{}, in, counts, false)
	if e != nil || got.ModelComplete || got.RouteHistogram[0] != 0 {
		t.Fatal("partial group became an initial model unit")
	}
}

func TestFirstChainContentUsesChainUnitsAndSentLedger(t *testing.T) {
	in, counts := outcomeTestInput(t, 0)
	route := [3]uint8{3, 1, 2}
	in.plans = append(in.plans, workloadPlan{side: 1, route: route})
	in.truth.setups = append(in.truth.setups, outcomeTestGroup(1, route, 300)...)
	in.established[1] = true
	in.truth.messages = append(in.truth.messages,
		actualMessage{side: 0, body: outcomeTestCopy(t, in.truth.arena, outcomeTestBody(2)), sent: true},
		actualMessage{side: 1, body: outcomeTestCopy(t, in.truth.arena, outcomeTestBody(3)), sent: true},
		actualMessage{side: 1, body: outcomeTestCopy(t, in.truth.arena, outcomeTestBody(1)), replied: true},
	)
	outcomeTestFragment(t, &in, 0, 1, outcomeTestBody(1))
	outcomeTestFragment(t, &in, 0, 1, outcomeTestBody(2))
	counts.Planned, counts.Attempted, counts.Established, counts.PreflightOK, counts.MessageBearing = 2, 2, 2, 2, 2
	got, e := firstChainOutcomes(predictions{}, in, counts, true)
	// two hits on side0 give one success among two chains; the replied-only duplicate is not a Sent source
	if e != nil || !got.ModelComplete || got.ContentFound != 1 || got.ContentMessages != 2 || got.MeasuredMessages != 3 || got.RouteHistogram[0] != 1 || got.RouteHistogram[3] != 1 {
		t.Fatalf("chain units %+v, %v", got, e)
	}
}

func TestFirstChainRejectsMalformedOwnership(t *testing.T) {
	cases := []struct {
		name string
		edit func(*evaluationInput)
	}{
		{"duplicate circuit", func(in *evaluationInput) { in.truth.setups = append(in.truth.setups, in.truth.setups[0]) }},
		{"missing owner", func(in *evaluationInput) { in.views.nodes[0].setups[0].circuit = 999 }},
		{"wrong observed hop", func(in *evaluationInput) { in.views.nodes[0].setups[0].index = 1 }},
		{"duplicate observed owner", func(in *evaluationInput) {
			in.views.nodes[0].setups = append(in.views.nodes[0].setups, in.views.nodes[0].setups[0])
		}},
		{"invalid order", func(in *evaluationInput) { in.truth.setups[0].hop = 1 }},
		{"duplicate roster", func(in *evaluationInput) { in.truth.setups[0].roster = 1 }},
		{"unplanned side", func(in *evaluationInput) { in.truth.setups[0].side = 1 }},
		{"false initial route", func(in *evaluationInput) { in.plans[0].route = [3]uint8{0, 2, 1} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, counts := outcomeTestInput(t, 0)
			c.edit(&in)
			if _, e := firstChainOutcomes(predictions{}, in, counts, true); reasonOf(e) != ReasonLabel {
				t.Fatalf("error %v, want fixed label_mismatch", e)
			}
		})
	}
}

func TestFirstChainRejectsCountAndMaskMismatch(t *testing.T) {
	cases := []struct {
		name string
		edit func(*evaluationInput, *Counts)
	}{
		{"planned", func(_ *evaluationInput, c *Counts) { c.Planned = 2 }},
		{"attempted", func(_ *evaluationInput, c *Counts) { c.Attempted = 0 }},
		{"established", func(_ *evaluationInput, c *Counts) { c.Established = 0 }},
		{"overlapping refusal", func(_ *evaluationInput, c *Counts) { c.Refused = 1 }},
		{"overlapping setup failure", func(_ *evaluationInput, c *Counts) { c.SetupFailed = 1 }},
		{"preflight evidence", func(in *evaluationInput, _ *Counts) { in.established = nil }},
		{"sent ledger", func(_ *evaluationInput, c *Counts) { c.MessageBearing = 0 }},
		{"stage mask", func(in *evaluationInput, _ *Counts) { in.views.nodes[0].setups[0].stages |= 32 }},
		{"controlled duplicate", func(in *evaluationInput, _ *Counts) { in.public.controlled = []int{0, 0} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, counts := outcomeTestInput(t, 0)
			c.edit(&in, &counts)
			if _, e := firstChainOutcomes(predictions{}, in, counts, true); reasonOf(e) != ReasonContract {
				t.Fatalf("error %v, want fixed observation_contract", e)
			}
		})
	}
	in, counts := outcomeTestInput(t, 0)
	got, e := firstChainOutcomes(predictions{}, in, counts, false)
	if e != nil || got.ModelComplete {
		t.Fatal("unclean cohort became model complete")
	}
}

func TestFirstChainRejectsInvalidContentBinding(t *testing.T) {
	for _, problem := range []string{"source", "hop", "body size", "duplicate body", "equal body", "extent"} {
		t.Run(problem, func(t *testing.T) {
			in, counts := outcomeTestInput(t, 0)
			outcomeTestFragment(t, &in, 0, 1, outcomeTestBody(1))
			want := ReasonLabel
			switch problem {
			case "source":
				in.fragmentSource = nil
				want = ReasonContract
			case "hop":
				in.truth.fragments[0].hop = 99
			case "body size":
				in.truth.messages[0].body.size = 127
			case "duplicate body":
				in.truth.messages = append(in.truth.messages, in.truth.messages[0])
			case "equal body":
				in.truth.messages[0].body = outcomeTestCopy(t, in.truth.arena, bytes.Repeat([]byte{3}, 128))
			case "extent":
				in.truth.messages[0].body.offset = in.truth.arena.used
			}
			if _, e := firstChainOutcomes(predictions{}, in, counts, true); reasonOf(e) != want {
				t.Fatalf("error %v, want %s", e, want)
			}
		})
	}
}

func TestFirstChainRequiredObservableCoverage(t *testing.T) {
	cases := []struct {
		name   string
		roles  uint8
		reason Reason
		edit   func(*evaluationInput)
	}{
		{"hop", 7, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].setups[0].hop = 0 }},
		{"hop stage", 7, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].setups[0].stages &^= stageLocal }},
		{"input stage", 7, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].setups[0].stages &^= stageInput }},
		{"incoming binding", 7, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].setups[0].connection = 0 }},
		{"incoming record", 7, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].connections = in.views.nodes[0].connections[1:] }},
		{"incoming direction", 7, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[0].initiator = true }},
		{"incoming authentication", 7, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[0].authenticated = false }},
		{"duplicate generation", 7, ReasonContract, func(in *evaluationInput) {
			in.views.nodes[0].connections = append(in.views.nodes[0].connections, in.views.nodes[0].connections[0])
		}},
		{"NK local endpoint", 1, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].connections[0].localPort = 0 }},
		{"NK remote endpoint", 1, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].connections[0].remotePort = 0 }},
		{"NK normalizer", 1, ReasonContract, func(in *evaluationInput) { in.nkEndpoints = nil }},
		{"NK wrong local endpoint", 1, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[0].localPort++ }},
		{"NK duplicate token", 1, ReasonContract, func(in *evaluationInput) { in.nkEndpoints[uint32(2001)<<16|1001] = 5 }},
		{"NK contradictory selector", 1, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[0].selectorPort = 2002 }},
		{"KK selector", 6, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].connections[0].selectorPort = 0 }},
		{"KK predecessor normalizer", 6, ReasonContract, func(in *evaluationInput) { delete(in.portToRoster, in.views.nodes[0].connections[0].selectorPort) }},
		{"KK unconfirmed predecessor", 6, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[0].peer = 255 }},
		{"KK conflicting predecessor", 6, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[0].peer = 4 }},
		{"outgoing binding", 3, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].setups[0].outConnection = 0 }},
		{"opened successor address", 3, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].setups[0].nextPort = 0 }},
		{"outgoing record", 3, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections = in.views.nodes[0].connections[:1] }},
		{"outgoing unknown generation", 3, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].setups[0].outConnection = 999 }},
		{"outgoing remote endpoint", 3, ReasonNone, func(in *evaluationInput) { in.views.nodes[0].connections[1].remotePort = 0 }},
		{"outgoing normalizer", 3, ReasonContract, func(in *evaluationInput) { delete(in.portToRoster, in.views.nodes[0].connections[1].remotePort) }},
		{"outgoing authentication", 3, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[1].authenticated = false }},
		{"outgoing direction", 3, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[1].initiator = false }},
		{"outgoing wrong generation", 3, ReasonContract, func(in *evaluationInput) {
			in.views.nodes[0].setups[0].outConnection = in.views.nodes[0].setups[0].connection
		}},
		{"outgoing conflicting peer", 3, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[1].peer = 4 }},
		{"outgoing wrong address", 3, ReasonContract, func(in *evaluationInput) { in.views.nodes[0].connections[1].remotePort++ }},
	}
	for _, population := range []string{"echo", "peer"} {
		for role := uint8(0); role < 3; role++ {
			for _, c := range cases {
				if c.roles&(1<<role) == 0 {
					continue
				}
				t.Run(population+decimal(int(role))+"/"+c.name, func(t *testing.T) {
					in, counts := outcomeTestInput(t, role)
					in.public.population = population
					c.edit(&in)
					got, e := firstChainOutcomes(predictions{}, in, counts, true)
					if reasonOf(e) != c.reason {
						t.Fatalf("error %v, want %s", e, c.reason)
					}
					if e == nil {
						var measured uint64
						for _, n := range got.RouteHistogram {
							measured += n
						}
						if measured != 0 || got.ModelComplete || counts.Planned != 1 {
							t.Fatal("required missing observation became measured partial R")
						}
					}
				})
			}
		}
	}
}

func TestFirstChainMissingCoverageRetainsIndependentContentEvidence(t *testing.T) {
	in, counts := outcomeTestInput(t, 0)
	in.views.nodes[0].setups[0].outConnection = 0
	outcomeTestFragment(t, &in, 0, 1, outcomeTestBody(1))
	got, e := firstChainOutcomes(predictions{}, in, counts, true)
	if e != nil || got.ModelComplete || got.RouteHistogram[0] != 0 || got.RouteHistogram[3] != 0 || got.ContentFound != 1 || got.ContentMessages != 1 || got.Touched != 1 || got.Capture.Roles[0] != 1 {
		t.Fatal("missing R coverage erased independent descriptive evidence")
	}
}

func TestFirstChainControlHeaderCannotReplaceBoundSuccessor(t *testing.T) {
	for _, population := range []string{"echo", "peer"} {
		for role := uint8(0); role < 2; role++ {
			in, counts := outcomeTestInput(t, role)
			in.public.population = population
			node := &in.views.nodes[0]
			s := &node.setups[0]
			s.outConnection = 0
			node.cells = []cellView{{connection: node.connections[1].generation, kind: 3, dir: 1, circuit: s.nextCircuit, counter: uint64(s.index) + 1, stages: stageWritten}}
			got, e := firstChainOutcomes(predictions{}, in, counts, true)
			if e != nil || got.ModelComplete || !reflect.DeepEqual(got.RouteHistogram, make([]uint64, len(got.RouteHistogram))) || node.setups[0].outConnection != 0 {
				t.Fatal("header-only candidate replaced missing child-bound successor")
			}
			node.cells = append(node.cells, node.cells[0])
			got, e = firstChainOutcomes(predictions{}, in, counts, true)
			if e != nil || got.ModelComplete {
				t.Fatal("control headers changed unavailable binding into a measured outcome")
			}
		}
	}
}

func TestFirstChainEqualHeadersDoNotEstablishLocalOwnership(t *testing.T) {
	in, _ := outcomeTestInput(t, 0)
	node := in.views.nodes[0]
	a := node.setups[0]
	a.inner = outcomeTestCopy(t, in.truth.arena, []byte("public test setup A ciphertext"))
	b := a
	b.generation, b.hop, b.circuit = 90, 9, 900
	b.inner = outcomeTestCopy(t, in.truth.arena, []byte("public test setup B ciphertext"))
	other := node.connections[1]
	other.generation = 91
	node.connections = append(node.connections, other)
	b.outConnection = other.generation
	node.setups = []setupView{a, b}
	node.cells = []cellView{{connection: other.generation, kind: 3, dir: 1, circuit: b.nextCircuit, counter: uint64(b.index) + 1, stages: stageWritten}}
	a.outConnection = 0
	if _, available, e := firstChainClaim(node, a, in); e != nil || available {
		t.Fatal("another setup's equal header repaired missing intended binding")
	}
	// exact child-bound generations distinguish the two buffers even when their control headers agree
	a.outConnection = node.connections[1].generation
	if _, available, e := firstChainClaim(node, a, in); e != nil || !available {
		t.Fatal("existing exact binding incorrectly depended on control-header uniqueness")
	}
	if _, available, e := firstChainClaim(node, b, in); e != nil || !available {
		t.Fatal("second exact binding incorrectly depended on control-header uniqueness")
	}
}

func TestFirstChainRejectsWrongEndpointOccupant(t *testing.T) {
	for _, swapped := range []bool{false, true} {
		in, counts := outcomeTestInput(t, 0, 2)
		pred := predictions{}
		if swapped {
			outcomeTestSecondSide(t, &in, &counts)
			pred.methods = []predictedMethod{{method: "mixed", values: []pairValue{{0, 0, .1}, {0, 1, .9}, {1, 0, .8}, {1, 1, .1}}, matches: []metrics.ViewEdge{{First: 0, Second: 1}, {First: 1, Second: 0}}}}
		}
		before, e := firstChainOutcomes(pred, in, counts, true)
		if e != nil || !before.ModelComplete {
			t.Fatal("valid endpoint crosswalk unavailable")
		}
		in.nkEndpoints[uint32(2000)<<16|1000] = 6
		if swapped {
			in.nkEndpoints[uint32(2000)<<16|1001] = 5
		}
		var links []metrics.ViewEdge
		var values []pairValue
		if swapped {
			links = append(links, pred.methods[0].matches...)
			values = append(values, pred.methods[0].values...)
		}
		if _, e = firstChainOutcomes(pred, in, counts, true); reasonOf(e) != ReasonContract {
			t.Fatalf("swapped %v: wrong normalized occupant became lower measured R: %v", swapped, e)
		}
		if in.nkEndpoints[uint32(2000)<<16|1000] != 6 || swapped && (!reflect.DeepEqual(links, pred.methods[0].matches) || !reflect.DeepEqual(values, pred.methods[0].values) || in.nkEndpoints[uint32(2000)<<16|1001] != 5) {
			t.Fatal("invalid normalizer or frozen prediction was repaired or mutated")
		}
	}
}

func TestFirstChainWrongMixedLinksUseEachOwnEndpointSource(t *testing.T) {
	in, counts := outcomeTestInput(t, 0, 2)
	outcomeTestSecondSide(t, &in, &counts)
	pred := predictions{methods: []predictedMethod{{method: "mixed", values: []pairValue{{0, 0, .1}, {0, 1, .9}, {1, 0, .8}, {1, 1, .1}}, matches: []metrics.ViewEdge{{First: 0, Second: 1}, {First: 1, Second: 0}}}}}
	links := append([]metrics.ViewEdge(nil), pred.methods[0].matches...)
	values := append([]pairValue(nil), pred.methods[0].values...)
	got, e := firstChainOutcomes(pred, in, counts, true)
	// both routes share relay occupants, so these wrong cross-side links still recover all four positions
	if e != nil || !got.ModelComplete || got.RouteHistogram[4] != 2 || got.Touched != 2 || got.Ends != 2 || !reflect.DeepEqual(links, pred.methods[0].matches) || !reflect.DeepEqual(values, pred.methods[0].values) {
		t.Fatalf("own-source normalization followed a predicted target: %+v, %v", got, e)
	}
}

func TestFirstChainRebuildCannotSupplyMissingInitialNeighbor(t *testing.T) {
	in, counts := outcomeTestInput(t, 0)
	in.views.nodes[0].setups[0].connection = 0
	later := outcomeTestNode(0, 0, 0, 200, 8)
	in.views.nodes[0].setups = append(in.views.nodes[0].setups, later.setups...)
	in.views.nodes[0].connections = append(in.views.nodes[0].connections, later.connections...)
	in.truth.setups = append(in.truth.setups, outcomeTestGroup(0, [3]uint8{0, 1, 2}, 200)...)
	got, e := firstChainOutcomes(predictions{}, in, counts, true)
	if e != nil || got.ModelComplete || !reflect.DeepEqual(got.RouteHistogram, []uint64{0, 0, 0, 0, 0}) || counts.Planned != 1 {
		t.Fatal("rebuilt neighbor repaired unavailable initial view")
	}
}

func TestFirstChainClaimCannotReadPrivateTruth(t *testing.T) {
	in, _ := outcomeTestInput(t, 0)
	node, setup := in.views.nodes[0], in.views.nodes[0].setups[0]
	before, available, e := firstChainClaim(node, setup, in)
	if e != nil || !available {
		t.Fatal("test claim unavailable")
	}
	in.truth.setups, in.truth.ownership, in.plans = nil, nil, nil
	after, available, e := firstChainClaim(node, setup, in)
	if e != nil || !available || !reflect.DeepEqual(before, after) {
		t.Fatal("claim depended on private truth")
	}
	in.nkEndpoints = nil
	if _, _, e = firstChainClaim(node, setup, in); reasonOf(e) != ReasonContract {
		t.Fatal("missing endpoint token repaired from private side or route")
	}
}

func TestFirstChainRejectsInvalidFrozenEdges(t *testing.T) {
	for _, links := range [][]metrics.ViewEdge{{{First: -1, Second: 0}}, {{First: 0, Second: 1}}, {{First: 0, Second: 0}, {First: 0, Second: 0}}} {
		in, counts := outcomeTestInput(t, 0, 2)
		pred := predictions{methods: []predictedMethod{{method: "mixed", matches: links}}}
		if _, e := firstChainOutcomes(pred, in, counts, true); reasonOf(e) != ReasonContract {
			t.Fatal("invalid frozen edge accepted")
		}
	}
}

func TestFirstChainInputsRemainReadOnly(t *testing.T) {
	in, counts := outcomeTestInput(t, 0, 2)
	outcomeTestFragment(t, &in, 2, 3, outcomeTestBody(1))
	pred := predictions{methods: []predictedMethod{{method: "mixed", matches: []metrics.ViewEdge{{First: 0, Second: 0}}}}}
	setups := append([]actualSetup(nil), in.truth.setups...)
	messages := append([]actualMessage(nil), in.truth.messages...)
	fragments := append([]contentFragment(nil), in.truth.fragments...)
	first := append([]setupView(nil), in.views.nodes[0].setups...)
	second := append([]setupView(nil), in.views.nodes[1].setups...)
	links := append([]metrics.ViewEdge(nil), pred.methods[0].matches...)
	firstConnections := append([]connectionView(nil), in.views.nodes[0].connections...)
	secondConnections := append([]connectionView(nil), in.views.nodes[1].connections...)
	nkEndpoints, portToRoster := map[uint32]int{}, map[uint16]int{}
	for endpoint, token := range in.nkEndpoints {
		nkEndpoints[endpoint] = token
	}
	for port, position := range in.portToRoster {
		portToRoster[port] = position
	}
	arena := append([]byte(nil), in.truth.arena.buffer.Bytes()[:in.truth.arena.used]...)
	if _, e := firstChainOutcomes(pred, in, counts, true); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(setups, in.truth.setups) || !reflect.DeepEqual(messages, in.truth.messages) || !reflect.DeepEqual(fragments, in.truth.fragments) || !reflect.DeepEqual(first, in.views.nodes[0].setups) || !reflect.DeepEqual(second, in.views.nodes[1].setups) || !reflect.DeepEqual(firstConnections, in.views.nodes[0].connections) || !reflect.DeepEqual(secondConnections, in.views.nodes[1].connections) || !reflect.DeepEqual(nkEndpoints, in.nkEndpoints) || !reflect.DeepEqual(portToRoster, in.portToRoster) || !reflect.DeepEqual(links, pred.methods[0].matches) || !bytes.Equal(arena, in.truth.arena.buffer.Bytes()[:in.truth.arena.used]) || in.truth.ownership != nil {
		t.Fatal("outcome producer mutated frozen inputs")
	}
	in.nkEndpoints = nil
	if _, e := firstChainOutcomes(pred, in, counts, true); reasonOf(e) != ReasonContract || !reflect.DeepEqual(links, pred.methods[0].matches) || !reflect.DeepEqual(first, in.views.nodes[0].setups) || !reflect.DeepEqual(second, in.views.nodes[1].setups) {
		t.Fatal("normalization failure changed frozen observations or predictions")
	}
}
