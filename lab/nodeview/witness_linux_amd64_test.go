//go:build linux && amd64

package nodeview

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestRouteConnectionsSeed117(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		c := Config{Set: Mailbox, Phase: Structural, Suite: s, Seed: 117, Revision: strings.Repeat("1", 40)}
		row := Coordinate{ID: "mail-P0-C0-mailbox-first", Topology: "peer", Trust: "trusted", Population: "control", Controlled: []int{0, 4}, Setup: "concurrent", N: 5, H: 3, Conversations: 16, Settings: peerSettings(false, 0)}
		if got := drawRoutes(c, row, 32, 0); !slices.Equal(got, seed117TrustedRoutes) {
			t.Fatalf("%s routes %v", s, got)
		}
	}
}

func witnessRoundTrip(t *testing.T, cw childWitness) (childWitness, error, int) {
	t.Helper()
	w := encoder{}
	encodeChildWitness(&w, cw)
	if w.bad {
		t.Fatal("encode failed")
	}
	r := &decoder{b: w.b}
	got, e := decodeChildWitness(r, cw.role)
	if e == nil && r.end() != nil {
		t.Fatal("tail left bytes")
	}
	return got, e, len(w.b)
}

func TestChildWitnessCodec(t *testing.T) {
	relay := childWitness{role: roleRelay}
	for i := range relay.values {
		relay.values[i] = uint64(1000 + i)
	}
	relay.values[0], relay.values[1], relay.values[2] = uint64(reasonByte(ReasonLimit)), uint64(siteConnCap), uint64(phaseLead)
	relay.values[3] = latchOffset(850000000, 1000000000)
	got, e, n := witnessRoundTrip(t, relay)
	if e != nil || n != 202 || got != relay || int64(got.values[3]) != -150000000 {
		t.Fatalf("relay round trip %v %d", e, n)
	}
	client := childWitness{role: roleClient}
	for i := range clientWitnessValues {
		client.values[i] = uint64(i)
	}
	client.values[0], client.values[1], client.values[10] = uint64(reasonByte(ReasonContract)), uint64(phaseDrain), 3
	got, e, n = witnessRoundTrip(t, client)
	if e != nil || n != 114 || got != client {
		t.Fatalf("client round trip %v %d", e, n)
	}
	w := encoder{}
	encodeChildWitness(&w, client)
	if _, e = decodeChildWitness(&decoder{b: w.b}, roleRelay); e == nil {
		t.Fatal("wrong role accepted")
	}
	w.b[0] = 2
	if _, e = decodeChildWitness(&decoder{b: w.b}, roleClient); e == nil {
		t.Fatal("wrong version accepted")
	}
	w = encoder{}
	encodeChildWitness(&w, client)
	encodeChildWitness(&w, client)
	r := &decoder{b: w.b}
	if _, e = decodeChildWitness(r, roleClient); e != nil || r.end() == nil {
		t.Fatal("a second tail passed the frame end")
	}
	mutate := func(base childWitness, index int, v uint64) childWitness {
		base.values[index] = v
		return base
	}
	for name, cw := range map[string]childWitness{
		"site":                        mutate(relay, 1, uint64(siteLast)+1),
		"relay phase":                 mutate(relay, 2, uint64(phaseLast)+1),
		"reason":                      mutate(relay, 0, uint64(len(reasons))),
		"relay latch without reason":  mutate(relay, 0, 0),
		"client phase":                mutate(client, 1, uint64(phaseLast)+1),
		"finish":                      mutate(client, 10, 4),
		"client latch without reason": mutate(client, 0, 0),
	} {
		if _, e, _ = witnessRoundTrip(t, cw); reasonOf(e) != ReasonIPC {
			t.Fatalf("%s accepted", name)
		}
	}
	zero := childWitness{role: roleRelay}
	if got, e, _ = witnessRoundTrip(t, zero); e != nil || got != zero {
		t.Fatal("empty relay tail rejected")
	}
}

func TestEveryEndWriterCarriesTail(t *testing.T) {
	want := map[string][2]int{"relayChild": {0, 2}, "clientChild": {0, 1}, "clientRefused": {0, 1}, "scorerChild": {1, 0}, "finishTrainingCommand": {1, 0}}
	got := map[string][2]int{}
	fs := token.NewFileSet()
	for _, name := range []string{"child_linux_amd64.go", "echo_linux_amd64.go", "scorer_linux_amd64.go", "training_linux_amd64.go"} {
		file, e := parser.ParseFile(fs, name, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "terminal" || fn.Name.Name == "terminalWitness" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "terminal" || sel.Sel.Name == "terminalWitness") {
						count := got[fn.Name.Name]
						count[boolInt(sel.Sel.Name == "terminalWitness")]++
						got[fn.Name.Name] = count
					}
				}
				return true
			})
		}
	}
	if !maps.Equal(got, want) {
		t.Fatalf("terminal writers %v, want %v", got, want)
	}

	col := witnessCollector(t, &witnessClock{ns: 5})
	col.begin(10, 20)
	col.failAt(ReasonLimit, siteConnCap, 0)
	end, e := decodeTerminal(&decoder{b: terminalBody(t, func(c *childIO) error { return c.terminalWitness(Counts{}, ReasonLimit, relayTail(col, 7, 9)) })}, roleRelay)
	// the latch at 5 precedes the epoch at 10: lead, offset -5
	if e != nil || end.witness.values[1] != uint64(siteConnCap) || end.witness.values[2] != uint64(phaseLead) || int64(end.witness.values[3]) != -5 || end.witness.values[9] != 7 || end.witness.values[10] != 9 {
		t.Fatalf("relay tail %v %v", e, end.witness.values)
	}
	early := terminalBody(t, func(c *childIO) error { return c.terminalWitness(Counts{}, ReasonNone, childWitness{role: roleRelay}) })
	if _, e = decodeTerminal(&decoder{b: early}, roleRelay); e != nil {
		t.Fatal("early relay terminal rejected")
	}
	if _, e = decodeTerminal(&decoder{b: early}, roleClient); reasonOf(e) != ReasonIPC {
		t.Fatal("relay tail decoded as a client")
	}
	scorer := terminalBody(t, func(c *childIO) error { return c.terminal(Counts{}, ReasonNone) })
	if _, e = decodeTerminal(&decoder{b: scorer}, roleScorer); e != nil {
		t.Fatal("scorer terminal gained a tail")
	}
	if _, e = decodeTerminal(&decoder{b: scorer}, roleTrainer); e != nil {
		t.Fatal("trainer terminal gained a tail")
	}
	if _, e = decodeTerminal(&decoder{b: scorer}, roleRelay); reasonOf(e) != ReasonIPC {
		t.Fatal("relay terminal without a tail was accepted")
	}
	refused := terminalBody(t, func(c *childIO) error {
		var command bytes.Buffer
		commands := &protocolWriter{w: &command, limit: 1 << 20}
		stop := encoder{}
		stop.u8(1)
		ack := encoder{}
		ack.u8(0)
		if e := commands.send(opStop, stop); e != nil {
			return e
		}
		if e := commands.send(opAck, ack); e != nil {
			return e
		}
		reader, e := newProtocolReader(&command, [16]byte{}, 1<<20)
		if e != nil {
			return e
		}
		c.command = reader
		r, w, e := os.Pipe()
		if e != nil {
			return e
		}
		w.Close()
		defer r.Close()
		c.files[0] = r
		p := &privateCapture{}
		p.latch(ReasonLabel)
		return clientRefused(c, p, Counts{Planned: 1, Attempted: 1, Refused: 1}, func() {}, ReasonRefused)
	})
	end, e = decodeTerminal(&decoder{b: refused}, roleClient)
	if e != nil || end.reason != ReasonRefused || end.witness.values[0] != uint64(reasonByte(ReasonLabel)) || end.witness.values[1] != uint64(phaseBeforeBegin) || end.witness.values[2] != 0 {
		t.Fatalf("refused client tail %v %v", e, end.witness.values)
	}
}

func terminalBody(t *testing.T, write func(*childIO) error) []byte {
	t.Helper()
	var command, status bytes.Buffer
	commands := &protocolWriter{w: &command, limit: 1 << 20}
	ack := encoder{}
	ack.u8(0)
	if e := commands.send(opAck, ack); e != nil {
		t.Fatal(e)
	}
	reader, e := newProtocolReader(&command, [16]byte{}, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.close()
	c := &childIO{command: reader, status: &protocolWriter{w: &status, limit: 1 << 20}, view: &protocolWriter{w: io.Discard, limit: 1 << 20}, truth: &protocolWriter{w: io.Discard, limit: 1 << 20}}
	if e = write(c); e != nil {
		t.Fatal(e)
	}
	replies, e := newProtocolReader(&status, [16]byte{}, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer replies.close()
	op, r, e := replies.next()
	if e != nil || op != opEnd {
		t.Fatal("no terminal frame")
	}
	return append([]byte(nil), r.b[r.at:]...)
}

func TestClientCaptureLayout(t *testing.T) {
	var capture privateCapture
	if unsafe.Sizeof(capture) != 328 || unsafe.Offsetof(capture.err) != 296 || unsafe.Offsetof(capture.frozen) != 312 || unsafe.Offsetof(capture.latchAt) != 320 {
		t.Fatal("client capture layout")
	}
	// control rounds 328 + 112 up to one 8192-byte page, so the client total is unchanged
	if n, e := clientTruthBackingBytes(); e != nil || n != 1875968 {
		t.Fatal("client backing total changed", n, e)
	}
	p := &privateCapture{}
	p.latch(ReasonLimit)
	first := p.latchAt
	p.latch(ReasonContract)
	if first <= 0 || p.latchAt != first {
		t.Fatal("client latch time not written once")
	}
}

func TestTaskWitnessLines(t *testing.T) {
	if waitCPU(nil) != 0 {
		t.Fatal("waitCPU(nil)")
	}
	// 3 s of cpu over 1.5 s of wall: quota 2000 caps 32 cpus at 2, so 3e9*1e6/(1.5e9*2) = 1e6
	if got := utilizationPPM(3000000000, 1500000000, 32, 2000); got != 1000000 {
		t.Fatal("utilization", got)
	}
	if got := utilizationPPM(3000000000, 1500000000, 32, 0); got != 62500 {
		t.Fatal("utilization without quota", got)
	}
	w := &taskWitness{routes: [][3]uint8{{0, 1, 4}, {2, 3, 4}}, relayCount: 5, unanswered: 0, recorded: true, startNS: 1000000000, endNS: 2500000000, startCPU: 100000000, endCPU: 600000000, host: [2]hostStat{{total: 1000, steal: 10, ok: true}, {total: 2000, steal: 30, ok: true}}}
	w.relays[0].summary[19] = 2
	w.relays[0].cpuNS = 1000000000
	w.relays[1].summary[19] = 2
	w.relays[4].summary[19] = 2
	w.relays[4].selected = true
	w.relays[4].cpuNS = 1000000000
	w.relays[2].tail = childWitness{role: roleRelay}
	w.relays[2].tail.values[0], w.relays[2].tail.values[1], w.relays[2].tail.values[2], w.relays[2].tail.values[3] = uint64(reasonByte(ReasonLimit)), uint64(siteConnCap), uint64(phaseWindow), 1500000000
	w.relays[2].tail.values[4] = 128
	w.relays[2].summary[19] = 2
	w.relays[3].summary[19] = 2
	w.clients = []clientWitness{{rebuilt: 0, cpuNS: 500000000}, {rebuilt: 0, cpuNS: 0}}
	w.clients[1].tail.values[0], w.clients[1].tail.values[1], w.clients[1].tail.values[2] = 4, uint64(phaseLead), latchOffset(850000000, 1000000000)
	w.clients[0].tail.values[3] = 2
	lines := w.lines("gost", "trusted-admission", "ok", "pass", 32, 2000, 4)
	// children 2.5 s + controller 0.5 s over 1.5 s on 2 cpus: 1e6 ppm; steal 20/1000
	want := []string{
		"nodeview-witness v1 suite=gost case=trusted-admission exec=ok outcome=pass rebuilt_total=0 unanswered=0 wall_ms=1500 nproc=32 cpu_limit_millis=2000 gomaxprocs=4 children_cpu_ms=2500 controller_cpu_ms=500 utilization_ppm=1000000 host_steal_ppm=20000 cgroup_cpu_ms=none",
		"nodeview-witness v1 suite=gost relay=0 selected=0 reason=none flags=[] conns=2 base=2 predicted=2 unattributed=0 pending_hw=0 cells_hw=0 contexts_hw=0 arena_hw=0 free_spans_hw=0 calls=0 callback_ms=0 cpu_ms=1000 cpu_window_ms=0 wall_window_ms=0 visits=setup_out:0,setup_hop:0,history:0,pair:0,deliver:0,pending:0 queue_ge_3500ms=0 queue_ge_7s=0 queue_max_ms=0 deliver_early=calls:0,us:0 deliver_late=calls:0,us:0 stats=accepted:0,forwarded:0,delivered:0,dropped:0,broken:0,accept_retries:0,refused_links:0,refused_busy:0,failed_extend:0,timed_out:0,expired:0 latch=none",
		"nodeview-witness v1 suite=gost relay=1 selected=0 reason=none flags=[] conns=2 base=2 predicted=2 unattributed=0 pending_hw=0 cells_hw=0 contexts_hw=0 arena_hw=0 free_spans_hw=0 calls=0 callback_ms=0 cpu_ms=0 cpu_window_ms=0 wall_window_ms=0 visits=setup_out:0,setup_hop:0,history:0,pair:0,deliver:0,pending:0 queue_ge_3500ms=0 queue_ge_7s=0 queue_max_ms=0 deliver_early=calls:0,us:0 deliver_late=calls:0,us:0 stats=accepted:0,forwarded:0,delivered:0,dropped:0,broken:0,accept_retries:0,refused_links:0,refused_busy:0,failed_extend:0,timed_out:0,expired:0 latch=none",
		"nodeview-witness v1 suite=gost relay=2 selected=0 reason=none flags=[] conns=2 base=2 predicted=2 unattributed=0 pending_hw=0 cells_hw=0 contexts_hw=0 arena_hw=0 free_spans_hw=0 calls=0 callback_ms=0 cpu_ms=0 cpu_window_ms=0 wall_window_ms=0 visits=setup_out:0,setup_hop:0,history:0,pair:0,deliver:0,pending:0 queue_ge_3500ms=0 queue_ge_7s=0 queue_max_ms=0 deliver_early=calls:0,us:0 deliver_late=calls:0,us:0 stats=accepted:0,forwarded:0,delivered:0,dropped:0,broken:0,accept_retries:0,refused_links:0,refused_busy:0,failed_extend:0,timed_out:0,expired:0 latch=conn_cap@window+1500 inv=128/0/0/0 closed_age_ms=0",
		"nodeview-witness v1 suite=gost relay=3 selected=0 reason=none flags=[] conns=2 base=2 predicted=2 unattributed=0 pending_hw=0 cells_hw=0 contexts_hw=0 arena_hw=0 free_spans_hw=0 calls=0 callback_ms=0 cpu_ms=0 cpu_window_ms=0 wall_window_ms=0 visits=setup_out:0,setup_hop:0,history:0,pair:0,deliver:0,pending:0 queue_ge_3500ms=0 queue_ge_7s=0 queue_max_ms=0 deliver_early=calls:0,us:0 deliver_late=calls:0,us:0 stats=accepted:0,forwarded:0,delivered:0,dropped:0,broken:0,accept_retries:0,refused_links:0,refused_busy:0,failed_extend:0,timed_out:0,expired:0 latch=none",
		"nodeview-witness v1 suite=gost relay=4 selected=1 reason=none flags=[] conns=2 base=2 predicted=2 unattributed=0 pending_hw=0 cells_hw=0 contexts_hw=0 arena_hw=0 free_spans_hw=0 calls=0 callback_ms=0 cpu_ms=1000 cpu_window_ms=0 wall_window_ms=0 visits=setup_out:0,setup_hop:0,history:0,pair:0,deliver:0,pending:0 queue_ge_3500ms=0 queue_ge_7s=0 queue_max_ms=0 deliver_early=calls:0,us:0 deliver_late=calls:0,us:0 stats=accepted:0,forwarded:0,delivered:0,dropped:0,broken:0,accept_retries:0,refused_links:0,refused_busy:0,failed_extend:0,timed_out:0,expired:0 latch=none",
		"nodeview-witness v1 suite=gost clients n=2 rebuilt_sum=0 rebuilt_max=0 rebuilt_nonzero=0 ends=reply_timeout:2,send_failed:0,refused:0,far_close:0,after:0 dial=attempts:0,failures:0 finish=none:2,rebuild:0,refused:0,other:0 refusals=0 conv_unanswered=through_drain:0,total:0 clients_cpu_ms=500 latches=[1:lead-150]",
	}
	if !slices.Equal(lines, want) {
		for i := range max(len(lines), len(want)) {
			if i >= len(lines) || i >= len(want) || lines[i] != want[i] {
				t.Errorf("line %d\n got %q", i, lines)
				break
			}
		}
	}
	absent := (&taskWitness{}).lines("c25519", "trusted-admission", "err", "fail", 4, 0, 4)
	if len(absent) != 1 || absent[0] != "nodeview-witness v1 suite=c25519 case=trusted-admission exec=err outcome=fail witness absent" {
		t.Fatal(absent)
	}
}

func TestHostStatParse(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	a := parseHostStat("cpu  100 10 50 800 20 5 5 10 7 0\ncpu0 1 2 3\n")
	b := parseHostStat("cpu  200 10 100 1500 40 10 10 30 7 0\n")
	// totals 1000 and 1900, busy 1000-800-20 = 180 and 1900-1500-40 = 360, steal 10 and 30
	if a != (hostStat{busy: 180, steal: 10, total: 1000, ok: true}) || b != (hostStat{busy: 360, steal: 30, total: 1900, ok: true}) {
		t.Fatal(a, b)
	}
	// (30-10)*1e6/(1900-1000) = 22222
	if ppm, ok := stealPPM([2]hostStat{a, b}); !ok || ppm != 22222 {
		t.Fatal(ppm)
	}
	if limit, ok := parseCPULimit("200000 100000\n"); !ok || limit != 2000 {
		t.Fatal(limit)
	}
	if _, ok := parseCPULimit("max 100000\n"); ok {
		t.Fatal("max parsed as a limit")
	}
	if v, ok := parseCgroupUsage("usage_usec 1234\nuser_usec 1000\n"); !ok || v != 1234 {
		t.Fatal(v)
	}
}

type witnessRefusal struct{ error }

func TestBoundaryEndsByCause(t *testing.T) {
	b := &boundaryClientState{}
	b.until = monotonicNS() + 3600000000000
	var added uint64
	b.unanswered = func() uint64 { added += 2; return added }
	for _, cause := range []error{conversation.ErrReplyTimeout, conversation.ErrSendFailed, nil, witnessRefusal{errors.New("refused class")}} {
		b.event(conversation.Event{Kind: conversation.CircuitEnded, Cause: cause})
	}
	b.event(conversation.Event{Kind: conversation.CircuitRebuilt})
	b.until = 1
	b.event(conversation.Event{Kind: conversation.CircuitEnded, Cause: conversation.ErrReplyTimeout})
	// four ends before cutoff plus drain each add 2 unanswered requests: 8; the end after until is not counted
	if b.ends != (circuitEnds{replyTimeout: 1, sendFailed: 1, farClose: 1, refused: 1, after: 1}) || !b.initialEnded || b.unansweredThroughDrain != 8 || added != 10 {
		t.Fatalf("%+v", b.ends)
	}
	early := &boundaryClientState{}
	early.event(conversation.Event{Kind: conversation.CircuitEnded, Cause: conversation.ErrReplyTimeout})
	if early.ends.replyTimeout != 1 {
		t.Fatal("an end before the workload began fell outside the counted interval")
	}
}

func TestDialCounters(t *testing.T) {
	b := &boundaryClientState{until: monotonicNS() + 3600000000000}
	fake := func(e error, generation uint32) func() (*client.Client, uint32, error) {
		return func() (*client.Client, uint32, error) {
			if e != nil {
				return nil, 0, e
			}
			return &client.Client{}, generation, nil
		}
	}
	if _, g, e := countedDial(b, fake(nil, 7)); e != nil || g != 7 || b.current != 7 {
		t.Fatal("successful dial")
	}
	if _, _, e := countedDial(b, fake(os.ErrDeadlineExceeded, 9)); e == nil || b.current != 7 {
		t.Fatal("failed dial moved the generation")
	}
	b.until = 1
	if _, _, e := countedDial(b, fake(os.ErrDeadlineExceeded, 9)); e == nil {
		t.Fatal("failed dial")
	}
	if b.dials != (dialCounts{attempts: 2, failures: 1}) || b.dialsAfter != (dialCounts{attempts: 1, failures: 1}) {
		t.Fatalf("%+v %+v", b.dials, b.dialsAfter)
	}
}
