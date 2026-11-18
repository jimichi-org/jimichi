//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

func TestBoundarySharedSettingsCodec(t *testing.T) {
	for id := uint8(0); id <= 7; id++ {
		s := peerSettings(false, 0)
		if id > 0 {
			s, _ = boundaryProfileSettings(id)
		}
		w := encoder{}
		encodeSettings(&w, s)
		if len(w.b) != 93 || w.b[92] != id {
			t.Fatal("shared profile field moved or disappeared")
		}
		r := decoder{b: w.b}
		got := decodeSettings(&r)
		if r.end() != nil || got != s || got.validate(true) != nil {
			t.Fatal("settings round trip")
		}
		for n := 0; n < len(w.b); n++ {
			r := decoder{b: w.b[:n]}
			decodeSettings(&r)
			if r.end() == nil {
				t.Fatal("legacy/truncated settings accepted")
			}
		}
		w.b[92] = 8
		r = decoder{b: w.b}
		decodeSettings(&r)
		if r.end() == nil {
			t.Fatal("unknown profile accepted")
		}
	}
}

func TestBoundaryRebuildLocalEvidenceExcludesPeerAuthority(t *testing.T) {
	for _, missing := range []string{"none", "close", "end", "initial", "newer", "rebuild"} {
		t.Run(missing, func(t *testing.T) {
			in := boundaryReceiptInput(t)
			p := &privateCapture{truth: in.truth, generation: 2, completeGeneration: 2, nextSetupHop: 255}
			p.truth.setups = []actualSetup{{side: 0, hop: 2}, {side: 0, hop: 1}, {side: 0, hop: 0}, {side: 0, hop: 2}, {side: 0, hop: 1}, {side: 0, hop: 0}}
			generation, _, e := p.completedSince(constructionMark{ordinal: 1, records: 3})
			if e != nil || generation != 2 {
				t.Fatal("new generation did not complete its actual recorded setup group")
			}
			b := &boundaryClientState{initial: 1, current: generation, closeRequested: true}
			b.event(conversation.Event{Kind: conversation.CircuitEnded})
			st := conversation.Stats{Rebuilds: 1}
			switch missing {
			case "close":
				b.closeRequested = false
			case "end":
				b.initialEnded = false
			case "initial":
				b.initial = 0
			case "newer":
				b.current = b.initial
			case "rebuild":
				st.Rebuilds = 0
			}
			before := append([]actualMessage(nil), p.truth.messages...)
			want := ReasonIncomplete
			if missing == "none" {
				want = ReasonNone
			}
			if reasonOf(checkBoundaryClient(7, 0, false, st, p, 100, 200, b)) != want {
				t.Fatal("local rebuild decision mixed peer authority or accepted missing lifecycle evidence")
			}
			if !reflect.DeepEqual(before, p.truth.messages) {
				t.Fatal("local rebuild check resolved or erased message evidence")
			}
			if missing == "none" && oldBoundaryLocalReceipts(p.truth.messages) {
				t.Fatal("old local receipt guard did not reject this exact unresolved-own-send prefix")
			}
		})
	}
	p := &privateCapture{}
	b := &boundaryClientState{initial: 1, current: 2}
	if reasonOf(checkBoundaryClient(7, 0, false, conversation.Stats{Rebuilds: 1}, p, 100, 200, b)) != ReasonIncomplete {
		t.Fatal("Dial alone supplied a close/end witness")
	}
	b.event(conversation.Event{Kind: conversation.CircuitEnded})
	if reasonOf(checkBoundaryClient(7, 0, false, conversation.Stats{Rebuilds: 1}, p, 100, 200, b)) != ReasonIncomplete {
		t.Fatal("cleanup-style ending supplied an intentional close witness")
	}
}

func oldBoundaryLocalReceipts(messages []actualMessage) bool {
	for _, message := range messages {
		if !message.replied {
			return false
		}
	}
	return true
}

type readinessWaitCircuit struct {
	replies chan []byte
	store   *mailbox.Store
	id      uint64
}

func (c *readinessWaitCircuit) Send(body []byte) error {
	reply := c.store.Deliver(c.id, bytes.Clone(body))
	select {
	case c.replies <- reply:
		return nil
	default:
		clear(reply)
		return fail(ReasonBroken)
	}
}
func (c *readinessWaitCircuit) Replies() <-chan []byte { return c.replies }
func (c *readinessWaitCircuit) Refused() error         { return nil }
func (c *readinessWaitCircuit) MaxPayload() int        { return mailbox.RequestSize }
func (c *readinessWaitCircuit) Close() error           { return nil }

func TestPeerReadyWaitPreservesDeadlineCancellationAndClosure(t *testing.T) {
	p, e := suite.New(jcrypto.SuiteC25519)
	if e != nil {
		t.Fatal(e)
	}
	fetch, e := secmem.New(mailbox.CapSize)
	if e != nil {
		t.Fatal(e)
	}
	defer fetch.Release()
	fetch.Bytes()[0] = 1
	queue, e := mailbox.QueueID(p, fetch.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	id, e := e2e.NewIdentity(p, "127.0.0.1:9000", queue)
	if e != nil {
		t.Fatal(e)
	}
	defer id.Close()
	store, e := mailbox.NewStore(p, mailbox.DefaultLimits(), time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	circuit := &readinessWaitCircuit{replies: make(chan []byte, 256), store: store, id: 1}
	defer func() {
		for len(circuit.replies) > 0 {
			clear(<-circuit.replies)
		}
	}()
	conv, e := conversation.Start(conversation.Config{Provider: p, Self: id, Fetch: fetch, First: circuit, Dial: func() (conversation.Circuit, error) { return nil, fail(ReasonBroken) }, Rate: 50 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	defer conv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, row := range []struct {
		ctx   context.Context
		conv  *conversation.Conversation
		role  e2e.Role
		until int64
		want  Reason
	}{
		{nil, conv, e2e.RoleInitiator, 1, ReasonContract},
		{context.Background(), nil, e2e.RoleInitiator, 1, ReasonContract},
		{context.Background(), conv, 0, 1, ReasonContract},
		{context.Background(), conv, e2e.RoleInitiator, 0, ReasonContract},
		{ctx, conv, e2e.RoleInitiator, monotonicNS() + int64(time.Second), ReasonCancelled},
		{context.Background(), conv, e2e.RoleInitiator, monotonicNS() - 1, ReasonIncomplete},
		{context.Background(), conv, e2e.RoleInitiator, monotonicNS() + int64(10*time.Millisecond), ReasonIncomplete},
	} {
		if reasonOf(awaitPeerReady(row.ctx, row.conv, row.role, row.until)) != row.want {
			t.Fatal("real wait lost its finite deadline or precise failure")
		}
	}
	peerFetch, e := secmem.New(mailbox.CapSize)
	if e != nil {
		t.Fatal(e)
	}
	defer peerFetch.Release()
	peerFetch.Bytes()[0] = 2
	peerQueue, e := mailbox.QueueID(p, peerFetch.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	peerID, e := e2e.NewIdentity(p, "127.0.0.1:9000", peerQueue)
	if e != nil {
		t.Fatal(e)
	}
	defer peerID.Close()
	peerCircuit := &readinessWaitCircuit{replies: make(chan []byte, 256), store: store, id: 2}
	defer func() {
		for len(peerCircuit.replies) > 0 {
			clear(<-peerCircuit.replies)
		}
	}()
	peer, e := conversation.Start(conversation.Config{Provider: p, Self: peerID, Fetch: peerFetch, First: peerCircuit, Dial: func() (conversation.Circuit, error) { return nil, fail(ReasonBroken) }, Rate: 50 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	ownCard, peerCard := id.Card(), peerID.Card()
	defer clear(ownCard.Static)
	defer clear(peerCard.Static)
	role, e := peerReadinessRole(ownCard, peerCard)
	if e != nil {
		t.Fatal(e)
	}
	peerRole, e := peerReadinessRole(peerCard, ownCard)
	if e != nil {
		t.Fatal(e)
	}
	if conv.Pair(peerCard) != nil || peer.Pair(ownCard) != nil {
		t.Fatal("actual Conversation pair failed")
	}
	until := monotonicNS() + int64(10*time.Second)
	if e := awaitPeerReady(context.Background(), conv, role, until); e != nil {
		t.Fatal(e)
	}
	if e := awaitPeerReady(context.Background(), peer, peerRole, until); e != nil {
		t.Fatal(e)
	}
	if reasonOf(awaitPeerReady(context.Background(), conv, role, monotonicNS()-1)) != ReasonIncomplete {
		t.Fatal("already ready actual Conversation bypassed the delayed cutoff")
	}
	conv.Close()
	if reasonOf(awaitPeerReady(context.Background(), conv, e2e.RoleInitiator, monotonicNS()+int64(time.Second))) != ReasonBroken {
		t.Fatal("closed actual Conversation accepted readiness")
	}
	select {
	case <-conv.Done():
	default:
		t.Fatal("actual Conversation owner did not join")
	}
	peer.Close()
}

func TestBoundaryPublicCardSettingsAndPhaseTasks(t *testing.T) {
	own, peer := e2e.Card{Static: []byte{1}}, e2e.Card{Static: []byte{2}}
	s, _ := boundaryProfileSettings(6)
	for _, side := range []uint16{0, 1} {
		initiator, responder, e := boundaryClientSettings(s, side, own, peer)
		want, _ := boundaryProfileSideSettings(6, 0)
		if e != nil || responder || initiator != want {
			t.Fatal("smaller public Static did not select initiator settings")
		}
		got, responder, e := boundaryClientSettings(s, side, peer, own)
		want, _ = boundaryProfileSideSettings(6, 1)
		if e != nil || !responder || got != want {
			t.Fatal("larger public Static did not select responder settings")
		}
	}
	if _, _, e := boundaryClientSettings(s, 0, own, own); e == nil {
		t.Fatal("equal Static accepted")
	}
	for _, phase := range []Phase{Structural, Train, Pilot, Primary} {
		c := Config{Set: Mailbox, Phase: phase, Suite: jcrypto.SuiteC25519}
		p := Plan{Configurations: canonicalCoordinates(Mailbox)}
		count := 0
		for _, task := range registeredTasks(c, p) {
			if task.coordinate.Settings.ControlProfile == 0 {
				continue
			}
			count++
			profile, _ := boundaryProfileFor(task.coordinate.Settings.ControlProfile)
			if phase != Structural || task.repeat != 0 || !reflect.DeepEqual(task.routes, profile.routes[:]) {
				t.Fatal("boundary escaped its exact structural route recipe")
			}
		}
		if phase == Structural && count != 7 || phase != Structural && count != 0 {
			t.Fatal("boundary phase membership")
		}
	}
}

func TestTrainingTasksRandomizeCoverPairsWithoutRefill(t *testing.T) {
	c := Config{Set: Mailbox, Phase: Train, Suite: jcrypto.SuiteC25519, Seed: 117}
	tasks := pairedMailboxTasks(c, Plan{Configurations: canonicalCoordinates(Mailbox)})
	if len(tasks) != 20 {
		t.Fatal("five runs per four configurations required")
	}
	seen := map[string]map[int]bool{}
	for i := 0; i < len(tasks); i += 2 {
		a, b := tasks[i], tasks[i+1]
		if a.repeat != b.repeat || a.coordinate.Settings.RelayPeriodNS != b.coordinate.Settings.RelayPeriodNS || a.coordinate.Settings.CoverPuts == b.coordinate.Settings.CoverPuts {
			t.Fatal("cover pair lost its repeat")
		}
		for _, task := range []executionTask{a, b} {
			if task.coordinate.Population != "classifier" || task.coordinate.Settings.ControlProfile != 0 || task.repeat < 0 || task.repeat >= 5 {
				t.Fatal("nontraining coordinate")
			}
			if seen[task.coordinate.ID] == nil {
				seen[task.coordinate.ID] = map[int]bool{}
			}
			if seen[task.coordinate.ID][task.repeat] {
				t.Fatal("training refill")
			}
			seen[task.coordinate.ID][task.repeat] = true
		}
	}
	if len(seen) != 4 {
		t.Fatal("training matrix missing")
	}
}
