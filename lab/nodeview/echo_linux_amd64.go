//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/pki"
)

func init() { waitMonotonic = waitUntil }

func encodeWorkload(w workloadPlan, budgets ...*memoryBudget) encoder {
	b := encoder{}
	if len(budgets) > 0 {
		b.budget = budgets[0]
	}
	b.u16(w.side)
	b.u8(3)
	for _, n := range w.route {
		b.u8(n)
	}
	b.i64(w.gapSeed)
	b.i64(w.lifetimeSeed)
	b.i64(w.phaseSeed)
	b.u16(uint16(len(w.bodies)))
	for _, body := range w.bodies {
		b.raw(w.bodyArena.bytes(body))
	}
	b.u8(w.topology)
	b.bytes(w.contact, 2048)
	return b
}
func decodeWorkload(r *decoder, a *lockedArena) (workloadPlan, error) {
	w := workloadPlan{side: r.u16()}
	if r.u8() != 3 {
		return w, fail(ReasonIPC)
	}
	seen := map[uint8]bool{}
	for i := range w.route {
		w.route[i] = r.u8()
		if w.route[i] >= 5 || seen[w.route[i]] {
			return w, fail(ReasonIPC)
		}
		seen[w.route[i]] = true
	}
	w.gapSeed, w.lifetimeSeed, w.phaseSeed = r.i64(), r.i64(), r.i64()
	n := int(r.u16())
	if n > 128 {
		return w, fail(ReasonIPC)
	}
	for range n {
		body := r.take(128)
		ref, ok := a.copy(body)
		if !ok {
			return w, fail(ReasonLimit)
		}
		w.bodies = append(w.bodies, ref)
	}
	w.bodyArena = a
	w.structural = n == 1
	w.topology = r.u8()
	w.contact = append([]byte(nil), r.bytes(2048)...)
	if r.end() != nil || w.topology < 1 || w.topology > 2 {
		return w, fail(ReasonIPC)
	}
	return w, nil
}

func clientChild(c *childIO) (err error) {
	receipt := childCleanupReceipt{}
	defer func() {
		if c.afterCleanup != nil {
			c.afterCleanup(receipt)
		}
	}()
	w := encoder{}
	w.u8(roleClient)
	w.u8(byte(c.suite))
	w.u16(0)
	w.u8(1)
	if e := c.status.send(opBoot, w); e != nil {
		return e
	}
	r, e := c.receive(opConfigure)
	if e != nil {
		return e
	}
	cfg, e := decodeApplication(r)
	if e != nil {
		return e
	}
	if cfg.suite != c.suite {
		return fail(ReasonIPC)
	}
	p, e := suite.New(c.suite)
	if e != nil {
		return fail(ReasonEnrollment)
	}
	priv, e := newPrivateCapture(0)
	if e != nil {
		return e
	}
	receipt.PrivateCreated = true
	defer func() { priv.close(); receipt.PrivateClosed = true }()
	if e = c.cancelledAt(initClientPrivate); e != nil {
		return e
	}
	op := &observedProvider{CryptoProvider: p, private: priv}
	entries := make([]pki.MirrorEntry, 5)
	addrs := make([]string, 5)
	ports := make(map[uint16]bool)
	for i, node := range cfg.roster {
		addrs[i] = loopback(node.port)
		entries[i] = pki.MirrorEntry{Addr: addrs[i], Bundle: node.bundle}
		ports[node.port] = true
	}
	view, e := verify.MirrorEntries(op, verify.Options{Auth: true, Trust: policy(cfg.anchor)}, addrs, entries, time.Now())
	if e != nil {
		return fail(ReasonEnrollment)
	}
	for i, node := range cfg.roster {
		if view.Missing(i) != nil {
			if cfg.settings.ControlProfile != 0 {
				return fail(ReasonEnrollment)
			}
			continue
		}
		v, e := pki.Verify(op, policy(cfg.anchor), addrs[i], node.bundle, time.Now())
		if e != nil {
			return fail(ReasonEnrollment)
		}
		rec := verify.NewRecord(pki.Skew, 8*time.Minute)
		rec.Hold(0)
		if conflict, ok := rec.Take(node.bundle, v, time.Now()); conflict != nil || !ok {
			return fail(ReasonEnrollment)
		}
	}
	if e := c.ready(1); e != nil {
		return e
	}
	var identity *e2e.Identity
	var fetch *secmem.Buffer
	var circuit *client.Client
	var initialGeneration uint32
	var conv *conversation.Conversation
	var observer *observerLifetime
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if observer != nil {
				observer.join()
				receipt.ObserverJoined = true
			}
			if conv != nil {
				conv.Close()
				receipt.ConversationClosed = true
			}
			if circuit != nil {
				circuit.Close()
				receipt.InitialCircuitClosed = true
			}
			if identity != nil {
				identity.Close()
				receipt.IdentityReleased = true
			}
			if fetch != nil {
				fetch.Release()
				receipt.FetchReleased = true
			}
			priv.close()
			receipt.PrivateClosed = true
		})
	}
	defer cleanup()
	if cfg.topology == 2 {
		fetch, e = secmem.New(mailbox.CapSize)
		if e != nil {
			return fail(ReasonUnsupported)
		}
		receipt.FetchCreated = true
		defer func() { fetch.Release(); receipt.FetchReleased = true }()
		if e = c.cancelledAt(initClientFetch); e != nil {
			return e
		}
		if _, e = io.ReadFull(rand.Reader, fetch.Bytes()); e != nil {
			return fail(ReasonChild)
		}
		queue, e := mailbox.QueueID(op, fetch.Bytes())
		if e != nil {
			return fail(ReasonChild)
		}
		identity, e = e2e.NewIdentity(op, addrs[cfg.mailbox], queue)
		clear(queue[:])
		if e != nil {
			return fail(ReasonChild)
		}
		receipt.IdentityCreated = true
		defer func() { identity.Close(); receipt.IdentityReleased = true }()
		if e = c.cancelledAt(initClientIdentity); e != nil {
			return e
		}
		w = encoder{}
		w.u16(1)
		w.bytes(identity.Card().Bytes(), 2048)
		if e := c.status.send(opContact, w); e != nil {
			return e
		}
	}
	r, e = c.receive(opClientPlan)
	if e != nil {
		return e
	}
	plan, e := decodeWorkload(r, priv.truth.arena)
	if e != nil {
		return e
	}
	if plan.topology != cfg.topology {
		return fail(ReasonIPC)
	}
	if cfg.topology == 2 && (len(plan.contact) != 0 || plan.route[2] != cfg.mailbox) {
		return fail(ReasonIPC)
	}
	priv.side, priv.route = plan.side, plan.route
	profile, boundary := boundaryProfileFor(cfg.settings.ControlProfile)
	if boundary && (cfg.topology != 2 || plan.side > 1 || plan.route != profile.routes[plan.side] || len(plan.bodies) != profile.sourceCount) {
		return fail(ReasonIPC)
	}
	plan.defaultsControl = cfg.settings.KeepaliveNS == 30000000000
	if !boundary && (plan.defaultsControl && len(plan.bodies) != 100 || !plan.defaultsControl && len(plan.bodies) != 0 && len(plan.bodies) != 1) {
		return fail(ReasonIPC)
	}
	path := []int{int(plan.route[0]), int(plan.route[1]), int(plan.route[2])}
	var verdict client.MirrorVerdict
	if cfg.topology == 2 {
		verdict, _, _ = view.JudgeTo(path[0], int(cfg.mailbox), 3, int(cfg.missing))
	} else {
		verdict, _, _ = view.Judge(path[0], 3, int(cfg.missing))
	}
	counts := Counts{Planned: 1, Attempted: 1}
	if verdict != client.MirrorTaken {
		counts.Refused = 1
		w = encoder{}
		w.u8(2)
		w.bool(false)
		if e := c.status.send(opReady, w); e != nil {
			return e
		}
		if e := c.errorStatus(ReasonRefused); e != nil {
			return e
		}
		return clientRefused(c, priv, counts, cleanup, ReasonRefused)
	}
	var drawn []int
	var entropy io.Reader = rand.Reader
	if view.Holds(path) {
		entropy = prescribedChoiceReader(view.Usable(), path, cfg.topology == 2)
	}
	if cfg.topology == 2 {
		drawn, e = view.DrawTo(path[0], int(cfg.mailbox), 3, entropy)
	} else {
		drawn, e = view.Draw(path[0], 3, entropy)
	}
	if e != nil {
		return semanticFailure(e, ReasonEnrollment)
	}
	if len(drawn) != 3 {
		return fail(ReasonEnrollment)
	}
	path = drawn
	for i, n := range path {
		priv.route[i] = uint8(n)
	}
	cc := client.Config{Provider: op, Chain: view.Chain(drawn), Dial: ownedDial(ports, nil), DialTimeout: 5 * time.Second, HandshakeTimeout: 5 * time.Second}
	if cfg.topology == 1 && cfg.settings.RateNS > 0 {
		cc.Mode = client.ConstantRate
		cc.Rate = time.Duration(cfg.settings.RateNS)
	}
	circuit, initialGeneration, e = dialObservedClient(cc, priv)
	if e != nil {
		return initialClientFailure(c, priv, counts, cleanup, e)
	}
	defer circuit.Close()
	receipt.InitialCircuitCreated = true
	if e = c.cancelledAt(initClientCircuit); e != nil {
		return e
	}
	var preflight []byte
	defer func() { secmem.Zero(preflight) }()
	if cfg.topology == 1 {
		var b [128]byte
		defer clear(b[:])
		if _, e = rand.Read(b[:]); e != nil {
			return fail(ReasonChild)
		}
		preflight = append([]byte(nil), b[:]...)
		clear(b[:])
	} else {
		req := mailbox.Request{Tag: 65535}
		copy(req.Fetch[:], fetch.Bytes())
		preflight = req.Bytes()
		clear(req.Fetch[:])
	}
	if e = authenticatedPreflight(circuit, preflight, cfg.topology == 2, 5*time.Second); e != nil {
		return e
	}
	counts.Established, counts.PreflightOK = 1, 1
	if e := c.ready(2); e != nil {
		return e
	}
	orphan := false
	var peerCard e2e.Card
	var boundaryState boundaryClientState
	var boundaryResponder bool
	if cfg.topology == 2 {
		r, e := c.receive(opContact)
		if e != nil {
			return e
		}
		n := r.u16()
		if n == 1 {
			raw := r.bytes(2048)
			peerCard, e = e2e.DecodeCard(raw)
			if e != nil || len(raw) == 0 || peerCard.Mailbox != loopback(cfg.roster[cfg.mailbox].port) {
				return fail(ReasonIPC)
			}
		} else if n == 0 {
			if !validOrphanChild(cfg, view, plan) {
				return fail(ReasonIPC)
			}
			orphan = true
		} else {
			return fail(ReasonIPC)
		}
		if r.end() != nil {
			return fail(ReasonIPC)
		}
		gate := make(chan struct{})
		adapter := &observedCircuit{Circuit: circuit, private: priv, gate: gate, conversation: &conv, generation: initialGeneration}
		cs := cfg.settings
		if boundary {
			cs, boundaryResponder, e = boundaryClientSettings(cs, plan.side, identity.Card(), peerCard)
			if e != nil {
				return e
			}
			boundaryState.initial, boundaryState.current = initialGeneration, initialGeneration
		}
		dial := func() (conversation.Circuit, error) {
			next, generation, e := dialObservedClient(cc, priv)
			if e != nil {
				return nil, e
			}
			boundaryState.mu.Lock()
			boundaryState.current = generation
			boundaryState.mu.Unlock()
			return &observedCircuit{Circuit: next, private: priv, gate: gate, conversation: &conv, generation: generation}, nil
		}
		conv, e = conversation.Start(conversation.Config{Provider: op, Self: identity, Fetch: fetch, First: adapter, Dial: dial, Rate: time.Duration(cs.RateNS), CoverPuts: cs.CoverPuts, Window: cs.Window, ReplyTimeout: time.Duration(cs.ReplyTimeoutNS), Keepalive: time.Duration(cs.KeepaliveNS), StaleAfter: time.Duration(cs.StaleAfterNS), RebuildFor: time.Duration(cs.RebuildForNS), MaxRefusals: cs.MaxRefusals, Outbox: cs.Outbox, Hold: cs.Hold, Inbox: cs.Inbox, Session: e2e.Options{StaleFetches: cs.StaleFetches}, Events: boundaryState.event})
		if e != nil {
			close(gate)
			return fail(ReasonSetup)
		}
		close(gate)
		receipt.ConversationCreated = true
		defer func() { conv.Close(); receipt.ConversationClosed = true }()
		if e = c.cancelledAt(initClientConversation); e != nil {
			return e
		}
		delayedPair := boundary && !profile.pairedBeforeBegin
		if !orphan && !delayedPair && conv.Pair(peerCard) != nil {
			return fail(ReasonSetup)
		}
		if !orphan && !delayedPair {
			deadline := time.NewTimer(30 * time.Second)
			tick := time.NewTicker(10 * time.Millisecond)
			ready := false
			for !ready {
				select {
				case <-deadline.C:
					tick.Stop()
					return fail(ReasonSetup)
				case <-conv.Done():
					deadline.Stop()
					tick.Stop()
					return fail(ReasonBroken)
				case <-tick.C:
					st := conv.Stats()
					ready = st.State == e2e.StateConfirmed || st.State == e2e.StateEstablished && st.Session.DummiesReceived > 0
				}
			}
			deadline.Stop()
			tick.Stop()
			if e := c.ready(3); e != nil {
				return e
			}
		}
	}
	r, e = c.receive(opBegin)
	if e != nil {
		return e
	}
	epoch, duration, cutoff := r.i64(), r.i64(), r.i64()
	if r.end() != nil || duration != cfg.settings.DurationNS || cutoff != epoch+duration {
		return fail(ReasonIPC)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if boundary && profile.actions[plan.side] == boundaryCloseBeforeEpoch {
		conv.Close()
		circuit.Close()
		if monotonicNS() >= epoch {
			return fail(ReasonIncomplete)
		}
	}
	workDone := make(chan error, 1)
	readDone := make(chan struct{})
	observer = &observerLifetime{cancel: cancel, close: func() {
		if conv != nil {
			conv.Close()
			receipt.ConversationClosed = true
		}
		circuit.Close()
		receipt.InitialCircuitClosed = true
	}, workDone: workDone, readDone: readDone}
	receipt.ObserverStarted = true
	terminalComplete := false
	defer func() {
		workErr := observer.join()
		receipt.ObserverJoined = true
		if !terminalComplete && workErr != nil && reasonOf(workErr) != ReasonCancelled {
			err = mergeChildFailure(c, err, workErr)
		}
	}()
	go func() {
		if boundary {
			workDone <- boundaryWorkload(ctx, c, conv, circuit, &boundaryState, peerCard, priv, plan, profile, epoch, cutoff)
			return
		}
		if orphan {
			select {
			case <-ctx.Done():
				workDone <- nil
			case <-conv.Done():
				if ctx.Err() != nil {
					workDone <- nil
				} else {
					workDone <- fail(ReasonBroken)
				}
			}
			return
		}
		if conv == nil {
			workDone <- echoWorkload(ctx, circuit, priv, plan, epoch, cutoff, plan.structural)
		} else {
			workDone <- peerWorkload(ctx, conv, priv, plan, epoch, cutoff, plan.structural)
		}
	}()
	go func() {
		defer close(readDone)
		if conv == nil && plan.structural {
			<-ctx.Done()
			return
		}
		if conv == nil {
			for {
				select {
				case <-ctx.Done():
					return
				case body, ok := <-circuit.Replies():
					if !ok {
						return
					}
					markReply(priv, body)
					secmem.Zero(body)
				}
			}
		} else {
			for {
				select {
				case <-ctx.Done():
					return
				case body, ok := <-conv.Messages():
					if !ok {
						return
					}
					markPeerReply(priv, body)
					secmem.Zero(body)
				}
			}
		}
	}()
	if e = c.cancelledAt(initClientObservers); e != nil {
		return e
	}
	r, e = c.receive(opStop)
	if e != nil {
		return e
	}
	if r.u8() > 2 || r.end() != nil {
		return fail(ReasonIPC)
	}
	cancel()
	if boundary {
		st := conv.Stats()
		counts.Rebuilt = st.Rebuilds
		if e = checkBoundaryClient(cfg.settings.ControlProfile, plan.side, boundaryResponder, st, priv, epoch, cutoff, &boundaryState); e != nil {
			err = e
		}
	} else if conv != nil {
		counts.Rebuilt = conv.Stats().Rebuilds
	}
	if e = observer.join(); e != nil && reasonOf(e) != ReasonCancelled {
		err = mergeChildFailure(c, err, e)
	}
	priv.mu.Lock()
	priv.frozen = true
	for _, m := range priv.truth.messages {
		if m.sent {
			counts.MessageBearing = 1
		}
		if m.sent && !m.replied {
			counts.Unanswered++
		}
	}
	if priv.err != ReasonNone {
		err = mergeChildFailure(c, err, fail(priv.err))
	}
	priv.mu.Unlock()
	if e = sendTruth(c, &priv.truth); e != nil {
		return e
	}
	if e = c.terminal(counts, reasonOf(err)); e != nil {
		return e
	}
	priv.truth.close()
	if conv != nil {
		conv.Close()
	}
	if identity != nil {
		identity.Close()
	}
	if fetch != nil {
		fetch.Release()
	}
	cleanup()
	if e = c.cleaned(); e != nil {
		return e
	}
	terminalComplete = true
	return nil
}

func mergeChildFailure(c *childIO, current, next error) error {
	result := mergeRuntimeFailure(current, next)
	if current != nil && next != nil && reasonOf(current) != reasonOf(next) {
		for _, cause := range []error{current, next} {
			if e := c.errorStatus(reasonOf(cause)); e != nil {
				result = mergeRuntimeFailure(result, semanticFailure(e, ReasonIPC))
			}
		}
	}
	return result
}

func validOrphanChild(cfg applicationConfig, view verify.View, plan workloadPlan) bool {
	if cfg.topology != 2 || cfg.mailbox != 4 || cfg.missing < 1 || cfg.missing > 2 || cfg.settings != peerSettings(false, 0) || plan.side != 3 || plan.route != [3]uint8{1, 0, 4} || !errors.Is(view.Missing(0), pki.ErrUnknownCA) {
		return false
	}
	for i := 1; i < 5; i++ {
		if view.Missing(i) != nil {
			return false
		}
	}
	verdict, _, _ := view.JudgeTo(1, 4, 3, int(cfg.missing))
	return verdict == client.MirrorTaken
}

func markReply(p *privateCapture, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.truth.messages {
		if equalBytes(p.truth.arena.bytes(p.truth.messages[i].body), body) {
			p.truth.messages[i].replied = true
			return
		}
	}
	p.err = ReasonLabel
}

func dialObservedClient(cfg client.Config, p *privateCapture) (*client.Client, uint32, error) {
	mark := p.constructionMark()
	c, e := client.Dial(cfg)
	if e != nil {
		return nil, 0, e
	}
	group, _, e := p.completedSince(mark)
	if e != nil {
		c.Close()
		return nil, 0, e
	}
	return c, group, nil
}

func prescribedChoiceReader(usable []bool, path []int, peer bool) io.Reader {
	others := make([]int, 0, len(usable))
	for i, ok := range usable {
		if ok && i != path[0] && (!peer || i != path[2]) {
			others = append(others, i)
		}
	}
	var b []byte
	limit := len(path) - 1
	if peer {
		limit--
	}
	for step := range limit {
		at := -1
		for i := step; i < len(others); i++ {
			if others[i] == path[step+1] {
				at = i
				break
			}
		}
		if at < 0 {
			return bytes.NewReader(nil)
		}
		bound := uint64(len(others) - step)
		v := uint64(at - step)
		reject := -bound % bound
		for v < reject {
			v += bound
		}
		b = binary.BigEndian.AppendUint64(b, v)
		others[step], others[at] = others[at], others[step]
	}
	return bytes.NewReader(b)
}
func markPeerReply(p *privateCapture, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(body) != 128 || len(p.truth.messages) >= maxMessages {
		p.err = ReasonLabel
		return
	}
	r, ok := p.truth.arena.copy(body)
	if !ok {
		p.err = ReasonLimit
		return
	}
	p.truth.messages = append(p.truth.messages, actualMessage{side: p.side, body: r, replied: true})
}
func initialClientFailure(c *childIO, p *privateCapture, counts Counts, cleanup func(), cause error) error {
	counts.SetupFailed = 1
	cause = semanticFailure(cause, ReasonSetup)
	w := encoder{}
	w.u8(2)
	w.bool(false)
	if e := c.status.send(opReady, w); e != nil {
		return mergeChildFailure(c, cause, e)
	}
	if e := c.errorStatus(reasonOf(cause)); e != nil {
		return mergeChildFailure(c, cause, e)
	}
	return clientRefused(c, p, counts, cleanup, reasonOf(cause))
}

func clientRefused(c *childIO, p *privateCapture, counts Counts, cleanup func(), reason Reason) error {
	op, r, e := c.command.next()
	if e != nil {
		return semanticFailure(e, ReasonIPC)
	}
	if op == opBegin {
		_ = r.i64()
		_ = r.i64()
		_ = r.i64()
		if r.end() != nil {
			return fail(ReasonIPC)
		}
		op, r, e = c.command.next()
		if e != nil {
			return semanticFailure(e, ReasonIPC)
		}
	}
	if op != opStop || r.u8() > 2 || r.end() != nil {
		return fail(ReasonIPC)
	}
	if e = sendTruth(c, &p.truth); e != nil {
		return e
	}
	if e = c.terminal(counts, reason); e != nil {
		return e
	}
	p.truth.close()
	cleanup()
	return c.cleaned()
}

func peerWorkload(ctx context.Context, c *conversation.Conversation, p *privateCapture, w workloadPlan, epoch, cutoff int64, structural bool) error {
	if e := waitUntil(ctx, epoch); e != nil {
		return e
	}
	count := 0
	if w.defaultsControl {
		if len(w.bodies) != 100 {
			return fail(ReasonIPC)
		}
		for i, offset := range defaultsOffsets() {
			if e := waitUntil(ctx, epoch+offset); e != nil {
				return e
			}
			p.mu.Lock()
			p.truth.messages = append(p.truth.messages, actualMessage{side: p.side, body: w.bodies[i]})
			index := len(p.truth.messages) - 1
			e := c.Send(p.truth.arena.bytes(w.bodies[i]))
			p.truth.messages[index].sent = e == nil
			p.mu.Unlock()
			if e != nil {
				return semanticFailure(e, ReasonBroken)
			}
		}
		return nil
	}
	for _, segment := range [][2]int64{{0, 10000000000}, {20000000000, 30000000000}} {
		rng := newGapRand(w.gapSeed, segment[0])
		next := epoch + segment[0]
		end := min(cutoff, epoch+segment[1])
		for next < end {
			if count >= 128 {
				return fail(ReasonLimit)
			}
			if e := waitUntil(ctx, next); e != nil {
				return e
			}
			p.mu.Lock()
			i, e := -1, error(nil)
			if structural && len(w.bodies) == 1 {
				p.truth.messages = append(p.truth.messages, actualMessage{side: p.side, body: w.bodies[0]})
				i = len(p.truth.messages) - 1
			} else {
				i, e = randomMessage(&p.truth, p.side)
			}
			if e == nil {
				e = c.Send(p.truth.arena.bytes(p.truth.messages[i].body))
				p.truth.messages[i].sent = e == nil
			}
			p.mu.Unlock()
			if e != nil {
				return semanticFailure(e, ReasonBroken)
			}
			count++
			if structural {
				return nil
			}
			next += int64(rng.ExpFloat64() * float64(200*time.Millisecond))
		}
	}
	return nil
}
