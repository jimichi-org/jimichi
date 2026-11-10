//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"golang.org/x/sys/unix"
)

type childIO struct {
	afterCleanup        func(childCleanupReceipt)
	cancelInit          func(childInitStage) bool
	command             *protocolReader
	status, view, truth *protocolWriter
	files               [4]*os.File
	role                byte
	suite               jcrypto.Suite
}

type childInitStage byte

const (
	initRelayListener childInitStage = iota + 1
	initRelayCollector
	initRelayIdentity
	initRelayLink
	initRelayOnion
	initRelayRing
	initRelayNode
	initRelayServe
	initClientPrivate
	initClientFetch
	initClientIdentity
	initClientCircuit
	initClientConversation
	initClientObservers
)

func (c *childIO) cancelledAt(stage childInitStage) error {
	if c.cancelInit != nil && c.cancelInit(stage) {
		return fail(ReasonCancelled)
	}
	return nil
}

type childCleanupReceipt struct {
	IdentityCreated, IdentityReleased           bool
	LinkCreated, LinkReleased                   bool
	OnionCreated, OnionReleased                 bool
	FetchCreated, FetchReleased                 bool
	PrivateCreated, PrivateClosed               bool
	CollectorCreated, CollectorClosed           bool
	ListenerCreated, ListenerClosed             bool
	ObserverStarted, ObserverJoined             bool
	ServeStarted, ServeJoined                   bool
	RingCreated, RingClosed                     bool
	NodeCreated, NodeClosed                     bool
	ConversationCreated, ConversationClosed     bool
	InitialCircuitCreated, InitialCircuitClosed bool
}

func MaybeRunChild(args []string) (handled bool, code int) {
	private := false
	for _, a := range args {
		if strings.HasPrefix(a, "--nodeview-child-v1") {
			private = true
		}
	}
	if !private {
		return false, 0
	}
	if len(args) != 1 {
		return true, 2
	}
	role := byte(0)
	for i, name := range roleNames {
		if args[0] == "--nodeview-child-v1="+name && i != 0 {
			role = byte(i)
		}
	}
	if role == 0 || os.Getenv("JIMICHI_NODEVIEW_V1") != "1" {
		return true, 2
	}
	tokenText := os.Getenv("JIMICHI_NODEVIEW_TOKEN")
	if len(tokenText) != 32 || strings.ToLower(tokenText) != tokenText {
		return true, 2
	}
	raw, e := hex.DecodeString(tokenText)
	if e != nil {
		return true, 2
	}
	var token [16]byte
	copy(token[:], raw)
	s, e := suite.Parse(os.Getenv("JIMICHI_NODEVIEW_SUITE"))
	if e != nil {
		return true, 2
	}
	c := &childIO{role: role, suite: s}
	for i := range c.files {
		if unix.SetNonblock(3+i, true) != nil {
			return true, 2
		}
		c.files[i] = os.NewFile(uintptr(3+i), "nodeview")
		if c.files[i] == nil || validatePipe(c.files[i], i != 0) != nil {
			return true, 2
		}
		defer c.files[i].Close()
	}
	defer func() {
		if recover() != nil {
			handled = true
			code = 1
		}
	}()
	need := clientArenaBytes
	if role == roleRelay {
		need = relayArenaBytes
	} else if role >= roleScorer {
		need = controllerArenaBytes
	}
	if protectProcess(need) != nil {
		return true, 3
	}
	c.command, e = newProtocolReader(c.files[0], token, controllerArenaBytes)
	if e != nil {
		return true, 3
	}
	defer c.command.close()
	c.status = &protocolWriter{w: c.files[1], token: token, limit: 1 << 20}
	c.view = &protocolWriter{w: c.files[2], token: token, limit: relayArenaBytes}
	c.truth = &protocolWriter{w: c.files[3], token: token, limit: clientArenaBytes}
	if role == roleRelay {
		c.truth.limit = relayArenaBytes
	}
	var err error
	switch role {
	case roleRelay:
		err = relayChild(c)
	case roleClient:
		err = clientChild(c)
	case roleScorer:
		err = scorerChild(c)
	case roleTrainer, roleFitAuditor:
		err = trainingChild(c)
	}
	if err != nil {
		w := encoder{}
		w.u8(reasonByte(reasonOf(err)))
		_ = c.status.send(opError, w)
		return true, 1
	}
	return true, 0
}

func reasonByte(r Reason) byte {
	for i, v := range reasons {
		if v == r {
			return byte(i)
		}
	}
	return byte(ReasonIndexIncomplete)
}

const ReasonIndexIncomplete = 21

func decodeReason(r *decoder) Reason {
	v := int(r.u8())
	if v >= len(reasons) {
		r.bad = true
		return ReasonIPC
	}
	return reasons[v]
}

func (c *childIO) receive(want byte) (*decoder, error) {
	op, r, e := c.command.next()
	if e != nil {
		return nil, semanticFailure(e, ReasonIPC)
	}
	if op != want {
		return nil, fail(ReasonIPC)
	}
	return r, nil
}
func (c *childIO) ready(kind byte) error {
	w := encoder{}
	w.u8(kind)
	w.bool(true)
	return c.status.send(opReady, w)
}
func (c *childIO) errorStatus(reason Reason) error {
	w := encoder{}
	w.u8(reasonByte(reason))
	return c.status.send(opError, w)
}
func (c *childIO) terminal(counts Counts, reason Reason) error {
	w := encoder{}
	status := byte(0)
	if reason != ReasonNone {
		status = 1
	}
	w.u8(status)
	w.u8(reasonByte(reason))
	w.u64(c.status.frames + 1)
	w.u64(c.view.frames)
	w.u64(c.truth.frames)
	encodeCounts(&w, counts)
	if e := c.status.send(opEnd, w); e != nil {
		return e
	}
	r, e := c.receive(opAck)
	if e != nil {
		return e
	}
	status = r.u8()
	if r.end() != nil || status != 0 {
		return fail(ReasonIPC)
	}
	return nil
}
func (c *childIO) cleaned() error {
	w := encoder{}
	w.bool(true)
	w.bool(true)
	if e := c.status.send(opCleaned, w); e != nil {
		return e
	}
	var b [1]byte
	n, e := c.files[0].Read(b[:])
	if n != 0 || e != io.EOF {
		return fail(ReasonIPC)
	}
	return nil
}

type publicRelay struct {
	port   uint16
	bundle []byte
}
type applicationConfig struct {
	suite    jcrypto.Suite
	topology byte
	auth     bool
	missing  uint8
	anchor   pki.Anchor
	roster   []publicRelay
	mailbox  uint8
	selected bool
	settings Settings
}

func decodeApplication(r *decoder) (applicationConfig, error) {
	c := applicationConfig{suite: jcrypto.Suite(r.u8()), topology: r.u8(), auth: r.bool(), missing: r.u8()}
	a, e := pki.ParseAnchor(r.ascii(256))
	if e != nil {
		return c, fail(ReasonIPC)
	}
	c.anchor = a
	n := int(r.u16())
	if n != 5 {
		return c, fail(ReasonIPC)
	}
	seen := map[uint16]bool{}
	for range n {
		port := r.u16()
		b := bytes.Clone(r.bytes(4096))
		if port == 0 || seen[port] || len(b) == 0 {
			return c, fail(ReasonIPC)
		}
		seen[port] = true
		c.roster = append(c.roster, publicRelay{port, b})
	}
	c.mailbox = r.u8()
	c.selected = r.bool()
	c.settings = decodeSettings(r)
	if r.end() != nil || !c.auth || c.missing > 2 || c.topology < 1 || c.topology > 2 || c.anchor.Suite != c.suite || c.settings.validate(c.topology == 2) != nil || c.topology == 2 && c.mailbox >= 5 || c.topology == 1 && c.mailbox != 255 {
		return c, fail(ReasonIPC)
	}
	if c.settings.ControlProfile != 0 && (c.topology != 2 || c.mailbox != 4 || c.missing != 2) {
		return c, fail(ReasonIPC)
	}
	return c, nil
}
func encodeApplication(c applicationConfig, budgets ...*memoryBudget) encoder {
	w := encoder{}
	if len(budgets) > 0 {
		w.budget = budgets[0]
	}
	w.u8(byte(c.suite))
	w.u8(c.topology)
	w.bool(c.auth)
	w.u8(c.missing)
	w.ascii(c.anchor.String(), 256)
	w.u16(uint16(len(c.roster)))
	for _, r := range c.roster {
		w.u16(r.port)
		w.bytes(r.bundle, 4096)
	}
	w.u8(c.mailbox)
	w.bool(c.selected)
	encodeSettings(&w, c.settings)
	return w
}
func policy(anchor pki.Anchor) pki.Policy {
	return pki.Policy{Anchor: anchor, Skew: pki.Skew, MaxLife: pki.MaxDescriptorLife, MinLife: 0}
}

func relayChild(c *childIO) (err error) {
	receipt := childCleanupReceipt{}
	defer func() {
		if c.afterCleanup != nil {
			c.afterCleanup(receipt)
		}
	}()
	p, e := suite.New(c.suite)
	if e != nil {
		return fail(ReasonEnrollment)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return fail(ReasonChild)
	}
	receipt.ListenerCreated = true
	defer func() { ln.Close(); receipt.ListenerClosed = true }()
	if e = c.cancelledAt(initRelayListener); e != nil {
		return e
	}
	port := addressPort([]byte(ln.Addr().String()))
	pubSize := p.HandshakeInfo().PublicKeySize
	col, e := newCollector(monotonicNS, false, pubSize)
	if e != nil {
		return e
	}
	receipt.CollectorCreated = true
	defer func() { col.close(); receipt.CollectorClosed = true }()
	if e = c.cancelledAt(initRelayCollector); e != nil {
		return e
	}
	op := &observedProvider{CryptoProvider: p, collector: col}
	w := encoder{}
	w.u8(roleRelay)
	w.u8(byte(c.suite))
	w.u16(port)
	w.u8(1)
	if e := c.status.send(opBoot, w); e != nil {
		return e
	}
	r, e := c.receive(opChallenge)
	if e != nil {
		return e
	}
	name := r.ascii(32)
	expectedPort := r.u16()
	var nonce [16]byte
	copy(nonce[:], r.take(16))
	anchor, e := pki.ParseAnchor(r.ascii(256))
	before, after := r.i64(), r.i64()
	ttl := r.i64()
	if r.end() != nil || e != nil || expectedPort != port || !pki.ValidName(name) || ttl != int64(10*time.Minute) || after-before != 3660 {
		return fail(ReasonIPC)
	}
	_ = anchor
	id, e := pki.NewIdentity(op, name, loopback(port))
	if e != nil {
		return fail(ReasonEnrollment)
	}
	receipt.IdentityCreated = true
	defer func() { id.Close(); receipt.IdentityReleased = true }()
	if e = c.cancelledAt(initRelayIdentity); e != nil {
		return e
	}
	linkPriv, linkPub, e := op.GenerateEphemeral()
	if e != nil {
		return fail(ReasonEnrollment)
	}
	receipt.LinkCreated = true
	defer func() { linkPriv.Release(); receipt.LinkReleased = true }()
	if e = c.cancelledAt(initRelayLink); e != nil {
		return e
	}
	onionPriv, onionPub, e := op.GenerateEphemeral()
	if e != nil {
		return fail(ReasonEnrollment)
	}
	ownedOnion := true
	receipt.OnionCreated = true
	defer func() {
		if ownedOnion {
			onionPriv.Release()
			receipt.OnionReleased = true
		}
	}()
	if e = c.cancelledAt(initRelayOnion); e != nil {
		return e
	}
	request, e := id.Request(nonce)
	clear(nonce[:])
	if e != nil {
		return fail(ReasonEnrollment)
	}
	w = encoder{}
	w.bytes(request, 1024)
	if e := c.status.send(opRequest, w); e != nil {
		return e
	}
	r, e = c.receive(opCertificate)
	if e != nil {
		return e
	}
	cert := r.bytes(2048)
	if r.end() != nil {
		return fail(ReasonIPC)
	}
	if id.Install(cert, time.Now()) != nil {
		return fail(ReasonEnrollment)
	}
	id.SetKeys(linkPub, onionPub, 0)
	if id.Refresh(time.Now(), time.Duration(ttl)) != nil {
		return fail(ReasonEnrollment)
	}
	bundle, ok := id.Bundle()
	if !ok {
		return fail(ReasonEnrollment)
	}
	w = encoder{}
	w.bytes(bundle, 4096)
	if e := c.status.send(opBundle, w); e != nil {
		return e
	}
	configureOp, r, e := c.command.next()
	if e != nil {
		return semanticFailure(e, ReasonIPC)
	}
	if configureOp == opStop {
		if r.u8() > 2 || r.end() != nil {
			return fail(ReasonIPC)
		}
		if e = c.terminal(Counts{}, ReasonNone); e != nil {
			return e
		}
		ln.Close()
		col.close()
		id.Close()
		linkPriv.Release()
		onionPriv.Release()
		receipt.OnionReleased = true
		ownedOnion = false
		return c.cleaned()
	}
	if configureOp != opConfigure {
		return fail(ReasonIPC)
	}
	cfg, e := decodeApplication(r)
	if e != nil {
		return e
	}
	if cfg.suite != c.suite || cfg.anchor.String() != anchor.String() {
		return fail(ReasonIPC)
	}
	col.peer = cfg.topology == 2
	peers := map[string]relay.Peer{}
	ports := map[uint16]bool{}
	now := time.Now()
	self := -1
	for i, node := range cfg.roster {
		addr := loopback(node.port)
		ports[node.port] = true
		if node.port == port {
			self = i
		}
		peer, e := verify.Peer(p, policy(cfg.anchor), addr, node.bundle, now)
		if e != nil {
			if cfg.settings.ControlProfile != 0 {
				return fail(ReasonEnrollment)
			}
			continue
		}
		v, e := pki.Verify(p, policy(cfg.anchor), addr, node.bundle, now)
		if e != nil {
			return fail(ReasonEnrollment)
		}
		record := verify.NewRecord(pki.Skew, 8*time.Minute)
		record.Hold(0)
		if conflict, ok := record.Take(node.bundle, v, now); conflict != nil || !ok {
			return fail(ReasonEnrollment)
		}
		peers[addr] = peer
	}
	if self < 0 {
		return fail(ReasonEnrollment)
	}
	if cfg.settings.ControlProfile != 0 && cfg.selected != (self == 4) {
		return fail(ReasonIPC)
	}
	col.view.position = uint8(self)
	ring, e := relay.NewOnionRing(op, onionPriv, onionPub, 0)
	if e != nil {
		return fail(ReasonEnrollment)
	}
	ownedOnion = false
	receipt.RingCreated = true
	defer func() { ring.Close(); receipt.OnionReleased = true; receipt.RingClosed = true }()
	if e = c.cancelledAt(initRelayRing); e != nil {
		return e
	}
	var store *mailbox.Store
	var sweepStop chan struct{}
	var sweepDone chan struct{}
	var sweepOnce sync.Once
	stopSweep := func() {
		sweepOnce.Do(func() {
			if sweepStop != nil {
				close(sweepStop)
				<-sweepDone
			}
		})
	}
	var deliver relay.Deliver
	if cfg.topology == 2 {
		limits := mailbox.DefaultLimits()
		if self == int(cfg.mailbox) {
			var ok bool
			limits, ok = boundaryProfileStoreLimits(cfg.settings.ControlProfile)
			if !ok {
				return fail(ReasonIPC)
			}
		}
		store, e = mailbox.NewStore(op, limits, time.Now)
		if e != nil {
			return fail(ReasonChild)
		}
		defer store.Close()
		sweepStop = make(chan struct{})
		sweepDone = make(chan struct{})
		go func() { store.Run(sweepStop); close(sweepDone) }()
		defer stopSweep()
		deliver = store.Deliver
	} else {
		deliver = func(_ uint64, b []byte) []byte { return b }
	}
	deliver = observeDeliver(col, p, deliver)
	rc := relay.Config{Provider: op, Addr: loopback(port), StaticPriv: linkPriv, StaticPub: linkPub, Identity: id.Public(), Onion: ring, Deliver: deliver, Period: time.Duration(cfg.settings.RelayPeriodNS), MaxHandshakes: 32, MaxLinks: 512, MaxHandshakesPerSource: -1, MaxLinksPerSource: -1, SourceLinkRate: -1, SourceSetupRate: -1, AllowAnonymous: false, Peers: func(addr string) (relay.Peer, bool) { peer, ok := peers[addr]; return peer, ok }, Dial: ownedDial(ports, col)}
	node, e := relay.New(rc)
	if e != nil {
		return fail(ReasonEnrollment)
	}
	receipt.NodeCreated = true
	defer func() { node.Close(); receipt.NodeClosed = true }()
	if e = c.cancelledAt(initRelayNode); e != nil {
		return e
	}
	baseline := relayStats(node.Stats().Snapshot())
	done := make(chan struct{})
	go func() { _ = node.Serve(observedListener{ln, col}); close(done) }()
	receipt.ServeStarted = true
	var serveOnce sync.Once
	stopServe := func() {
		serveOnce.Do(func() {
			node.Close()
			receipt.NodeClosed = true
			ln.Close()
			receipt.ListenerClosed = true
			<-done
			receipt.ServeJoined = true
		})
	}
	defer stopServe()
	if e = c.cancelledAt(initRelayServe); e != nil {
		return e
	}
	if e := c.ready(1); e != nil {
		return e
	}
	opcode, r, e := c.command.next()
	if e != nil {
		return semanticFailure(e, ReasonIPC)
	}
	if opcode == opBegin {
		epoch, duration, cutoff := r.i64(), r.i64(), r.i64()
		if r.end() != nil || epoch <= 0 || duration != cfg.settings.DurationNS || cutoff != epoch+duration {
			return fail(ReasonIPC)
		}
		col.begin(epoch, cutoff)
		opcode, r, e = c.command.next()
		if e != nil {
			return semanticFailure(e, ReasonIPC)
		}
	}
	if opcode != opStop || r.u8() > 2 || r.end() != nil {
		return fail(ReasonIPC)
	}
	col.mu.Lock()
	col.cleanup = true
	col.mu.Unlock()
	stopServe()
	if e = col.freeze(); e != nil {
		err = mergeChildFailure(c, err, e)
	}
	col.mu.Lock()
	for i := range col.view.connections {
		v := &col.view.connections[i]
		if v.authenticated {
			confirmedPort := v.selectorPort
			if v.initiator {
				confirmedPort = v.remotePort
			}
			for j, n := range cfg.roster {
				if n.port == confirmedPort && peers[loopback(n.port)].LinkPub != nil {
					v.peer = uint8(j)
				}
			}
		}
	}
	col.mu.Unlock()
	summary := processSummary{mask: 7}
	delta, deltaErr := checkedStatsDelta(baseline, relayStats(node.Stats().Snapshot()))
	if deltaErr != nil {
		summary.mask &^= 1
		err = mergeChildFailure(c, err, deltaErr)
	} else {
		copy(summary.values[:16], delta[:])
	}
	if col.observerValid {
		summary.values[16] = col.summary.Calls
		summary.values[17] = col.summary.CallbackNS
		summary.values[18] = col.summary.ArenaHighWater
		summary.values[19] = col.summary.ConnectionsHighWater
		summary.values[20] = col.summary.PendingHighWater
		summary.values[21] = col.summary.ContextsHighWater
		summary.values[22] = col.summary.CellsHighWater
	} else {
		summary.mask &^= 2
	}
	peak, rssErr := selfRSS()
	if rssErr != nil {
		summary.mask &^= 4
		err = mergeChildFailure(c, err, rssErr)
	} else {
		summary.values[23] = peak
	}
	if cfg.selected {
		if _, e = selectedStreamSize(col.view, len(col.transports), true); e != nil {
			return e
		}
	}
	if e = c.view.send(opView, encodeProcessSummary(summary)); e != nil {
		return e
	}
	if cfg.selected {
		if e = sendView(c, col); e != nil {
			return e
		}
		if e = sendFragments(c, col); e != nil {
			return e
		}
	}
	counts := Counts{LocalProcessed: uint64(len(col.view.cells))}
	for _, v := range col.view.cells {
		if v.stages&stageSealed != 0 {
			counts.TransportSealed++
		}
		if v.stages&stageWritten != 0 {
			counts.WriteComplete++
		}
		if v.terminal == terminalNoWrite {
			counts.TerminalUnwritten++
		}
		if v.terminal == terminalCutoff {
			counts.CutoffCensored++
		}
	}
	counts.Released = uint64(len(col.view.releases))
	if e = c.terminal(counts, reasonOf(err)); e != nil {
		return e
	}
	col.close()
	node.Close()
	ring.Close()
	id.Close()
	linkPriv.Release()
	stopSweep()
	if store != nil {
		store.Close()
	}
	if e = c.cleaned(); e != nil {
		return e
	}
	return nil
}

func relayStats(s relay.Counters) [16]uint64 {
	return [16]uint64{s.Accepted, s.Forwarded, s.Delivered, s.Dropped, s.Padding, s.Broken, s.AcceptRetries, s.RefusedLinks, s.RefusedBusy, s.RefusedSource, s.RefusedRate, s.RefusedSetups, s.RefusedExtend, s.FailedExtend, s.TimedOut, s.Expired}
}

func waitUntil(ctx context.Context, ns int64) error {
	now := monotonicNS()
	if now <= 0 || ns <= 0 {
		return fail(ReasonClock)
	}
	d := time.Duration(ns - now)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fail(ReasonCancelled)
	case <-t.C:
		return nil
	}
}
func envToken(token [16]byte, s jcrypto.Suite) []string {
	return []string{"PATH=" + os.Getenv("PATH"), "JIMICHI_NODEVIEW_V1=1", "JIMICHI_NODEVIEW_TOKEN=" + hex.EncodeToString(token[:]), "JIMICHI_NODEVIEW_SUITE=" + s.String(), "GOTRACEBACK=none", "GOMAXPROCS=" + strconv.Itoa(2)}
}
