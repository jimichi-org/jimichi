//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

type actorTranscript struct {
	child    *childIO
	writer   *protocolWriter
	command  *os.File
	files    []*os.File
	status   chan statusFrame
	done     chan struct{}
	joined   chan struct{}
	err      error
	receipts []childCleanupReceipt
}

func newActorTranscript(t *testing.T, s jcrypto.Suite, role byte, configure ...func(*childIO)) *actorTranscript {
	t.Helper()
	a := &actorTranscript{child: &childIO{suite: s, role: role}, status: make(chan statusFrame, 64), done: make(chan struct{}), joined: make(chan struct{})}
	token := [16]byte{11, 17, 23, role, byte(s)}
	var parent [4]*os.File
	for i := range 4 {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		a.files = append(a.files, r, w)
		if i == 0 {
			a.child.files[i], parent[i] = r, w
		} else {
			a.child.files[i], parent[i] = w, r
		}
	}
	a.command = parent[0]
	a.writer = &protocolWriter{w: a.command, token: token, limit: 1 << 20}
	reader, e := newProtocolReader(a.child.files[0], token, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	a.child.command = reader
	a.child.status = &protocolWriter{w: a.child.files[1], token: token, limit: 1 << 20}
	a.child.view = &protocolWriter{w: a.child.files[2], token: token, limit: relayArenaBytes}
	a.child.truth = &protocolWriter{w: a.child.files[3], token: token, limit: relayArenaBytes}
	a.child.afterCleanup = func(receipt childCleanupReceipt) { a.receipts = append(a.receipts, receipt) }
	for _, setup := range configure {
		setup(a.child)
	}
	status, e := newProtocolReader(parent[1], token, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	var readers sync.WaitGroup
	readers.Add(3)
	go func() {
		defer readers.Done()
		defer status.close()
		for {
			op, r, e := status.next()
			frame := statusFrame{op: op, err: e}
			if e == nil {
				frame.body = bytes.Clone(r.b)
			}
			a.status <- frame
			if e != nil {
				return
			}
		}
	}()
	for _, file := range parent[2:] {
		go func(file *os.File) {
			defer readers.Done()
			_, _ = io.Copy(io.Discard, file)
		}(file)
	}
	go func() { readers.Wait(); close(a.joined) }()
	go func() {
		if role == roleRelay {
			a.err = relayChild(a.child)
		} else {
			a.err = clientChild(a.child)
		}
		reader.close()
		for _, file := range a.child.files {
			file.Close()
		}
		close(a.done)
	}()
	t.Cleanup(func() {
		a.command.Close()
		for _, file := range a.files {
			file.Close()
		}
		select {
		case <-a.done:
		case <-time.After(10 * time.Second):
			t.Error("participant did not terminate after owned pipe close")
		}
		select {
		case <-a.joined:
		case <-time.After(10 * time.Second):
			t.Error("participant transcript readers did not join")
		}
	})
	return a
}

func (a *actorTranscript) next(t *testing.T, want byte) *decoder {
	t.Helper()
	select {
	case frame := <-a.status:
		if frame.err != nil || frame.op != want {
			t.Fatalf("actor status: opcode %d, want %d, error %v", frame.op, want, frame.err)
		}
		t.Cleanup(func() { clear(frame.body) })
		return &decoder{b: frame.body}
	case <-time.After(10 * time.Second):
		t.Fatalf("actor status %d did not arrive", want)
		return nil
	}
}

func (a *actorTranscript) send(t *testing.T, opcode byte, body encoder) {
	t.Helper()
	if e := a.writer.send(opcode, body); e != nil {
		t.Fatal(e)
	}
}

func (a *actorTranscript) boot(t *testing.T) uint16 {
	t.Helper()
	r := a.next(t, opBoot)
	role, s, port, version := r.u8(), jcrypto.Suite(r.u8()), r.u16(), r.u8()
	if r.end() != nil || role != a.child.role || s != a.child.suite || version != 1 || (role == roleRelay) != (port != 0) {
		t.Fatal("actor boot contract changed")
	}
	return port
}

func (a *actorTranscript) ready(t *testing.T, kind byte) {
	t.Helper()
	r := a.next(t, opReady)
	if r.u8() != kind || !r.bool() || r.end() != nil {
		t.Fatalf("actor ready %d did not succeed", kind)
	}
}

func (a *actorTranscript) failed(t *testing.T, want Reason) childCleanupReceipt {
	t.Helper()
	select {
	case <-a.done:
	case <-time.After(10 * time.Second):
		t.Fatal("failed actor retained its state owner")
	}
	if reasonOf(a.err) != want {
		t.Fatalf("actor failure: %v, want %s", a.err, want)
	}
	select {
	case <-a.joined:
	case <-time.After(10 * time.Second):
		t.Fatal("failed actor left an unjoined transcript reader")
	}
	for {
		frame := <-a.status
		if frame.err != nil {
			if frame.err != io.EOF {
				t.Fatalf("actor output did not end cleanly: %v", frame.err)
			}
			break
		}
		clear(frame.body)
		if frame.op == opReady || frame.op == opContact || frame.op == opEnd || frame.op == opCleaned {
			t.Fatal("failed actor reported a later successful state")
		}
	}
	if len(a.receipts) != 1 {
		t.Fatal("actor cleanup did not complete exactly once")
	}
	return a.receipts[0]
}

func assertActorCleanup(t *testing.T, r childCleanupReceipt, identity, fetch, observer bool) {
	t.Helper()
	if r.IdentityCreated != identity || r.FetchCreated != fetch || r.ObserverStarted != observer {
		t.Fatal("participant creation stage disagrees with its actual transcript")
	}
	assertActorReleased(t, r)
	if r.ListenerCreated && (!r.CollectorCreated || r.LinkCreated != identity || r.OnionCreated != identity || r.FetchCreated || r.PrivateCreated) {
		t.Fatal("relay partial initialization ownership changed")
	}
	if identity && !r.ListenerCreated && (!r.PrivateCreated || r.LinkCreated || r.OnionCreated) {
		t.Fatal("client initialized without a private owner or acquired relay keys")
	}
}

func assertActorReleased(t *testing.T, r childCleanupReceipt) {
	t.Helper()
	for _, pair := range [][2]bool{
		{r.IdentityCreated, r.IdentityReleased},
		{r.LinkCreated, r.LinkReleased},
		{r.OnionCreated, r.OnionReleased},
		{r.FetchCreated, r.FetchReleased},
		{r.PrivateCreated, r.PrivateClosed},
		{r.CollectorCreated, r.CollectorClosed},
		{r.ListenerCreated, r.ListenerClosed},
		{r.ObserverStarted, r.ObserverJoined},
		{r.ServeStarted, r.ServeJoined},
		{r.InitialCircuitCreated, r.InitialCircuitClosed},
		{r.RingCreated, r.RingClosed},
		{r.NodeCreated, r.NodeClosed},
		{r.ConversationCreated, r.ConversationClosed},
	} {
		if pair[0] != pair[1] {
			t.Fatal("participant retained an initialized resource after definitive return")
		}
	}
}

func actorAuthority(t *testing.T, s jcrypto.Suite) (jcrypto.CryptoProvider, *pki.CA) {
	t.Helper()
	p, e := suite.New(s)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := pki.NewCA(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(ca.Close)
	return p, ca
}

func actorChallenge(port uint16, nonce [16]byte, ca *pki.CA) encoder {
	now := time.Now()
	w := encoder{}
	w.ascii("actor-node", 32)
	w.u16(port)
	w.b = append(w.b, nonce[:]...)
	w.ascii(ca.Anchor().String(), 256)
	w.i64(now.Add(-time.Minute).Unix())
	w.i64(now.Add(time.Hour).Unix())
	w.i64(int64(10 * time.Minute))
	return w
}

func actorEnrollment(t *testing.T, a *actorTranscript, port uint16, p jcrypto.CryptoProvider, ca *pki.CA) *pki.Request {
	t.Helper()
	nonce := [16]byte{1, 2, 3, 5, 8, 13, 21}
	a.send(t, opChallenge, actorChallenge(port, nonce, ca))
	r := a.next(t, opRequest)
	request, e := pki.ParseRequest(r.bytes(1024))
	if e != nil || r.end() != nil || request.Check(p, nonce, "actor-node", loopback(port)) != nil {
		t.Fatal("actual relay request did not bind its challenged nonce and endpoint")
	}
	nonce[0] ^= 1
	if request.Check(p, nonce, "actor-node", loopback(port)) == nil || request.Check(p, request.Nonce, "other-node", loopback(port)) == nil || request.Check(p, request.Nonce, "actor-node", loopback(port^1)) == nil {
		t.Fatal("actual relay request accepted a foreign nonce or roster binding")
	}
	return request
}

func actorCertificate(t *testing.T, a *actorTranscript, request *pki.Request, ca *pki.CA) []byte {
	t.Helper()
	now := time.Now()
	cert, e := ca.Issue(request, now.Add(-time.Minute), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	w := encoder{}
	w.bytes(cert.Marshal(), 2048)
	a.send(t, opCertificate, w)
	r := a.next(t, opBundle)
	bundle := bytes.Clone(r.bytes(4096))
	if r.end() != nil {
		t.Fatal("actual relay bundle framing failed")
	}
	return bundle
}

func actorPublicRoster(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, ownPort uint16, ownBundle []byte) applicationConfig {
	t.Helper()
	cfg := applicationConfig{suite: p.Suite(), topology: 2, auth: true, missing: 2, anchor: ca.Anchor(), mailbox: 4, settings: peerSettings(false, 0)}
	for i := range 5 {
		if i == 0 && ownPort != 0 {
			cfg.roster = append(cfg.roster, publicRelay{ownPort, bytes.Clone(ownBundle)})
			continue
		}
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { listener.Close() })
		port := addressPort([]byte(listener.Addr().String()))
		id, e := pki.NewIdentity(p, "public-node"+decimal(i), loopback(port))
		if e != nil {
			t.Fatal(e)
		}
		defer id.Close()
		requestBytes, e := id.Request([16]byte{byte(i + 1)})
		if e != nil {
			t.Fatal(e)
		}
		request, e := pki.ParseRequest(requestBytes)
		if e != nil {
			t.Fatal(e)
		}
		cert, e := ca.Issue(request, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if e != nil || id.Install(cert.Marshal(), time.Now()) != nil {
			t.Fatal("public roster identity enrollment failed")
		}
		link, linkPublic, e := p.GenerateEphemeral()
		if e != nil {
			t.Fatal(e)
		}
		defer link.Release()
		onion, onionPublic, e := p.GenerateEphemeral()
		if e != nil {
			t.Fatal(e)
		}
		defer onion.Release()
		id.SetKeys(linkPublic, onionPublic, 0)
		if e := id.Refresh(time.Now(), 10*time.Minute); e != nil {
			t.Fatal(e)
		}
		bundle, ok := id.Bundle()
		if !ok {
			t.Fatal("public roster descriptor missing")
		}
		cfg.roster = append(cfg.roster, publicRelay{port, bundle})
	}
	return cfg
}

func exerciseActorEnrollmentFailures(t *testing.T, s jcrypto.Suite) {
	t.Helper()
	p, ca := actorAuthority(t, s)
	for _, state := range []string{"boot-eof", "challenge-port", "challenge-trailing", "request-eof", "certificate-opcode", "certificate-malformed", "certificate-trailing", "certificate-roster", "bundle-eof", "bundle-stop-malformed", "configure-suite", "configure-shape", "ready-eof", "ready-stop-malformed", "ready-begin-malformed"} {
		t.Logf("relay actor failure stage %s", state)
		a := newActorTranscript(t, s, roleRelay)
		port := a.boot(t)
		want := ReasonIPC
		switch state {
		case "boot-eof":
			a.command.Close()
		case "challenge-port", "challenge-trailing":
			w := actorChallenge(port, [16]byte{7}, ca)
			if state == "challenge-port" {
				w = actorChallenge(0, [16]byte{7}, ca)
			} else {
				w.u8(1)
			}
			a.send(t, opChallenge, w)
		default:
			request := actorEnrollment(t, a, port, p, ca)
			switch state {
			case "request-eof":
				a.command.Close()
			case "certificate-opcode":
				a.send(t, opChallenge, encoder{})
			case "certificate-malformed":
				w := encoder{}
				w.bytes([]byte{1, 2, 3}, 2048)
				a.send(t, opCertificate, w)
				want = ReasonEnrollment
			case "certificate-trailing":
				cert, e := ca.Issue(request, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				if e != nil {
					t.Fatal(e)
				}
				w := encoder{}
				w.bytes(cert.Marshal(), 2048)
				w.u8(1)
				a.send(t, opCertificate, w)
			case "certificate-roster":
				other, e := pki.NewIdentity(p, "other-node", loopback(port))
				if e != nil {
					t.Fatal(e)
				}
				raw, e := other.Request(request.Nonce)
				other.Close()
				if e != nil {
					t.Fatal(e)
				}
				foreign, e := pki.ParseRequest(raw)
				if e != nil {
					t.Fatal(e)
				}
				cert, e := ca.Issue(foreign, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				if e != nil {
					t.Fatal(e)
				}
				w := encoder{}
				w.bytes(cert.Marshal(), 2048)
				a.send(t, opCertificate, w)
				want = ReasonEnrollment
			default:
				bundle := actorCertificate(t, a, request, ca)
				if _, e := pki.Verify(p, policy(ca.Anchor()), loopback(port), bundle, time.Now()); e != nil {
					t.Fatalf("actual signed bundle rejected: %v", e)
				}
				if state == "bundle-eof" {
					a.command.Close()
					break
				}
				if state == "bundle-stop-malformed" {
					w := encoder{}
					w.u8(3)
					a.send(t, opStop, w)
					break
				}
				cfg := actorPublicRoster(t, p, ca, port, bundle)
				if state == "configure-suite" {
					cfg.suite = jcrypto.Suite(255)
				} else if state == "configure-shape" {
					cfg.roster[1].port = cfg.roster[0].port
				}
				a.send(t, opConfigure, encodeApplication(cfg))
				if state == "ready-eof" || state == "ready-stop-malformed" || state == "ready-begin-malformed" {
					a.ready(t, 1)
					if state == "ready-eof" {
						a.command.Close()
					} else if state == "ready-stop-malformed" {
						w := encoder{}
						w.u8(3)
						a.send(t, opStop, w)
					} else {
						w := encoder{}
						w.i64(0)
						w.i64(cfg.settings.DurationNS)
						w.i64(cfg.settings.DurationNS)
						a.send(t, opBegin, w)
					}
				}
			}
		}
		receipt := a.failed(t, want)
		assertActorCleanup(t, receipt, state != "boot-eof" && state != "challenge-port" && state != "challenge-trailing", false, false)
		if !receipt.ListenerCreated || receipt.ServeStarted != (state == "ready-eof" || state == "ready-stop-malformed" || state == "ready-begin-malformed") {
			t.Fatal("relay listener or Serve stage changed")
		}
	}
	for _, state := range []string{"boot-eof", "configure-opcode", "configure-ports", "configure-bundle", "ready-eof", "early-contact", "plan-route", "plan-contact"} {
		t.Logf("client actor failure stage %s", state)
		a := newActorTranscript(t, s, roleClient)
		a.boot(t)
		want := ReasonIPC
		created := false
		if state == "boot-eof" {
			a.command.Close()
		} else if state == "configure-opcode" {
			a.send(t, opContact, encoder{})
		} else {
			cfg := actorPublicRoster(t, p, ca, 0, nil)
			if state == "configure-ports" {
				cfg.roster[1].port = cfg.roster[0].port
			} else if state == "configure-bundle" {
				cfg.settings, _ = boundaryProfileSettings(3)
				cfg.roster[0].bundle = []byte{1, 2, 3}
				want = ReasonEnrollment
			}
			a.send(t, opConfigure, encodeApplication(cfg))
			if state != "configure-ports" && state != "configure-bundle" {
				a.ready(t, 1)
				r := a.next(t, opContact)
				if r.u16() != 1 || len(r.bytes(2048)) == 0 || r.end() != nil {
					t.Fatal("client did not create its real contact before workload admission")
				}
				created = true
				switch state {
				case "ready-eof":
					a.command.Close()
				case "early-contact":
					w := encoder{}
					w.u16(0)
					a.send(t, opContact, w)
				case "plan-route", "plan-contact":
					grant, e := sourceAttemptCeiling()
					if e != nil {
						t.Fatal(e)
					}
					plan := workloadPlan{topology: 2, route: [3]uint8{0, 1, 4}, sourceLimit: grant}
					if state == "plan-route" {
						plan.route = [3]uint8{0, 0, 4}
					} else {
						plan.contact = []byte{1}
					}
					a.send(t, opClientPlan, encodeWorkload(plan))
				}
			}
		}
		receipt := a.failed(t, want)
		assertActorCleanup(t, receipt, created, created, false)
		if receipt.PrivateCreated != (created || state == "configure-bundle") || receipt.InitialCircuitCreated {
			t.Fatal("client private initialization or pre-plan dial stage changed")
		}
	}
}

func actorConfigureClient(t *testing.T, a *actorTranscript, f *fixture, side uint16) []byte {
	t.Helper()
	card := actorClientPlan(t, a, f, side)
	a.ready(t, 2)
	return card
}

func actorClientPlan(t *testing.T, a *actorTranscript, f *fixture, side uint16) []byte {
	t.Helper()
	a.boot(t)
	cfg := applicationConfig{f.suite, f.topology, true, f.missing, f.anchor, f.roster, f.mailbox, false, f.settings}
	a.send(t, opConfigure, encodeApplication(cfg))
	a.ready(t, 1)
	r := a.next(t, opContact)
	if r.u16() != 1 {
		t.Fatal("client contact count changed")
	}
	card := bytes.Clone(r.bytes(2048))
	if r.end() != nil || len(card) == 0 {
		t.Fatal("client contact missing")
	}
	path := [3]uint8{0, 1, 4}
	if side == 1 {
		path = [3]uint8{2, 3, 4}
	}
	grant, e := sourceAttemptCeiling()
	if e != nil {
		t.Fatal(e)
	}
	plan := workloadPlan{sourceLimit: grant, side: side, topology: 2, route: path, gapSeed: 1171 + int64(side), lifetimeSeed: 1172 + int64(side), phaseSeed: 1173 + int64(side)}
	a.send(t, opClientPlan, encodeWorkload(plan))
	return card
}

func exerciseActorContactFailures(t *testing.T, ctx context.Context, s jcrypto.Suite) {
	t.Helper()
	f, e := newFixture(ctx, s, peerSettings(false, 0), 2, nil, nil, "", 2, fixtureResources{usage: &resourceUsage{}})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := f.close(); e != nil {
			t.Errorf("actor stand cleanup: %v", e)
		}
	}()
	exerciseActorLiveInitializationCancellation(t, f)
	for _, state := range []string{"ready2-eof", "illegal-orphan", "contact-count", "contact-card", "duplicate-plan"} {
		t.Logf("preflight actor failure stage %s", state)
		a := newActorTranscript(t, s, roleClient)
		card := actorConfigureClient(t, a, f, 0)
		clear(card)
		if state == "ready2-eof" {
			a.command.Close()
		} else if state == "duplicate-plan" {
			a.send(t, opClientPlan, encoder{})
		} else {
			w := encoder{}
			switch state {
			case "illegal-orphan":
				w.u16(0)
			case "contact-count":
				w.u16(2)
			case "contact-card":
				w.u16(1)
				w.bytes([]byte{1, 2, 3}, 2048)
			}
			a.send(t, opContact, w)
		}
		receipt := a.failed(t, ReasonIPC)
		assertActorCleanup(t, receipt, true, true, false)
		if !receipt.InitialCircuitCreated {
			t.Fatal("negative Contact case did not pass a real circuit preflight")
		}
	}
	for _, state := range []string{"ready3-eof", "duplicate-contact", "begin-stop-malformed", "begin-eof", "begin-late-contact"} {
		t.Logf("paired actor failure stage %s", state)
		actors := []*actorTranscript{newActorTranscript(t, s, roleClient), newActorTranscript(t, s, roleClient)}
		cards := [][]byte{actorConfigureClient(t, actors[0], f, 0), actorConfigureClient(t, actors[1], f, 1)}
		for i, a := range actors {
			w := encoder{}
			w.u16(1)
			w.bytes(cards[i^1], 2048)
			a.send(t, opContact, w)
		}
		clear(cards[0])
		clear(cards[1])
		for _, a := range actors {
			a.ready(t, 3)
		}
		started := state == "begin-stop-malformed" || state == "begin-eof" || state == "begin-late-contact"
		for _, a := range actors {
			if started {
				epoch := monotonicNS() + int64(time.Second)
				w := encoder{}
				w.i64(epoch)
				w.i64(f.settings.DurationNS)
				w.i64(epoch + f.settings.DurationNS)
				a.send(t, opBegin, w)
			}
			switch state {
			case "ready3-eof", "begin-eof":
				a.command.Close()
			case "begin-stop-malformed":
				w := encoder{}
				w.u8(3)
				a.send(t, opStop, w)
			default:
				w := encoder{}
				w.u16(0)
				a.send(t, opContact, w)
			}
		}
		for _, a := range actors {
			assertActorCleanup(t, a.failed(t, ReasonIPC), true, true, started)
		}
	}
	if e := f.stop(0); e != nil {
		t.Fatalf("actor stand stop: %v", e)
	}
	if e := f.finish(); e != nil {
		t.Fatalf("actor stand terminal handshake: %v", e)
	}
	for _, child := range f.children {
		if child.reason != ReasonNone || len(child.flags) != 0 || child.waitErr != nil || child.usageErr != nil {
			t.Fatal("actor stand did not finish with clean terminal and owned Wait results")
		}
		if !child.reaped || !child.joinReaders(time.Time{}) {
			t.Fatal("actor stand finished before definitive Wait and reader joins")
		}
	}
	if e := f.close(); e != nil {
		t.Fatalf("actor stand cleanup: %v", e)
	}
	if quarantinedFixtures.Load() != 0 || f.arena.buffer != nil {
		t.Fatal("actor stand retained ownership after definite termination")
	}
}
