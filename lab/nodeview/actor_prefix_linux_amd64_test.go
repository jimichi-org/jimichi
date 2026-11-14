//go:build linux && amd64

package nodeview

import (
	"slices"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func actorCancelAt(target childInitStage, calls *[]childInitStage) func(*childIO) {
	return func(c *childIO) {
		c.cancelInit = func(stage childInitStage) bool {
			*calls = append(*calls, stage)
			return stage == target
		}
	}
}

func assertActorPrefix(t *testing.T, got, want childCleanupReceipt, calls []childInitStage, target childInitStage) {
	t.Helper()
	created := func(r childCleanupReceipt) [13]bool {
		return [13]bool{r.IdentityCreated, r.LinkCreated, r.OnionCreated, r.FetchCreated, r.PrivateCreated, r.CollectorCreated, r.ListenerCreated, r.ObserverStarted, r.ServeStarted, r.InitialCircuitCreated, r.RingCreated, r.NodeCreated, r.ConversationCreated}
	}
	if created(got) != created(want) {
		t.Fatalf("partial initialization cancellation at stage %d did not own its exact acquired prefix", target)
	}
	assertActorReleased(t, got)
	first := initRelayListener
	if target >= initClientPrivate {
		first = initClientPrivate
	}
	var expected []childInitStage
	for stage := first; stage <= target; stage++ {
		expected = append(expected, stage)
	}
	if !slices.Equal(calls, expected) {
		t.Fatalf("partial initialization cancellation at stage %d skipped or replayed an acquired stage", target)
	}
}

func exerciseActorInitializationCancellation(t *testing.T, s jcrypto.Suite) {
	t.Helper()
	p, ca := actorAuthority(t, s)
	for target := initRelayListener; target <= initRelayServe; target++ {
		t.Logf("relay partial initialization cancellation stage %d", target)
		var calls []childInitStage
		a := newActorTranscript(t, s, roleRelay, actorCancelAt(target, &calls))
		if target >= initRelayIdentity {
			port := a.boot(t)
			if target <= initRelayOnion {
				a.send(t, opChallenge, actorChallenge(port, [16]byte{13, 17, 23}, ca))
			} else {
				request := actorEnrollment(t, a, port, p, ca)
				bundle := actorCertificate(t, a, request, ca)
				cfg := actorPublicRoster(t, p, ca, port, bundle)
				a.send(t, opConfigure, encodeApplication(cfg))
			}
		}
		want := childCleanupReceipt{ListenerCreated: true, CollectorCreated: target >= initRelayCollector, IdentityCreated: target >= initRelayIdentity, LinkCreated: target >= initRelayLink, OnionCreated: target >= initRelayOnion, RingCreated: target >= initRelayRing, NodeCreated: target >= initRelayNode, ServeStarted: target >= initRelayServe}
		assertActorPrefix(t, a.failed(t, ReasonCancelled), want, calls, target)
	}
	for _, target := range []childInitStage{initClientPrivate, initClientFetch, initClientIdentity} {
		t.Logf("client partial initialization cancellation stage %d", target)
		var calls []childInitStage
		a := newActorTranscript(t, s, roleClient, actorCancelAt(target, &calls))
		a.boot(t)
		cfg := actorPublicRoster(t, p, ca, 0, nil)
		a.send(t, opConfigure, encodeApplication(cfg))
		if target >= initClientFetch {
			a.ready(t, 1)
		}
		want := childCleanupReceipt{PrivateCreated: true, FetchCreated: target >= initClientFetch, IdentityCreated: target >= initClientIdentity}
		assertActorPrefix(t, a.failed(t, ReasonCancelled), want, calls, target)
	}
}

func exerciseActorLiveInitializationCancellation(t *testing.T, f *fixture) {
	t.Helper()
	for _, target := range []childInitStage{initClientCircuit, initClientConversation, initClientObservers} {
		t.Logf("live client partial initialization cancellation stage %d", target)
		var calls []childInitStage
		a := newActorTranscript(t, f.suite, roleClient, actorCancelAt(target, &calls))
		if target == initClientCircuit {
			card := actorClientPlan(t, a, f, 0)
			clear(card)
		} else {
			peer := newActorTranscript(t, f.suite, roleClient)
			cards := [][]byte{actorConfigureClient(t, a, f, 0), actorConfigureClient(t, peer, f, 1)}
			body := encoder{}
			body.u16(1)
			body.bytes(cards[1], 2048)
			a.send(t, opContact, body)
			if target == initClientObservers {
				body = encoder{}
				body.u16(1)
				body.bytes(cards[0], 2048)
				peer.send(t, opContact, body)
				a.ready(t, 3)
				peer.ready(t, 3)
				epoch := monotonicNS() + int64(time.Second)
				body = encoder{}
				body.i64(epoch)
				body.i64(f.settings.DurationNS)
				body.i64(epoch + f.settings.DurationNS)
				a.send(t, opBegin, body)
			}
			clear(cards[0])
			clear(cards[1])
			want := childCleanupReceipt{PrivateCreated: true, FetchCreated: true, IdentityCreated: true, InitialCircuitCreated: true, ConversationCreated: true, ObserverStarted: target == initClientObservers}
			assertActorPrefix(t, a.failed(t, ReasonCancelled), want, calls, target)
			peer.command.Close()
			assertActorCleanup(t, peer.failed(t, ReasonIPC), true, true, false)
			continue
		}
		want := childCleanupReceipt{PrivateCreated: true, FetchCreated: true, IdentityCreated: true, InitialCircuitCreated: true, ConversationCreated: target >= initClientConversation, ObserverStarted: target >= initClientObservers}
		assertActorPrefix(t, a.failed(t, ReasonCancelled), want, calls, target)
	}
}
