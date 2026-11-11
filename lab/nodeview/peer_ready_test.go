package nodeview

import (
	"bytes"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/e2e"
)

var mailboxControlAllocationRoleSink e2e.Role
var mailboxControlAllocationErrorSink error

func TestPeerReadinessRoleAllocationFreeOnEveryReturn(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			size := 32
			other := jcrypto.SuiteGOST
			if s == jcrypto.SuiteGOST {
				size, other = 64, jcrypto.SuiteC25519
			}
			a := e2e.Card{Suite: s, Static: bytes.Repeat([]byte{1}, size)}
			b := e2e.Card{Suite: s, Static: bytes.Repeat([]byte{2}, size)}
			for _, row := range []struct {
				name      string
				own, peer e2e.Card
				role      e2e.Role
				want      Reason
			}{
				{"initiator", a, b, e2e.RoleInitiator, ReasonNone},
				{"responder", b, a, e2e.RoleResponder, ReasonNone},
				{"unknown-own-suite", e2e.Card{Suite: jcrypto.Suite(255), Static: a.Static}, b, 0, ReasonContract},
				{"different-peer-suite", a, e2e.Card{Suite: other, Static: b.Static}, 0, ReasonContract},
				{"unknown-peer-suite", a, e2e.Card{Suite: jcrypto.Suite(255), Static: b.Static}, 0, ReasonContract},
				{"empty-own-key", e2e.Card{Suite: s}, b, 0, ReasonContract},
				{"short-own-key", e2e.Card{Suite: s, Static: a.Static[:size-1]}, b, 0, ReasonContract},
				{"long-own-key", e2e.Card{Suite: s, Static: bytes.Repeat([]byte{1}, size+1)}, b, 0, ReasonContract},
				{"empty-peer-key", a, e2e.Card{Suite: s}, 0, ReasonContract},
				{"short-peer-key", a, e2e.Card{Suite: s, Static: b.Static[:size-1]}, 0, ReasonContract},
				{"long-peer-key", a, e2e.Card{Suite: s, Static: bytes.Repeat([]byte{2}, size+1)}, 0, ReasonContract},
				{"equal-keys", a, a, 0, ReasonContract},
			} {
				t.Run(row.name, func(t *testing.T) {
					ownBefore, peerBefore := bytes.Clone(row.own.Static), bytes.Clone(row.peer.Static)
					defer clear(ownBefore)
					defer clear(peerBefore)
					allocations := testing.AllocsPerRun(100, func() {
						mailboxControlAllocationRoleSink, mailboxControlAllocationErrorSink = peerReadinessRole(row.own, row.peer)
					})
					if mailboxControlAllocationRoleSink != row.role || reasonOf(mailboxControlAllocationErrorSink) != row.want {
						t.Fatal("allocation path returned the wrong role or reason")
					}
					if row.want != ReasonNone {
						if actual, ok := mailboxControlAllocationErrorSink.(failure); !ok || actual.reason != row.want {
							t.Fatal("allocation path changed the existing dynamic failure type")
						}
					}
					if !bytes.Equal(ownBefore, row.own.Static) || !bytes.Equal(peerBefore, row.peer.Static) {
						t.Fatal("allocation path mutated a borrowed public key")
					}
					if allocations != 0 {
						t.Errorf("helper allocated %.0f times on this return path, want 0", allocations)
					}
					mailboxControlAllocationRoleSink, mailboxControlAllocationErrorSink = 0, nil
				})
			}
		})
	}
}

func TestPeerSessionReadinessUsesAuthenticatedRole(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		size := 32
		if s == jcrypto.SuiteGOST {
			size = 64
		}
		a := e2e.Card{Suite: s, Static: bytes.Repeat([]byte{1}, size)}
		b := e2e.Card{Suite: s, Static: bytes.Repeat([]byte{2}, size)}
		beforeA, beforeB := bytes.Clone(a.Static), bytes.Clone(b.Static)
		for _, order := range []struct {
			own, peer e2e.Card
			want      e2e.Role
		}{{a, b, e2e.RoleInitiator}, {b, a, e2e.RoleResponder}} {
			if role, e := peerReadinessRole(order.own, order.peer); e != nil || role != order.want {
				t.Fatal("public key order did not select the authenticated role")
			}
		}
		for _, bad := range []e2e.Card{{}, a, {Suite: s, Static: b.Static[:size-1]}, {Suite: jcrypto.Suite(255), Static: b.Static}} {
			if _, e := peerReadinessRole(a, bad); reasonOf(e) != ReasonContract {
				t.Fatal("invalid public role shape accepted")
			}
			if _, e := peerReadinessRole(bad, a); reasonOf(e) != ReasonContract {
				t.Fatal("invalid own public role shape accepted")
			}
		}
		foreign := b
		foreign.Suite = jcrypto.SuiteGOST
		if s == jcrypto.SuiteGOST {
			foreign.Suite = jcrypto.SuiteC25519
		}
		if _, e := peerReadinessRole(a, foreign); reasonOf(e) != ReasonContract {
			t.Fatal("different suites accepted")
		}
		if allocations := testing.AllocsPerRun(10, func() { _, _ = peerReadinessRole(a, b) }); allocations != 0 {
			t.Fatal("public role derivation allocated")
		}
		if !bytes.Equal(a.Static, beforeA) || !bytes.Equal(b.Static, beforeB) {
			t.Fatal("public role derivation changed a borrowed card")
		}
		clear(beforeA)
		clear(beforeB)
		for _, role := range []e2e.Role{0, e2e.RoleInitiator, e2e.RoleResponder, 255} {
			for _, paired := range []bool{false, true} {
				for _, state := range []e2e.State{0, e2e.StateHandshaking, e2e.StateEstablished, e2e.StateConfirmed, e2e.StateStale, 255} {
					want := paired && (role == e2e.RoleInitiator && state == e2e.StateEstablished || role == e2e.RoleResponder && state == e2e.StateConfirmed)
					if peerSessionReady(role, paired, state) != want {
						t.Fatal("readiness role/state table changed")
					}
				}
			}
		}
		t.Run(s.String(), func(t *testing.T) { authenticatedReadyPrefix(t, s) })
	}
}

func authenticatedReadyPrefix(t *testing.T, s jcrypto.Suite) {
	t.Helper()
	p, e := suite.New(s)
	if e != nil {
		t.Fatal(e)
	}
	a, e := e2e.NewIdentity(p, "127.0.0.1:9000", [e2e.QueueSize]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := e2e.NewIdentity(p, "127.0.0.1:9000", [e2e.QueueSize]byte{2})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	ac, bc := a.Card(), b.Card()
	defer clear(ac.Static)
	defer clear(bc.Static)
	if bytes.Compare(ac.Static, bc.Static) > 0 {
		a, b, ac, bc = b, a, bc, ac
	}
	ini, e := e2e.NewSession(p, a, bc, e2e.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer ini.Close()
	resp, e := e2e.NewSession(p, b, ac, e2e.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Close()
	kk1, ok := ini.Handshake()
	if !ok {
		t.Fatal("actual initiator did not offer KK1")
	}
	defer clear(kk1)
	ini.Stored(kk1)
	if _, e := resp.Receive(kk1); e != nil {
		t.Fatal(e)
	}
	kk2, ok := resp.Handshake()
	if !ok {
		t.Fatal("actual responder did not offer authenticated KK2")
	}
	defer clear(kk2)
	resp.Stored(kk2)
	if _, e := ini.Receive(kk2); e != nil {
		t.Fatal(e)
	}
	st := ini.Stats()
	if ini.State() != e2e.StateEstablished || st.DummiesReceived != 0 || !peerSessionReady(ini.Role(), true, ini.State()) || oldPeerReadiness(ini.State(), st.DummiesReceived) {
		t.Fatal("actual no-reverse-dummy prefix did not distinguish the old readiness decision")
	}
	if peerSessionReady(resp.Role(), true, resp.State()) || !oldPeerReadiness(resp.State(), 1) {
		t.Fatal("a stale lifetime counter authorized a fresh established responder")
	}
	dummy, e := ini.SealDummy()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(dummy)
	if _, e := resp.Receive(dummy); e != nil || !peerSessionReady(resp.Role(), true, resp.State()) {
		t.Fatal("actual authenticated confirmation did not admit the responder")
	}
	for _, lifetime := range []uint64{0, 1, ^uint64(0)} {
		for _, epoch := range []uint64{0, 1, ^uint64(0)} {
			st.DummiesReceived, st.DummiesSent, st.Handshakes = lifetime, lifetime, lifetime
			sample := conversation.Stats{Paired: true, State: ini.State(), Epoch: epoch, Session: st}
			if !peerSessionReady(ini.Role(), sample.Paired, sample.State) {
				t.Fatal("lifetime metadata altered scalar readiness")
			}
		}
	}
}

func oldPeerReadiness(state e2e.State, received uint64) bool {
	return state == e2e.StateConfirmed || state == e2e.StateEstablished && received > 0
}

func TestPeerReadyAcceptanceHasStrictDeadline(t *testing.T) {
	until := time.Unix(123, 456)
	for _, row := range []struct {
		cancelled bool
		now       time.Time
		want      Reason
	}{{false, until.Add(-time.Nanosecond), ReasonNone}, {false, until, ReasonIPC}, {false, until.Add(time.Nanosecond), ReasonIPC}, {true, until.Add(-time.Nanosecond), ReasonCancelled}, {true, until, ReasonCancelled}} {
		if reasonOf(readyAcceptanceError(row.cancelled, row.now, until)) != row.want {
			t.Fatal("deadline equality or cancellation precedence changed")
		}
	}
}
