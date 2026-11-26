package conversation

import (
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

// the worst case of a restart with the default bounds: the side that stayed
// goes stale, then a fresh kk1 waits out one HandshakeTimeout
const restartBound = 240 * time.Second

// a client restarted with a container keeps its identity and F: its old
// conversation is gone and a new one pairs with the same contact
func (n *testNet) restart(pr *testPeer, peer *testPeer) *testPeer {
	n.t.Helper()
	pr.paused = true
	pr.c.teardown()
	again := n.join(pr.name+" again", pr.party, pr.up, pr.down, nil)
	if err := again.c.onPair(peer.party.id.Card()); err != nil {
		n.t.Fatalf("%s pairs: %v", again.name, err)
	}
	return again
}

// either side restarts with the same identity and F, on the default stale
// bound and handshake timeout: the conversation comes back within
// restartBound and carries messages both ways
func TestRestartWithTheSameIdentityRecovers(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, restarted := range []e2e.Role{e2e.RoleInitiator, e2e.RoleResponder} {
			t.Run(restarted.String(), func(t *testing.T) {
				n := newNet(t, p, nil)
				pi, pr := parties(t, p)
				ini := n.join("initiator", pi, 1, 1, nil)
				resp := n.join("responder", pr, 1, 1, nil)
				n.start(t, ini, resp)
				ini.send(t, "before")
				n.until("a message before the restart", 20, func() bool { return resp.count("before") == 1 })

				stayed := ini
				if restarted == e2e.RoleInitiator {
					stayed = resp
					ini = n.restart(ini, resp)
				} else {
					resp = n.restart(resp, ini)
				}
				epoch := stayed.c.epoch
				limit := int(restartBound / testRate)
				took := n.until("a new confirmed session", limit, func() bool {
					return stayed.c.epoch > epoch && confirmed(ini, resp)
				})
				ini.send(t, "there")
				resp.send(t, "back")
				took += n.until("messages both ways", 20, func() bool { return resp.count("there") == 1 && ini.count("back") == 1 })
				if took > limit {
					t.Fatalf("the conversation came back after %v, over %v", ticks(took), restartBound)
				}
				t.Logf("back after %v", ticks(took))
			})
		}
	})
}

// the restarted responder has no ring of the kk1s it saw, and its identity is
// the old one, so an old kk1 of the initiator opens again: it is taken into a
// session that is never confirmed, since the keys of its data need the
// initiator's ephemeral key of that kk1, and the fresh kk1 of the initiator
// replaces it within the same bound
func TestOldKK1ReplayedToARestartedResponder(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, nil)
		pi, pr := parties(t, p)
		ini := n.join("initiator", pi, 1, 1, nil)
		resp := n.join("responder", pr, 1, 1, nil)
		n.start(t, ini, resp)
		var old [mailbox.RecordSize]byte
		found := false
		for _, rec := range ini.circ().puts() {
			if rec != nil && rec[0] == 0x01 {
				copy(old[:], rec)
				found = true
				break
			}
		}
		if !found {
			t.Fatal("no kk1 among the puts of the initiator")
		}

		resp = n.restart(resp, ini)
		epoch := ini.c.epoch
		if st := n.putFrom(1<<40, resp, old); st != mailbox.PutStored {
			t.Fatalf("the replay was not stored: %#x", st)
		}
		replayed := n.until("the replay taken", 20, func() bool { return resp.session().Handshakes > 0 })
		if resp.state() != e2e.StateEstablished || resp.session().ReplayedHandshakes != 0 {
			t.Fatalf("after the replay the responder is %v, %+v", resp.state(), resp.session())
		}

		limit := int(restartBound / testRate)
		took := replayed
		for ; !(ini.c.epoch > epoch && confirmed(ini, resp)); took++ {
			if ini.c.epoch == epoch && resp.state() == e2e.StateConfirmed {
				t.Fatal("the session of the replay was confirmed")
			}
			if took > limit {
				t.Fatalf("no fresh session within %v", restartBound)
			}
			n.step()
		}
		ini.send(t, "there")
		resp.send(t, "back")
		took += n.until("messages both ways", 20, func() bool { return resp.count("there") == 1 && ini.count("back") == 1 })
		if took > limit {
			t.Fatalf("the conversation came back after %v, over %v", ticks(took), restartBound)
		}
		t.Logf("back after %v", ticks(took))
	})
}
