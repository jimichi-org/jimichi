package mailbox_test

import (
	"net"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/relay"
)

func startNode(t *testing.T, p jcrypto.CryptoProvider, deliver relay.Deliver) client.Node {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	r, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, StaticPub: pub, Deliver: deliver})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = r.Serve(ln) }()
	t.Cleanup(func() {
		r.Close()
		_ = ln.Close()
	})
	return client.Node{Addr: ln.Addr().String(), StaticPub: pub}
}

func exchange(t *testing.T, cl *client.Client, req mailbox.Request) mailbox.Reply {
	t.Helper()
	if err := cl.Send(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-cl.Replies():
		r, err := mailbox.ParseReply(b)
		if err != nil {
			t.Fatalf("reply of %d bytes: %v", len(b), err)
		}
		if err := r.Answers(&req); err != nil {
			t.Fatal(err)
		}
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no reply")
	}
	return mailbox.Reply{}
}

// two circuits of three hops end on one mailbox: a record put on one comes
// out of a fetch on the other, and the same circuit cannot switch queues
func TestRoundTripThroughRelays(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteGOST, jcrypto.SuiteC25519} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			store, err := mailbox.NewStore(p, mailbox.DefaultLimits(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(store.Close)
			exit := startNode(t, p, store.Deliver)
			dial := func() *client.Client {
				cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{startNode(t, p, nil), startNode(t, p, nil), exit}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = cl.Close() })
				if cl.MaxPayload() < mailbox.RequestSize {
					t.Fatalf("payload limit %d below a request", cl.MaxPayload())
				}
				return cl
			}
			alice, bob := dial(), dial()

			var fa, fb [mailbox.CapSize]byte
			fa[0], fb[0] = 0xa, 0xb
			qb, err := mailbox.QueueID(p, fb[:])
			if err != nil {
				t.Fatal(err)
			}
			var rec [mailbox.RecordSize]byte
			copy(rec[:], "a record of the end-to-end layer")

			r := exchange(t, alice, mailbox.Request{Tag: 0, Fetch: fa, Put: qb, Record: rec})
			if r.Status != mailbox.PutStored {
				t.Fatalf("put: status %#02x", r.Status)
			}
			r = exchange(t, bob, mailbox.Request{Tag: 0, Fetch: fb})
			if r.Status != mailbox.StatusRecord || r.Record != rec {
				t.Fatalf("fetch: status %#02x", r.Status)
			}
			r = exchange(t, bob, mailbox.Request{Tag: 1, Fetch: fb})
			if r.Status != mailbox.PutNone {
				t.Fatalf("second fetch: status %#02x", r.Status)
			}

			moved := mailbox.Request{Tag: 2, Fetch: fb}
			if err := bob.Send((&mailbox.Request{Tag: 1, Fetch: fa}).Bytes()); err != nil {
				t.Fatal(err)
			}
			select {
			case b := <-bob.Replies():
				r, err := mailbox.ParseReply(b)
				if err != nil || r.Status != mailbox.StatusBad || r.Tag != 1 {
					t.Fatalf("other fetch queue on a bound circuit: %#02x, %v", r.Status, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no reply")
			}
			exchange(t, bob, moved)

			st := store.Stats()
			if st.Puts != 1 || st.Hits != 1 || st.Bad != 1 || st.Bindings != 2 || st.Queues != 1 {
				t.Fatalf("counters %+v", st)
			}
		})
	}
}
