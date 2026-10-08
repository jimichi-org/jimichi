package conversation

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/relay"
)

// the conversation as a binary would run it: its own loop and ticker, the
// reply reader, circuits of three relays in this process with the mailbox
// Store as the Deliver of the exit, and real time

// the relays here forward at once, so a round trip is the cryptography of
// three hops each way; GOST in pure Go under the race detector needs a slower
// rate than that to keep up
func liveRate(p jcrypto.CryptoProvider) time.Duration {
	if p.Suite() == jcrypto.SuiteGOST {
		return 40 * time.Millisecond
	}
	return 10 * time.Millisecond
}

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

type relayNet struct {
	p     jcrypto.CryptoProvider
	store *mailbox.Store
	chain []client.Node
}

func newRelayNet(t *testing.T, p jcrypto.CryptoProvider) *relayNet {
	t.Helper()
	store, err := mailbox.NewStore(p, mailbox.DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	exit := startNode(t, p, store.Deliver)
	return &relayNet{p: p, store: store, chain: []client.Node{startNode(t, p, nil), startNode(t, p, nil), exit}}
}

type livePeer struct {
	name  string
	party party
	c     *Conversation

	mu     sync.Mutex
	circs  []*client.Client
	events []Event
}

func (r *relayNet) join(t *testing.T, name string, pt party, change func(*Config)) *livePeer {
	t.Helper()
	lp := &livePeer{name: name, party: pt}
	first, err := lp.dial(r)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Provider:     r.p,
		Self:         pt.id,
		Fetch:        pt.f,
		First:        first,
		Dial:         func() (Circuit, error) { return lp.dial(r) },
		Rate:         liveRate(r.p),
		CoverPuts:    true,
		ReplyTimeout: 200 * liveRate(r.p),
		Events: func(ev Event) {
			lp.mu.Lock()
			lp.events = append(lp.events, ev)
			lp.mu.Unlock()
		},
	}
	if change != nil {
		change(&cfg)
	}
	c, err := newConversation(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.firstPause = 2 * liveRate(r.p)
	c.launch()
	lp.c = c
	t.Cleanup(c.Close)
	return lp
}

func (lp *livePeer) dial(r *relayNet) (Circuit, error) {
	cl, err := client.Dial(client.Config{Provider: r.p, Chain: r.chain})
	if err != nil {
		return nil, err
	}
	lp.mu.Lock()
	lp.circs = append(lp.circs, cl)
	lp.mu.Unlock()
	return cl, nil
}

func (lp *livePeer) current() *client.Client {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	return lp.circs[len(lp.circs)-1]
}

func (lp *livePeer) expect(t *testing.T, body string) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case m, ok := <-lp.c.Messages():
			if !ok {
				t.Fatalf("%s: the conversation ended with %v before %q", lp.name, lp.c.Err(), body)
			}
			if string(m) == body {
				return
			}
		case <-deadline:
			t.Fatalf("%s: no %q, %+v", lp.name, body, lp.c.Stats())
		}
	}
}

func (lp *livePeer) send(t *testing.T, body string) {
	t.Helper()
	if err := lp.c.Send([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

// the responder speaks first and the initiator only answers, with cover puts
// and without: the round trip needs the initiator's first record after kk2.
// Then the circuit of the initiator is closed under it, and the conversation
// goes on over a rebuilt one with the same session
func TestConversationOverRelays(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, cover := range []bool{true, false} {
			t.Run(fmt.Sprintf("cover puts %v", cover), func(t *testing.T) {
				r := newRelayNet(t, p)
				pi, pr := parties(t, p)
				ini := r.join(t, "initiator", pi, coverPuts(cover))
				resp := r.join(t, "responder", pr, coverPuts(cover))
				if err := ini.c.Pair(resp.party.id.Card()); err != nil {
					t.Fatal(err)
				}
				resp.send(t, "ping")
				if err := resp.c.Pair(ini.party.id.Card()); err != nil {
					t.Fatal(err)
				}
				if err := resp.c.Pair(ini.party.id.Card()); err != nil {
					t.Fatalf("the same card again: %v", err)
				}
				ini.expect(t, "ping")
				ini.send(t, "pong")
				resp.expect(t, "pong")

				epoch := ini.c.Stats().Epoch
				_ = ini.current().Close()
				deadline := time.Now().Add(20 * time.Second)
				for ini.c.Stats().Rebuilds == 0 {
					if time.Now().After(deadline) {
						t.Fatalf("no rebuild: %+v", ini.c.Stats())
					}
					time.Sleep(liveRate(p))
				}
				resp.send(t, "after")
				ini.expect(t, "after")
				ini.send(t, "again")
				resp.expect(t, "again")

				st := ini.c.Stats()
				ini.mu.Lock()
				events := append([]Event(nil), ini.events...)
				ini.mu.Unlock()
				if st.Epoch != epoch || st.BadReplies != 0 || st.Rebuilds != 1 || st.Refusals != 0 {
					t.Fatalf("initiator %+v, events %v", st, events)
				}
				if len(events) != 2 || events[0].Kind != CircuitEnded || events[1].Kind != CircuitRebuilt {
					t.Fatalf("events %v", events)
				}
				if s := r.store.Stats(); s.Bad != 0 || s.Puts == 0 || s.Hits == 0 {
					t.Fatalf("mailbox %+v", s)
				}

				ini.c.Close()
				select {
				case <-ini.c.Done():
				default:
					t.Fatal("Done is open after Close")
				}
				if ini.c.Err() != nil {
					t.Fatalf("Err after Close: %v", ini.c.Err())
				}
				if err := ini.c.Pair(resp.party.id.Card()); err != ErrClosed {
					t.Fatalf("Pair after Close: %v", err)
				}
				for range ini.c.Messages() {
				}
			})
		}
	})
}

// a contact card that changes after pinning ends the conversation in its own
// loop: Pair answers ErrContactChanged and Done closes
func TestAnotherCardEndsTheLoop(t *testing.T) {
	p := c25519(t)
	r := newRelayNet(t, p)
	pi, pr := parties(t, p)
	a := r.join(t, "a", pi, nil)
	if err := a.c.Pair(newParty(t, p).id.Card()); err != nil {
		t.Fatal(err)
	}
	if err := a.c.Pair(pr.id.Card()); err != ErrContactChanged {
		t.Fatalf("another card: %v", err)
	}
	select {
	case <-a.c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the conversation did not end")
	}
	if a.c.Err() != ErrContactChanged {
		t.Fatalf("Err %v", a.c.Err())
	}
}
