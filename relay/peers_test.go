package relay_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/relay"
)

func peersOf(nodes ...*node) func(string) (relay.Peer, bool) {
	peers := make(map[string]relay.Peer, len(nodes))
	for _, n := range nodes {
		peers[n.addr] = relay.Peer{LinkPub: n.pub, Identity: n.identity}
	}
	return func(addr string) (relay.Peer, bool) {
		peer, ok := peers[addr]
		return peer, ok
	}
}

func countDials(n *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

func TestExtendOutsidePeersIsRefusedWithoutADial(t *testing.T) {
	p := c25519.New()
	known := startNode(t, p, nil)
	outside := startNode(t, p, nil)
	var dials atomic.Int32
	entry := startRelay(t, p, relay.Config{Peers: peersOf(known), Dial: countDials(&dials)})

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, outside)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	expectEnd(t, cl)

	if n := dials.Load(); n != 0 {
		t.Fatalf("the relay dialled %d times for an address outside its peers", n)
	}
	// the refused setup is a dropped cell as well, like any setup that fails
	if got := entry.r.Stats().Snapshot(); got.RefusedExtend != 1 || got.Dropped != 1 {
		t.Fatalf("refused extends = %d, dropped = %d, want 1 and 1", got.RefusedExtend, got.Dropped)
	}
	if got := outside.r.Stats().Snapshot().Accepted; got != 0 {
		t.Fatalf("the node outside the peers accepted %d cells", got)
	}
}

// an empty key would turn the link anonymous, so it is no key at all
func TestPeerWithoutAKeyIsRefused(t *testing.T) {
	p := c25519.New()
	next := startNode(t, p, nil)
	var dials atomic.Int32
	entry := startRelay(t, p, relay.Config{
		Peers: func(string) (relay.Peer, bool) { return relay.Peer{}, true },
		Dial:  countDials(&dials),
	})

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, next)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	expectEnd(t, cl)

	if dials.Load() != 0 || entry.r.Stats().Snapshot().RefusedExtend != 1 {
		t.Fatalf("dials = %d, refused extends = %d, want 0 and 1", dials.Load(), entry.r.Stats().Snapshot().RefusedExtend)
	}
}

type writeCounter struct {
	net.Conn
	written *atomic.Int64
}

func (w writeCounter) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	w.written.Add(int64(n))
	return n, err
}

// the next node holds another key than the one its peer was given: the link
// handshake fails, the setup is never written to it and the circuit ends
func TestSetupIsNotForwardedToANodeWithAnotherKey(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 1)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- payload
		return nil
	})
	priv, other, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	var dials atomic.Int32
	var written atomic.Int64
	entry := startRelay(t, p, relay.Config{
		Peers: func(addr string) (relay.Peer, bool) { return relay.Peer{LinkPub: other}, addr == exit.addr },
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := countDials(&dials)(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return writeCounter{Conn: conn, written: &written}, nil
		},
	})

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	_ = cl.Send([]byte("for the holder of the key only"))
	expectEnd(t, cl)

	if n := dials.Load(); n != 1 {
		t.Fatalf("the relay dialled %d times, want 1", n)
	}
	hello, _ := link.InitiatorHandshakeSize(p)
	if n := written.Load(); n != int64(hello) {
		t.Fatalf("the relay wrote %d bytes to the node with another key, want its hello of %d and no setup", n, hello)
	}
	if got := exit.r.Stats().Snapshot().Accepted; got != 0 {
		t.Fatalf("a node without the expected link key accepted %d cells", got)
	}
	select {
	case <-delivered:
		t.Fatal("a message was delivered over a link with the wrong key")
	default:
	}
	// a failed handshake onwards has a counter of its own and drops the setup cell
	if got := entry.r.Stats().Snapshot(); got.FailedExtend != 1 || got.Dropped != 1 || got.RefusedExtend != 0 || got.TimedOut != 0 {
		t.Fatalf("failed extends = %d, dropped = %d, refused extends = %d, timed out = %d, want 1, 1, 0, 0",
			got.FailedExtend, got.Dropped, got.RefusedExtend, got.TimedOut)
	}
}

func signingKey(t *testing.T, p jcrypto.CryptoProvider) []byte {
	t.Helper()
	priv, pub, err := p.GenerateSigning()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	return pub
}

// authenticated nodes e, a and x, each binding its own identity; c is a
// descriptor that names the keys of a under another identity, at an address
// whose connections reach a. A chain through a delivers. A chain through c
// fails wherever c stands: as the entry the client's link to it is not
// confirmed; in the middle the link onwards is not confirmed; and where that
// link is sound, the layer built for c does not open at a
func TestChainBindsTheIdentityOfEveryNode(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			delivered := make(chan []byte, 4)
			exit := startRelay(t, p, relay.Config{
				Identity: signingKey(t, p),
				Deliver: func(_ uint64, payload []byte) []byte {
					delivered <- append([]byte(nil), payload...)
					return nil
				},
				Peers: peersOf(),
			})
			a := startRelay(t, p, relay.Config{Identity: signingKey(t, p), Peers: peersOf(exit)})
			const cAddr = "relay-c.test:9000"
			c := &node{addr: cAddr, pub: a.pub, identity: signingKey(t, p)}
			toA := func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == cAddr {
					addr = a.addr
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
			// the entry knows c by what its descriptor says; the second entry
			// reaches a under the address of c with the identity of a, so only
			// the setup layer tells the two apart
			entry := startRelay(t, p, relay.Config{Identity: signingKey(t, p), Peers: peersOf(a, c), Dial: toA})
			sound := startRelay(t, p, relay.Config{
				Identity: signingKey(t, p),
				Peers: func(addr string) (relay.Peer, bool) {
					if addr == cAddr {
						return relay.Peer{LinkPub: a.pub, Identity: a.identity}, true
					}
					return relay.Peer{}, false
				},
				Dial: toA,
			})

			cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, a, exit)})
			if err != nil {
				t.Fatalf("Dial through a: %v", err)
			}
			if err := cl.Send([]byte("through a")); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case got := <-delivered:
				if string(got) != "through a" {
					t.Fatalf("delivered %q", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("nothing delivered through a")
			}
			_ = cl.Close()

			asEntry := chainOf(c, exit)
			asEntry[0].Addr = a.addr
			if cl, err := client.Dial(client.Config{Provider: p, Chain: asEntry}); !errors.Is(err, link.ErrHandshake) {
				if cl != nil {
					_ = cl.Close()
				}
				t.Fatalf("c as the entry: Dial = %v, want %v", err, link.ErrHandshake)
			}

			for _, tc := range []struct {
				name   string
				first  *node
				failed uint64
				// setups a dropped because the layer did not open
				dropped uint64
			}{
				{"c in the middle", entry, 1, 0},
				{"c in the middle over a sound link", sound, 0, 1},
			} {
				before := a.r.Stats().Snapshot()
				cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(tc.first, c, exit)})
				if err != nil {
					t.Fatalf("%s: Dial: %v", tc.name, err)
				}
				_ = cl.Send([]byte("through c"))
				expectEnd(t, cl)
				_ = cl.Close()
				if got := tc.first.r.Stats().Snapshot().FailedExtend; got != tc.failed {
					t.Fatalf("%s: %d failed extends, want %d", tc.name, got, tc.failed)
				}
				got := a.r.Stats().Snapshot()
				if got.Forwarded != before.Forwarded || got.Dropped-before.Dropped != tc.dropped {
					t.Fatalf("%s: a forwarded %d cells meant for c and dropped %d, want 0 and %d",
						tc.name, got.Forwarded-before.Forwarded, got.Dropped-before.Dropped, tc.dropped)
				}
			}
			select {
			case got := <-delivered:
				t.Fatalf("delivered %q through c", got)
			default:
			}
		})
	}
}

func TestChainWithPeersDeliversOnEverySuite(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			exit := startRelay(t, p, relay.Config{
				Deliver: func(_ uint64, payload []byte) []byte { return append([]byte("echo:"), payload...) },
				Peers:   peersOf(),
			})
			middle := startRelay(t, p, relay.Config{Peers: peersOf(exit)})
			entry := startRelay(t, p, relay.Config{Peers: peersOf(middle)})

			cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer cl.Close()
			if err := cl.Send([]byte("ping")); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case reply, open := <-cl.Replies():
				if !open || string(reply) != "echo:ping" {
					t.Fatalf("reply %q, open %v", reply, open)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no reply came back")
			}
			for i, n := range []*node{entry, middle, exit} {
				if got := n.r.Stats().Snapshot(); got.RefusedExtend != 0 || got.FailedExtend != 0 {
					t.Fatalf("hop %d refused %d extends and failed %d", i, got.RefusedExtend, got.FailedExtend)
				}
			}
		})
	}
}
