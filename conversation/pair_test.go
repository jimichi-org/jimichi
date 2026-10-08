package conversation

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
)

// keeps every secret the provider hands out from the moment it is armed
type keyTracker struct {
	jcrypto.CryptoProvider
	mu    sync.Mutex
	armed bool
	bufs  []*secmem.Buffer
}

func (p *keyTracker) keep(b *secmem.Buffer) *secmem.Buffer {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.armed && b != nil {
		p.bufs = append(p.bufs, b)
	}
	return b
}

func (p *keyTracker) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateEphemeral()
	return p.keep(priv), pub, err
}

func (p *keyTracker) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.Agree(priv, pub, ctx)
	return p.keep(b), err
}

func (p *keyTracker) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.MixKey(chain, secret, ctx)
	return p.keep(b), err
}

func (p *keyTracker) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	return p.keep(b), err
}

func (p *keyTracker) held() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, b := range p.bufs {
		if b.Bytes() != nil {
			n++
		}
	}
	return n
}

func TestPairWithTheSameCardAgainIsNil(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	b := n.join("b", pr, 1, 1, nil)
	n.start(t, a, b)
	session := a.c.session
	if err := a.c.onPair(b.party.id.Card()); err != nil || a.c.session != session || a.c.finished {
		t.Fatalf("the same card again: %v", err)
	}
}

// another card after pinning is the hard stop: the conversation ends with
// ErrContactChanged, the circuit is closed and every session key is released
func TestAnotherCardEndsTheConversation(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		track := &keyTracker{CryptoProvider: p}
		n := newNet(t, track, nil)
		pi, pr := parties(t, track)
		stranger := newParty(t, track)
		a := n.join("a", pi, 1, 1, nil)
		b := n.join("b", pr, 1, 1, nil)
		track.mu.Lock()
		track.armed = true
		track.mu.Unlock()
		n.start(t, a, b)
		n.run(5)
		if track.held() == 0 {
			t.Fatal("the session holds no keys")
		}

		first := a.circ()
		if err := a.c.onPair(stranger.id.Card()); err != ErrContactChanged {
			t.Fatalf("another card: %v", err)
		}
		a.settle()
		if a.c.Err() != ErrContactChanged || !first.closed || a.c.circ != nil {
			t.Fatalf("err %v, circuit closed %v", a.c.Err(), first.closed)
		}
		select {
		case <-a.c.Done():
		default:
			t.Fatal("Done is open")
		}
		if _, ok := <-a.c.Messages(); ok {
			t.Fatal("Messages is open")
		}
		if err := a.c.Send([]byte("late")); err != ErrClosed {
			t.Fatalf("Send after the end: %v", err)
		}
		if err := a.c.onPair(b.party.id.Card()); err != ErrClosed {
			t.Fatalf("Pair after the end: %v", err)
		}
		// b still holds its own session; a holds nothing
		b.c.teardown()
		if held := track.held(); held != 0 {
			t.Fatalf("%d keys still held", held)
		}
	})
}

func TestPairRefusesACardItCannotUse(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, pr := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	b := n.join("b", pr, 1, 1, nil)

	elsewhere := b.party.id.Card()
	elsewhere.Mailbox = "relay-4.jimichi.svc.cluster.local:9000"
	gost := b.party.id.Card()
	gost.Suite = jcrypto.SuiteGOST
	gost.Static = bytes.Repeat([]byte{7}, 64)
	for _, c := range []struct {
		name string
		card e2e.Card
		want error
	}{
		{"another mailbox", elsewhere, e2e.ErrCard},
		{"another suite", gost, e2e.ErrCard},
		{"its own card", a.party.id.Card(), e2e.ErrSelf},
	} {
		if err := a.c.onPair(c.card); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v, want %v", c.name, err, c.want)
		}
		if a.c.session != nil || a.c.finished {
			t.Fatalf("%s left a session or ended the conversation", c.name)
		}
	}
	n.start(t, a, b)
}

// records that arrive before pinning are held, the oldest pushed out, and go
// to the session in order once the contact is pinned
func TestRecordsBeforePinningAreTakenAfter(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		n := newNet(t, p, nil)
		pi, pr := parties(t, p)
		ini := n.join("initiator", pi, 1, 1, nil)
		resp := n.join("responder", pr, 1, 1, func(c *Config) { c.Hold = 2 })
		for range 3 {
			n.putFrom(1<<40, resp, garbage(t, 0x03))
		}
		if err := ini.c.onPair(resp.party.id.Card()); err != nil {
			t.Fatal(err)
		}
		n.until("kk1 held", 20, func() bool {
			return len(resp.c.held) == 2 && resp.c.held[1][0] == 0x01
		})
		if st := resp.c.Stats(); st.HeldDropped == 0 || st.Paired {
			t.Fatalf("%+v", st)
		}
		if err := resp.c.onPair(ini.party.id.Card()); err != nil {
			t.Fatal(err)
		}
		if resp.state() != e2e.StateEstablished || resp.c.held != nil {
			t.Fatalf("the responder in %v after pinning", resp.state())
		}
		n.until("the session", 20, func() bool { return confirmed(ini, resp) })
	})
}

func TestSendRefusesALongBodyAndDropsWhenFull(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	a := n.join("a", pi, 1, 1, func(c *Config) { c.Outbox = 2 })
	if err := a.c.Send(make([]byte, e2e.MaxBody+1)); err != e2e.ErrTooLong {
		t.Fatalf("a body of %d bytes: %v", e2e.MaxBody+1, err)
	}
	a.send(t, "1", "2", "3")
	if got := a.outbox(); len(got) != 2 || a.c.Stats().OutboxDropped != 1 {
		t.Fatalf("outbox %q, %+v", got, a.c.Stats())
	}
	if err := a.c.Send(make([]byte, e2e.MaxBody)); err != nil {
		t.Fatal(err)
	}
}

// a body given back takes its place by the order of Send
func TestGiveBackKeepsTheOrderOfSend(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	a.send(t, "1", "2", "3", "4")
	one, two := a.c.takeBody(), a.c.takeBody()
	three := a.c.takeBody()
	a.c.giveBack(two)
	a.c.giveBack(three)
	a.c.giveBack(one)
	if got := a.outbox(); strings.Join(got, "") != "1234" {
		t.Fatalf("outbox %q", got)
	}
}

func TestDefaults(t *testing.T) {
	if DefaultWindow != 16 || DefaultKeepalive != 30*time.Second || DefaultStaleAfter != 90*time.Second ||
		DefaultReplyTimeout != 10*time.Second || DefaultRebuildFor != 10*time.Minute || DefaultMaxRefusals != 3 ||
		DefaultOutbox != 256 || DefaultHold != 16 || DefaultInbox != 256 ||
		firstPause != time.Second || maxPause != time.Minute || replyBuffer != 256 {
		t.Fatal("the documented values changed")
	}
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, _ := parties(t, p)
	a := n.join("a", pi, 1, 1, nil)
	cfg := a.c.cfg
	if cfg.Window != 16 || cfg.Keepalive != DefaultKeepalive || cfg.StaleAfter != DefaultStaleAfter ||
		cfg.ReplyTimeout != DefaultReplyTimeout || cfg.RebuildFor != DefaultRebuildFor || cfg.MaxRefusals != 3 ||
		cfg.Outbox != 256 || cfg.Hold != 16 || cfg.Inbox != 256 || cap(a.c.messages) != 256 {
		t.Fatalf("%+v", cfg)
	}
	// 90 s of fetches every 200 ms
	if a.c.opts.StaleFetches != 450 || a.c.opts.Now == nil {
		t.Fatalf("session options %+v", a.c.opts)
	}
}

func TestStartRefusesABadConfig(t *testing.T) {
	p := c25519(t)
	n := newNet(t, p, nil)
	pi, other := parties(t, p)
	zero, err := secmem.New(mailbox.CapSize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(zero.Release)
	short, err := secmem.New(mailbox.CapSize - 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(short.Release)
	small := n.circuit(1, 1)
	small.payload = mailbox.RequestSize - 1
	gostSelf := newParty(t, mustSuite(t, jcrypto.SuiteGOST))

	good := func() Config {
		return Config{Provider: p, Self: pi.id, Fetch: pi.f, First: n.circuit(1, 1), Dial: func() (Circuit, error) { return nil, errors.New("no") }, Rate: testRate}
	}
	for _, c := range []struct {
		name   string
		change func(*Config)
	}{
		{"no provider", func(c *Config) { c.Provider = nil }},
		{"no identity", func(c *Config) { c.Self = nil }},
		{"no capability", func(c *Config) { c.Fetch = nil }},
		{"no circuit", func(c *Config) { c.First = nil }},
		{"no Dial", func(c *Config) { c.Dial = nil }},
		{"no rate", func(c *Config) { c.Rate = 0 }},
		{"a circuit too small for a request", func(c *Config) { c.First = small }},
		{"another capability than the card's", func(c *Config) { c.Fetch = other.f }},
		{"a zero capability", func(c *Config) { c.Fetch = zero }},
		{"a short capability", func(c *Config) { c.Fetch = short }},
		{"an identity of another suite", func(c *Config) { c.Self = gostSelf.id }},
		{"a keepalive as long as the stale bound", func(c *Config) { c.Keepalive, c.StaleAfter = time.Minute, time.Minute }},
		{"a reply timeout past the reply buffer", func(c *Config) { c.ReplyTimeout = 255 * testRate }},
	} {
		cfg := good()
		c.change(&cfg)
		if conv, err := Start(cfg); err == nil {
			conv.Close()
			t.Fatalf("%s: started", c.name)
		}
	}
	cfg := good()
	cfg.ReplyTimeout = 254 * testRate
	conv, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	conv.Close()
	if conv.Err() != nil {
		t.Fatalf("Err after Close: %v", conv.Err())
	}
}
