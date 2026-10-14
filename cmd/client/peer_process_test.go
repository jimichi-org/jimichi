package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

// a client process started by the tests below takes these in place of a
// minute between counter lines and 10 min of failed rebuilds
const (
	reportEveryVar = "JIMICHI_TEST_REPORT_EVERY"
	rebuildForVar  = "JIMICHI_TEST_REBUILD_FOR"
)

func init() {
	for name, v := range map[string]*time.Duration{reportEveryVar: &reportEvery, rebuildForVar: &rebuildFor} {
		s := os.Getenv(name)
		if s == "" {
			continue
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			panic(err)
		}
		*v = d
	}
}

// two -peer clients as processes of their own, the test binary running main,
// over three relays of this process: the last keeps the mailbox, and one info
// server hands out the unsigned bundles of all three for whichever entry a
// client draws

// the relays forward at once, so the round trip of one request on an idle bed
// is the work it costs along the chain, tens of times more with GOST in pure
// Go than with X25519 under the race detector, which the clients run under as
// well, beside the tests of other packages. Clients that ask faster than the
// bed works queue their requests in the relays until replies time out, and a
// client whose messages come faster than its requests carry them queues them
// in its outbox ahead of its answers to the other one. So the rate follows a
// measured round trip, a message takes several ticks, and a wait counts the
// requests the clients made against the ticks the protocol needs
const (
	probes = 5
	// two clients, each request about a round trip of work: a rate of four
	// round trips keeps the bed at half a core
	rateOverRoundTrip = 4
	// above conversation.MinRate of the client's reply timeout
	minPeerRate = 50 * time.Millisecond
	// a message every this many ticks leaves the ticks between to the answers
	// to the other client and the copies of sticky records
	messageTicks = 4
	// kk1, kk2 and the initiator's confirming record
	handshakeLegs = 3
	// how many times the ticks a wait needs the test gives it before it calls
	// the clients stuck, and the wall time no wait goes past
	slack   = 5
	maxWait = 2 * time.Minute
)

type peerBed struct {
	p        jcrypto.CryptoProvider
	addrs    []string
	nodes    []client.Node
	store    *mailbox.Store
	infoPort string
	info     *infoServer
	relays   []*relay.Relay
	lns      []net.Listener
	// the slowest round trip of the probe, the build of its circuit, and the
	// request period they give
	roundTrip, build, rate time.Duration
	// the introduced clients, whose fetches at the mailbox count their ticks
	talkers []talker

	mu sync.Mutex
	// requests that fetch, per queue, and every fetch capability the mailbox saw
	fetches map[[mailbox.IDSize]byte]int
	caps    map[[mailbox.CapSize]byte]bool
}

type talker struct {
	pr    *peerProc
	queue [mailbox.IDSize]byte
}

func newPeerBed(t *testing.T, s jcrypto.Suite) *peerBed {
	t.Helper()
	p := provider(t, s)
	store, err := mailbox.NewStore(p, mailbox.DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	bed := &peerBed{
		p: p, store: store,
		fetches: make(map[[mailbox.IDSize]byte]int), caps: make(map[[mailbox.CapSize]byte]bool),
	}
	var bundles [][]byte
	for i := range 3 {
		var deliver relay.Deliver
		if i == 2 {
			deliver = bed.deliver
		}
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
		b, err := pki.Unsigned(p, pub, pub)
		if err != nil {
			t.Fatal(err)
		}
		bed.addrs = append(bed.addrs, ln.Addr().String())
		bed.nodes = append(bed.nodes, client.Node{Addr: ln.Addr().String(), StaticPub: pub})
		bed.relays = append(bed.relays, r)
		bed.lns = append(bed.lns, ln)
		bundles = append(bundles, b)
	}
	info, at := serveInfo(t, nil)
	m := mirrorOf(t, bed.addrs, bundles)
	info.mirror.Store(&m)
	_, port, err := net.SplitHostPort(at)
	if err != nil {
		t.Fatal(err)
	}
	bed.info, bed.infoPort = info, port
	bed.measure(t)
	t.Cleanup(func() { t.Logf("bed: %s", bed.report()) })
	return bed
}

// a probe circuit through the chain of the listed order sends one request at a
// time; a request that asks for nothing costs the mailbox the same hash as any
// other and counts as no fetch
func (bed *peerBed) measure(t *testing.T) {
	t.Helper()
	start := time.Now()
	cl, err := client.Dial(client.Config{Provider: bed.p, Chain: bed.nodes})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	bed.build = time.Since(start)
	for i := range probes {
		req := mailbox.Request{Tag: uint16(i)}
		start := time.Now()
		if err := cl.Send(req.Bytes()); err != nil {
			t.Fatal(err)
		}
		select {
		case _, ok := <-cl.Replies():
			if !ok {
				t.Fatalf("the probe circuit ended: %v", cl.Refused())
			}
		case <-time.After(time.Minute):
			t.Fatal("no reply to the probe")
		}
		bed.roundTrip = max(bed.roundTrip, time.Since(start))
	}
	bed.rate = max(minPeerRate, rateOverRoundTrip*bed.roundTrip)
}

// the counter lines of a client every two ticks
func (bed *peerBed) reportEvery() time.Duration { return 2 * bed.rate }

func ticksOf(d, rate time.Duration) uint64 { return uint64((d + rate - 1) / rate) }

// a leg takes a record from one client to the other: a tick for its sender to
// put it, a round trip, and a tick for the first fetch of the other one to
// pass it at the mailbox
func (bed *peerBed) legs(n int) uint64 {
	return uint64(n) * (2 + ticksOf(bed.roundTrip, bed.rate))
}

// polls until done, counting the most requests either client made meanwhile
// at the mailbox, by the queue each fetches. A starved runner drops ticks of
// the clients' tickers as it slows the bed, so wall time says little about the
// protocol, while a client that keeps asking past slack times the ticks a wait
// needs is stuck. A wait in which neither client asks ends at slack squared
// times the ticks it needs in wall time, and none goes past maxWait, so a
// stuck pair fails with the logs and the report before the test times out
func (bed *peerBed) wait(t *testing.T, what string, need uint64, done func() bool) {
	t.Helper()
	from := make([]int, len(bed.talkers))
	for i, tk := range bed.talkers {
		from[i] = bed.fetchesOf(tk.queue)
	}
	start := time.Now()
	deadline := start.Add(min(time.Duration(slack*slack*need)*bed.rate, maxWait))
	poll := time.NewTicker(min(bed.rate, 100*time.Millisecond))
	defer poll.Stop()
	for {
		var n uint64
		for i, tk := range bed.talkers {
			n = max(n, uint64(bed.fetchesOf(tk.queue)-from[i]))
		}
		if done() {
			t.Logf("%s: %d ticks of %d allowed, %v", what, n, slack*need, time.Since(start).Round(time.Millisecond))
			return
		}
		for _, tk := range bed.talkers {
			if tk.pr.exited() {
				t.Fatalf("%s exited before %s", tk.pr.name, what)
			}
		}
		if n > slack*need || time.Now().After(deadline) {
			t.Fatalf("%s: not in %d ticks and %v, %d ticks needed", what, n, time.Since(start).Round(time.Millisecond), need)
		}
		<-poll.C
	}
}

func (bed *peerBed) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "rate %v, round trip %v, build %v", bed.rate, bed.roundTrip, bed.build)
	for _, tk := range bed.talkers {
		fmt.Fprintf(&b, "\nrequests of %s at the mailbox: %d", tk.pr.name, bed.fetchesOf(tk.queue))
	}
	fmt.Fprintf(&b, "\nmailbox: %+v", bed.store.Stats())
	return b.String()
}

// the mailbox of the last relay, with the fetches counted on the way in: the
// store zeroes the request
func (bed *peerBed) deliver(circuit uint64, payload []byte) []byte {
	if req, err := mailbox.ParseRequest(payload); err == nil && req.Fetches() {
		if queue, err := mailbox.QueueID(bed.p, req.Fetch[:]); err == nil {
			bed.mu.Lock()
			bed.fetches[queue]++
			bed.caps[req.Fetch] = true
			bed.mu.Unlock()
		}
	}
	return bed.store.Deliver(circuit, payload)
}

func (bed *peerBed) fetchesOf(queue [mailbox.IDSize]byte) int {
	bed.mu.Lock()
	defer bed.mu.Unlock()
	return bed.fetches[queue]
}

func (bed *peerBed) capabilities() [][]byte {
	bed.mu.Lock()
	defer bed.mu.Unlock()
	var out [][]byte
	for f := range bed.caps {
		out = append(out, f[:])
	}
	return out
}

// every relay stops and closes its links, so no circuit can be built again
func (bed *peerBed) down() {
	for i, r := range bed.relays {
		r.Close()
		_ = bed.lns[i].Close()
	}
}

type peerProc struct {
	name string
	cmd  *exec.Cmd
	out  *logBuffer
	done chan struct{}
	// how long a line of the process may take in wall time: one written at
	// once, or a counter line of its report period
	patience time.Duration
}

var (
	ownHashLine = regexp.MustCompile(`(?m)^\S+ \S+ card_hash=([0-9a-f]{64})$`)
	adminLine   = regexp.MustCompile(`(?m) admin listening on (\S+)$`)
	stoppedLine = regexp.MustCompile(`(?m) e2e state=stopped requests=(\d+) `)
	sessionLine = regexp.MustCompile(`(?m) e2e state=(established|confirmed) requests=\d+ `)
)

func (bed *peerBed) start(t *testing.T, name string, env []string, extra ...string) *peerProc {
	t.Helper()
	args := []string{
		"-peer", "-nodes", strings.Join(bed.addrs, ","), "-mailbox", bed.addrs[2], "-hops", "3",
		"-mode", "fixed", "-rate", bed.rate.String(), "-info-port", bed.infoPort, "-suite", bed.p.Suite().String(),
		"-auth=false", "-admin", "127.0.0.1:0",
	}
	pr := startClient(t, name, env, append(args, extra...)...)
	pr.patience = max(pr.patience, 4*bed.reportEvery())
	return pr
}

func startClient(t *testing.T, name string, env []string, args ...string) *peerProc {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, args...)
	cmd.Env = append(append(os.Environ(), asClient+"=1"), env...)
	pr := &peerProc{name: name, cmd: cmd, out: &logBuffer{}, done: make(chan struct{}), patience: time.Minute}
	cmd.Stdout, cmd.Stderr = pr.out, pr.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = cmd.Wait()
		close(pr.done)
	}()
	t.Cleanup(func() {
		ended := "killed by the test"
		select {
		case <-pr.done:
			ended = cmd.ProcessState.String()
		default:
			_ = cmd.Process.Kill()
			<-pr.done
		}
		if t.Failed() {
			out := pr.out.String()
			t.Logf("%s, %s, %d bytes of output:\n%s", name, ended, len(out), out)
		}
	})
	return pr
}

func (pr *peerProc) exited() bool {
	select {
	case <-pr.done:
		return true
	default:
		return false
	}
}

// waits for the output to satisfy found
func (pr *peerProc) await(t *testing.T, what string, found func(string) bool) string {
	t.Helper()
	for limit := time.Now().Add(pr.patience); ; time.Sleep(20 * time.Millisecond) {
		out := pr.out.String()
		if found(out) {
			return out
		}
		if pr.exited() {
			t.Fatalf("%s exited before %s", pr.name, what)
		}
		if time.Now().After(limit) {
			t.Fatalf("%s: no %s", pr.name, what)
		}
	}
}

// waits for the process to exit and returns its code
func (pr *peerProc) exit(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case <-pr.done:
	case <-time.After(within):
		t.Fatalf("%s did not exit", pr.name)
	}
	return pr.cmd.ProcessState.ExitCode()
}

// the operator's stop: SIGTERM, which the process answers with code 0. Windows
// has no such signal to send
func (pr *peerProc) terminate(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	if err := pr.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := pr.exit(t, 30*time.Second); code != 0 || !strings.Contains(pr.out.String(), " shutting down\n") {
		t.Fatalf("%s: exit code %d after SIGTERM, want 0 and the line of the shutdown:\n%s", pr.name, code, pr.out.String())
	}
}

func (pr *peerProc) admin(t *testing.T) string {
	t.Helper()
	out := pr.await(t, "admin listener", adminLine.MatchString)
	return adminLine.FindStringSubmatch(out)[1]
}

func httpCall(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(text)
}

// the card a client hands out, checked against the one card_hash line it
// printed before its admin listener
func (pr *peerProc) card(t *testing.T, p jcrypto.CryptoProvider) (string, string) {
	t.Helper()
	admin := pr.admin(t)
	out := pr.out.String()
	hashes := ownHashLine.FindAllStringSubmatch(out, -1)
	if len(hashes) != 1 || strings.Index(out, "card_hash=") > strings.Index(out, "admin listening") {
		t.Fatalf("%s: %d card_hash lines, want one before the admin listener:\n%s", pr.name, len(hashes), out)
	}
	code, text := httpCall(t, http.MethodGet, "http://"+admin+"/card", "")
	if code != http.StatusOK {
		t.Fatalf("%s: GET /card = %d", pr.name, code)
	}
	text = strings.TrimSuffix(text, "\n")
	card, err := e2e.ParseCard(text)
	if err != nil {
		t.Fatalf("%s: the card does not parse: %v", pr.name, err)
	}
	h, err := e2e.CardHash(p, card)
	if err != nil || hex.EncodeToString(h) != hashes[0][1] {
		t.Fatalf("%s: the card hashes to %x, the log says %s", pr.name, h, hashes[0][1])
	}
	return text, hashes[0][1]
}

func roundTrips(out string) int { return strings.Count(out, " e2e round trip in ") }

// introduces two clients the way scripts/introduce.sh does; from here on the
// waits of the bed count their ticks
func (bed *peerBed) introduce(t *testing.T, a, b *peerProc) (cardA, hashA, cardB, hashB string) {
	t.Helper()
	cardA, hashA = a.card(t, bed.p)
	cardB, hashB = b.card(t, bed.p)
	bed.talkers = []talker{{a, queueOf(t, cardA)}, {b, queueOf(t, cardB)}}
	for _, put := range []struct {
		to   *peerProc
		card string
	}{{a, cardB}, {b, cardA}, {a, cardB}} {
		if code, _ := httpCall(t, http.MethodPut, "http://"+put.to.admin(t)+"/contact", put.card); code != http.StatusNoContent {
			t.Fatalf("%s: PUT /contact = %d", put.to.name, code)
		}
	}
	a.await(t, "the pinned line", func(out string) bool { return strings.Contains(out, " contact pinned card_hash="+hashB+" role=") })
	b.await(t, "the pinned line", func(out string) bool { return strings.Contains(out, " contact pinned card_hash="+hashA+" role=") })
	return cardA, hashA, cardB, hashB
}

// every form a value could take in a line of text
func encodings(b []byte) []string {
	return []string{
		hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
		base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
	}
}

// every node of the bed listens on loopback, so a node shows in a line by its
// port and not by its host
func logsAnAddress(out string, addrs []string) bool {
	for _, addr := range addrs {
		if strings.Contains(out, addr) {
			return true
		}
	}
	return false
}

func queueOf(t *testing.T, card string) [mailbox.IDSize]byte {
	t.Helper()
	c, err := e2e.ParseCard(card)
	if err != nil {
		t.Fatal(err)
	}
	return c.Queue
}

// a sends two messages and answers, b sends without end and answers: a's
// round trips stop at -count while b's go on, so a keeps fetching and
// answering past its last message, and both write their counter lines.
// Another card at b stops it: 409 on every request, one line, no request at
// the mailbox for its queue from then on, counter lines with state=stopped and
// the same number of requests, and the process stays up until SIGTERM. Neither
// card, F, a queue, the text nor a node address reaches the output
func TestPeersTalkAsProcesses(t *testing.T) {
	suites := []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}
	if testing.Short() {
		// the checks of the output are the same for both suites
		suites = suites[:1]
	}
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			bed := newPeerBed(t, s)
			plain := []string{"-harden=false", "-keymem", "none", "-message", "secret text"}
			interval := (messageTicks * bed.rate).String()
			env := []string{reportEveryVar + "=" + bed.reportEvery().String()}
			a := bed.start(t, "a", env, append(plain, "-interval", interval, "-count", "2", "-respond")...)
			b := bed.start(t, "b", env, append(plain, "-interval", interval, "-count", "0", "-respond")...)
			cardA, hashA, cardB, _ := bed.introduce(t, a, b)

			// the handshake, a's first message and b's answer; the second message
			// goes a tick later, and an answer may wait for a message of b's own
			bed.wait(t, "two round trips of a", bed.legs(handshakeLegs+2)+1+messageTicks, func() bool {
				return roundTrips(a.out.String()) >= 2
			})
			seen := roundTrips(b.out.String())
			bed.wait(t, "round trips of b past a's count", bed.legs(2)+3*messageTicks, func() bool {
				return roundTrips(b.out.String()) >= seen+3
			})
			// a third message of a would have come back meanwhile
			if got := roundTrips(a.out.String()); got != 2 {
				t.Fatalf("a logged %d round trips with -count 2", got)
			}
			a.await(t, "a counter line of the session", sessionLine.MatchString)

			other := newPeerID(t, bed.p, bed.addrs[2]).card.String()
			admin := b.admin(t)
			if code, _ := httpCall(t, http.MethodPut, "http://"+admin+"/contact", other); code != http.StatusConflict {
				t.Fatalf("another card: %d", code)
			}
			refusal := " contact card changed, refusing: pinned card_hash=" + hashA + "\n"
			b.await(t, "the refusal", func(out string) bool { return strings.Contains(out, refusal) })
			for _, req := range [][2]string{{http.MethodGet, "/card"}, {http.MethodPut, "/contact"}} {
				if code, _ := httpCall(t, req[0], "http://"+admin+req[1], cardA); code != http.StatusConflict {
					t.Fatalf("stopped: %s %s = %d", req[0], req[1], code)
				}
			}
			stopped := func(out string) [][]string {
				return stoppedLine.FindAllStringSubmatch(out[strings.Index(out, refusal):], -1)
			}
			out := b.await(t, "two counter lines of the stopped state", func(out string) bool { return len(stopped(out)) >= 2 })
			if lines := stopped(out); lines[0][1] != lines[1][1] {
				t.Fatalf("the stopped client went on with its requests: %s, then %s", lines[0][1], lines[1][1])
			}
			queueA, queueB := queueOf(t, cardA), queueOf(t, cardB)
			fetchedA, fetchedB := bed.fetchesOf(queueA), bed.fetchesOf(queueB)
			// requests of a, so that the count of b proves something
			const ticks = 10
			bed.wait(t, "requests of a beside the stopped b", ticks, func() bool {
				return bed.fetchesOf(queueA) >= fetchedA+ticks
			})
			if got := bed.fetchesOf(queueB); got != fetchedB {
				t.Fatalf("the mailbox took %d more requests for the queue of the stopped client", got-fetchedB)
			}
			if b.exited() {
				t.Fatal("the stopped client exited")
			}

			secrets := []string{cardA, cardB, other, "secret text"}
			for _, card := range []string{cardA, cardB, other} {
				c, err := e2e.ParseCard(card)
				if err != nil {
					t.Fatal(err)
				}
				secrets = append(secrets, card[strings.Index(card, ":")+1:])
				secrets = append(secrets, encodings(c.Static)...)
				secrets = append(secrets, encodings(c.Queue[:])...)
			}
			caps := bed.capabilities()
			if len(caps) != 2 {
				t.Fatalf("the mailbox saw %d fetch capabilities, want one per client", len(caps))
			}
			for _, f := range caps {
				secrets = append(secrets, encodings(f)...)
			}
			for _, pr := range []*peerProc{a, b} {
				out := pr.out.String()
				for _, secret := range secrets {
					if strings.Contains(out, secret) {
						t.Fatalf("%s logged %q:\n%s", pr.name, secret, out)
					}
				}
				if logsAnAddress(out, bed.addrs) {
					t.Fatalf("%s logged a node address:\n%s", pr.name, out)
				}
			}
			if st := bed.store.Stats(); st.Puts == 0 || st.Hits == 0 || st.Bad != 0 {
				t.Fatalf("mailbox %+v", st)
			}
			a.terminate(t)
			b.terminate(t)
		})
	}
}

// a refusal of the flags is code 2 and comes before any request
func TestPeerFlagRefusalIsCodeTwoBeforeTheNetwork(t *testing.T) {
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	for _, c := range []struct {
		name  string
		extra []string
	}{
		{"one hop", []string{"-hops", "1"}},
		{"admin on all addresses", []string{"-admin", "0.0.0.0:9201"}},
		{"immediate mode", []string{"-mode", "immediate"}},
		{"jitter as long as the rate", []string{"-jitter", "50ms"}},
		{"a mailbox off the list", []string{"-mailbox", "127.0.0.1:1"}},
		{"a long message", []string{"-message", strings.Repeat("m", maxText+1)}},
		{"a bad keymem", []string{"-keymem", "everything"}},
	} {
		extra := c.extra
		t.Run(c.name, func(t *testing.T) {
			pr := bed.start(t, "refused", nil, append([]string{"-harden=false", "-keymem", "none"}, extra...)...)
			if code := pr.exit(t, 30*time.Second); code != 2 {
				t.Fatalf("exit code %d, want 2:\n%s", code, pr.out.String())
			}
			if strings.Contains(pr.out.String(), "card_hash=") {
				t.Fatalf("an identity was made before the flags were checked:\n%s", pr.out.String())
			}
		})
	}
	if got := bed.info.requests.Load(); got != 0 {
		t.Fatalf("%d requests to the info port", got)
	}
}

// the first chain is drawn once the card_hash line is out, and a mirror the
// client cannot take is code 1 with a line that names no node
func TestPeerWithoutAChainExitsOne(t *testing.T) {
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	// a mirror without the mailbox
	m := *bed.info.mirror.Load()
	entries, err := pki.ParseMirror(m)
	if err != nil {
		t.Fatal(err)
	}
	short, err := pki.MarshalMirror(entries[:2])
	if err != nil {
		t.Fatal(err)
	}
	bed.info.mirror.Store(&short)
	pr := bed.start(t, "no chain", nil, "-harden=false", "-keymem", "none")
	code := pr.exit(t, 60*time.Second)
	out := pr.out.String()
	if code != 1 || !strings.Contains(out, "refusing to build the circuit: ") {
		t.Fatalf("exit code %d:\n%s", code, out)
	}
	if strings.Index(out, "card_hash=") < 0 || strings.Index(out, "card_hash=") > strings.Index(out, "refusing") {
		t.Fatalf("no card_hash line before the first chain:\n%s", out)
	}
	if logsAnAddress(out, bed.addrs) {
		t.Fatalf("the refusal names a node:\n%s", out)
	}
}

// a circuit that cannot be built again within the rebuild bound ends the
// conversation and the process with code 1; the line names no node
func TestPeerThatCannotRebuildExitsOne(t *testing.T) {
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	pr := bed.start(t, "alone", []string{rebuildForVar + "=2s"}, "-harden=false", "-keymem", "none")
	pr.admin(t)
	bed.down()
	code := pr.exit(t, 60*time.Second)
	out := pr.out.String()
	if code != 1 || !strings.Contains(out, " conversation ended: conversation: no new circuit in time\n") {
		t.Fatalf("exit code %d, want 1 and the end of the conversation:\n%s", code, out)
	}
	if !strings.Contains(out, " circuit rebuild failed: ") || logsAnAddress(out, bed.addrs) {
		t.Fatalf("no failed rebuild, or a line names a node:\n%s", out)
	}
}

// an entry played by the test that takes every circuit of a fixed chain and
// answers its first request with a reply nobody sealed, which the client
// refuses; the mailbox behind it is never reached
func refusingEntry(t *testing.T, p jcrypto.CryptoProvider) (addrs []string, infoPort string, circuits *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	linkPriv, linkPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(linkPriv.Release)
	circuits = new(atomic.Int32)
	serve := func(raw net.Conn) {
		defer raw.Close()
		conn, err := link.Accept(raw, p, linkPriv, linkPub, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var setup, cell wire.Cell
		if conn.ReadCell(&setup) != nil {
			return
		}
		hdr, err := setup.Header()
		if err != nil || conn.ReadCell(&cell) != nil {
			return
		}
		circuits.Add(1)
		reply, err := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: hdr.Circuit}, make([]byte, wire.BodySize))
		if err != nil || conn.WriteCell(reply) != nil {
			return
		}
		for conn.ReadCell(&cell) == nil {
		}
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(raw)
		}
	}()

	addrs = []string{ln.Addr().String(), "127.0.0.2:9000", "127.0.0.3:9000"}
	bundles := make([][]byte, len(addrs))
	for i := range addrs {
		linkKey := agreementKey(t, p)
		if i == 0 {
			linkKey = linkPub
		}
		if bundles[i], err = pki.Unsigned(p, linkKey, agreementKey(t, p)); err != nil {
			t.Fatal(err)
		}
	}
	info, at := serveInfo(t, nil)
	mirror := mirrorOf(t, addrs, bundles)
	info.mirror.Store(&mirror)
	_, infoPort, err = net.SplitHostPort(at)
	if err != nil {
		t.Fatal(err)
	}
	return addrs, infoPort, circuits
}

// three refused replies end the conversation and the process with code 3,
// each circuit rebuilt through the same entry in between
func TestPeerWithRefusedRepliesExitsThree(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	addrs, infoPort, circuits := refusingEntry(t, p)
	pr := startClient(t, "refused", nil,
		"-peer", "-nodes", strings.Join(addrs, ","), "-fixed-chain", "-mailbox", addrs[2], "-hops", "3",
		"-mode", "fixed", "-rate", "50ms", "-info-port", infoPort, "-suite", p.Suite().String(),
		"-auth=false", "-harden=false", "-keymem", "none", "-admin", "127.0.0.1:0")
	code := pr.exit(t, 60*time.Second)
	out := pr.out.String()
	if code != 3 || !strings.Contains(out, " conversation ended: conversation: too many replies refused\n") {
		t.Fatalf("exit code %d, want 3 and the end of the conversation:\n%s", code, out)
	}
	if got := strings.Count(out, " circuit closed: client: reply refused: did not open\n"); got != 3 || circuits.Load() != 3 {
		t.Fatalf("%d refusals logged over %d circuits, want 3 of each:\n%s", got, circuits.Load(), out)
	}
	if got := strings.Count(out, " circuit rebuilt through the same entry\n"); got != 2 || logsAnAddress(out, addrs) {
		t.Fatalf("%d rebuilds logged, want 2 and no node address:\n%s", got, out)
	}
}

// SIGTERM ends a client that waits for its contact with code 0
func TestPeerExitsZeroOnSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM to send on windows")
	}
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	pr := bed.start(t, "alone", nil, "-harden=false", "-keymem", "none")
	pr.admin(t)
	pr.terminate(t)
}
