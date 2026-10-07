//go:build linux

package main

import (
	"bufio"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

// bounds the locked memory of this process until the test ends. Only the soft
// limit moves, and it can be raised back without a capability
func boundMemlock(t *testing.T, limit uint64) {
	t.Helper()
	var was unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
		t.Fatal(err)
	}
	lim := unix.Rlimit{Cur: min(limit, was.Max), Max: was.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
			t.Errorf("RLIMIT_MEMLOCK not restored: %v", err)
		}
	})
}

func protectedPolicy(t *testing.T) {
	t.Helper()
	before := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secmem.SetPolicy(before) })
}

// takes every page that can still be locked, as the circuits of a busy node
// do, and gives them back when the test ends; a process that may lock without
// the bound, with CAP_IPC_LOCK, has nothing to measure
func useUpLockedMemory(t *testing.T, bound uint64) []*secmem.Buffer {
	t.Helper()
	var taken []*secmem.Buffer
	t.Cleanup(func() {
		for _, b := range taken {
			b.Release()
		}
	})
	for uint64(len(taken)) <= bound/uint64(os.Getpagesize()) {
		b, err := secmem.New(1)
		if err != nil {
			return taken
		}
		taken = append(taken, b)
	}
	t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
	return nil
}

// with locked memory used up to the last page, the pages a rotating node holds
// make room for the next key and its pair check, and the release of the
// replaced key takes them again when the rotation could not
func TestHeldPagesCoverARotationWithLockedMemoryUsedUp(t *testing.T) {
	const bound = 1 << 20
	protectedPolicy(t)
	boundMemlock(t, bound)
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			linkPriv, link, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			linkPriv.Release()
			priv, pub, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			if !priv.Locked() {
				t.Fatal("the onion key is not locked")
			}
			ring, err := relay.NewOnionRing(p, priv, pub, 0)
			if err != nil {
				t.Fatal(err)
			}
			clk := &clock{now: t0}
			var out logBuffer
			n := &node{p: p, link: link, ttl: time.Hour, now: clk.Now, logger: log.New(&out, "", 0)}
			n.onion = newOnionKeys(ring, 3*time.Hour, time.Hour, true, clk.Now())
			n.onion.hold()
			t.Cleanup(n.closeOnion)
			if n.onion.reserve == nil {
				t.Fatal("no pages held before the locked memory is used up")
			}
			rotated := func(want uint32, when string) {
				t.Helper()
				if epoch, _ := ring.Current(); epoch != want || n.onion.failures.Load() != 0 {
					t.Fatalf("%s: epoch %d, want %d: %q", when, epoch, want, out.String())
				}
			}

			if len(useUpLockedMemory(t, bound)) == 0 {
				t.Fatal("the bound left no page to take: the test measures nothing")
			}
			clk.advance(3 * time.Hour)
			n.rotateIfDue()
			rotated(1, "the first rotation with no page left")

			clk.advance(n.onion.grace)
			n.rotateIfDue()
			rotated(1, "the release of the replaced key")
			if n.onion.reserve == nil {
				t.Fatal("the release of the replaced key took no pages for the next rotation")
			}

			useUpLockedMemory(t, bound)
			clk.advance(3*time.Hour - n.onion.grace)
			n.rotateIfDue()
			rotated(2, "the rotation after the release, with no page left again")
		})
	}
}

// a node started with room for its two keys and the held pages and nothing more
// starts: the pair check of the link key runs before the pages are held, and
// with them held first it would find no room. Those held pages then make the
// first rotation with no page left to lock
func TestStartingNodeHoldsItsPagesAfterThePairChecks(t *testing.T) {
	const bound = 1 << 20
	protectedPolicy(t)
	boundMemlock(t, bound)
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			taken := useUpLockedMemory(t, bound)
			// the link key, the onion key and the held pages
			const room = 2 + rotationPages
			if len(taken) < room {
				t.Fatalf("%d pages taken, want at least %d to give back", len(taken), room)
			}
			for _, b := range taken[:room] {
				b.Release()
			}

			clk := &clock{now: time.Now()}
			var out logBuffer
			stop := make(chan os.Signal, 1)
			returned := make(chan error, 1)
			cfg := config{
				listen: "127.0.0.1:0", info: "127.0.0.1:0", stats: "127.0.0.1:0",
				descriptorTTL: time.Hour, onionRotate: time.Hour, lock: true, now: clk.Now,
			}
			go func() { returned <- serveNode(p, cfg, log.New(&out, "", 0), stop) }()
			defer func() {
				stop <- os.Interrupt
				if err := <-returned; err != nil {
					t.Errorf("serveNode: %v", err)
				}
			}()
			waitFor := func(what string, found func(string) bool) {
				t.Helper()
				for limit := time.Now().Add(10 * time.Second); !found(out.String()); time.Sleep(10 * time.Millisecond) {
					select {
					case err := <-returned:
						returned <- err
						t.Fatalf("%s: the node stopped: %v\n%s", what, err, out.String())
					default:
					}
					if time.Now().After(limit) {
						t.Fatalf("%s:\n%s", what, out.String())
					}
				}
			}
			waitFor("the node did not start", listening.MatchString)

			useUpLockedMemory(t, bound)
			clk.advance(time.Hour)
			waitFor("the node did not try to rotate", func(log string) bool {
				return strings.Contains(log, "onion key rotated epoch=1\n") || strings.Contains(log, "onion key rotation: ")
			})
			if strings.Contains(out.String(), "onion key rotation: ") {
				t.Fatalf("the first rotation found no held pages:\n%s", out.String())
			}
		})
	}
}

// a limit just under the minimum is refused by the minimum before any key is
// made, and not by whichever allocation of the start found no room first
func TestNodeUnderTheMemlockMinimumNamesTheLimit(t *testing.T) {
	protectedPolicy(t)
	boundMemlock(t, minMemlock-1)
	// a node that went on would fail here and not at the minimum
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		var out logBuffer
		cfg := config{
			listen: taken.Addr().String(), info: "127.0.0.1:0", stats: "127.0.0.1:0",
			descriptorTTL: time.Hour, onionRotate: time.Hour, lock: true,
		}
		err = serveNode(noKeys{p, t}, cfg, log.New(&out, "", 0), make(chan os.Signal))
		if err == nil || !strings.Contains(err.Error(), "RLIMIT_MEMLOCK is") || errors.Is(err, secmem.ErrNotLocked) {
			t.Fatalf("%s: serveNode under the minimum: %v\n%s", s, err, out.String())
		}
		if out.String() != "" {
			t.Fatalf("%s: a node refused by the minimum logged %q", s, out.String())
		}
	}
}

// the classes a failed rotation is logged as are those of the errors secmem
// returns, whatever the size asked for
func TestRotationClassOfMemoryFailures(t *testing.T) {
	protectedPolicy(t)
	b, err := secmem.New(math.MaxInt / 2)
	if err == nil {
		b.Release()
		t.Skip("the mapping was granted here")
	}
	if got := rotationClass(err); got != secmem.ErrNotMapped.Error() {
		t.Fatalf("a failed mmap is logged as %q, want %q", got, secmem.ErrNotMapped)
	}
	boundMemlock(t, 0)
	for _, size := range []int{32, 64} {
		b, err := secmem.New(size)
		if err == nil {
			b.Release()
			t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
		}
		if got := rotationClass(err); got != secmem.ErrNotLocked.Error() {
			t.Fatalf("a failed mlock of %d bytes is logged as %q, want %q", size, got, secmem.ErrNotLocked)
		}
	}
}

// a provider that fails the test once a key is asked for
type noKeys struct {
	jcrypto.CryptoProvider
	t *testing.T
}

func (p noKeys) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	p.t.Error("a key was made before the memlock minimum was checked")
	return nil, nil, errors.New("no key")
}

const asBoundNode = "JIMICHI_TEST_AS_BOUND_NODE"

// the binary's minimum is enough for a rotating node to go through a rotation
// and serve a circuit with each of its two keys. The node runs in a process of
// its own, so the bound counts its pages alone and not those of the clients
func TestRotatingNodeRunsAtTheMemlockMinimum(t *testing.T) {
	if name := os.Getenv(asBoundNode); name != "" {
		runBoundNode(t, name)
		return
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max < minMemlock {
		t.Skipf("RLIMIT_MEMLOCK hard limit %d is below the minimum %d", lim.Max, minMemlock)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			var out logBuffer
			cmd := exec.Command(self, "-test.run=^TestRotatingNodeRunsAtTheMemlockMinimum$", "-test.v")
			cmd.Env = append(os.Environ(), asBoundNode+"="+s.String())
			cmd.Stdout, cmd.Stderr = &out, &out
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			defer func() {
				_ = input.Close()
				select {
				case err := <-exited:
					if err != nil {
						t.Errorf("the node process: %v\n%s", err, out.String())
					}
				case <-time.After(10 * time.Second):
					_ = cmd.Process.Kill()
					t.Errorf("the node process did not stop:\n%s", out.String())
				}
			}()

			logged := func(what string, found func(string) bool) {
				t.Helper()
				for limit := time.Now().Add(10 * time.Second); !found(out.String()); time.Sleep(10 * time.Millisecond) {
					if strings.Contains(out.String(), "--- SKIP") {
						t.Skipf("the node process skipped:\n%s", out.String())
					}
					if time.Now().After(limit) {
						t.Fatalf("%s:\n%s", what, out.String())
					}
				}
			}
			logged("the node did not start", listening.MatchString)
			addrs := listening.FindStringSubmatch(out.String())
			cells, info := addrs[1], addrs[2]
			read := func() pki.Verified {
				t.Helper()
				code, bundle := call(t, http.MethodGet, "http://"+info+"/descriptor", nil)
				if code != http.StatusOK {
					t.Fatalf("GET /descriptor = %d", code)
				}
				nodes, err := pki.Unverified(p, []string{cells}, [][]byte{bundle})
				if err != nil {
					t.Fatal(err)
				}
				return nodes[0]
			}

			first := read()
			if _, err := io.WriteString(input, "\n"); err != nil {
				t.Fatal(err)
			}
			logged("the node did not rotate", func(log string) bool {
				return strings.Contains(log, "onion key rotated epoch=1\n") || strings.Contains(log, "onion key rotation: ")
			})
			var next pki.Verified
			for wait := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if next = read(); next.Epoch == 1 {
					break
				}
				if time.Now().After(wait) {
					t.Fatalf("the node serves epoch %d after its rotation:\n%s", next.Epoch, out.String())
				}
			}
			for _, onion := range [][]byte{next.OnionPub, first.OnionPub} {
				cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{{Addr: cells, StaticPub: onion, LinkPub: next.LinkPub}}})
				if err != nil {
					t.Fatalf("Dial: %v\n%s", err, out.String())
				}
				_ = cl.Send([]byte("ping"))
				select {
				case reply, open := <-cl.Replies():
					if !open || string(reply) != "ping" {
						t.Fatalf("no echo at the minimum:\n%s", out.String())
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("the circuit neither answered nor closed:\n%s", out.String())
				}
				cl.Close()
			}
			if strings.Contains(out.String(), "secmem: ") || strings.Contains(out.String(), "onion key rotation: ") {
				t.Fatalf("the node ran short of locked memory:\n%s", out.String())
			}
		})
	}
}

// a line on standard input moves the clock of the node by an hour, the end of
// the input stops it
func runBoundNode(t *testing.T, name string) {
	s, err := suite.Parse(name)
	if err != nil {
		t.Fatal(err)
	}
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	lim.Cur = minMemlock
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	if err := checkMemlock(); err != nil {
		t.Fatal(err)
	}
	probe, err := secmem.New(minMemlock + 1)
	if err == nil {
		probe.Release()
		t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
	}

	clk := &clock{now: time.Now()}
	stop := make(chan os.Signal, 1)
	go func() {
		in := bufio.NewScanner(os.Stdin)
		for in.Scan() {
			clk.advance(time.Hour)
		}
		stop <- os.Interrupt
	}()
	cfg := config{
		listen: "127.0.0.1:0", info: "127.0.0.1:0", stats: "127.0.0.1:0", echo: true,
		descriptorTTL: time.Hour, onionRotate: time.Hour, lock: true, now: clk.Now,
	}
	if err := serveNode(p, cfg, log.New(os.Stdout, "", 0), stop); err != nil {
		t.Fatalf("serveNode: %v", err)
	}
}
