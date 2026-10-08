//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// a client process started by the tests below runs main under the soft limit
// this names; it is set before main starts, as a pod's limit would be
const asBoundClient = "JIMICHI_TEST_MEMLOCK"

func init() {
	v := os.Getenv(asBoundClient)
	if v == "" {
		return
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		panic(err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		panic(err)
	}
	lim.Cur = min(n, lim.Max)
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		panic(err)
	}
}

// a process that may lock without the bound, with CAP_IPC_LOCK, has nothing
// to measure: one page under a soft limit of one page must not lock twice
func lockingIsBounded(t *testing.T) bool {
	t.Helper()
	var was unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
		t.Fatal(err)
	}
	if was.Max < minPeerMemlock {
		t.Skipf("RLIMIT_MEMLOCK hard limit %d is below the minimum %d", was.Max, minPeerMemlock)
	}
	before := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secmem.SetPolicy(before) }()
	page := uint64(os.Getpagesize())
	lim := unix.Rlimit{Cur: page, Max: was.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
			t.Errorf("RLIMIT_MEMLOCK not restored: %v", err)
		}
	}()
	var taken []*secmem.Buffer
	defer func() {
		for _, b := range taken {
			b.Release()
		}
	}()
	for range 3 {
		b, err := secmem.New(1)
		if err != nil {
			return true
		}
		taken = append(taken, b)
	}
	return false
}

// two clients at the minimum of the binary, each in a process of its own with
// every key memory measure on: both start, are introduced, hold a handshake
// and talk without a page they could not lock
func TestPeersTalkAtTheMemlockMinimum(t *testing.T) {
	if !lockingIsBounded(t) {
		t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
	}
	suites := []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}
	if testing.Short() {
		suites = suites[:1]
	}
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			bed := newPeerBed(t, s)
			env := []string{asBoundClient + "=" + strconv.Itoa(minPeerMemlock)}
			a := bed.start(t, "a", env, "-interval", "100ms", "-count", "3", "-respond")
			b := bed.start(t, "b", env, "-interval", "100ms", "-count", "3", "-respond")
			introduce(t, bed.p, a, b)
			for _, pr := range []*peerProc{a, b} {
				pr.await(t, "three round trips", func(out string) bool { return roundTrips(out) >= 3 })
			}
			time.Sleep(200 * time.Millisecond)
			for _, pr := range []*peerProc{a, b} {
				out := pr.out.String()
				if pr.exited() || strings.Contains(out, "secmem: ") || strings.Contains(out, "not locked") {
					t.Fatalf("%s ran short of locked memory:\n%s", pr.name, out)
				}
			}
		})
	}
}

// a limit one byte under the minimum is refused by the check, before the
// identity and before any request
func TestPeerUnderTheMemlockMinimumNamesTheLimit(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max < minPeerMemlock {
		t.Skipf("RLIMIT_MEMLOCK hard limit %d is below the minimum %d", lim.Max, minPeerMemlock)
	}
	bed := newPeerBed(t, jcrypto.SuiteC25519)
	pr := bed.start(t, "under", []string{asBoundClient + "=" + strconv.Itoa(minPeerMemlock-1)})
	select {
	case <-pr.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the client did not exit")
	}
	out := pr.out.String()
	if code := pr.cmd.ProcessState.ExitCode(); code != 1 || !strings.Contains(out, "RLIMIT_MEMLOCK is "+strconv.Itoa(minPeerMemlock-1)+" bytes") {
		t.Fatalf("exit code %d:\n%s", code, out)
	}
	if strings.Contains(out, "card_hash=") || bed.info.requests.Load() != 0 {
		t.Fatalf("an identity or a request before the check:\n%s", out)
	}
}
