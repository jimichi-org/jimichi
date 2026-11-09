//go:build linux && amd64

package keymem

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func init() { testChildHook = syntheticChild }

func syntheticChild(args []string) (bool, int) {
	mode := os.Getenv("JIMICHI_KEYMEM_SYNTHETIC_CHILD")
	if mode == "" || len(args) != 1 || args[0] != privateArg {
		return false, 0
	}
	f := [4]*os.File{os.NewFile(3, "command"), os.NewFile(4, "oracle"), os.NewFile(5, "export"), os.NewFile(6, "status")}
	if validateDescriptors(f) != nil {
		return true, 2
	}
	defer func() {
		for _, file := range f {
			file.Close()
		}
	}()
	var cfg childConfig
	raw, e := readFrame(f[0], maxConfigBytes)
	if e != nil || decodeStrict(raw, &cfg) != nil {
		return true, 2
	}
	if mode == "crash-entry" {
		return true, 7
	}
	w := statusWriter{file: f[3], nonce: &cfg.Nonce, last: "entry"}
	if secmem.SetPolicy(secmem.Protected) != nil || secmem.HardenProcess() != nil {
		return true, 7
	}
	protection := Protection{RequestedPolicy: cfg.Policy, EffectivePolicy: cfg.Policy}
	if cfg.Policy == "all" {
		protection.Offheap = true
		protection.Lock = true
		protection.Dontdump = true
		protection.Zero = true
		protection.ProtectedAllocationsLocked = pointer(true)
	}
	if w.send("configured", configuredData{GOOS: "linux", GOARCH: "amd64", Runtime: "go1.27.3", BinaryDigest: "synthetic-digest", BinaryDigestSuite: cfg.Suite, Protection: protection}) != nil {
		return true, 7
	}
	fail := func(class string, cleanup bool) int {
		f[0].Close()
		f[1].Close()
		f[2].Close()
		var extra *string
		if cleanup {
			extra = pointer("child_cleanup_failed")
		}
		if strings.HasSuffix(mode, "-late-status") {
			time.Sleep(20 * time.Millisecond)
		}
		w.send("failed", failedData{LastOK: w.last, ErrorClass: class, CleanupError: extra})
		f[3].Close()
		return 1
	}
	if strings.HasPrefix(mode, "protection") {
		return true, fail("protection_unavailable", false)
	}
	if strings.HasPrefix(mode, "allocation") {
		return true, fail("allocation_failed", false)
	}
	if strings.HasPrefix(mode, "workload") {
		return true, fail("workload_failed", strings.Contains(mode, "cleanup"))
	}
	if mode == "malformed-status-crash" {
		writeAll(f[3], []byte{0, 0, 0, 1, '{'})
		return true, 7
	}
	if mode == "malformed-oracle-crash" {
		writeAll(f[1], []byte{9, 0, 0, 32})
		return true, 7
	}
	for i := 0; i < 4; i++ {
		b, e := secmem.New(32)
		if e != nil {
			return true, 7
		}
		for j := range b.Bytes() {
			b.Bytes()[j] = byte(0x11 * (i + 1))
		}
		kind, index := byte(1), byte(i)
		if i == 3 {
			kind, index = 2, 255
		}
		e = exportOracle(f[1], kind, index, b)
		b.Release()
		if e != nil {
			return true, 7
		}
	}
	f[1].Close()
	ready := readyData{EchoOK: true, SelectedCount: 3, AEADUses: [3]uint64{1, 1, 1}, ActiveLengths: [3]uint64{32, 32, 32}, MarkerAddress: 4096, EchoReadyNS: 1}
	if w.send("workload-ready", ready) != nil {
		return true, 7
	}
	if readCapture(f[0], cfg.Nonce) != nil {
		return true, fail("protocol_invalid", false)
	}
	if strings.HasPrefix(mode, "lifecycle") {
		return true, fail("lifecycle_failed", strings.Contains(mode, "cleanup"))
	}
	if mode == "blocked-dump" {
		prefix := heapStart()
		prefix.u(1, 8192, 127<<20)
		if writeAll(f[2], prefix) != nil {
			return true, 7
		}
		var chunk [65536]byte
		for {
			if _, e := f[2].Write(chunk[:]); e != nil {
				return true, 7
			}
		}
	}
	if mode == "held-dump-eof" {
		time.Sleep(10 * time.Second)
		return true, 7
	}
	stream := validHeap()
	if mode == "malformed-dump" {
		stream = append(heapFixture("wrong"), stream...)
	}
	if writeAll(f[2], stream) != nil {
		return true, 7
	}
	f[2].Close()
	ret := returnedData{Timing: Timing{EchoReadyNS: pointer(uint64(1)), CaptureDurationNS: pointer(uint64(2))}, NumGC: GC{EchoReady: pointer(uint32(0)), BeforeCapture: pointer(uint32(0)), AfterCapture: pointer(uint32(0))}}
	if cfg.Checkpoint != "active" {
		ret.Timing.CloseDurationNS = pointer(uint64(1))
		ret.Timing.CloseToCaptureNS = pointer(uint64(time.Second))
		ret.ReleasedLengths = pointer([3]uint64{})
	}
	if w.send("capture-returned", ret) != nil {
		return true, 7
	}
	if mode == "crash-returned" {
		return true, 7
	}
	if strings.HasPrefix(mode, "cleanup") {
		return true, fail("cleanup_failed", false)
	}
	if w.send("cleaned", cleanedData{MarkerCleared: true}) != nil {
		return true, 7
	}
	if mode == "held-status-eof" {
		time.Sleep(10 * time.Second)
		return true, 7
	}
	f[3].Close()
	return true, 0
}

func TestSupervisorOwnedFailuresAndReaderSchedules(t *testing.T) {
	if e := secmem.SetPolicy(secmem.Protected); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		mode, want string
		cleanup    bool
	}{
		{"crash-entry", "target_failed", false},
		{"protection", "protection_unavailable", false}, {"protection-late-status", "protection_unavailable", false},
		{"allocation", "allocation_failed", false}, {"allocation-late-status", "allocation_failed", false},
		{"workload", "workload_failed", false}, {"workload-late-status", "workload_failed", false},
		{"workload-cleanup", "workload_failed", true}, {"workload-cleanup-late-status", "workload_failed", true},
		{"lifecycle", "lifecycle_failed", false}, {"lifecycle-late-status", "lifecycle_failed", false},
		{"lifecycle-cleanup", "lifecycle_failed", true},
		{"cleanup", "cleanup_failed", false}, {"cleanup-late-status", "cleanup_failed", false},
		{"crash-returned", "target_failed", false},
		{"malformed-status-crash", "protocol_invalid", false}, {"malformed-oracle-crash", "oracle_invalid", false},
		{"malformed-dump", "parse_invalid", false}, {"normal", "evaluated", false},
		{"held-dump-eof", "capture_timeout", false}, {"held-status-eof", "capture_timeout", false},
		{"blocked-dump", "capture_timeout", false},
	} {
		t.Run(test.mode, func(t *testing.T) {
			t.Setenv("JIMICHI_KEYMEM_SYNTHETIC_CHILD", test.mode)
			deadline := 5 * time.Second
			if test.mode == "blocked-dump" || test.mode == "held-dump-eof" || test.mode == "held-status-eof" {
				deadline = 300 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			c := Config{Suite: jcrypto.SuiteC25519, Repeats: 1, Revision: strings.Repeat("0", 40)}
			row := newTrial(c, plannedCell{Policy: "none", Checkpoint: "active"})
			cfg := childConfig{Version: 1, Nonce: strings.Repeat("0", 32), Suite: "c25519", Policy: "none", Checkpoint: "active", Relays: []relayPublic{}}
			got := runTrial(ctx, row, cfg, "synthetic-digest")
			if got.Status != test.want {
				t.Fatalf("status %s, want %s", got.Status, test.want)
			}
			if test.cleanup {
				if got.CleanupError == nil || *got.CleanupError != "child_cleanup_failed" {
					t.Fatal("missing separate cleanup failure")
				}
			} else if got.CleanupError != nil {
				t.Fatal("induced abort reported cleanup failure")
			}
			if got.Status != "evaluated" {
				if got.AnyMatch != nil {
					t.Fatal("failed trial published outcome")
				}
				for _, key := range got.Keys {
					if key.Matches != nil {
						t.Fatal("failed trial published matches")
					}
				}
			}
		})
	}
}

func TestSupervisorPrecedence(t *testing.T) {
	base := trialEvidence{status: statusResult{EOF: true, Failed: &failedData{ErrorClass: "workload_failed"}}, exitCode: 1, oracle: oracleResult{Err: errOracleInvalid}, parser: parserEvidence{err: errCaptureIncomplete}, parsed: true}
	if resolve(base) != "workload_failed" {
		t.Fatal("short stream overrode cause")
	}
	base.cleanup = pointer("fixture_cleanup_failed")
	if resolve(base) != "workload_failed" {
		t.Fatal("cleanup overrode cause")
	}
	base.parser.err = errParseInvalid
	if resolve(base) != "parse_invalid" {
		t.Fatal("malformed dump lost priority")
	}
	base.parser.err = errCaptureLimit
	if resolve(base) != "capture_limit" {
		t.Fatal("limit lost priority")
	}
	base.oracle.Independent = true
	if resolve(base) != "oracle_invalid" {
		t.Fatal("oracle lost priority")
	}
	base.status.Independent = true
	if resolve(base) != "protocol_invalid" {
		t.Fatal("status lost priority")
	}
	for _, code := range []int{0, 2, 7} {
		e := trialEvidence{status: statusResult{EOF: true, Failed: &failedData{ErrorClass: "workload_failed"}}, exitCode: code}
		want := "target_failed"
		if code == 0 {
			want = "protocol_invalid"
		}
		if resolve(e) != want {
			t.Fatal("failed exit mismatch")
		}
	}
	if resolve(trialEvidence{status: statusResult{EOF: true, Cleaned: &cleanedData{}}, exitCode: 1}) != "protocol_invalid" {
		t.Fatal("cleaned exit mismatch")
	}
	if resolve(trialEvidence{deadline: true, exitCode: -1}) != "capture_timeout" {
		t.Fatal("deadline lost priority")
	}
	if resolve(trialEvidence{cancelled: true, exitCode: -1}) != "controller_failed" {
		t.Fatal("explicit cancellation lost priority")
	}
}

func TestAuxiliaryReaderOrdersPreserveReportedCause(t *testing.T) {
	for _, test := range []struct {
		class string
		phase int
	}{{"protection_unavailable", 1}, {"allocation_failed", 1}, {"workload_failed", 1}, {"lifecycle_failed", 2}, {"cleanup_failed", 3}} {
		for _, statusFirst := range []bool{false, true} {
			c := ipcTestConfig()
			last := []string{"entry", "configured", "workload-ready", "capture-returned"}[test.phase]
			raw := append(statusTestPrefix(t, c, test.phase), statusTestFrame(t, &c.Nonce, uint64(test.phase+1), "failed", failedData{LastOK: last, ErrorClass: test.class, CleanupError: pointer("child_cleanup_failed")})...)
			var st statusResult
			var oracle oracleResult
			readStatus := func() { st = readStatuses(bytes.NewReader(raw), c, "public-binary-digest", make(chan statusEvent, 2)) }
			readShort := func() { oracle = readOracle(bytes.NewReader(nil)) }
			if statusFirst {
				readStatus()
				readShort()
			} else {
				readShort()
				readStatus()
			}
			if st.Independent || st.Err != nil || !st.EOF || st.Failed == nil {
				t.Fatal("invalid synthetic failure prefix")
			}
			got := resolve(trialEvidence{status: st, oracle: oracle, exitCode: 1, parser: parserEvidence{err: errCaptureIncomplete}, parsed: true, cleanup: pointer("child_cleanup_failed")})
			oracle.release()
			if got != test.class {
				t.Fatal("reader completion order changed primary cause")
			}
		}
	}
}

func TestCaptureWriterHeldOpenIsPending(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	nonce := strings.Repeat("0", 32)
	body := captureBody(nonce)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if writeAll(w, header[:]) != nil || writeAll(w, body) != nil {
		t.Fatal("write")
	}
	done := make(chan error, 1)
	go func() { done <- readCapture(r, nonce) }()
	select {
	case <-done:
		t.Fatal("authorized without EOF")
	case <-time.After(20 * time.Millisecond):
	}
	w.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestParserCancellationUnblocksFullOwnedPipe(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer w.Close()
		var b [65536]byte
		for {
			if _, e := w.Write(b[:]); e != nil {
				return
			}
		}
	}()
	r.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer not joined")
	}
}

func TestPrivateBootstrapMissingDescriptors(t *testing.T) {
	if handled, code := MaybeRunChild([]string{privateArg, "extra"}); !handled || code != 2 {
		t.Fatal("private arguments accepted")
	}
	if validateDescriptors([4]*os.File{}) == nil {
		t.Fatal("missing descriptors accepted")
	}
}
