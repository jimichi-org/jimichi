//go:build linux && amd64

package keymem

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
	"golang.org/x/sys/unix"
)

var positiveRoot *[32]byte

type trackedProvider struct {
	jcrypto.CryptoProvider
	oracle   *os.File
	selected [3]*secmem.Buffer
	count    int
	uses     [3]uint64
}

func (p *trackedProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	key, e := p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	if e != nil {
		return key, e
	}
	if purpose != "cell" {
		return key, nil
	}
	if size != 32 || p.KeySize() != 32 || key == nil || key.Len() != 32 || p.count >= 3 {
		if key != nil {
			key.Release()
		}
		return nil, errOracleInvalid
	}
	if e = exportOracle(p.oracle, 1, byte(p.count), key); e != nil {
		key.Release()
		return nil, errOracleInvalid
	}
	p.selected[p.count] = key
	p.count++
	return key, nil
}

func (p *trackedProvider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	aead, e := p.CryptoProvider.NewAEAD(key)
	if e != nil {
		return aead, e
	}
	for i, k := range p.selected {
		if k != nil && key == k {
			p.uses[i]++
		}
	}
	return aead, nil
}

func (p *trackedProvider) lengths() [3]uint64 {
	var out [3]uint64
	for i, k := range p.selected {
		if k != nil {
			out[i] = uint64(k.Len())
		}
	}
	return out
}

func (p *trackedProvider) locked() bool {
	if p.count != 3 {
		return false
	}
	for _, k := range p.selected {
		if k == nil || !k.Locked() {
			return false
		}
	}
	return true
}

type statusWriter struct {
	file  *os.File
	nonce *string
	seq   uint64
	last  string
}

func (w *statusWriter) send(kind string, data any) error {
	raw, e := jsonBody(data)
	if e != nil {
		return errProtocolInvalid
	}
	s := statusEnvelope{Version: 1, Nonce: w.nonce, Seq: w.seq + 1, Type: kind, Data: raw}
	if e = writeFrame(w.file, s, maxStatusBytes); e != nil {
		return e
	}
	w.seq++
	if kind != "failed" {
		w.last = kind
	}
	return nil
}

func MaybeRunChild(args []string) (bool, int) {
	if len(args) == 0 || args[0] != privateArg {
		return false, 0
	}
	if len(args) != 1 {
		return true, 2
	}
	return true, runChild()
}

func runChild() int {
	entry := time.Now()
	files := [4]*os.File{os.NewFile(3, "command"), os.NewFile(4, "oracle"), os.NewFile(5, "export"), os.NewFile(6, "status")}
	if validateDescriptors(files) != nil {
		return 2
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	w := statusWriter{file: files[3], last: "entry"}
	var c childConfig
	var tracked *trackedProvider
	var cl *client.Client
	var marker *[32]byte
	cleanup := func() (*[3]uint64, *string) {
		var cleanupError *string
		if cl != nil {
			if cl.Close() != nil {
				cleanupError = pointer("child_cleanup_failed")
			}
			cl = nil
		}
		if marker != nil {
			clear(marker[:])
			marker = nil
		}
		positiveRoot = nil
		if tracked == nil || tracked.count != 3 {
			return nil, cleanupError
		}
		lengths := tracked.lengths()
		if lengths != [3]uint64{} {
			cleanupError = pointer("child_cleanup_failed")
			return nil, cleanupError
		}
		tracked.selected = [3]*secmem.Buffer{}
		return &lengths, cleanupError
	}
	fail := func(class string) int {
		_ = files[0].Close()
		_ = files[1].Close()
		_ = files[2].Close()
		lengths, cleanupError := cleanup()
		_ = w.send("failed", failedData{LastOK: w.last, ErrorClass: class, CleanupError: cleanupError, ReleasedLengths: lengths})
		_ = files[3].Close()
		return 1
	}
	b, e := readFrame(files[0], maxConfigBytes)
	if e != nil || decodeStrict(b, &c) != nil || c.validate() != nil {
		return fail("protocol_invalid")
	}
	w.nonce = &c.Nonce
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fail("unsupported_platform")
	}
	if runtime.Version() != "go1.27.3" {
		return fail("unsupported_runtime")
	}
	policy := secmem.Baseline
	if c.Policy == "all" {
		policy = secmem.Protected
	}
	if secmem.SetPolicy(policy) != nil || secmem.HardenProcess() != nil {
		return fail("protection_unavailable")
	}
	protection, e := inspectProtection(c.Policy, true)
	if e != nil {
		return fail(childClass(e, "protection_unavailable"))
	}
	s, e := suite.Parse(c.Suite)
	if e != nil {
		return fail("protocol_invalid")
	}
	p, e := suite.New(s)
	if e != nil {
		return fail("workload_failed")
	}
	digest, e := ownDigest(p)
	if e != nil {
		return fail("workload_failed")
	}
	if e = w.send("configured", configuredData{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Runtime: runtime.Version(), BinaryDigest: digest, BinaryDigestSuite: c.Suite, Protection: protection}); e != nil {
		return 1
	}
	anchor, e := pki.ParseAnchor(c.Anchor)
	if e != nil {
		return fail("workload_failed")
	}
	addrs := make([]string, 3)
	bundles := make([][]byte, 3)
	for i, r := range c.Relays {
		addrs[i] = r.Address
		bundles[i], e = base64.StdEncoding.Strict().DecodeString(r.Bundle)
		if e != nil {
			return fail("workload_failed")
		}
	}
	verified, e := pki.VerifyChain(p, pki.Policy{Anchor: anchor, Skew: pki.Skew, MinLife: pki.MinDescriptorLife}, addrs, bundles, time.Now())
	if e != nil {
		return fail("workload_failed")
	}
	chain := make([]client.Node, 3)
	for i, v := range verified {
		if len(v.Identity) == 0 {
			return fail("workload_failed")
		}
		chain[i] = client.Node{Addr: v.Addr, StaticPub: v.OnionPub, LinkPub: v.LinkPub, Identity: v.Identity}
	}
	tracked = &trackedProvider{CryptoProvider: p, oracle: files[1]}
	cl, e = client.Dial(client.Config{Provider: tracked, Chain: chain, Mode: client.Immediate})
	if e != nil {
		return fail(childClass(e, "workload_failed"))
	}
	if tracked.count != 3 || tracked.uses != [3]uint64{1, 1, 1} || tracked.lengths() != [3]uint64{32, 32, 32} {
		return fail("oracle_invalid")
	}
	if c.Policy == "all" && !tracked.locked() {
		return fail("protection_unavailable")
	}
	payload := []byte("jimichi/keymem/v1")
	if e = cl.Send(payload); e != nil {
		return fail(childClass(e, "workload_failed"))
	}
	reply, ok := <-cl.Replies()
	if !ok || !bytes.Equal(reply, payload) {
		return fail("workload_failed")
	}
	echoReady := time.Now()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	echoGC := ms.NumGC
	marker = new([32]byte)
	positiveRoot = marker
	if randomFill(marker[:]) != nil {
		return fail("workload_failed")
	}
	if e = exportMarker(files[1], marker); e != nil {
		return fail("oracle_invalid")
	}
	if e = files[1].Close(); e != nil {
		return fail("oracle_invalid")
	}
	ready := readyData{EchoOK: true, SelectedCount: 3, AEADUses: tracked.uses, ActiveLengths: tracked.lengths(), MarkerAddress: uint64(uintptr(unsafe.Pointer(marker))), EchoReadyNS: uint64(echoReady.Sub(entry)), NumGCEchoReady: echoGC}
	if e = w.send("workload-ready", ready); e != nil {
		return fail("protocol_invalid")
	}
	if readCapture(files[0], c.Nonce) != nil {
		return fail("protocol_invalid")
	}
	ret := returnedData{Timing: Timing{EchoReadyNS: &ready.EchoReadyNS}, NumGC: GC{EchoReady: &echoGC}}
	var closedAt time.Time
	if c.Checkpoint != "active" {
		start := time.Now()
		e = cl.Close()
		closedAt = time.Now()
		cl = nil
		if e != nil || tracked.lengths() != [3]uint64{} {
			return fail("lifecycle_failed")
		}
		ret.Timing.CloseDurationNS = pointer(uint64(closedAt.Sub(start)))
		ret.ReleasedLengths = pointer(tracked.lengths())
		if c.Checkpoint == "closed-1s" {
			time.Sleep(time.Until(closedAt.Add(time.Second)))
		}
	} else if tracked.lengths() != [3]uint64{32, 32, 32} {
		return fail("lifecycle_failed")
	}
	if e = unix.SetNonblock(int(files[2].Fd()), false); e != nil {
		return fail("lifecycle_failed")
	}
	runtime.ReadMemStats(&ms)
	ret.NumGC.BeforeCapture = pointer(ms.NumGC)
	before := time.Now()
	if c.Checkpoint != "active" {
		ret.Timing.CloseToCaptureNS = pointer(uint64(before.Sub(closedAt)))
	}
	debug.WriteHeapDump(files[2].Fd())
	after := time.Now()
	runtime.KeepAlive(marker)
	ret.Timing.CaptureDurationNS = pointer(uint64(after.Sub(before)))
	runtime.ReadMemStats(&ms)
	ret.NumGC.AfterCapture = pointer(ms.NumGC)
	if e = files[2].Close(); e != nil {
		return fail("lifecycle_failed")
	}
	if e = w.send("capture-returned", ret); e != nil {
		return fail("lifecycle_failed")
	}
	lengths, cleanupError := cleanup()
	if cleanupError != nil || lengths == nil {
		return fail("cleanup_failed")
	}
	if e = w.send("cleaned", cleanedData{ReleasedLengths: *lengths, MarkerCleared: true}); e != nil {
		return 1
	}
	if e = files[3].Close(); e != nil {
		return 1
	}
	return 0
}

func childClass(e error, fallback string) string {
	if errors.Is(e, secmem.ErrNotLocked) || errors.Is(e, errProtectionUnavailable) {
		return "protection_unavailable"
	}
	if errors.Is(e, secmem.ErrNotMapped) || errors.Is(e, errAllocationFailed) {
		return "allocation_failed"
	}
	if errors.Is(e, errOracleInvalid) {
		return "oracle_invalid"
	}
	return fallback
}

func ownDigest(p jcrypto.CryptoProvider) (string, error) {
	path, e := os.Executable()
	if e != nil {
		return "", errControllerFailed
	}
	f, e := os.Open(path)
	if e != nil {
		return "", errControllerFailed
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() < 1 || info.Size() > maxBinaryBytes {
		return "", errControllerFailed
	}
	b, e := io.ReadAll(io.LimitReader(f, maxBinaryBytes+1))
	if e != nil || len(b) > maxBinaryBytes {
		return "", errControllerFailed
	}
	return hex.EncodeToString(p.Hash(b)), nil
}

func inspectProtection(requested string, check bool) (Protection, error) {
	p := secmem.CurrentPolicy()
	out := Protection{RequestedPolicy: requested, EffectivePolicy: p.String(), Offheap: p.OffHeap, Lock: p.Lock, Dontdump: p.DontDump, Zero: p.Zero}
	dump, e := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if e != nil {
		return out, errProtectionUnavailable
	}
	out.Dumpable = uint64(dump)
	var core, mem unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_CORE, &core) != nil || unix.Getrlimit(unix.RLIMIT_MEMLOCK, &mem) != nil {
		return out, errProtectionUnavailable
	}
	out.CoreSoft = core.Cur
	out.CoreHard = core.Max
	out.MemlockSoft = mem.Cur
	out.MemlockHard = mem.Max
	if requested == "all" && check {
		probe, e := secmem.New(32)
		if e != nil {
			return out, allocationClass(e)
		}
		locked := probe.Locked()
		probe.Release()
		out.ProtectedAllocationsLocked = &locked
	}
	if !validProtection(out, requested, true) {
		return out, errProtectionUnavailable
	}
	return out, nil
}
