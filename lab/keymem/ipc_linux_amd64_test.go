//go:build linux && amd64

package keymem

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

const ipcNonce = "0123456789abcdef0123456789abcdef"

func ipcTestConfig() childConfig {
	return childConfig{Version: 1, Nonce: ipcNonce, Suite: "c25519", Policy: "none", Checkpoint: "active", Anchor: (pki.Anchor{Suite: jcrypto.SuiteC25519, Pub: []byte{1, 2, 3}}).String(), Relays: []relayPublic{{"127.0.0.1:10001", "AQ=="}, {"127.0.0.1:10002", "Ag=="}, {"127.0.0.1:10003", "Aw=="}}}
}

func ipcJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ipcRawFrame(body []byte) []byte {
	b := make([]byte, 4, len(body)+4)
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	return append(b, body...)
}

func ipcPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}

func TestIPCConfigValidation(t *testing.T) {
	if err := ipcTestConfig().validate(); err != nil {
		t.Fatal("valid public config rejected")
	}
	for _, tt := range []struct {
		name string
		edit func(*childConfig)
	}{
		{"version", func(c *childConfig) { c.Version = 2 }},
		{"short-nonce", func(c *childConfig) { c.Nonce = "0123" }},
		{"uppercase-nonce", func(c *childConfig) { c.Nonce = strings.Repeat("A", 32) }},
		{"nonhex-nonce", func(c *childConfig) { c.Nonce = strings.Repeat("g", 32) }},
		{"suite", func(c *childConfig) { c.Suite = "other" }},
		{"policy", func(c *childConfig) { c.Policy = "offheap" }},
		{"checkpoint", func(c *childConfig) { c.Checkpoint = "closed" }},
		{"short-relay-list", func(c *childConfig) { c.Relays = c.Relays[:2] }},
		{"extra-relay", func(c *childConfig) { c.Relays = append(c.Relays, c.Relays[0]) }},
		{"anchor-suite", func(c *childConfig) { c.Anchor = "gost:AQ==" }},
		{"anchor-noncanonical", func(c *childConfig) { c.Anchor += "\n" }},
		{"anchor-size", func(c *childConfig) { c.Anchor = strings.Repeat("x", 257) }},
		{"host", func(c *childConfig) { c.Relays[0].Address = "localhost:10001" }},
		{"external-address", func(c *childConfig) { c.Relays[0].Address = "192.0.2.1:10001" }},
		{"ipv6", func(c *childConfig) { c.Relays[0].Address = "[::1]:10001" }},
		{"zero-port", func(c *childConfig) { c.Relays[0].Address = "127.0.0.1:0" }},
		{"port-overflow", func(c *childConfig) { c.Relays[0].Address = "127.0.0.1:65536" }},
		{"noncanonical-port", func(c *childConfig) { c.Relays[0].Address = "127.0.0.1:010001" }},
		{"bundle-unpadded", func(c *childConfig) { c.Relays[0].Bundle = "AQ" }},
		{"bundle-newline", func(c *childConfig) { c.Relays[0].Bundle = "AQ==\n" }},
		{"bundle-empty", func(c *childConfig) { c.Relays[0].Bundle = "" }},
		{"bundle-pad-bits", func(c *childConfig) { c.Relays[0].Bundle = "AR==" }},
		{"bundle-too-large", func(c *childConfig) { c.Relays[0].Bundle = base64.StdEncoding.EncodeToString(make([]byte, 4097)) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := ipcTestConfig()
			tt.edit(&c)
			if !errors.Is(c.validate(), errProtocolInvalid) {
				t.Fatal("invalid public config accepted")
			}
		})
	}
}

func TestIPCStrictJSON(t *testing.T) {
	valid := ipcJSON(t, ipcTestConfig())
	for _, tt := range []struct {
		name string
		raw  []byte
	}{
		{"valid", valid},
		{"duplicate", bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)},
		{"duplicate-nested", bytes.Replace(valid, []byte(`"address":"127.0.0.1:10001"`), []byte(`"address":"127.0.0.1:10001","address":"127.0.0.1:10001"`), 1)},
		{"unknown", append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"unknown":1}`)...)},
		{"missing", bytes.Replace(valid, []byte(`"version":1,`), nil, 1)},
		{"null-required", bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":null`), 1)},
		{"wrong-type", bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":"1"`), 1)},
		{"noninteger", bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1.0`), 1)},
		{"negative", bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":-1`), 1)},
		{"trailing-json", append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{"trailing-text", append(append([]byte(nil), valid...), 'x')},
		{"invalid-utf8", append(append([]byte(nil), valid...), 0xff)},
		{"null-relays", bytes.Replace(valid, ipcJSON(t, ipcTestConfig().Relays), []byte("null"), 1)},
		{"null-nested", bytes.Replace(valid, []byte(`"address":"127.0.0.1:10001"`), []byte(`"address":null`), 1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var c childConfig
			err := decodeStrict(tt.raw, &c)
			if tt.name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if tt.name == "negative" {
				if err == nil && c.validate() == nil {
					t.Fatal("negative config integer accepted")
				}
				return
			}
			if !errors.Is(err, errProtocolInvalid) {
				t.Fatal("malformed JSON accepted")
			}
		})
	}
}

func TestIPCFrameBoundsAndTruncations(t *testing.T) {
	for _, raw := range [][]byte{nil, {0}, {0, 0, 0}, {0, 0, 0, 2, 'a'}} {
		if _, err := readFrame(bytes.NewReader(raw), 10); err == nil {
			t.Fatal("short frame accepted")
		}
	}
	for _, length := range []uint32{0, 11, math.MaxUint32} {
		h := make([]byte, 4)
		binary.BigEndian.PutUint32(h, length)
		if _, err := readFrame(bytes.NewReader(h), 10); !errors.Is(err, errProtocolInvalid) {
			t.Fatal("out-of-bounds frame accepted")
		}
	}
	var framed bytes.Buffer
	if err := writeFrame(&framed, map[string]int{"v": 1}, 7); err != nil {
		t.Fatal(err)
	}
	if framed.Len() != 11 || binary.BigEndian.Uint32(framed.Bytes()[:4]) != 7 {
		t.Fatal("incorrect public framing")
	}
	if err := writeFrame(io.Discard, map[string]int{"v": 1}, 6); !errors.Is(err, errProtocolInvalid) {
		t.Fatal("oversized output frame accepted")
	}
}

func TestIPCCaptureExactFrameAndClosure(t *testing.T) {
	r, w := ipcPipe(t)
	if err := writeCapture(w, ipcNonce); err != nil {
		t.Fatal(err)
	}
	var wire [80]byte
	if _, err := io.ReadFull(r, wire[:]); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(wire[:4]) != 76 || string(wire[4:]) != `{"version":1,"nonce":"0123456789abcdef0123456789abcdef","command":"capture"}` {
		t.Fatal("capture frame spelling differs")
	}
	var one [1]byte
	if n, err := r.Read(one[:]); n != 0 || err != io.EOF {
		t.Fatal("capture writer was not closed")
	}
	if _, err := w.Write(one[:]); !errors.Is(err, os.ErrClosed) {
		t.Fatal("capture writer remains usable")
	}
	r, w = ipcPipe(t)
	if err := writeCapture(w, ipcNonce); err != nil {
		t.Fatal(err)
	}
	if err := readCapture(r, ipcNonce); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(one[:]); !errors.Is(err, os.ErrClosed) {
		t.Fatal("accepted command descriptor remains open")
	}
}

func TestIPCCaptureRejectsExtraAndTruncatedInput(t *testing.T) {
	valid := ipcRawFrame(captureBody(ipcNonce))
	cases := map[string][]byte{
		"duplicate":            append(append([]byte(nil), valid...), valid...),
		"trailing-byte":        append(append([]byte(nil), valid...), 0),
		"partial-second-frame": append(append([]byte(nil), valid...), 0, 0, 0),
		"wrong-nonce":          ipcRawFrame(captureBody(strings.Repeat("a", 32))),
		"wrong-length":         ipcRawFrame(append(captureBody(ipcNonce), ' ')),
		"reordered-json":       ipcRawFrame([]byte(`{"nonce":"0123456789abcdef0123456789abcdef","version":1,"command":"capture"}`)),
	}
	for i := 0; i < len(valid); i++ {
		cases["truncation-"+strconv.Itoa(i)] = valid[:i]
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			r, w := ipcPipe(t)
			if err := writeAll(w, raw); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(readCapture(r, ipcNonce), errProtocolInvalid) {
				t.Fatal("invalid capture authorization accepted")
			}
		})
	}
}

func TestIPCDescriptorContract(t *testing.T) {
	var files [4]*os.File
	var reads, writes [4]*os.File
	for i := range files {
		reads[i], writes[i] = ipcPipe(t)
		files[i] = writes[i]
	}
	files[0] = reads[0]
	if err := validateDescriptors(files); err != nil {
		t.Fatal("valid distinct pipes rejected")
	}
	for _, tt := range []struct {
		name string
		edit func(*[4]*os.File)
	}{
		{"missing", func(f *[4]*os.File) { f[2] = nil }},
		{"wrong-read-direction", func(f *[4]*os.File) { f[0] = writes[0] }},
		{"wrong-write-direction", func(f *[4]*os.File) { f[1] = reads[1] }},
		{"same-pipe-identity", func(f *[4]*os.File) { f[1] = writes[0] }},
		{"same-descriptor", func(f *[4]*os.File) { f[2] = f[1] }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := files
			tt.edit(&f)
			if !errors.Is(validateDescriptors(f), errProtocolInvalid) {
				t.Fatal("invalid pipe descriptors accepted")
			}
		})
	}
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	invalid := files
	invalid[3] = f
	if !errors.Is(validateDescriptors(invalid), errProtocolInvalid) {
		t.Fatal("nonpipe descriptor accepted")
	}
	r, w := ipcPipe(t)
	w.Close()
	invalid = files
	invalid[3] = w
	_ = r
	if !errors.Is(validateDescriptors(invalid), errProtocolInvalid) {
		t.Fatal("closed descriptor accepted")
	}
}

func oracleTestWire() []byte {
	var raw []byte
	for i := 0; i < 4; i++ {
		kind, index := byte(1), byte(i)
		if i == 3 {
			kind, index = 2, 255
		}
		raw = append(raw, kind, index, 0, 32)
		raw = append(raw, bytes.Repeat([]byte{byte(i + 1)}, 32)...)
	}
	return raw
}

func TestIPCOracleExactFrames(t *testing.T) {
	raw := oracleTestWire()
	if len(raw) != 144 {
		t.Fatal("incorrect oracle fixture length")
	}
	o := readOracle(bytes.NewReader(raw))
	defer o.release()
	if o.Err != nil {
		t.Fatal(o.Err)
	}
	for i, b := range o.Patterns {
		if b == nil || b.Len() != 32 || !b.Locked() {
			t.Fatal("oracle did not retain protected references")
		}
		if i < 4 && !bytes.Equal(b.Bytes(), bytes.Repeat([]byte{byte(i + 1)}, 32)) {
			t.Fatal("oracle ordering changed")
		}
	}
	o.release()
	for _, b := range o.Patterns {
		if b != nil {
			t.Fatal("released oracle retained references")
		}
	}
}

func TestIPCOracleMalformedAndShortEvidence(t *testing.T) {
	valid := oracleTestWire()
	for _, tt := range []struct {
		name        string
		raw         []byte
		independent bool
	}{
		{"short-header", valid[:2], false},
		{"short-key", valid[:20], false},
		{"missing-marker", valid[:108], false},
		{"trailing-byte", append(append([]byte(nil), valid...), 0), true},
		{"fifth-frame", append(append([]byte(nil), valid...), valid[:36]...), true},
		{"wrong-kind", append([]byte{2}, valid[1:]...), true},
		{"wrong-index", append([]byte{1, 1}, valid[2:]...), true},
		{"wrong-size", append([]byte{1, 0, 0, 31}, valid[4:]...), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			o := readOracle(bytes.NewReader(tt.raw))
			defer o.release()
			if !errors.Is(o.Err, errOracleInvalid) || o.Independent != tt.independent {
				t.Fatal("incorrect oracle evidence classification")
			}
		})
	}
	for frame := 0; frame < 4; frame++ {
		for _, at := range []int{frame * 36, frame*36 + 1, frame*36 + 4, frame*36 + 35} {
			o := readOracle(bytes.NewReader(valid[:at]))
			o.release()
			if !errors.Is(o.Err, errOracleInvalid) || o.Independent {
				t.Fatal("short oracle was treated as independent malformed input")
			}
		}
	}
	collision := oracleTestWire()
	copy(collision[40:72], collision[4:36])
	o := readOracle(bytes.NewReader(collision))
	defer o.release()
	if !errors.Is(o.Err, errOracleInvalid) || !o.Independent {
		t.Fatal("oracle pattern collision accepted")
	}
}

func statusTestData(c childConfig) []any {
	p := Protection{RequestedPolicy: c.Policy, EffectivePolicy: c.Policy, MemlockSoft: 1 << 20, MemlockHard: 1 << 20}
	if c.Policy == "all" {
		p.Offheap, p.Lock, p.Dontdump, p.Zero = true, true, true, true
		p.ProtectedAllocationsLocked = pointer(true)
	}
	ready := readyData{EchoOK: true, SelectedCount: 3, AEADUses: [3]uint64{1, 1, 1}, ActiveLengths: [3]uint64{32, 32, 32}, MarkerAddress: 4096, EchoReadyNS: 7, NumGCEchoReady: 2}
	returned := returnedData{Timing: Timing{EchoReadyNS: pointer(uint64(7)), CaptureDurationNS: pointer(uint64(11))}, NumGC: GC{EchoReady: pointer(uint32(2)), BeforeCapture: pointer(uint32(3)), AfterCapture: pointer(uint32(4))}}
	if c.Checkpoint != "active" {
		returned.Timing.CloseDurationNS = pointer(uint64(5))
		returned.Timing.CloseToCaptureNS = pointer(uint64(1_000_000_000))
		returned.ReleasedLengths = pointer([3]uint64{})
	}
	return []any{configuredData{GOOS: "linux", GOARCH: "amd64", Runtime: "go1.27.3", BinaryDigest: "public-binary-digest", BinaryDigestSuite: c.Suite, Protection: p}, ready, returned, cleanedData{ReleasedLengths: [3]uint64{}, MarkerCleared: true}}
}

func statusTestFrame(t *testing.T, nonce *string, seq uint64, kind string, data any) []byte {
	t.Helper()
	return ipcRawFrame(ipcJSON(t, statusEnvelope{Version: 1, Nonce: nonce, Seq: seq, Type: kind, Data: ipcJSON(t, data)}))
}

func statusTestPrefix(t *testing.T, c childConfig, count int) []byte {
	t.Helper()
	var raw []byte
	types := []string{"configured", "workload-ready", "capture-returned", "cleaned"}
	for i, data := range statusTestData(c)[:count] {
		raw = append(raw, statusTestFrame(t, &c.Nonce, uint64(i+1), types[i], data)...)
	}
	return raw
}

func readTestStatuses(raw []byte, c childConfig) statusResult {
	return readStatuses(bytes.NewReader(raw), c, "public-binary-digest", make(chan statusEvent, 8))
}

func TestIPCStatusExactSuccessSchemas(t *testing.T) {
	for _, policy := range []string{"none", "all"} {
		for _, checkpoint := range []string{"active", "closed-now", "closed-1s"} {
			t.Run(policy+"/"+checkpoint, func(t *testing.T) {
				c := ipcTestConfig()
				c.Policy, c.Checkpoint = policy, checkpoint
				out := readTestStatuses(statusTestPrefix(t, c, 4), c)
				if out.Err != nil || !out.EOF || out.Independent || out.Configured == nil || out.Ready == nil || out.Returned == nil || out.Cleaned == nil || out.Failed != nil {
					t.Fatal("exact successful status sequence rejected")
				}
			})
		}
	}
}

func TestIPCStatusReportedFailurePhases(t *testing.T) {
	classes := map[string][]int{
		"unsupported_platform": {0}, "unsupported_runtime": {0},
		"protection_unavailable": {0, 1, 2}, "allocation_failed": {0, 1}, "workload_failed": {0, 1},
		"oracle_invalid": {1}, "protocol_invalid": {0, 1, 2}, "lifecycle_failed": {1, 2, 3}, "cleanup_failed": {3},
	}
	last := []string{"entry", "configured", "workload-ready", "capture-returned"}
	c := ipcTestConfig()
	for class, allowed := range classes {
		for phase := 0; phase < 4; phase++ {
			ok := false
			for _, v := range allowed {
				ok = ok || v == phase
			}
			t.Run(class+"/"+last[phase], func(t *testing.T) {
				data := failedData{LastOK: last[phase], ErrorClass: class, CleanupError: pointer("child_cleanup_failed"), ReleasedLengths: pointer([3]uint64{})}
				raw := append(statusTestPrefix(t, c, phase), statusTestFrame(t, &c.Nonce, uint64(phase+1), "failed", data)...)
				out := readTestStatuses(raw, c)
				if ok {
					if out.Err != nil || !out.EOF || out.Failed == nil || out.Failed.ErrorClass != class || out.Failed.LastOK != last[phase] || *out.Failed.CleanupError != "child_cleanup_failed" {
						t.Fatal("valid reported primary cause was lost")
					}
				} else if !errors.Is(out.Err, errProtocolInvalid) || !out.Independent {
					t.Fatal("forbidden failure phase accepted")
				}
			})
		}
	}
	data := failedData{LastOK: "entry", ErrorClass: "protocol_invalid"}
	out := readTestStatuses(statusTestFrame(t, nil, 1, "failed", data), c)
	if out.Err != nil || !out.EOF || out.Failed == nil {
		t.Fatal("invalid-config null-nonce failure rejected")
	}
}

func TestIPCStatusRejectsSchemaAndSequenceContradictions(t *testing.T) {
	c := ipcTestConfig()
	data := statusTestData(c)
	validFirst := statusTestFrame(t, &c.Nonce, 1, "configured", data[0])
	validBody := ipcJSON(t, statusEnvelope{Version: 1, Nonce: &c.Nonce, Seq: 1, Type: "configured", Data: ipcJSON(t, data[0])})
	cases := map[string][]byte{
		"wrong-nonce":            statusTestFrame(t, pointer(strings.Repeat("a", 32)), 1, "configured", data[0]),
		"null-normal-nonce":      statusTestFrame(t, nil, 1, "configured", data[0]),
		"wrong-seq":              statusTestFrame(t, &c.Nonce, 2, "configured", data[0]),
		"wrong-first-type":       statusTestFrame(t, &c.Nonce, 1, "workload-ready", data[1]),
		"duplicate-configured":   append(append([]byte(nil), validFirst...), statusTestFrame(t, &c.Nonce, 2, "configured", data[0])...),
		"duplicate-json-field":   ipcRawFrame(bytes.Replace(validBody, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)),
		"unknown-envelope-field": ipcRawFrame(append(append([]byte(nil), validBody[:len(validBody)-1]...), []byte(`,"extra":1}`)...)),
		"unknown-data-field":     ipcRawFrame(bytes.Replace(validBody, []byte(`"goos":"linux"`), []byte(`"goos":"linux","extra":1`), 1)),
		"missing-data-field":     ipcRawFrame(bytes.Replace(validBody, []byte(`"goos":"linux",`), nil, 1)),
		"duplicate-data-field":   ipcRawFrame(bytes.Replace(validBody, []byte(`"goos":"linux"`), []byte(`"goos":"linux","goos":"linux"`), 1)),
		"wrong-runtime":          ipcRawFrame(bytes.Replace(validBody, []byte(`"runtime":"go1.27.3"`), []byte(`"runtime":"go1.27.4"`), 1)),
		"wrong-digest":           ipcRawFrame(bytes.Replace(validBody, []byte(`"binary_digest":"public-binary-digest"`), []byte(`"binary_digest":"other"`), 1)),
		"oversized-body":         ipcRawFrame(bytes.Repeat([]byte{' '}, maxStatusBytes+1)),
		"zero-body":              {0, 0, 0, 0},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			out := readTestStatuses(raw, c)
			if !errors.Is(out.Err, errProtocolInvalid) || !out.Independent {
				t.Fatal("status contradiction was not independent protocol evidence")
			}
		})
	}
}

func TestIPCStatusReadyAndReturnedValidation(t *testing.T) {
	c := ipcTestConfig()
	data := statusTestData(c)
	for _, edit := range []func(*readyData){
		func(d *readyData) { d.EchoOK = false }, func(d *readyData) { d.SelectedCount = 2 },
		func(d *readyData) { d.AEADUses[1] = 2 }, func(d *readyData) { d.ActiveLengths[2] = 0 },
		func(d *readyData) { d.MarkerAddress = 0 }, func(d *readyData) { d.MarkerAddress = math.MaxUint64 - 31 },
	} {
		d := data[1].(readyData)
		edit(&d)
		raw := append(statusTestPrefix(t, c, 1), statusTestFrame(t, &c.Nonce, 2, "workload-ready", d)...)
		out := readTestStatuses(raw, c)
		if !errors.Is(out.Err, errProtocolInvalid) || !out.Independent {
			t.Fatal("invalid workload readiness accepted")
		}
	}
	for _, checkpoint := range []string{"active", "closed-now", "closed-1s"} {
		c.Checkpoint = checkpoint
		base := statusTestData(c)[2].(returnedData)
		for _, edit := range []func(*returnedData){
			func(d *returnedData) { d.Timing.EchoReadyNS = nil },
			func(d *returnedData) { d.Timing.EchoReadyNS = pointer(uint64(8)) },
			func(d *returnedData) { d.Timing.CaptureDurationNS = nil },
			func(d *returnedData) { d.NumGC.EchoReady = nil },
			func(d *returnedData) { d.NumGC.EchoReady = pointer(uint32(1)) },
			func(d *returnedData) { d.NumGC.BeforeCapture = nil },
			func(d *returnedData) { d.NumGC.BeforeCapture = pointer(uint32(1)) },
			func(d *returnedData) { d.NumGC.AfterCapture = nil },
			func(d *returnedData) { d.NumGC.AfterCapture = pointer(uint32(2)) },
		} {
			d := base
			edit(&d)
			raw := append(statusTestPrefix(t, c, 2), statusTestFrame(t, &c.Nonce, 3, "capture-returned", d)...)
			if out := readTestStatuses(raw, c); !errors.Is(out.Err, errProtocolInvalid) || !out.Independent {
				t.Fatal("invalid returned metadata accepted")
			}
		}
		ready := statusTestData(c)[1].(readyData)
		bad := base
		if checkpoint == "active" {
			bad.ReleasedLengths = pointer([3]uint64{})
		} else {
			bad.ReleasedLengths = nil
		}
		if validReturned(bad, checkpoint, &ready) {
			t.Fatal("wrong release metadata accepted")
		}
		if checkpoint == "closed-1s" {
			bad = base
			bad.Timing.CloseToCaptureNS = pointer(uint64(999_999_999))
			if validReturned(bad, checkpoint, &ready) {
				t.Fatal("early delayed checkpoint accepted")
			}
		}
	}
}

func TestIPCStatusTerminalAndShortEvidence(t *testing.T) {
	c := ipcTestConfig()
	failed := statusTestFrame(t, &c.Nonce, 1, "failed", failedData{LastOK: "entry", ErrorClass: "workload_failed"})
	for name, terminal := range map[string][]byte{"failed": failed, "cleaned": statusTestPrefix(t, c, 4)} {
		for _, extra := range [][]byte{{1}, {0, 0, 0}, ipcRawFrame([]byte(`{}`))} {
			t.Run(name, func(t *testing.T) {
				raw := append(append([]byte(nil), terminal...), extra...)
				out := readTestStatuses(raw, c)
				if !errors.Is(out.Err, errProtocolInvalid) || !out.Independent {
					t.Fatal("bytes after a terminal status were treated as a short-stream consequence")
				}
			})
		}
	}
	for _, raw := range [][]byte{{1}, {0, 0, 0}, {0, 0, 0, 5, '{'}} {
		out := readTestStatuses(raw, c)
		if !errors.Is(out.Err, errProtocolInvalid) || out.Independent || out.EOF {
			t.Fatal("unexplained short status stream was treated as independent malformed input")
		}
	}
	for _, edit := range []func(*failedData){
		func(d *failedData) { d.LastOK = "configured" }, func(d *failedData) { d.ErrorClass = "unknown" },
		func(d *failedData) { d.CleanupError = pointer("fixture_cleanup_failed") }, func(d *failedData) { d.ReleasedLengths = pointer([3]uint64{1, 0, 0}) },
	} {
		d := failedData{LastOK: "entry", ErrorClass: "workload_failed"}
		edit(&d)
		if out := readTestStatuses(statusTestFrame(t, &c.Nonce, 1, "failed", d), c); !errors.Is(out.Err, errProtocolInvalid) || !out.Independent {
			t.Fatal("invalid terminal failure accepted")
		}
	}
	out := readTestStatuses(statusTestFrame(t, nil, 1, "failed", failedData{LastOK: "entry", ErrorClass: "workload_failed"}), c)
	if !errors.Is(out.Err, errProtocolInvalid) || !out.Independent {
		t.Fatal("null nonce outside invalid-config failure accepted")
	}
}

func TestIPCProtectionEvidence(t *testing.T) {
	for _, policy := range []string{"none", "all"} {
		c := ipcTestConfig()
		c.Policy = policy
		good := statusTestData(c)[0].(configuredData).Protection
		if !validProtection(good, policy, true) {
			t.Fatal("valid protection evidence rejected")
		}
		for _, edit := range []func(*Protection){
			func(p *Protection) { p.RequestedPolicy = "other" }, func(p *Protection) { p.EffectivePolicy = "other" },
			func(p *Protection) { p.Offheap = !p.Offheap }, func(p *Protection) { p.Lock = !p.Lock },
			func(p *Protection) { p.Dontdump = !p.Dontdump }, func(p *Protection) { p.Zero = !p.Zero },
			func(p *Protection) { p.Dumpable = 1 }, func(p *Protection) { p.CoreSoft = 1 }, func(p *Protection) { p.CoreHard = 1 },
		} {
			bad := good
			edit(&bad)
			if validProtection(bad, policy, true) {
				t.Fatal("invalid effective protection accepted")
			}
		}
		bad := good
		if policy == "all" {
			bad.ProtectedAllocationsLocked = pointer(false)
		} else {
			bad.ProtectedAllocationsLocked = pointer(true)
		}
		if validProtection(bad, policy, true) {
			t.Fatal("invalid locked-allocation evidence accepted")
		}
	}
}

func TestIPCExporterSourceContract(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "ipc_linux_amd64.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "exportOracle" && fn.Name.Name != "exportMarker") {
			continue
		}
		writes, borrows := 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch target := call.Fun.(type) {
			case *ast.Ident:
				if target.Name == "append" || target.Name == "string" || target.Name == "copy" {
					t.Fatal("exporter clones or encodes payload bytes")
				}
			case *ast.SelectorExpr:
				if target.Sel.Name == "Write" {
					writes++
				}
				if target.Sel.Name == "Bytes" {
					borrows++
				}
				if target.Sel.Name == "Clone" || target.Sel.Name == "Marshal" || target.Sel.Name == "Encode" || target.Sel.Name == "NewWriter" {
					t.Fatal("exporter buffers or serializes payload bytes")
				}
			}
			return true
		})
		if writes != 2 {
			t.Fatal("exporter must directly write one header and one live payload")
		}
		if fn.Name.Name == "exportOracle" && borrows != 1 {
			t.Fatal("oracle exporter must borrow once")
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assignment, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, right := range assignment.Rhs {
				call, ok := right.(*ast.CallExpr)
				if !ok {
					continue
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Bytes" {
					t.Fatal("exporter retains a Bytes alias")
				}
			}
			return true
		})
	}
}

func TestIPCStrictRequiredStatusMembers(t *testing.T) {
	c := ipcTestConfig()
	for _, data := range statusTestData(c) {
		raw := ipcJSON(t, data)
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatal(err)
		}
		for name := range members {
			changed := make(map[string]json.RawMessage, len(members))
			for k, v := range members {
				changed[k] = v
			}
			delete(changed, name)
			dst := reflect.New(reflect.TypeOf(data)).Interface()
			if !errors.Is(decodeStrict(ipcJSON(t, changed), dst), errProtocolInvalid) {
				t.Fatal("absent required status member accepted")
			}
		}
	}
}
