//go:build linux && amd64

package keymem

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/pki"
	"golang.org/x/sys/unix"
)

var noncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type relayPublic struct {
	Address string `json:"address"`
	Bundle  string `json:"bundle"`
}

func jsonBody(value any) (json.RawMessage, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return nil, errProtocolInvalid
	}
	return b, nil
}

type childConfig struct {
	Version    int           `json:"version"`
	Nonce      string        `json:"nonce"`
	Suite      string        `json:"suite"`
	Policy     string        `json:"policy"`
	Checkpoint string        `json:"checkpoint"`
	Anchor     string        `json:"anchor"`
	Relays     []relayPublic `json:"relays"`
}

func (c childConfig) validate() error {
	if c.Version != 1 || !noncePattern.MatchString(c.Nonce) || (c.Suite != "c25519" && c.Suite != "gost") || (c.Policy != "none" && c.Policy != "all") || (c.Checkpoint != "active" && c.Checkpoint != "closed-now" && c.Checkpoint != "closed-1s") || len(c.Anchor) > 256 || len(c.Relays) != 3 {
		return errProtocolInvalid
	}
	a, e := pki.ParseAnchor(c.Anchor)
	if e != nil || a.Suite.String() != c.Suite {
		return errProtocolInvalid
	}
	for _, r := range c.Relays {
		host, port, e := net.SplitHostPort(r.Address)
		if e != nil || host != "127.0.0.1" {
			return errProtocolInvalid
		}
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != port || net.JoinHostPort(host, port) != r.Address {
			return errProtocolInvalid
		}
		if len(r.Bundle) > base64.StdEncoding.EncodedLen(4096) {
			return errProtocolInvalid
		}
		b, e := base64.StdEncoding.Strict().DecodeString(r.Bundle)
		if e != nil || len(b) == 0 || len(b) > 4096 || base64.StdEncoding.EncodeToString(b) != r.Bundle {
			return errProtocolInvalid
		}
	}
	return nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if n < 0 || n > len(p) {
			return errProtocolInvalid
		}
		p = p[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func writeFrame(w io.Writer, value any, max int) error {
	b, e := json.Marshal(value)
	if e != nil || len(b) < 1 || len(b) > max {
		return errProtocolInvalid
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if e = writeAll(w, h[:]); e != nil {
		return errProtocolInvalid
	}
	if e = writeAll(w, b); e != nil {
		return errProtocolInvalid
	}
	return nil
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, errProtocolInvalid
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		if e == io.EOF {
			e = io.ErrUnexpectedEOF
		}
		return nil, e
	}
	return b, nil
}

func validateTokens(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return errProtocolInvalid
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return errProtocolInvalid
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errProtocolInvalid
			}
			seen[s] = true
			if e = validateTokens(d); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return errProtocolInvalid
		}
	case '[':
		for d.More() {
			if e := validateTokens(d); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return errProtocolInvalid
		}
	default:
		return errProtocolInvalid
	}
	return nil
}

func validateShape(raw json.RawMessage, t reflect.Type) error {
	if t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return validateShape(raw, t.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errProtocolInvalid
	}
	switch t.Kind() {
	case reflect.Struct:
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || len(m) != t.NumField() {
			return errProtocolInvalid
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			v, ok := m[f.Tag.Get("json")]
			if !ok {
				return errProtocolInvalid
			}
			if e := validateShape(v, f.Type); e != nil {
				return e
			}
		}
	case reflect.Array, reflect.Slice:
		var a []json.RawMessage
		if json.Unmarshal(raw, &a) != nil {
			return errProtocolInvalid
		}
		if t.Kind() == reflect.Array && len(a) != t.Len() {
			return errProtocolInvalid
		}
		for _, v := range a {
			if e := validateShape(v, t.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}

func decodeStrict(raw []byte, dst any) error {
	if !utf8.Valid(raw) {
		return errProtocolInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := validateTokens(d); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errProtocolInvalid
	}
	if e := validateShape(raw, reflect.TypeOf(dst).Elem()); e != nil {
		return e
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(dst); e != nil {
		return errProtocolInvalid
	}
	return nil
}

func captureBody(nonce string) []byte {
	return []byte(`{"version":1,"nonce":"` + nonce + `","command":"capture"}`)
}

func writeCapture(f *os.File, nonce string) error {
	b := captureBody(nonce)
	if len(b) != 76 || !noncePattern.MatchString(nonce) {
		return errProtocolInvalid
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], 76)
	if e := writeAll(f, h[:]); e != nil {
		return errProtocolInvalid
	}
	if e := writeAll(f, b); e != nil {
		return errProtocolInvalid
	}
	if e := f.Close(); e != nil {
		return errors.Join(errProtocolInvalid, errControllerFailed)
	}
	return nil
}

func readCapture(f *os.File, nonce string) error {
	b, e := readFrame(f, 76)
	if e != nil || !bytes.Equal(b, captureBody(nonce)) {
		return errProtocolInvalid
	}
	var extra [1]byte
	n, e := f.Read(extra[:])
	if n != 0 || e != io.EOF {
		return errProtocolInvalid
	}
	if e = f.Close(); e != nil {
		return errProtocolInvalid
	}
	return nil
}

func validateDescriptors(files [4]*os.File) error {
	var stats [4]unix.Stat_t
	for i, f := range files {
		if f == nil || unix.Fstat(int(f.Fd()), &stats[i]) != nil || stats[i].Mode&unix.S_IFMT != unix.S_IFIFO {
			return errProtocolInvalid
		}
		flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if e != nil {
			return errProtocolInvalid
		}
		mode := unix.O_WRONLY
		if i == 0 {
			mode = unix.O_RDONLY
		}
		if flags&unix.O_ACCMODE != mode {
			return errProtocolInvalid
		}
		for j := 0; j < i; j++ {
			if stats[i].Dev == stats[j].Dev && stats[i].Ino == stats[j].Ino {
				return errProtocolInvalid
			}
		}
	}
	return nil
}

func exportOracle(f *os.File, kind, index byte, key *secmem.Buffer) error {
	if key == nil || key.Len() != 32 {
		return errOracleInvalid
	}
	header := [4]byte{kind, index, 0, 32}
	if n, e := f.Write(header[:]); e != nil || n != len(header) {
		return errOracleInvalid
	}
	if n, e := f.Write(key.Bytes()); e != nil || n != 32 {
		return errOracleInvalid
	}
	return nil
}

func exportMarker(f *os.File, marker *[32]byte) error {
	header := [4]byte{2, 255, 0, 32}
	if n, e := f.Write(header[:]); e != nil || n != len(header) {
		return errOracleInvalid
	}
	if n, e := f.Write(marker[:]); e != nil || n != 32 {
		return errOracleInvalid
	}
	return nil
}

type oracleResult struct {
	Patterns    [5]*secmem.Buffer
	Err         error
	Independent bool
}

func (o *oracleResult) release() {
	for i, b := range o.Patterns {
		if b != nil {
			b.Release()
			o.Patterns[i] = nil
		}
	}
}

func readOracle(f io.Reader) (o oracleResult) {
	for i := 0; i < 4; i++ {
		var h [4]byte
		if _, e := io.ReadFull(f, h[:]); e != nil {
			o.Err = errOracleInvalid
			return
		}
		kind, index := byte(1), byte(i)
		if i == 3 {
			kind, index = 2, 255
		}
		if h != [4]byte{kind, index, 0, 32} {
			o.Err = errOracleInvalid
			o.Independent = true
			return
		}
		b, e := secmem.New(32)
		if e != nil {
			o.Err = allocationClass(e)
			o.Independent = true
			return
		}
		o.Patterns[i] = b
		if !b.Locked() {
			o.Err = errProtectionUnavailable
			o.Independent = true
			return
		}
		if _, e := io.ReadFull(f, b.Bytes()); e != nil {
			o.Err = errOracleInvalid
			return
		}
	}
	n, e := f.Read(o.Patterns[3].Bytes()[:1])
	if n != 0 {
		o.Err = errOracleInvalid
		o.Independent = true
		return
	}
	if e != io.EOF {
		o.Err = errControllerFailed
		return
	}
	b, e := secmem.New(32)
	if e != nil {
		o.Err = allocationClass(e)
		o.Independent = true
		return
	}
	o.Patterns[4] = b
	if !b.Locked() {
		o.Err = errProtectionUnavailable
		o.Independent = true
		return
	}
	if randomFill(b.Bytes()) != nil {
		o.Err = errControllerFailed
		return
	}
	for i := range o.Patterns {
		for j := 0; j < i; j++ {
			if bytes.Equal(o.Patterns[i].Bytes(), o.Patterns[j].Bytes()) {
				o.Err = errOracleInvalid
				o.Independent = true
				return
			}
		}
	}
	return
}

func randomFill(b []byte) error {
	for len(b) > 0 {
		n, e := unix.Getrandom(b, 0)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil || n <= 0 {
			return errControllerFailed
		}
		b = b[n:]
	}
	return nil
}

func allocationClass(e error) error {
	if errors.Is(e, secmem.ErrNotLocked) {
		return errProtectionUnavailable
	}
	if errors.Is(e, secmem.ErrNotMapped) {
		return errAllocationFailed
	}
	return errAllocationFailed
}

type statusEnvelope struct {
	Version int             `json:"version"`
	Nonce   *string         `json:"nonce"`
	Seq     uint64          `json:"seq"`
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
}

type configuredData struct {
	GOOS              string     `json:"goos"`
	GOARCH            string     `json:"goarch"`
	Runtime           string     `json:"runtime"`
	BinaryDigest      string     `json:"binary_digest"`
	BinaryDigestSuite string     `json:"binary_digest_suite"`
	Protection        Protection `json:"protection"`
}

type readyData struct {
	EchoOK         bool      `json:"echo_ok"`
	SelectedCount  uint64    `json:"selected_count"`
	AEADUses       [3]uint64 `json:"aead_uses"`
	ActiveLengths  [3]uint64 `json:"active_lengths"`
	MarkerAddress  uint64    `json:"marker_address"`
	EchoReadyNS    uint64    `json:"echo_ready_ns"`
	NumGCEchoReady uint32    `json:"num_gc_echo_ready"`
}

type returnedData struct {
	Timing          Timing     `json:"timing"`
	NumGC           GC         `json:"num_gc"`
	ReleasedLengths *[3]uint64 `json:"released_lengths"`
}

type cleanedData struct {
	ReleasedLengths [3]uint64 `json:"released_lengths"`
	MarkerCleared   bool      `json:"marker_cleared"`
}

type failedData struct {
	LastOK          string     `json:"last_ok"`
	ErrorClass      string     `json:"error_class"`
	CleanupError    *string    `json:"cleanup_error"`
	ReleasedLengths *[3]uint64 `json:"released_lengths"`
}

type statusResult struct {
	Configured  *configuredData
	Ready       *readyData
	Returned    *returnedData
	Cleaned     *cleanedData
	Failed      *failedData
	Err         error
	Independent bool
	EOF         bool
}

type statusEvent struct {
	Ready *readyData
	Fatal bool
}

func failurePhase(class, last string) bool {
	allowed := map[string][]string{
		"unsupported_platform": {"entry"}, "unsupported_runtime": {"entry"},
		"protection_unavailable": {"entry", "configured", "workload-ready"},
		"allocation_failed":      {"entry", "configured"}, "workload_failed": {"entry", "configured"},
		"oracle_invalid": {"configured"}, "protocol_invalid": {"entry", "configured", "workload-ready"},
		"lifecycle_failed": {"configured", "workload-ready", "capture-returned"}, "cleanup_failed": {"capture-returned"},
	}
	for _, phase := range allowed[class] {
		if phase == last {
			return true
		}
	}
	return false
}

func validProtection(p Protection, policy string, configured bool) bool {
	all := policy == "all"
	if p.RequestedPolicy != policy || p.EffectivePolicy != policy || p.Offheap != all || p.Lock != all || p.Dontdump != all || p.Zero != all || p.Dumpable != 0 || p.CoreSoft != 0 || p.CoreHard != 0 {
		return false
	}
	if !all {
		return p.ProtectedAllocationsLocked == nil
	}
	return p.ProtectedAllocationsLocked != nil && *p.ProtectedAllocationsLocked && configured
}

func readStatuses(r io.Reader, c childConfig, digest string, events chan<- statusEvent) (out statusResult) {
	var total uint64
	last := "entry"
	seq := uint64(1)
	bad := func() {
		out.Err = errProtocolInvalid
		out.Independent = true
		select {
		case events <- statusEvent{Fatal: true}:
		default:
		}
	}
	for {
		b, e := readFrame(r, maxStatusBytes)
		if e == io.EOF {
			out.EOF = true
			return
		}
		if e != nil {
			out.Err = errProtocolInvalid
			if errors.Is(e, errProtocolInvalid) || (errors.Is(e, io.ErrUnexpectedEOF) && (out.Failed != nil || out.Cleaned != nil)) {
				bad()
			}
			return
		}
		total += uint64(len(b) + 4)
		if total > maxStatusStream {
			bad()
			return
		}
		var s statusEnvelope
		if decodeStrict(b, &s) != nil || s.Version != 1 || s.Seq != seq {
			bad()
			return
		}
		if out.Failed != nil || out.Cleaned != nil {
			bad()
			return
		}
		if s.Nonce == nil {
			if seq != 1 || s.Type != "failed" {
				bad()
				return
			}
		} else if *s.Nonce != c.Nonce {
			bad()
			return
		}
		if s.Type == "failed" {
			var f failedData
			if decodeStrict(s.Data, &f) != nil || f.LastOK != last || !failurePhase(f.ErrorClass, last) || (f.CleanupError != nil && *f.CleanupError != "child_cleanup_failed") || (f.ReleasedLengths != nil && *f.ReleasedLengths != [3]uint64{}) || (s.Nonce == nil && (f.ErrorClass != "protocol_invalid" || last != "entry")) {
				bad()
				return
			}
			out.Failed = &f
			seq++
			continue
		}
		if s.Nonce == nil {
			bad()
			return
		}
		switch seq {
		case 1:
			var d configuredData
			if s.Type != "configured" || decodeStrict(s.Data, &d) != nil || d.GOOS != "linux" || d.GOARCH != "amd64" || d.Runtime != "go1.27.3" || d.BinaryDigest != digest || d.BinaryDigestSuite != c.Suite || !validProtection(d.Protection, c.Policy, true) {
				bad()
				return
			}
			out.Configured = &d
		case 2:
			var d readyData
			if s.Type != "workload-ready" || decodeStrict(s.Data, &d) != nil || !d.EchoOK || d.SelectedCount != 3 || d.AEADUses != [3]uint64{1, 1, 1} || d.ActiveLengths != [3]uint64{32, 32, 32} || d.MarkerAddress == 0 || d.MarkerAddress > math.MaxUint64-32 || d.EchoReadyNS > uint64(trialTimeout) {
				bad()
				return
			}
			out.Ready = &d
			select {
			case events <- statusEvent{Ready: &d}:
			default:
			}
		case 3:
			var d returnedData
			if s.Type != "capture-returned" || decodeStrict(s.Data, &d) != nil || !validReturned(d, c.Checkpoint, out.Ready) {
				bad()
				return
			}
			out.Returned = &d
		case 4:
			var d cleanedData
			if s.Type != "cleaned" || decodeStrict(s.Data, &d) != nil || d.ReleasedLengths != [3]uint64{} || !d.MarkerCleared {
				bad()
				return
			}
			out.Cleaned = &d
		default:
			bad()
			return
		}
		last = s.Type
		seq++
	}
}

func validReturned(d returnedData, checkpoint string, ready *readyData) bool {
	for _, v := range []*uint64{d.Timing.EchoReadyNS, d.Timing.CloseDurationNS, d.Timing.CloseToCaptureNS, d.Timing.CaptureDurationNS} {
		if v != nil && *v > uint64(trialTimeout) {
			return false
		}
	}
	if ready == nil || d.Timing.EchoReadyNS == nil || *d.Timing.EchoReadyNS != ready.EchoReadyNS || d.Timing.CaptureDurationNS == nil || d.NumGC.EchoReady == nil || *d.NumGC.EchoReady != ready.NumGCEchoReady || d.NumGC.BeforeCapture == nil || d.NumGC.AfterCapture == nil || *d.NumGC.BeforeCapture < *d.NumGC.EchoReady || *d.NumGC.AfterCapture < *d.NumGC.BeforeCapture {
		return false
	}
	if checkpoint == "active" {
		return d.ReleasedLengths == nil && d.Timing.CloseDurationNS == nil && d.Timing.CloseToCaptureNS == nil
	}
	if d.ReleasedLengths == nil || *d.ReleasedLengths != [3]uint64{} || d.Timing.CloseDurationNS == nil || d.Timing.CloseToCaptureNS == nil {
		return false
	}
	return checkpoint != "closed-1s" || *d.Timing.CloseToCaptureNS >= uint64(1000000000)
}
