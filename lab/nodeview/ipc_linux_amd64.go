//go:build linux && amd64

package nodeview

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"os"
	"sync"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"golang.org/x/sys/unix"
)

const (
	opBoot byte = 1 + iota
	opChallenge
	opRequest
	opCertificate
	opBundle
	opConfigure
	opReady
	opContact
	opClientPlan
	opBegin
	opStop
	opView
	opTruth
	opPredict
	opTrain
	opPredictions
	opEnd
	opCleaned
	opError
	opTrained
	opAck
	opFitCheck
)
const (
	roleRelay byte = 1 + iota
	roleClient
	roleScorer
	roleTrainer
	roleFitAuditor
)

var roleNames = []string{"", "relay", "client", "scorer", "trainer", "fit-auditor"}

type encoder struct {
	b      []byte
	bad    bool
	budget *memoryBudget
	err    error
}

func (w *encoder) raw(b []byte) {
	const limit = 65532 - 26
	if w.err != nil {
		return
	}
	if w.bad || len(b) > limit-len(w.b) {
		w.bad = true
		return
	}
	need := len(w.b) + len(b)
	if need > cap(w.b) {
		capacity := min(limit, max(64, max(need, 2*cap(w.b))))
		if e := w.budget.checkAllocation(uint64(capacity)); e != nil {
			w.err = e
			return
		}
		next := make([]byte, need, capacity)
		copy(next, w.b)
		copy(next[len(w.b):], b)
		clear(w.b[:cap(w.b)])
		w.b = next
		return
	}
	w.b = append(w.b, b...)
}
func (w *encoder) wipe()       { clear(w.b[:cap(w.b)]); w.b = nil }
func (w *encoder) u8(v uint8)  { w.raw([]byte{v}) }
func (w *encoder) bool(v bool) { w.u8(byte(boolInt(v))) }
func (w *encoder) u16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.raw(b[:])
}
func (w *encoder) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.raw(b[:])
}
func (w *encoder) u64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.raw(b[:])
}
func (w *encoder) i64(v int64) { w.u64(uint64(v)) }
func (w *encoder) i32(v int32) { w.u32(uint32(v)) }
func (w *encoder) f64(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		w.bad = true
	}
	w.u64(math.Float64bits(v))
}
func (w *encoder) bytes(b []byte, max int) {
	if len(b) > max || len(b) > 65535 {
		w.bad = true
		return
	}
	w.u16(uint16(len(b)))
	w.raw(b)
}
func (w *encoder) ascii(s string, max int) {
	for _, b := range []byte(s) {
		if b == 0 || b > 127 {
			w.bad = true
			return
		}
	}
	w.bytes([]byte(s), max)
}

type decoder struct {
	b   []byte
	at  int
	bad bool
}

func (r *decoder) take(n int) []byte {
	if n < 0 || n > len(r.b)-r.at {
		r.bad = true
		return make([]byte, max(0, min(n, 8)))
	}
	p := r.b[r.at : r.at+n]
	r.at += n
	return p
}
func (r *decoder) u8() byte {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *decoder) bool() bool {
	v := r.u8()
	if v > 1 {
		r.bad = true
	}
	return v == 1
}
func (r *decoder) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *decoder) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *decoder) u64() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *decoder) i64() int64 { return int64(r.u64()) }
func (r *decoder) i32() int32 { return int32(r.u32()) }
func (r *decoder) f64() float64 {
	v := math.Float64frombits(r.u64())
	if math.IsNaN(v) || math.IsInf(v, 0) {
		r.bad = true
	}
	return v
}
func (r *decoder) bytes(max int) []byte {
	n := int(r.u16())
	if n > max {
		r.bad = true
		return nil
	}
	return r.take(n)
}
func (r *decoder) ascii(max int) string {
	b := r.bytes(max)
	for _, v := range b {
		if v == 0 || v > 127 {
			r.bad = true
		}
	}
	return string(b)
}
func (r *decoder) end() error {
	if r.bad || r.at != len(r.b) {
		return fail(ReasonIPC)
	}
	return nil
}

type protocolWriter struct {
	budget        *memoryBudget
	mu            sync.Mutex
	w             io.Writer
	token         [16]byte
	sequence      uint64
	frames, bytes uint64
	limit         uint64
	forcedOpcode  byte
	timeout       time.Duration
}

func (w *protocolWriter) setTimeout(timeout time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timeout = timeout
}

func (w *protocolWriter) send(op byte, body encoder) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer body.wipe()
	if body.err != nil {
		return body.err
	}
	if w.forcedOpcode != 0 {
		op = w.forcedOpcode
	}
	if file, ok := w.w.(*os.File); ok {
		timeout := w.timeout
		if timeout == 0 {
			timeout = 2 * time.Second
		}
		if file.SetWriteDeadline(time.Now().Add(timeout)) != nil {
			return fail(ReasonIPC)
		}
	}
	if body.bad || op < 1 || op > 22 || len(body.b) > 65532-26 || w.frames >= maxIPCMessages || w.sequence == math.MaxUint64 {
		return fail(ReasonIPC)
	}
	n := uint64(len(body.b) + 30)
	if w.bytes+n > w.limit {
		return fail(ReasonLimit)
	}
	var header [30]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(body.b)+26))
	header[4], header[5] = 1, op
	binary.BigEndian.PutUint64(header[6:14], w.sequence)
	copy(header[14:], w.token[:])
	if e := writeAll(w.w, header[:]); e != nil {
		return fail(ReasonIPC)
	}
	if e := writeAll(w.w, body.b); e != nil {
		return fail(ReasonIPC)
	}
	w.sequence++
	w.frames++
	w.bytes += n
	return nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return fail(ReasonIPC)
		}
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type protocolReader struct {
	r                              io.Reader
	token                          [16]byte
	sequence, frames, bytes, limit uint64
	scratch                        *secmem.Buffer
}

func newProtocolReader(r io.Reader, token [16]byte, limit uint64) (*protocolReader, error) {
	b, e := secmem.New(maxFrameBytes)
	if e != nil || !b.Locked() {
		if b != nil {
			b.Release()
		}
		return nil, fail(ReasonUnsupported)
	}
	return &protocolReader{r: r, token: token, limit: limit, scratch: b}, nil
}
func (r *protocolReader) close() {
	if r.scratch != nil {
		r.scratch.Release()
		r.scratch = nil
	}
}
func (r *protocolReader) next() (byte, *decoder, error) {
	var prefix [4]byte
	n, e := io.ReadFull(r.r, prefix[:])
	if e != nil {
		if e == io.EOF && n == 0 {
			return 0, nil, io.EOF
		}
		return 0, nil, fail(ReasonIPC)
	}
	l := int(binary.BigEndian.Uint32(prefix[:]))
	if l < 26 || l > 65532 || r.frames >= maxIPCMessages || r.sequence == math.MaxUint64 || r.bytes+uint64(l+4) > r.limit {
		return 0, nil, fail(ReasonIPC)
	}
	b := r.scratch.Bytes()[:l]
	if _, e = io.ReadFull(r.r, b); e != nil {
		return 0, nil, fail(ReasonIPC)
	}
	if b[0] != 1 || b[1] < 1 || b[1] > 22 || binary.BigEndian.Uint64(b[2:10]) != r.sequence || !bytes.Equal(b[10:26], r.token[:]) {
		return 0, nil, fail(ReasonIPC)
	}
	r.sequence++
	r.frames++
	r.bytes += uint64(l + 4)
	return b[1], &decoder{b: b[26:]}, nil
}

func validatePipe(f *os.File, write bool) error {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return fail(ReasonIPC)
	}
	flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if e != nil {
		return fail(ReasonIPC)
	}
	access := flags & unix.O_ACCMODE
	if write && access != unix.O_WRONLY || !write && access != unix.O_RDONLY {
		return fail(ReasonIPC)
	}
	return nil
}

func encodeSettings(w *encoder, s Settings) {
	for _, v := range []int64{s.RateNS, s.RelayPeriodNS, s.ReplyTimeoutNS, s.KeepaliveNS, s.StaleAfterNS, s.RebuildForNS} {
		w.i64(v)
	}
	for _, v := range []int{s.Window, s.MaxRefusals, s.Outbox, s.Hold, s.Inbox, s.StaleFetches} {
		w.u16(uint16(v))
	}
	for _, v := range []int{s.SourceHandshakes, s.SourceLinks, s.SourceLinkRate, s.SourceSetupRate} {
		w.i32(int32(v))
	}
	for _, v := range []int{s.MaxHandshakes, s.MaxLinks, s.Dispatch} {
		w.u16(uint16(v))
	}
	w.bool(s.CoverPuts)
	kind := byte(2)
	if s.Workload == "active20-quiet10-v1" {
		kind = 1
	} else if s.Workload == "registered-structural-control" {
		kind = 3
	}
	w.u8(kind)
	w.i64(s.DurationNS)
	w.u8(s.ControlProfile)
}
func decodeSettings(r *decoder) Settings {
	s := Settings{RateNS: r.i64(), RelayPeriodNS: r.i64(), ReplyTimeoutNS: r.i64(), KeepaliveNS: r.i64(), StaleAfterNS: r.i64(), RebuildForNS: r.i64(), Window: int(r.u16()), MaxRefusals: int(r.u16()), Outbox: int(r.u16()), Hold: int(r.u16()), Inbox: int(r.u16()), StaleFetches: int(r.u16()), SourceHandshakes: int(r.i32()), SourceLinks: int(r.i32()), SourceLinkRate: int(r.i32()), SourceSetupRate: int(r.i32()), MaxHandshakes: int(r.u16()), MaxLinks: int(r.u16()), Dispatch: int(r.u16()), CoverPuts: r.bool()}
	switch r.u8() {
	case 1:
		s.Workload = "active20-quiet10-v1"
	case 2:
		s.Workload = "echo-exponential-v1"
	case 3:
		s.Workload = "registered-structural-control"
	default:
		r.bad = true
	}
	s.DurationNS = r.i64()
	s.ControlProfile = r.u8()
	if s.ControlProfile > 7 {
		r.bad = true
	}
	return s
}

func encodeCounts(w *encoder, c Counts) {
	for _, v := range []uint64{c.Planned, c.Attempted, c.Refused, c.SetupFailed, c.Established, c.PreflightOK, c.MessageBearing, c.Eligible, c.Unanswered, c.Rebuilt, c.Missing, c.LocalProcessed, c.TransportSealed, c.WriteComplete, c.TerminalUnwritten, c.CutoffCensored, c.Positive, c.Negative, c.Unknown, c.Released} {
		w.u64(v)
	}
}
func decodeCounts(r *decoder) Counts {
	return Counts{r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64(), r.u64()}
}
