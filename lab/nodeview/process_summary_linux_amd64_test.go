//go:build linux && amd64

package nodeview

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"testing"
)

func testProcessSummary() processSummary {
	s := processSummary{mask: 7}
	for i := range 16 {
		s.values[i] = uint64(i + 1)
	}
	s.values[16], s.values[17] = 100, 2000
	s.values[18], s.values[19], s.values[20], s.values[21], s.values[22] = 65536, 10, 11, 12, 13
	s.values[23] = 2 << 20
	return s
}

func TestProcessSummaryExactCodec(t *testing.T) {
	s := testProcessSummary()
	body := encodeProcessSummary(s)
	// five typed header bytes plus 24 eight-byte fields give 197; framing adds 30
	if body.bad || len(body.b) != 197 || !bytes.Equal(body.b[:5], []byte{6, 0, 1, 1, 7}) {
		t.Fatal("incorrect aggregate body layout")
	}
	for i, value := range s.values {
		if binary.BigEndian.Uint64(body.b[5+8*i:13+8*i]) != value {
			t.Fatalf("field %d changed order or endian", i)
		}
	}
	got, err := decodeProcessSummary(&decoder{b: body.b})
	if err != nil || got.mask != s.mask || got.values != s.values {
		t.Fatalf("aggregate round trip failed: %v", err)
	}
	var wire bytes.Buffer
	w := protocolWriter{w: &wire, limit: 1024}
	if err := w.send(opView, encodeProcessSummary(s)); err != nil {
		t.Fatal(err)
	}
	if wire.Len() != 227 || binary.BigEndian.Uint32(wire.Bytes()[:4]) != 223 || wire.Bytes()[5] != 12 {
		t.Fatal("incorrect aggregate frame layout")
	}
}

func TestProcessSummaryRejectsMalformedBody(t *testing.T) {
	valid := encodeProcessSummary(testProcessSummary()).b
	for n := 0; n < len(valid); n++ {
		if _, err := decodeProcessSummary(&decoder{b: valid[:n]}); err == nil {
			t.Fatalf("truncated body length %d accepted", n)
		}
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), valid...), 0),
		append([]byte{5}, valid[1:]...),
		append(append([]byte(nil), valid[:1]...), append([]byte{0, 2}, valid[3:]...)...),
		append(append([]byte(nil), valid[:3]...), append([]byte{2}, valid[4:]...)...),
		append(append([]byte(nil), valid[:4]...), append([]byte{8}, valid[5:]...)...),
	} {
		if _, err := decodeProcessSummary(&decoder{b: bad}); err == nil {
			t.Fatal("invalid kind/count/version/mask/length accepted")
		}
	}
	for _, in := range []*decoder{nil, {b: valid, at: -1}, {b: valid, at: len(valid) + 1}} {
		if _, err := decodeProcessSummary(in); err == nil {
			t.Fatal("invalid decoder state accepted")
		}
	}
}

func TestProcessSummaryMasksAndResourceCaps(t *testing.T) {
	for mask := byte(0); mask < 8; mask++ {
		s := processSummary{mask: mask}
		body := encodeProcessSummary(s)
		if body.bad {
			t.Fatal("missing group cannot be represented")
		}
		if got, err := decodeProcessSummary(&decoder{b: body.b}); err != nil || got.mask != mask {
			t.Fatalf("mask %d rejected: %v", mask, err)
		}
	}
	for _, index := range []int{0, 15, 16, 17, 18, 22, 23} {
		s := processSummary{}
		s.values[index] = 1
		if !encodeProcessSummary(s).bad {
			t.Fatalf("absent group field %d retained a value", index)
		}
	}
	for i, cap := range []uint64{32 << 20, 128, 512, 8192, 65536} {
		s := processSummary{mask: 7}
		s.values[18+i] = cap
		if encodeProcessSummary(s).bad {
			t.Fatalf("field %d rejected exact cap", i)
		}
		s.values[18+i]++
		if !encodeProcessSummary(s).bad {
			t.Fatalf("field %d accepted cap+1", i)
		}
		body := encodeProcessSummary(processSummary{mask: 7}).b
		binary.BigEndian.PutUint64(body[5+8*(18+i):13+8*(18+i)], cap+1)
		if _, err := decodeProcessSummary(&decoder{b: body}); err == nil {
			t.Fatal("decoder accepted excessive highwater")
		}
	}
}

func TestProcessSummaryAggregationKnownAnswer(t *testing.T) {
	var a summaryAccumulator
	for i := 1; i <= 5; i++ {
		s := processSummary{mask: 7}
		for j := range 16 {
			s.values[j] = uint64(i * (j + 1))
		}
		s.values[16], s.values[17] = uint64(i), uint64(10*i)
		for j := 18; j < 23; j++ {
			s.values[j] = uint64(i)
		}
		s.values[23] = uint64(1024 * i)
		if err := a.add(s); err != nil {
			t.Fatal(err)
		}
	}
	s, rss, err := a.result()
	// 1+2+3+4+5=15; per-process peaks use max=5 rather than sum=15
	if err != nil || s.Calls != 15 || s.CallbackNS != 150 || rss != 5120 || s.ArenaHighWater != 5 || s.ConnectionsHighWater != 5 || s.PendingHighWater != 5 || s.ContextsHighWater != 5 || s.CellsHighWater != 5 {
		t.Fatalf("sum/max mismatch: %v", err)
	}
	for i, value := range s.ObservedStats {
		if value != uint64(15*(i+1)) {
			t.Fatalf("Stats sum %d mismatch", i)
		}
	}
	if s.Counters != (CounterChecks{}) || s.Stages != ([5]uint64{}) || s.Roles != ([3]uint64{}) || s.Lifecycle != ([6]uint64{}) {
		t.Fatal("process summaries fabricated selected-event evidence")
	}
	if err := a.add(processSummary{mask: 7}); err == nil {
		t.Fatal("sixth relay summary accepted")
	}
	if _, _, err := a.result(); err == nil {
		t.Fatal("failed accumulator retained clean status")
	}
}

func TestProcessSummaryMissingIsUnavailable(t *testing.T) {
	for _, missing := range []int{-1, 0, 1, 2} {
		var a summaryAccumulator
		for i := range 5 {
			s := processSummary{mask: 7}
			if i == 4 {
				if missing == -1 {
					continue
				}
				s.mask &^= 1 << missing
			}
			if err := a.add(s); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := a.result(); err == nil {
			t.Fatal("missing group or relay converted to measured zero")
		}
	}
}

func TestProcessSummaryOverflowDoesNotCommit(t *testing.T) {
	for _, index := range []int{0, 15, 16, 17} {
		var a summaryAccumulator
		first := processSummary{mask: 7}
		first.values[index] = math.MaxUint64
		if err := a.add(first); err != nil {
			t.Fatal(err)
		}
		before := a.summary
		next := processSummary{mask: 7}
		next.values[index] = 1
		if err := a.add(next); err == nil || a.count != 1 || a.summary != before {
			t.Fatal("overflow wrapped or partially committed")
		}
		if _, _, err := a.result(); err == nil {
			t.Fatal("overflow became a clean result")
		}
	}
}

func TestProcessSummaryStatsDeltaAndRSSKnownAnswers(t *testing.T) {
	var before, after [16]uint64
	for i := range before {
		before[i], after[i] = uint64(100+i), uint64(103+2*i)
	}
	delta, err := checkedStatsDelta(before, after)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range delta {
		if value != uint64(3+i) {
			t.Fatal("Stats subtraction mismatch")
		}
	}
	after[15] = before[15] - 1
	if _, err := checkedStatsDelta(before, after); err == nil {
		t.Fatal("Stats underflow accepted")
	}
	if value, err := rssBytes(3); err != nil || value != 3072 {
		t.Fatal("Linux KiB conversion mismatch")
	}
	for _, value := range []int64{-1, int64(math.MaxUint64/1024) + 1} {
		if _, err := rssBytes(value); err == nil {
			t.Fatal("invalid RSS conversion accepted")
		}
	}
	for _, state := range []*os.ProcessState{nil, {}} {
		if _, err := waitRSS(state); err == nil {
			t.Fatal("missing owned Wait accounting accepted")
		}
	}
	if value, err := selfRSS(); err != nil || value == 0 || value%1024 != 0 {
		t.Fatalf("actual Linux self accounting unavailable: %v", err)
	}
}
