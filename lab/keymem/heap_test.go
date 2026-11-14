package keymem

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type heapFixture []byte

func (f *heapFixture) u(values ...uint64) {
	for _, v := range values {
		*f = binary.AppendUvarint(*f, v)
	}
}

func (f *heapFixture) blob(b []byte) {
	f.u(uint64(len(b)))
	*f = append(*f, b...)
}

func (f *heapFixture) text(s string) {
	f.blob([]byte(s))
}

func (f *heapFixture) object(address uint64, b []byte) {
	f.u(1, address)
	f.blob(b)
	f.u(0)
}

func (f *heapFixture) footer() {
	f.u(12, 0, 0, 0, 13, 0, 0, 0, 10)
	for range 281 {
		f.u(0)
	}
	f.u(0)
}

func heapStart() heapFixture {
	f := heapFixture(heapHeader)
	f.u(6, 0, 8, 0, math.MaxUint64)
	f.text("amd64")
	f.text("go1.27.4")
	f.u(1)
	return f
}

func testPatterns(t *testing.T) [5]*secmem.Buffer {
	t.Helper()
	var patterns [5]*secmem.Buffer
	for i := range patterns {
		patterns[i] = testPattern(t, bytes.Repeat([]byte{byte(0x11 * (i + 1))}, 32))
	}
	return patterns
}

func validHeap() heapFixture {
	f := heapStart()
	f.object(4096, bytes.Repeat([]byte{0x44}, 32))
	f.footer()
	return f
}

func TestHeapMinimalKnownAnswer(t *testing.T) {
	f := validHeap()
	r, err := parseHeap(bytes.NewReader(f), testPatterns(t), 4096)
	if err != nil {
		t.Fatal(err)
	}
	// one 32-byte marker object, no key occurrences; amd64 and go1.27.4 contribute 5+8 unscored bytes
	if !r.Complete || !r.PositiveOK || !r.NegativeOK || r.Matches != [3]uint64{} || r.ObjectRecords != 1 || r.ObjectBytes != 32 || r.UnscoredBlobBytes != 13 || r.StreamBytes != uint64(len(f)) {
		t.Fatalf("incorrect minimal-stream aggregate: %+v", r)
	}
}

func TestHeapEveryRecordAndFieldKind(t *testing.T) {
	f := heapStart()
	f.object(4096, bytes.Repeat([]byte{0x44}, 32))
	f.u(1, 8192, 0, 1, 0, 2, 8, 3, 16, 0)
	f.u(2)
	f.text("root")
	f.u(8192)
	for range 2 {
		f.u(3, 8192, 64)
		f.text("type")
		f.u(1)
	}
	f.u(4, 1, 2, 3, 4, 5, 0, 1, 8)
	f.text("waiting")
	f.u(9, 10, 11, 12)
	f.u(5, 1, 2, 3)
	f.blob(bytes.Repeat([]byte{0x11}, 32))
	f.u(4, 5, 6)
	f.text("frame")
	f.u(1, 0, 2, 8, 3, 16, 0)
	f.u(7, 1, 2, 3, 4, 5)
	f.u(8, 1, 2)
	f.u(9, 1, 2, 3)
	f.u(11, 1, 2, 3, 4, 5)
	f.u(14, 1, 2, 3, 4, 5, 6, 7)
	f.u(15, 1, 2, 3, 4, 5, 6)
	f.u(16, 1, 2, 1)
	f.text("function")
	f.text("file")
	f.u(42, 5, 6)
	f.u(17, 1, 2)
	f.footer()
	r, err := parseHeap(bytes.NewReader(f), testPatterns(t), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || r.ObjectRecords != 2 || r.Matches != [3]uint64{} {
		t.Fatal("record layout or field kinds incorrectly consumed")
	}
}

type smallHeapReader struct {
	reader io.Reader
	limit  int
}

func (r *smallHeapReader) Read(p []byte) (int, error) {
	if len(p) > r.limit {
		p = p[:r.limit]
	}
	return r.reader.Read(p)
}

func TestHeapChunkAndObjectBoundaries(t *testing.T) {
	patterns := testPatterns(t)
	f := heapStart()
	f.object(4096, bytes.Repeat([]byte{0x44}, 32))
	f.object(8192, bytes.Repeat([]byte{0x11}, 32))
	f.object(12288, bytes.Repeat([]byte{0x22}, 16))
	f.object(16384, bytes.Repeat([]byte{0x22}, 16))
	f.footer()
	for _, size := range []int{1, 2, 7, 31, 32, 33, 65536} {
		r, err := parseHeap(&smallHeapReader{bytes.NewReader(f), size}, patterns, 4096)
		if err != nil || r.Matches != [3]uint64{1, 0, 0} {
			t.Fatalf("read size %d: incorrect matching result or error", size)
		}
	}
}

func TestHeapOnlyObjectPayloadsMatch(t *testing.T) {
	f := heapStart()
	f.object(4096, bytes.Repeat([]byte{0x44}, 32))
	f.u(3, 0, 0)
	f.blob(bytes.Repeat([]byte{0x11}, 32))
	f.u(0)
	f.u(5, 0, 0, 0)
	f.blob(bytes.Repeat([]byte{0x11}, 32))
	f.u(0, 0, 0)
	f.blob(bytes.Repeat([]byte{0x11}, 32))
	f.u(0)
	for _, tag := range []uint64{12, 13} {
		f.u(tag, 0)
		f.blob(bytes.Repeat([]byte{0x11}, 32))
		f.u(0)
	}
	f.u(10)
	for range 281 {
		f.u(0)
	}
	f.u(0)
	r, err := parseHeap(bytes.NewReader(f), testPatterns(t), 4096)
	if err != nil || r.Matches != [3]uint64{} {
		t.Fatal("unscored bytes reached the matcher")
	}
}

func TestHeapControlsRequireOriginalRange(t *testing.T) {
	for _, tt := range []struct {
		name    string
		address uint64
		payload []byte
		marker  uint64
		want    error
	}{
		{"exact", 4096, bytes.Repeat([]byte{0x44}, 32), 4096, nil},
		{"interior", 4096, append([]byte{0}, bytes.Repeat([]byte{0x44}, 32)...), 4097, nil},
		{"stray-copy", 4096, bytes.Repeat([]byte{0x44}, 32), 8192, errControlFailed},
		{"wrong-offset", 4096, append([]byte{0}, bytes.Repeat([]byte{0x44}, 32)...), 4096, errControlFailed},
		{"uncovered-tail", 4096, bytes.Repeat([]byte{0x44}, 32), 4097, errControlFailed},
		{"negative", 4096, append(bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x55}, 32)...), 4096, errControlFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := heapStart()
			f.object(tt.address, tt.payload)
			f.footer()
			r, err := parseHeap(bytes.NewReader(f), testPatterns(t), tt.marker)
			if !errors.Is(err, tt.want) || !r.Complete {
				t.Fatal("incorrect control classification")
			}
			if err != nil && r.Matches != [3]uint64{} {
				t.Fatal("invalid controls retained key outcomes")
			}
		})
	}
}

func TestHeapEveryTruncationBoundary(t *testing.T) {
	f := heapStart()
	f.object(4096, bytes.Repeat([]byte{0x44}, 32))
	f.u(3, math.MaxUint64, math.MaxUint64)
	f.text("metadata")
	f.u(1)
	f.footer()
	patterns := testPatterns(t)
	for i := 0; i < len(f); i++ {
		r, err := parseHeap(bytes.NewReader(f[:i]), patterns, 4096)
		if !errors.Is(err, errCaptureIncomplete) || r.Complete || r.Matches != [3]uint64{} {
			t.Fatalf("truncation at %d was not unavailable", i)
		}
	}
}

func TestHeapInvalidGrammar(t *testing.T) {
	start := heapStart()
	cases := map[string]heapFixture{}
	add := func(name string, bytes ...byte) {
		cases[name] = append(append(heapFixture(nil), start...), bytes...)
	}
	add("unknown-tag", 18)
	add("nonminimal", 0x81, 0)
	add("overflow", 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2)
	add("continuation-overflow", 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80)
	add("bad-field-kind", 1, 0, 0, 4)
	add("invalid-type-bool", 3, 0, 0, 0, 2)
	add("invalid-goroutine-bool-six", 4, 0, 0, 0, 0, 0, 2)
	add("invalid-goroutine-bool-seven", 4, 0, 0, 0, 0, 0, 0, 2)
	add("early-eof", 0)
	add("duplicate-params", 6)
	add("duplicate-data", 12, 0, 0, 0, 12)
	add("duplicate-bss", 13, 0, 0, 0, 13)
	add("duplicate-memstats", append(append([]byte{10}, make([]byte, 281)...), 10)...)
	cases["trailing-byte"] = append(validHeap(), 0)
	cases["missing-params"] = heapFixture(append([]byte(heapHeader), 0))
	cases["wrong-header"] = heapFixture("go1.8 heap dump\n")
	for _, tt := range []struct {
		name string
		at   int
		b    byte
	}{
		{"big-endian", len(heapHeader) + 1, 1},
		{"invalid-endian-bool", len(heapHeader) + 1, 2},
		{"pointer-size", len(heapHeader) + 2, 4},
	} {
		f := append(heapFixture(nil), validHeap()...)
		f[tt.at] = tt.b
		cases[tt.name] = f
	}
	cases["wrong-architecture"] = heapFixture(bytes.Replace(validHeap(), []byte("amd64"), []byte("arm64"), 1))
	cases["wrong-runtime"] = heapFixture(bytes.Replace(validHeap(), []byte("go1.27.4"), []byte("go1.27.3"), 1))
	f := heapStart()
	f.u(1, math.MaxUint64, 1, 0)
	cases["object-range-overflow"] = f
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := parseHeap(bytes.NewReader(f), testPatterns(t), 4096)
			if !errors.Is(err, errParseInvalid) || r.Complete || r.Matches != [3]uint64{} {
				t.Fatal("malformed stream was not parse_invalid")
			}
		})
	}
}

func TestHeapLimits(t *testing.T) {
	cases := map[string]heapFixture{}
	f := heapStart()
	f.u(1, 0, heapStreamLimit)
	cases["blob-remaining-budget"] = f
	f = heapStart()
	f.u(2, heapStringLimit+1)
	cases["metadata-string"] = f
	f = heapStart()
	f.u(16, 0, 0, heapStackLimit+1)
	cases["memprof-stack"] = f
	f = heapStart()
	f.u(1, 0, 0)
	for range heapFieldLimit + 1 {
		f.u(1, 0)
	}
	cases["field-count"] = f
	f = heapStart()
	for range heapRecordLimit {
		f.u(8, 0, 0)
	}
	cases["record-count"] = f
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := parseHeap(bytes.NewReader(f), testPatterns(t), 4096)
			if !errors.Is(err, errCaptureLimit) || r.Complete || r.Matches != [3]uint64{} {
				t.Fatal("bound breach was not capture_limit")
			}
		})
	}
}

type errorHeapReader struct{}

func (errorHeapReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure")
}

type emptyHeapReader struct{}

func (emptyHeapReader) Read([]byte) (int, error) {
	return 0, nil
}

func TestHeapReadFailure(t *testing.T) {
	patterns := testPatterns(t)
	for _, reader := range []io.Reader{errorHeapReader{}, emptyHeapReader{}} {
		if _, err := parseHeap(reader, patterns, 4096); !errors.Is(err, errControllerFailed) {
			t.Fatal("raw read failure was not controller_failed")
		}
	}
}

func TestHeapMissingMandatoryRecords(t *testing.T) {
	for _, missing := range []uint64{10, 12, 13} {
		f := heapStart()
		f.object(4096, bytes.Repeat([]byte{0x44}, 32))
		for _, tag := range []uint64{12, 13, 10} {
			if tag == missing {
				continue
			}
			f.u(tag)
			if tag == 10 {
				for range 281 {
					f.u(0)
				}
			} else {
				f.u(0, 0, 0)
			}
		}
		f.u(0)
		if _, err := parseHeap(bytes.NewReader(f), testPatterns(t), 4096); !errors.Is(err, errParseInvalid) {
			t.Fatalf("missing mandatory tag %d accepted", missing)
		}
	}
}

type zeroHeapReader struct{}

func (zeroHeapReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestHeapActualStreamLimit(t *testing.T) {
	prefix := heapStart()
	prefix.object(4096, bytes.Repeat([]byte{0x44}, 32))
	prefix.u(12, 0)
	var suffix heapFixture
	suffix.u(0, 13, 0, 0, 0, 10)
	for range 281 {
		suffix.u(0)
	}
	suffix.u(0)
	n := heapStreamLimit - uint64(len(prefix)+len(suffix))
	for {
		encoded := binary.AppendUvarint(nil, n)
		next := heapStreamLimit - uint64(len(prefix)+len(encoded)+len(suffix))
		if next == n {
			prefix = append(prefix, encoded...)
			break
		}
		n = next
	}
	patterns := testPatterns(t)
	for _, extra := range []bool{false, true} {
		var trailing []byte
		if extra {
			trailing = []byte{1}
		}
		reader := io.MultiReader(bytes.NewReader(prefix), io.LimitReader(zeroHeapReader{}, int64(n)), bytes.NewReader(suffix), bytes.NewReader(trailing))
		r, err := parseHeap(reader, patterns, 4096)
		if extra {
			if !errors.Is(err, errCaptureLimit) || r.Complete || r.StreamBytes != heapStreamLimit+1 {
				t.Fatal("extra actual stream byte did not exceed the bound")
			}
		} else if err != nil || !r.Complete || r.StreamBytes != heapStreamLimit {
			t.Fatal("exactly bounded stream was rejected")
		}
	}
}

func TestHeapInvalidMarkerAndPatterns(t *testing.T) {
	patterns := testPatterns(t)
	if _, err := parseHeap(bytes.NewReader(validHeap()), patterns, math.MaxUint64-31); !errors.Is(err, errParseInvalid) {
		t.Fatal("overflowing marker range accepted")
	}
	patterns[0] = nil
	if _, err := parseHeap(bytes.NewReader(validHeap()), patterns, 4096); !errors.Is(err, errParseInvalid) {
		t.Fatal("missing pattern accepted")
	}
}
