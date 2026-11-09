package keymem

import (
	"bytes"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func testPattern(t *testing.T, data []byte) *secmem.Buffer {
	t.Helper()
	b, err := secmem.New(len(data))
	if err != nil {
		t.Fatal("protected test allocation failed")
	}
	copy(b.Bytes(), data)
	t.Cleanup(b.Release)
	return b
}

func TestMatcherOverlaps(t *testing.T) {
	m, err := newStreamMatcher(testPattern(t, []byte("aaa")))
	if err != nil {
		t.Fatal(err)
	}
	m.consume([]byte("aa"), 0, 0)
	m.consume([]byte("aaa"), 2, 0)
	// aaa starts at offsets 0, 1 and 2 in aaaaa, so there are three overlapping matches
	if m.count != 3 {
		t.Fatalf("match count = %d, want 3", m.count)
	}
}

func TestMatcherObjectReset(t *testing.T) {
	m, err := newStreamMatcher(testPattern(t, bytes.Repeat([]byte{0x61}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	m.consume(bytes.Repeat([]byte{0x61}, 16), 0, 0)
	m.reset()
	m.consume(bytes.Repeat([]byte{0x61}, 16), 0, 0)
	if m.count != 0 {
		t.Fatalf("matches crossed an object boundary")
	}
}

func TestMatcherPrefixFallback(t *testing.T) {
	m, err := newStreamMatcher(testPattern(t, []byte("ababac")))
	if err != nil {
		t.Fatal(err)
	}
	m.consume([]byte("ababababacababac"), 0, 4)
	if m.count != 2 {
		t.Fatalf("match count = %d, want 2", m.count)
	}
}

func TestMatcherInvalidPatterns(t *testing.T) {
	if _, err := newStreamMatcher(nil); err != errParseInvalid {
		t.Fatal("nil pattern accepted")
	}
	if _, err := newStreamMatcher(testPattern(t, make([]byte, 33))); err != errParseInvalid {
		t.Fatal("oversized pattern accepted")
	}
	b := testPattern(t, []byte{1})
	b.Release()
	if _, err := newStreamMatcher(b); err != errParseInvalid {
		t.Fatal("released pattern accepted")
	}
}
