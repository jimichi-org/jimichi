package mailbox

import (
	"bytes"
	"encoding/hex"
	"errors"
	"go/build"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

func providerOf(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// T = "jimichi/v2/<suite>/transcript/mailbox/queue" || 00 || 01 || 0010 || F,
// 62 bytes on c25519 and 60 on GOST, and the identifier is the first half of
// its hash: on c25519 `printf 'jimichi/v2/c25519/transcript/mailbox/queue\x00\x01\x00\x10\x00\x01...\x0f' | sha256sum`,
// on GOST the same bytes under Streebog-256 (gost34112012256 called directly; it reproduces example M1 of GOST R 34.11-2012)
func TestQueueIDVectors(t *testing.T) {
	f := make([]byte, CapSize)
	for i := range f {
		f[i] = byte(i)
	}
	for _, c := range []struct {
		suite jcrypto.Suite
		size  int
		want  string
	}{
		{jcrypto.SuiteC25519, 62, "069cdb04a5dd31eb20f345b4a3c404f1"},
		{jcrypto.SuiteGOST, 60, "f0cac9c3b1105dc46c814d8db9af8d04"},
	} {
		t.Run(c.suite.String(), func(t *testing.T) {
			tr, err := jcrypto.TranscriptBytes(c.suite, "mailbox/queue", f)
			if err != nil {
				t.Fatal(err)
			}
			if len(tr) != c.size {
				t.Fatalf("transcript of %d bytes, want %d", len(tr), c.size)
			}
			id, err := QueueID(providerOf(t, c.suite), f)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(id[:]); got != c.want {
				t.Fatalf("QueueID = %s, want %s", got, c.want)
			}
		})
	}
}

func TestQueueIDTakesSixteenBytes(t *testing.T) {
	p := providerOf(t, jcrypto.SuiteC25519)
	for _, n := range []int{0, 15, 17} {
		if _, err := QueueID(p, make([]byte, n)); !errors.Is(err, ErrCap) {
			t.Fatalf("QueueID of %d bytes: %v, want ErrCap", n, err)
		}
	}
	if _, err := QueueID(p, make([]byte, CapSize)); err != nil {
		t.Fatalf("a zero F is hashed like any other: %v", err)
	}
}

func filled(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func sampleRequest() Request {
	var r Request
	r.Tag = 0x1234
	copy(r.Fetch[:], filled(CapSize, 0xf1))
	copy(r.Put[:], filled(IDSize, 0xa2))
	copy(r.Record[:], filled(RecordSize, 0x5c))
	return r
}

func TestRequestLayout(t *testing.T) {
	if RequestSize != 427 || ReplySize != 396 || RecordSize != 392 {
		t.Fatalf("sizes %d, %d, %d, want 427, 396, 392", RequestSize, ReplySize, RecordSize)
	}
	r := sampleRequest()
	b := r.Bytes()
	want := append([]byte{0x01, 0x12, 0x34}, filled(CapSize, 0xf1)...)
	want = append(want, filled(IDSize, 0xa2)...)
	want = append(want, filled(RecordSize, 0x5c)...)
	if !bytes.Equal(b, want) {
		t.Fatalf("request bytes differ from the layout")
	}
	back, err := ParseRequest(b)
	if err != nil || back != r {
		t.Fatalf("ParseRequest(Bytes) = %v, %v", back.Tag, err)
	}
	for _, bad := range [][]byte{nil, b[:RequestSize-1], append(b, 0), append([]byte{0x02}, b[1:]...), append([]byte{0x00}, b[1:]...)} {
		if _, err := ParseRequest(bad); !errors.Is(err, ErrRequest) {
			t.Fatalf("ParseRequest of %d bytes starting %x: %v, want ErrRequest", len(bad), bad[:min(1, len(bad))], err)
		}
	}
}

func replyBytes(tag uint16, status byte, rec []byte) []byte {
	r := Reply{Tag: tag, Status: status}
	copy(r.Record[:], rec)
	return r.Bytes()
}

func TestReplyLayout(t *testing.T) {
	b := replyBytes(0xbeef, StatusRecord|PutStored, filled(RecordSize, 0x33))
	want := append([]byte{0x01, 0xbe, 0xef, 0x05}, filled(RecordSize, 0x33)...)
	if !bytes.Equal(b, want) {
		t.Fatal("reply bytes differ from the layout")
	}
	r, err := ParseReply(b)
	if err != nil || r.Tag != 0xbeef || r.Status != 0x05 || r.Record[0] != 0x33 {
		t.Fatalf("ParseReply = %+v, %v", r.Tag, err)
	}
}

func TestParseReplyIsStrict(t *testing.T) {
	rec := filled(RecordSize, 0x77)
	good := []struct {
		status byte
		rec    []byte
	}{
		{PutNone, nil}, {PutStored, nil}, {PutFull, nil}, {PutRefused, nil},
		{StatusRecord, rec}, {StatusRecord | PutStored, rec}, {StatusRecord | PutRefused, rec},
		{StatusBad, nil},
	}
	for _, g := range good {
		if _, err := ParseReply(replyBytes(7, g.status, g.rec)); err != nil {
			t.Fatalf("status %#02x refused: %v", g.status, err)
		}
	}

	valid := replyBytes(7, PutStored, nil)
	bad := map[string][]byte{
		"empty":                        nil,
		"one byte short":               valid[:ReplySize-1],
		"one byte long":                append(append([]byte{}, valid...), 0),
		"version 0":                    append([]byte{0x00}, valid[1:]...),
		"version 2":                    append([]byte{0x02}, valid[1:]...),
		"0x80 with a put outcome":      replyBytes(7, StatusBad|PutStored, nil),
		"0x80 with a record":           replyBytes(7, StatusBad|StatusRecord, rec),
		"record without 0x04":          replyBytes(7, PutStored, rec),
		"one record byte without 0x04": replyBytes(7, PutNone, []byte{0, 0, 1}),
		"0x80 with a record tail":      replyBytes(7, StatusBad, []byte{1}),
	}
	for bit := 3; bit <= 6; bit++ {
		bad["reserved bit "+string(rune('0'+bit))] = replyBytes(7, 1<<bit, nil)
	}
	for name, b := range bad {
		if _, err := ParseReply(b); !errors.Is(err, ErrReply) {
			t.Fatalf("%s: %v, want ErrReply", name, err)
		}
	}
}

func TestReplyAnswersItsRequest(t *testing.T) {
	both := sampleRequest()
	fetchOnly := both
	fetchOnly.Put = [IDSize]byte{}
	putOnly := both
	putOnly.Fetch = [CapSize]byte{}
	neither := both
	neither.Fetch, neither.Put = [CapSize]byte{}, [IDSize]byte{}

	for _, c := range []struct {
		name   string
		req    Request
		tag    uint16
		status byte
		ok     bool
	}{
		{"stored and fetched", both, both.Tag, PutStored | StatusRecord, true},
		{"full, empty queue", both, both.Tag, PutFull, true},
		{"refused", both, both.Tag, PutRefused, true},
		{"fetch only", fetchOnly, both.Tag, StatusRecord, true},
		{"put only", putOnly, both.Tag, PutStored, true},
		{"nothing asked", neither, both.Tag, PutNone, true},
		{"other tag", both, both.Tag + 1, PutStored, false},
		{"0x80 on a correct request", both, both.Tag, StatusBad, false},
		{"put outcome without a put", fetchOnly, both.Tag, PutStored, false},
		{"refusal without a put", fetchOnly, both.Tag, PutRefused, false},
		{"no put outcome for a put", both, both.Tag, PutNone, false},
		{"record without F", putOnly, both.Tag, PutStored | StatusRecord, false},
	} {
		r := Reply{Tag: c.tag, Status: c.status}
		if err := r.Answers(&c.req); (err == nil) != c.ok {
			t.Fatalf("%s: Answers = %v", c.name, err)
		}
	}
}

// the store keeps records as opaque bytes: the end-to-end layer stays out of
// the exit, and the exit stays out of the layer
func TestImportsOnlyCrypto(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if strings.Contains(imp, ".") && imp != "github.com/jimichi-org/jimichi/crypto" {
			t.Fatalf("mailbox imports %s", imp)
		}
	}
}
