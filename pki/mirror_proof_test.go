package pki

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// a proof takes the place of a bundle: the item carries the two bundles in
// their canonical order, and a mirror without proofs encodes as before
func TestMirrorCarriesProofs(t *testing.T) {
	p := c25519Provider(t)
	e := newEnv(t, p)
	n2 := e.node(t, "relay-2")
	b1 := e.node(t, "relay-1").bundle(t, t0, time.Hour)
	b3 := e.node(t, "relay-3").bundle(t, t0, time.Hour)
	x := n2.bundle(t, t0, time.Hour)
	// a second onion key under the same epoch: the two bundles conflict
	n2.id.SetKeys(n2.onion, agreementKey(t, p), 0)
	y := n2.bundle(t, t0.Add(time.Second), time.Hour)
	pr, err := NewProof(x, y)
	if err != nil {
		t.Fatal(err)
	}
	a1, a2, a3 := addrOf("relay-1"), addrOf("relay-2"), addrOf("relay-3")

	raw, err := MarshalMirror([]MirrorEntry{{Addr: a3, Bundle: b3}, {Addr: a2, Proof: pr}, {Addr: a1, Bundle: b1}})
	if err != nil {
		t.Fatalf("MarshalMirror: %v", err)
	}
	want := `[{"addr":"` + a1 + `","bundle":` + string(b1) + `},{"addr":"` + a2 + `","proof":[` + string(pr.A) + `,` + string(pr.B) + `]},{"addr":"` + a3 + `","bundle":` + string(b3) + `}]`
	if string(raw) != want {
		t.Fatalf("MarshalMirror wrote\n%s\nwant\n%s", raw, want)
	}
	got, err := ParseMirror(raw)
	if err != nil || len(got) != 3 {
		t.Fatalf("ParseMirror = %d entries, %v", len(got), err)
	}
	switch {
	case got[0].Addr != a1, !bytes.Equal(got[0].Bundle, b1), got[0].Proof != nil:
		t.Fatalf("entry 0: %+v", got[0])
	case got[1].Addr != a2, got[1].Bundle != nil, got[1].Proof == nil || !bytes.Equal(got[1].Proof.A, pr.A) || !bytes.Equal(got[1].Proof.B, pr.B):
		t.Fatalf("entry 1: %+v", got[1])
	case got[2].Addr != a3, !bytes.Equal(got[2].Bundle, b3), got[2].Proof != nil:
		t.Fatalf("entry 2: %+v", got[2])
	}
	if _, err := VerifyConflict(p, e.pol, a2, *got[1].Proof); err != nil {
		t.Fatalf("the proof read back does not verify: %v", err)
	}

	plain, err := MarshalMirror([]MirrorEntry{{Addr: a1, Bundle: b1}, {Addr: a3, Bundle: b3}})
	if err != nil || string(plain) != `[{"addr":"`+a1+`","bundle":`+string(b1)+`},{"addr":"`+a3+`","bundle":`+string(b3)+`}]` {
		t.Fatalf("a mirror without proofs: %v, %s", err, plain)
	}

	item := func(addr, bundle string) string { return `{"addr":"` + addr + `","bundle":` + bundle + `}` }
	proof := func(addr string, elements ...string) string {
		return `{"addr":"` + addr + `","proof":[` + strings.Join(elements, ",") + `]}`
	}
	lo, hi := string(pr.A), string(pr.B)
	for _, c := range []struct {
		name string
		raw  string
		want error
	}{
		{"bundle and proof in one item", `[{"addr":"` + a2 + `","bundle":` + lo + `,"proof":[` + lo + `,` + hi + `]}]`, ErrFormat},
		{"neither", `[{"addr":"` + a2 + `"}]`, ErrFormat},
		{"a proof of one", `[` + proof(a2, lo) + `]`, ErrFormat},
		{"a proof of three", `[` + proof(a2, lo, hi, string(b1)) + `]`, ErrFormat},
		{"equal elements", `[` + proof(a2, lo, lo) + `]`, ErrFormat},
		{"elements out of order", `[` + proof(a2, hi, lo) + `]`, ErrFormat},
		{"an element with a space inside", `[` + proof(a2, strings.Replace(lo, `,"suite"`, `, "suite"`, 1), hi) + `]`, ErrFormat},
		{"an element that is not a bundle", `[` + proof(a2, `{"v":1}`, hi) + `]`, ErrFormat},
		{"an empty proof", `[{"addr":"` + a2 + `","proof":[]}]`, ErrFormat},
		{"a null proof", `[{"addr":"` + a2 + `","proof":null}]`, ErrFormat},
		{"a null bundle", `[{"addr":"` + a2 + `","bundle":null}]`, ErrVersion},
		{"unsorted items", `[` + proof(a2, lo, hi) + `,` + item(a1, string(b1)) + `]`, ErrFormat},
		{"repeated address", `[` + item(a2, lo) + `,` + proof(a2, lo, hi) + `]`, ErrDuplicate},
		{"keys in another order", `[{"proof":[` + lo + `,` + hi + `],"addr":"` + a2 + `"}]`, ErrFormat},
	} {
		_, err := ParseMirror([]byte(c.raw))
		wantErr(t, c.name, err, c.want)
	}
	for _, c := range []struct {
		name    string
		entries []MirrorEntry
	}{
		{"an entry with a bundle and a proof", []MirrorEntry{{Addr: a2, Bundle: x, Proof: pr}}},
		{"an entry with neither", []MirrorEntry{{Addr: a2}}},
		{"a proof of one bundle twice", []MirrorEntry{{Addr: a2, Proof: &Proof{A: x, B: x}}}},
		{"a proof out of order", []MirrorEntry{{Addr: a2, Proof: &Proof{A: pr.B, B: pr.A}}}},
		{"a proof with an element that is not a bundle", []MirrorEntry{{Addr: a2, Proof: &Proof{A: []byte(`{"v":1}`), B: hiBytes(pr)}}}},
	} {
		if _, err := MarshalMirror(c.entries); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: MarshalMirror = %v, want %v", c.name, err, ErrFormat)
		}
	}
}

func hiBytes(pr *Proof) []byte { return pr.B }
