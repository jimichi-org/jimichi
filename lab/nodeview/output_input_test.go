//go:build linux && amd64 && goexperiment.jsonv2

package nodeview

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type outputMaskDocument struct {
	A int `json:"a"`
	B int `json:"b,omitempty"`
	C int `json:"c"`
}
type outputRangeI8 struct {
	Value int8 `json:"value"`
}
type outputRangeU8 struct {
	Value uint8 `json:"value"`
}
type outputRangeI64 struct {
	Value int64 `json:"value"`
}
type outputRangeU64 struct {
	Value uint64 `json:"value"`
}
type outputRangeF32 struct {
	Value float32 `json:"value"`
}
type outputRangeF64 struct {
	Value float64 `json:"value"`
}

func outputMaskCases(t *testing.T) {
	t.Helper()
	required, all, err := outputInputMask(reflect.TypeFor[outputMaskDocument]())
	if err != nil || required != 5 || all != 7 {
		t.Fatal("independent required/optional mask changed")
	}
	_, all, err = outputInputMask(reflect.TypeFor[Plan]())
	if err != nil || all != 34359738367 {
		t.Fatal("complete35-field mask changed")
	}
	for _, raw := range []string{`{"a":0,"c":0}`, `{"a":0,"b":0,"c":0}`} {
		if _, err := outputInputShapeBound([]byte(raw), reflect.TypeFor[outputMaskDocument](), true); err != nil {
			t.Fatal("valid required mask refused")
		}
	}
	for _, raw := range []string{`{"a":0}`, `{"a":0,"c":0,"a":1}`, `{"a":0,"c":0,"\u0061":1}`, `{"A":0,"c":0}`, `{"a":null,"c":0}`, `{"a":0,"c":0} {}`} {
		if _, err := outputInputShapeBound([]byte(raw), reflect.TypeFor[outputMaskDocument](), true); err == nil {
			t.Fatal("noncanonical mask input accepted")
		}
	}
	for _, set := range []Set{Compromise, Collude, Mailbox} {
		p := testNodeviewPlan(set)
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := outputInputShapeBound(data, reflect.TypeFor[Plan](), true); err != nil {
			t.Fatal("complete canonical Plan refused")
		}
	}
}

func outputRangeCases(t *testing.T) {
	t.Helper()
	corpus := []string{"-129", "-128", "-0", "0", "1", "127", "128", "255", "256", "1.0", "1e0", "9223372036854775807", "9223372036854775808", "18446744073709551615", "18446744073709551616", "-1.7976931348623157e308", "1.7976931348623157e308", "1e309", "-1e309", "5e-324", "1e-9999", "-0.0", "-0e9999", "3.4028234663852886e38", "3.4028236e38", "1.401298464324817e-45", "1e-1000", "0." + strings.Repeat("0", 4096) + "1e4097"}
	for _, typ := range []reflect.Type{reflect.TypeFor[outputRangeI8](), reflect.TypeFor[outputRangeU8](), reflect.TypeFor[outputRangeI64](), reflect.TypeFor[outputRangeU64](), reflect.TypeFor[outputRangeF32](), reflect.TypeFor[outputRangeF64]()} {
		for _, number := range corpus {
			data := []byte(`{"value":` + number + `}`)
			expected := reflect.New(typ)
			directErr := json.Unmarshal(data, expected.Interface())
			_, frontErr := outputInputShapeBound(data, typ, true)
			if (directErr == nil) != (frontErr == nil) {
				t.Fatalf("range acceptance differs for %s %q: %v/%v", typ, number, directErr, frontErr)
			}
			if frontErr == nil {
				actual := reflect.New(typ)
				if strictJSON(bytes.NewReader(data), actual.Interface()) != nil || !reflect.DeepEqual(expected.Interface(), actual.Interface()) {
					t.Fatal("accepted range changed authoritative typed value")
				}
				if typ == reflect.TypeFor[outputRangeF64]() && strings.HasPrefix(number, "-0") && math.Signbit(actual.Elem().Field(0).Float()) != math.Signbit(expected.Elem().Field(0).Float()) {
					t.Fatal("float sign was lost")
				}
			}
		}
	}
	if outputInputNumber("-0", reflect.TypeFor[uint8]()) == nil || outputInputNumber("1e0", reflect.TypeFor[int8]()) == nil || outputInputNumber("1.0", reflect.TypeFor[int8]()) == nil {
		t.Fatal("integer spelling restrictions changed")
	}
}

func outputHistoryCases(t *testing.T) {
	t.Helper()
	a := &outputArithmetic{}
	for _, row := range []struct{ n, want uint64 }{{0, 0}, {1, 32}, {2, 96}, {3, 224}, {5, 480}, {30, 2016}, {512, 32736}, {4096, 510560}, {32768, 4934240}} {
		if got := outputInputBucketHistory(row.n, a); got != row.want || a.err != nil {
			t.Fatalf("bucket history(%d)=%d, want%d", row.n, got, row.want)
		}
	}
	var at, numerator, denominator uint64
	for n := uint64(1); n <= 32768; n++ {
		got := outputInputBucketHistory(n, a)
		if at == 0 || got*denominator > numerator*(32*n) {
			at, numerator, denominator = n, got, 32*n
		}
	}
	if at != 27137 || numerator*27137 != denominator*154195 {
		t.Fatal("independent complete bucket ratio changed")
	}
	if outputInputDecoderHistory(402653183, a) != 1073741760 || outputInputDecoderHistory(402653184, a) != 2147483584 || outputInputDecoderHistory(4097, a) != 16320 {
		t.Fatal("typed ReadValue cliff/history changed")
	}
	for _, data := range [][]byte{[]byte(`"` + strings.Repeat(`\u0000`, 1024) + `"`), {'"', 0xff, 0xff, 0xff, '"'}, []byte(`"\ud800"`)} {
		l, err := outputInputLex(data)
		if err != nil || l.q < uint64(len(data)) || l.strings == 0 {
			t.Fatal("quoted maximum/replacement owner omitted")
		}
	}
	for _, n := range []uint64{math.MaxUint64, math.MaxUint64/32 + 1} {
		a := &outputArithmetic{}
		outputInputBucketHistory(n, a)
		if reasonOf(a.err) != ReasonLimit {
			t.Fatal("bucket overflow accepted")
		}
	}
}

func outputExactReadCases(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	original := []byte("immutable-source-file")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := outputReadExactCore(path, 0, true, func(uint64) error { return nil }, nil); err != nil || !bytes.Equal(data, original) {
		t.Fatal("stable executable bytes changed")
	}
	read := false
	if _, err := outputReadExactCore(path, 0, true, func(uint64) error { return fail(ReasonLimit) }, func() { read = true }); reasonOf(err) != ReasonLimit || read {
		t.Fatal("early source control refusal reached acquisition")
	}
	var need uint64
	if _, err := outputReadExactCore(path, 0, true, func(n uint64) error { need = n; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := outputReadExactCore(path, 0, true, func(n uint64) error {
		if n > need-1 {
			return fail(ReasonLimit)
		}
		return nil
	}, func() { read = true }); reasonOf(err) != ReasonLimit || read {
		t.Fatal("exact byte refusal reached read")
	}
	for _, mode := range []string{"replaced", "truncated", "growing", "mtime"} {
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		changed := func() {
			var err error
			switch mode {
			case "replaced":
				err = os.Rename(path, path+".old")
				if err == nil {
					err = os.WriteFile(path, original, 0600)
				}
			case "truncated":
				err = os.WriteFile(path, original[:2], 0600)
			case "growing":
				f, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
				err = e
				if err == nil {
					_, err = f.Write([]byte("extra"))
					f.Close()
				}
			case "mtime":
				err = os.Chtimes(path, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := outputReadExactCore(path, 0, true, func(uint64) error { return nil }, changed); err == nil {
			t.Fatal("changed executable premise accepted: " + mode)
		}
	}
	large := bytes.Repeat([]byte{'x'}, (32<<20)+1)
	if err := os.WriteFile(path, large, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := outputReadExactCore(path, 0, true, func(uint64) error { return nil }, nil); err != nil || len(got) != len(large) {
		t.Fatal("qualification size inequality became an executable runtime cap")
	}
}

func TestOutputInputRangeEquivalence(t *testing.T) { outputMaskCases(t); outputRangeCases(t) }
func TestOutputInputHistoriesAndExactAcquisition(t *testing.T) {
	outputHistoryCases(t)
	outputExactReadCases(t)
	outputEarlyAdmissionCases(t)
}

func outputEarlyAdmissionCases(t *testing.T) {
	t.Helper()
	p := testNodeviewPlan(Collude)
	phases := []func(func(uint64) error, func()) error{
		func(admit func(uint64) error, entered func()) error {
			return outputPlanPreparationCore(&p, admit, entered)
		},
		func(admit func(uint64) error, entered func()) error {
			return outputFrozenPreparationCore(&p, nil, admit, entered)
		},
		func(admit func(uint64) error, entered func()) error {
			return checkPlanningEstimateResources(admit, entered)
		},
	}
	for _, phase := range phases {
		var needs []uint64
		if err := phase(func(n uint64) error { needs = append(needs, n); return nil }, nil); err != nil || len(needs) < 2 {
			t.Fatal("early resource fixture failed")
		}
		for i, need := range needs {
			entered := 0
			err := phase(func(n uint64) error {
				if n > need-1 {
					return fail(ReasonLimit)
				}
				return nil
			}, func() { entered++ })
			want := 0
			if i > 1 {
				want = 1
			}
			if reasonOf(err) != ReasonLimit || entered != want {
				t.Fatal("early Plan/model/estimate denial crossed its source consumer")
			}
		}
		retained := uint64(4096)
		for attempt := uint64(1); attempt <= 2; attempt++ {
			limit := retained + needs[len(needs)-1] - 1
			previous := uint64(0)
			admit := func(n uint64) error {
				if n < previous {
					return ErrInvalid
				}
				a := &outputArithmetic{}
				next := a.add(retained, n-previous)
				if a.err != nil {
					return a.err
				}
				if next > limit {
					return fail(ReasonLimit)
				}
				retained, previous = next, n
				return nil
			}
			if reasonOf(phase(admit, nil)) != ReasonLimit || retained != 4096+attempt*needs[len(needs)-2] {
				t.Fatal("early refused attempt lost its admitted prefix")
			}
		}
	}
	for _, row := range []struct {
		data []byte
		typ  reflect.Type
	}{{[]byte("[]"), reflect.TypeFor[[]FrozenModel]()}, {func() []byte {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}(), reflect.TypeFor[Plan]()}} {
		var needs []uint64
		if err := outputInputInspectCore(row.data, row.typ, func(n uint64) error { needs = append(needs, n); return nil }, nil, nil); err != nil || len(needs) != 3 {
			t.Fatal("public resource input fixture failed")
		}
		for i, need := range needs {
			shape, decode := 0, 0
			err := outputInputInspectCore(row.data, row.typ, func(n uint64) error {
				if n > need-1 {
					return fail(ReasonLimit)
				}
				return nil
			}, func() { shape++ }, func() { decode++ })
			if reasonOf(err) != ReasonLimit || decode != 0 || i < 2 && shape != 0 || i == 2 && shape != 1 {
				t.Fatal("Plan/model codec/G refusal reached its next consumer")
			}
		}
	}
}
