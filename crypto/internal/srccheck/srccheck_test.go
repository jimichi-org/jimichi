package srccheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

const sample = `package p

const limit = 16

var kept [][]byte

var view = func(pw []byte) string {
	return unsafe.String(unsafe.SliceData(pw), len(pw))
}

var cloned = func(in []byte) string {
	pw := bytes.Clone(in)
	return unsafe.String(unsafe.SliceData(pw), len(pw))
}

var rebound = func(pw []byte) string {
	pw = bytes.Clone(pw)
	return unsafe.String(unsafe.SliceData(pw), len(pw))
}

func f(dst []byte) (*secmem.Buffer, error) {
	key, err := stretch(pw)
	if err != nil || len(key) == 0 {
		return nil, err
	}
	defer secmem.Zero(key[:cap(key)])
	kept = append(kept, bytes.Clone(key))
	copy(dst, key)
	copy(kept[0], key[:limit])
	other := key
	key = nil
	var tail []byte
	for _, dst := range kept {
		tail = dst
	}
	return secmem.NewFrom(key)
}
`

func parse(t *testing.T) []*ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "p.go", sample, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return []*ast.File{f}
}

func TestSinks(t *testing.T) {
	files := parse(t)
	got := Sinks(Func(t, files, "f").Body, "key")
	want := []string{"", "secmem.Zero", "secmem.Zero", "bytes.Clone", "copy(dst)", "copy(kept[0])", "", "secmem.NewFrom"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sinks of key: %q, want %q", got, want)
	}

	views := Calls(VarFunc(t, files, "view").Body, "unsafe.String")
	if len(views) != 1 {
		t.Fatalf("%d calls of unsafe.String in view", len(views))
	}
	got = Sinks(views[0], "pw")
	want = []string{"unsafe.SliceData", "unsafe.String"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sinks of pw in the call: %q, want %q", got, want)
	}
}

func TestCalls(t *testing.T) {
	body := Func(t, parse(t), "f").Body
	for name, want := range map[string]int{"copy": 2, "secmem.Zero": 1, "len": 1, "cap": 1, "bytes.Clone": 1, "string": 0} {
		if got := len(Calls(body, name)); got != want {
			t.Errorf("%d calls of %s, want %d", got, name, want)
		}
	}
}

func TestBinds(t *testing.T) {
	fn := Func(t, parse(t), "f")
	// dst: the parameter and the range value, tail = dst only reads it
	for name, want := range map[string]int{"dst": 2, "key": 2, "err": 1, "tail": 2, "other": 1, "kept": 1, "pw": 0} {
		if got := len(Binds(fn, name)); got != want {
			t.Errorf("%s bound %d times, want %d", name, got, want)
		}
	}
}

func TestParam(t *testing.T) {
	files := parse(t)
	for _, v := range []struct {
		lit, name string
		want      bool
	}{
		{"view", "pw", true},
		{"cloned", "in", true},
		{"cloned", "pw", false},
		{"rebound", "pw", false},
	} {
		if got := Param(VarFunc(t, files, v.lit), v.name); got != v.want {
			t.Errorf("%s: Param %s is %v", v.lit, v.name, got)
		}
	}
}
