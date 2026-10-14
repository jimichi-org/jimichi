package srccheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

const sample = `package p

func f() (*secmem.Buffer, error) {
	key, err := stretch(pw)
	if err != nil || len(key) == 0 {
		return nil, err
	}
	defer secmem.Zero(key[:cap(key)])
	kept = append(kept, bytes.Clone(key))
	other := key
	key = nil
	return secmem.NewFrom(key)
}
`

func TestSinks(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "p.go", sample, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	fn := Func(t, []*ast.File{f}, "f")
	got := Sinks(fn.Body, "key")
	want := []string{"", "secmem.Zero", "secmem.Zero", "bytes.Clone", "", "secmem.NewFrom"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sinks of key: %q, want %q", got, want)
	}
}
