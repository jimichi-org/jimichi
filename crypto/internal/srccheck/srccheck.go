// Package srccheck reads the source of a provider for the tests that guard how
// key material on the Go heap flows through it.
package srccheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// the non-test files of the package in dir
func Files(t testing.TB, dir string) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no source files in %s", dir)
	}
	return files
}

// a function or a method of the files by its bare name
func Func(t testing.TB, files []*ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return fn
			}
		}
	}
	t.Fatalf("no function %s", name)
	return nil
}

// "pkg.Name" for a call of a package function or a method, "Name" for a plain
// call, "?" otherwise
func CallName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
		return "?." + f.Sel.Name
	}
	return "?"
}

// for every use of the variable name in body, not counting the left side of
// an assignment, the call it goes into: the nearest enclosing call other than
// len and cap, or "" for a use outside any call (a plain assignment, a return,
// a composite literal)
func Sinks(body ast.Node, name string) []string {
	var sinks []string
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == name && !assigned(stack, id) {
			sinks = append(sinks, sink(stack))
		}
		stack = append(stack, n)
		return true
	})
	return sinks
}

func assigned(stack []ast.Node, id *ast.Ident) bool {
	if len(stack) == 0 {
		return false
	}
	as, ok := stack[len(stack)-1].(*ast.AssignStmt)
	if !ok {
		return false
	}
	for _, l := range as.Lhs {
		if l == id {
			return true
		}
	}
	return false
}

func sink(stack []ast.Node) string {
	for i := len(stack) - 1; i >= 0; i-- {
		switch n := stack[i].(type) {
		case *ast.CallExpr:
			if name := CallName(n); name != "len" && name != "cap" {
				return name
			}
		case ast.Stmt, *ast.CompositeLit, *ast.FuncLit:
			return ""
		}
	}
	return ""
}
