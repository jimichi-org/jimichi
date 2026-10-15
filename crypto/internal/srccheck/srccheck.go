// Package srccheck reads the source of a provider for the tests that guard how
// key material on the Go heap flows through it.
package srccheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
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

// the function literal a package variable is set to, by the variable's name
func VarFunc(t testing.TB, files []*ast.File, name string) *ast.FuncLit {
	t.Helper()
	for _, f := range files {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.VAR {
				continue
			}
			for _, s := range g.Specs {
				vs := s.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if id.Name != name || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.FuncLit); ok {
						return lit
					}
				}
			}
		}
	}
	t.Fatalf("no variable %s set to a function literal", name)
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

// the calls in body that CallName names name
func Calls(body ast.Node, name string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && CallName(call) == name {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

// the identifiers in node that declare or assign the variable name: the left
// side of an assignment, a var, the key or the value of a range clause, the
// name of a parameter, a result or a field
func Binds(node ast.Node, name string) []*ast.Ident {
	var ids []*ast.Ident
	add := func(e ast.Expr) {
		if id, ok := e.(*ast.Ident); ok && id.Name == name {
			ids = append(ids, id)
		}
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				add(l)
			}
		case *ast.RangeStmt:
			add(n.Key)
			add(n.Value)
		case *ast.ValueSpec:
			for _, id := range n.Names {
				add(id)
			}
		case *ast.Field:
			for _, id := range n.Names {
				add(id)
			}
		}
		return true
	})
	return ids
}

// whether name is a parameter of lit that lit binds nowhere else, so every
// use of name in lit is what the caller passed
func Param(lit *ast.FuncLit, name string) bool {
	b := Binds(lit, name)
	if len(b) != 1 {
		return false
	}
	for _, f := range lit.Type.Params.List {
		for _, id := range f.Names {
			if id == b[0] {
				return true
			}
		}
	}
	return false
}

// for every use of the variable name in body, not counting the left side of
// an assignment, the call it goes into: the nearest enclosing call other than
// len and cap, or "" for a use outside any call (a plain assignment, a return,
// a composite literal). A copy is named with its destination as written,
// "copy(dst)", since that is where the bytes stay
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
			switch name := CallName(n); {
			case name == "copy" && len(n.Args) == 2:
				return "copy(" + types.ExprString(n.Args[0]) + ")"
			case name != "len" && name != "cap":
				return name
			}
		case ast.Stmt, *ast.CompositeLit, *ast.FuncLit:
			return ""
		}
	}
	return ""
}
