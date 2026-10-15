package profile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/jimichi-org/jimichi"

func sources(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no source files")
	}
	return files
}

// the profile reaches cryptography only through the provider and the layers
// above it
func TestImports(t *testing.T) {
	allowed := map[string]bool{}
	for _, p := range []string{"crypto", "crypto/secmem", "e2e", "mailbox", "noise", "vault"} {
		allowed[module+"/"+p] = true
	}
	for _, f := range sources(t) {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case allowed[path]:
			case strings.HasPrefix(path, module+"/"), path == "crypto", strings.HasPrefix(path, "crypto/"),
				strings.Contains(strings.SplitN(path, "/", 2)[0], "."):
				t.Errorf("profile imports %s", path)
			}
		}
	}
}

// the pair of a volume is an agreement key only; the spy of every test fails
// on a signing call as well
func TestNoSigningInSource(t *testing.T) {
	for _, f := range sources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "GenerateSigning", "Sign", "Verify":
					t.Errorf("profile calls %s", sel.Sel.Name)
				}
			}
			return true
		})
	}
}
