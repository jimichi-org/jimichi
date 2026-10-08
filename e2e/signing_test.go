package e2e

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// a signature over a record or a transcript would prove its sender to anyone:
// the source names no signing method on any path, and reaches cryptography
// only through the provider
func TestNoSignatures(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || cryptoOutsideProvider(path) {
				t.Errorf("%s imports %s", fset.Position(imp.Pos()), imp.Path.Value)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "GenerateSigning", "Sign", "Verify":
					t.Errorf("%s: %s", fset.Position(sel.Pos()), sel.Sel.Name)
				}
			}
			return true
		})
	}
	if files == 0 {
		t.Fatal("no source files")
	}
}

func cryptoOutsideProvider(path string) bool {
	for _, prefix := range []string{
		"crypto/", "golang.org/x/crypto", "filippo.io/", "github.com/pedroalbanese/gogost",
		"github.com/jimichi-org/jimichi/crypto/c25519", "github.com/jimichi-org/jimichi/crypto/gost",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
