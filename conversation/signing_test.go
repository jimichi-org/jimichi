package conversation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// the driver reaches cryptography only through the e2e session and the
// mailbox codec: it calls no primitive of the provider itself and nothing that
// signs, since a signature over a record would prove its sender to anyone
func TestNoSignaturesAndNoCryptoOfItsOwn(t *testing.T) {
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
			if err != nil || !allowedImport(path) {
				t.Errorf("%s imports %s", fset.Position(imp.Pos()), imp.Path.Value)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "GenerateSigning", "Sign", "Verify", "GenerateEphemeral", "Agree", "MixKey", "DeriveKey", "NewAEAD", "Hash":
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

// the standard library outside crypto, and of the module only the provider
// interface, key memory, the end-to-end layer and the mailbox codec
func allowedImport(path string) bool {
	switch path {
	case "github.com/jimichi-org/jimichi/crypto",
		"github.com/jimichi-org/jimichi/crypto/secmem",
		"github.com/jimichi-org/jimichi/e2e",
		"github.com/jimichi-org/jimichi/mailbox":
		return true
	}
	return !strings.Contains(path, ".") && !strings.HasPrefix(path, "crypto")
}
