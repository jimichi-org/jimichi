package vault

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

const module = "github.com/jimichi-org/jimichi"

// vault reaches cryptography only through the provider, and of the standard
// library's crypto only crypto/rand. Every file counts whatever its build
// constraints
func TestImportsOnlyProvider(t *testing.T) {
	allowed := map[string]bool{module + "/crypto": true, module + "/crypto/secmem": true, "crypto/rand": true}
	files := 0
	for _, f := range sources(t) {
		files++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if allowed[path] {
				continue
			}
			if path == "crypto" || strings.HasPrefix(path, "crypto/") || strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
				t.Errorf("vault imports %s", path)
			}
		}
	}
	if files == 0 {
		t.Fatal("no source files")
	}
}

// the key DerivePair gives is an agreement key only: no path of vault names a
// signing method
func TestNoSigningInSource(t *testing.T) {
	for _, f := range sources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "GenerateSigning", "Sign", "Verify":
					t.Errorf("vault calls %s", sel.Sel.Name)
				}
			}
			return true
		})
	}
}

// no path calls one either: creation with two volumes, both opens, a
// wrong password, the identity used and taken
func TestNoSigningCalls(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		p.reset()
		_, file := mustCreate(t, p, volume(t, "a", []byte("x")), volume(t, "b", []byte("y")))
		for _, pw := range []string{"a", "b"} {
			v, _ := mustOpen(t, p, file, password(t, pw))
			peer, peerPub, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			peer.Release()
			ctx, err := jcrypto.NewContext(p, "test", peerPub)
			if err != nil {
				t.Fatal(err)
			}
			k, err := v.Identity().Agree(peerPub, ctx)
			if err != nil {
				t.Fatal(err)
			}
			k.Release()
			priv, _, fetch := v.Identity().Take()
			priv.Release()
			fetch.Release()
		}
		if _, _, err := open(p, file, password(t, "c")); err == nil {
			t.Fatal("a third password opened")
		}
		for _, call := range []string{"GenerateSigning", "Sign", "Verify"} {
			if n := p.count(call); n != 0 {
				t.Fatalf("%d calls of %s", n, call)
			}
		}
		if p.count("DerivePair") != 4 {
			t.Fatalf("%d calls of DerivePair, want 4", p.count("DerivePair"))
		}
	})
}

// the system below the client does not know the container: no package of
// the relay path, of the conversation or of the client, nor their tests,
// imports vault or a package under it
func TestNotImportedBelowClient(t *testing.T) {
	for _, dir := range []string{"relay", "cmd/relay", "wire", "link", "mailbox", "conversation", "e2e", "noise", "client"} {
		seen := 0
		err := filepath.WalkDir(filepath.Join("..", filepath.FromSlash(dir)), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == "testdata" || strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			seen++
			for _, imp := range f.Imports {
				p, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return err
				}
				if p == module+"/vault" || strings.HasPrefix(p, module+"/vault/") {
					t.Errorf("%s imports %s", filepath.ToSlash(path), p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if seen == 0 {
			t.Fatalf("no Go files under %s", dir)
		}
	}
}

// the non-test files of the package
func sources(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
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
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return files
}
