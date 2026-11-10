package nodeview

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSystemDoesNotImportObservationLab(t *testing.T) {
	for _, directory := range []string{"client", "relay", "wire", "link", "conversation", "mailbox", "pki", "crypto", "vault"} {
		root := filepath.Join("..", "..", directory)
		e := filepath.WalkDir(root, func(path string, entry fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			file, e := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if e != nil {
				return e
			}
			for _, item := range file.Imports {
				value, e := strconv.Unquote(item.Path.Value)
				if e != nil {
					return e
				}
				if strings.HasPrefix(value, "github.com/jimichi-org/jimichi/lab") {
					t.Errorf("system import depends on lab: %s", path)
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
}

func TestProductionAndObserverKeepProviderBoundary(t *testing.T) {
	e := filepath.WalkDir(filepath.Join("..", ".."), func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			if entry.Name() == "artifacts" || entry.Name() == ".git" || entry.Name() == ".dev" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		relative, e := filepath.Rel(filepath.Join("..", ".."), path)
		if e != nil {
			return e
		}
		if strings.HasPrefix(filepath.ToSlash(relative), "crypto/") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") && !strings.HasPrefix(filepath.ToSlash(relative), "lab/nodeview/") {
			return nil
		}
		file, e := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if e != nil {
			return e
		}
		for _, item := range file.Imports {
			value, e := strconv.Unquote(item.Path.Value)
			if e != nil {
				return e
			}
			if strings.HasPrefix(value, "github.com/jimichi-org/jimichi/crypto/gost") || strings.HasPrefix(value, "github.com/jimichi-org/jimichi/crypto/c25519") || strings.HasPrefix(value, "golang.org/x/crypto/") {
				t.Errorf("concrete primitive outside provider boundary: %s", relative)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestProviderObserverNeverReadsOrOwnsBorrowedKeys(t *testing.T) {
	file, e := parser.ParseFile(token.NewFileSet(), "provider.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "Bytes" || selector.Sel.Name == "Clone" || selector.Sel.Name == "Release" {
			t.Errorf("borrowed-key operation in provider wrapper: %s", selector.Sel.Name)
		}
		return true
	})
}
