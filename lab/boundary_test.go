package lab

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/jimichi-org/jimichi"

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

func isLab(path string) bool {
	for _, p := range []string{module + "/lab", module + "/cmd/lab"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// the testbed depends on the system and never the other way round: no package
// of the module outside lab and cmd/lab imports either of them, in its code or
// in its tests. Every .go file is read whatever its build constraints, so a
// file for another system, architecture, cgo setting or tag counts as well: the
// images are built with CGO_ENABLED=0, which no test run here selects. A
// package that knew the lab could take a seam meant for experiments into a
// production binary
func TestSystemDoesNotImportLab(t *testing.T) {
	bad, seen := labImports(t, moduleRoot(t))
	for _, b := range bad {
		t.Error(b)
	}
	for _, want := range []string{
		"crypto", "crypto/secmem", "crypto/suite", "crypto/c25519", "crypto/gost", "wire", "link", "pki",
		"relay", "client", "noise", "e2e", "mailbox", "cmd/relay", "cmd/client", "cmd/jimichi", "scripts",
	} {
		if !seen[want] {
			t.Errorf("the walk did not reach %s", want)
		}
	}
}

// the imports of lab or cmd/lab in the tree outside them, and the directories
// with Go files the walk read
func labImports(t *testing.T, root string) (bad []string, seen map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	seen = map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		name := d.Name()
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "artifacts") {
				return filepath.SkipDir
			}
			if isLab(module + "/" + rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range f.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil || isLab(imp) {
				bad = append(bad, rel+" imports "+spec.Path.Value)
			}
		}
		seen[filepath.ToSlash(filepath.Dir(rel))] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bad, seen
}

// files that no build of this test compiles are read too, tests included, and
// lab itself is left out
func TestLabImportsReadsFilesOfEveryBuild(t *testing.T) {
	root := t.TempDir()
	imp := func(path string) string { return strconv.Quote(module + path) }
	for name, text := range map[string]string{
		"relay/cgo.go":         "//go:build !cgo\n\npackage relay\n\nimport _ " + imp("/lab/metrics") + "\n",
		"relay/arm.go":         "//go:build arm64\n\npackage relay\n\nimport " + imp("/lab") + "\n",
		"relay/tagged.go":      "//go:build jimichilab\n\npackage relay\n\nimport (\n\t\"fmt\"\n\tl " + imp("/cmd/lab") + "\n)\n",
		"relay/relay_test.go":  "package relay_test\n\nimport " + imp("/lab/scenario") + "\n",
		"relay/relay.go":       "package relay\n\nimport " + imp("/wire") + "\n",
		"cmd/relay/main.go":    "//go:build ignore\n\npackage main\n\nimport " + imp("/labs") + "\n",
		"lab/lab.go":           "package lab\n\nimport " + imp("/lab/metrics") + "\n",
		"cmd/lab/main_test.go": "package main\n\nimport " + imp("/lab") + "\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bad, seen := labImports(t, root)
	if len(bad) != 4 || !seen["relay"] || !seen["cmd/relay"] || seen["lab"] || seen["cmd/lab"] {
		t.Fatalf("found %q in %v, want the four imports in relay", bad, seen)
	}
	for _, b := range bad {
		if !strings.HasPrefix(b, "relay/") {
			t.Fatalf("found %q", b)
		}
	}
}
