package lab

import (
	"errors"
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
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
// in its tests, on any system the code builds for. A package that knew the lab
// could take a seam meant for experiments into a production binary
func TestSystemDoesNotImportLab(t *testing.T) {
	root := moduleRoot(t)
	seen := map[string]bool{}
	for _, goos := range []string{"linux", "windows", "darwin"} {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH = goos, "amd64"
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			name := d.Name()
			if rel != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "artifacts") {
				return filepath.SkipDir
			}
			if isLab(module + "/" + rel) {
				return filepath.SkipDir
			}
			pkg, err := ctx.ImportDir(path, 0)
			if err != nil {
				var none *build.NoGoError
				if errors.As(err, &none) {
					return nil
				}
				return err
			}
			for _, list := range [][]string{pkg.Imports, pkg.TestImports, pkg.XTestImports} {
				for _, imp := range list {
					if isLab(imp) {
						t.Errorf("%s (%s) imports %s", rel, goos, imp)
					}
				}
			}
			seen[rel] = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
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
