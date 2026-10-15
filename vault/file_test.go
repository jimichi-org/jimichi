package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestNeverReplacesAFile(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		existing := []byte("a file that is not ours")
		path := vaultPath(t)
		if err := os.WriteFile(path, existing, 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Hour).Truncate(time.Second)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		untouched := func(what string) {
			t.Helper()
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, existing) {
				t.Fatalf("%s: the existing file changed", what)
			}
			if st, err := os.Stat(path); err != nil || !st.ModTime().Equal(old) {
				t.Fatalf("%s: the existing file was written", what)
			}
			if _, err := os.Stat(path + tmpSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s: tmp left: %v", what, err)
			}
		}
		err := Create(p, path, volume(t, "a", []byte("x")))
		wantErr(t, "Create over a file", err, ErrExists)
		untouched("Create")

		// the file appears after Prepare, before Write
		later := vaultPath(t)
		d, err := Prepare(p, volume(t, "a", []byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if err := os.WriteFile(later, existing, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(later, old, old); err != nil {
			t.Fatal(err)
		}
		path = later
		wantErr(t, "Write over a file", d.Write(later, nil), ErrExists)
		untouched("Write")

		// a refused Write leaves the draft whole
		fresh := vaultPath(t)
		if err := d.Write(fresh, nil); err != nil {
			t.Fatalf("Write after ErrExists: %v", err)
		}
		file, err := os.ReadFile(fresh)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := mustOpen(t, p, file, password(t, "a"))
		if string(v.Content()) != "x" {
			t.Fatalf("content %q", v.Content())
		}
	})
}

// a creation killed between the temporary file and the link. The test runs
// the step Write runs before the link, writeTmp on <path>.tmp, and stops
// there, which leaves the disk as the kill would; killing the test process
// itself is not needed for that
func TestKilledBeforeLink(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		path := vaultPath(t)
		d, err := Prepare(p, volume(t, "a", []byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if err := writeTmp(path+tmpSuffix, d.file); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a container after a kill before the link: %v", err)
		}
		_, err = Open(p, path, password(t, "a"))
		wantErr(t, "Open after the kill", err, os.ErrNotExist)
		if err := Clean(path); err != nil {
			t.Fatal(err)
		}
		noFile(t, path)
		if err := Clean(path); err != nil {
			t.Fatalf("Clean with nothing to clean: %v", err)
		}

		// a Write after a kill clears the leftover itself
		if err := writeTmp(path+tmpSuffix, []byte("left by a killed creation")); err != nil {
			t.Fatal(err)
		}
		if err := d.Write(path, nil); err != nil {
			t.Fatalf("Write over a leftover tmp: %v", err)
		}
		if _, err := os.Stat(path + tmpSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("tmp after Write: %v", err)
		}
		if st, err := os.Stat(path); err != nil || st.Size() != FileSize {
			t.Fatalf("container after Write: %v", err)
		}
	})
}

// opening is a function of the file: no byte, size, time or neighbour changes
func TestOpensChangeNothing(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		path, file := mustCreate(t, p, volume(t, "a", []byte("first")), volume(t, "b", []byte("second")))
		old := time.Now().Add(-time.Hour).Truncate(time.Second)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		names := func() []string {
			t.Helper()
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, e := range entries {
				out = append(out, e.Name())
			}
			return out
		}
		before := names()
		pws := []*secmem.Buffer{password(t, "a"), password(t, "b"), password(t, "wrong")}
		err := parallel(100, func(i int) error {
			v, err := Open(p, path, pws[i%3])
			if i%3 == 2 {
				if !errors.Is(err, ErrNoVolume) {
					return fmt.Errorf("open %d with a wrong password: %v", i, err)
				}
				return nil
			}
			if err != nil {
				return fmt.Errorf("open %d: %w", i, err)
			}
			v.Close()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, file) {
			t.Fatal("100 opens changed the file")
		}
		st, err := os.Stat(path)
		if err != nil || !st.ModTime().Equal(old) || st.Size() != FileSize {
			t.Fatal("100 opens wrote the file")
		}
		if after := names(); !slices.Equal(after, before) {
			t.Fatalf("the directory held %v before the opens and %v after", before, after)
		}
	})
}
