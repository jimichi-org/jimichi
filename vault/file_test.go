package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
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

		// the existing file is refused before a byte reaches the drive, so the
		// draft stays whole and its content can still change
		if d.image != nil {
			t.Fatal("a Write refused before the drive fixed the bytes")
		}
		fresh := vaultPath(t)
		if err := d.Write(fresh, content([]byte("changed"))); err != nil {
			t.Fatalf("Write after ErrExists: %v", err)
		}
		file, err := os.ReadFile(fresh)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := mustOpen(t, p, file, password(t, "a"))
		if string(v.Content()) != "changed" {
			t.Fatalf("content %q", v.Content())
		}
	})
}

// a tmp that cannot be opened holds no byte of the container, so the attempt
// fixes nothing and the content can still change
func TestUnopenedTmpFixesNothing(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		d, err := Prepare(p, volume(t, "a", []byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		missing := filepath.Join(t.TempDir(), "no such directory", "peer.vault")
		if err := d.Write(missing, nil); err == nil || errors.Is(err, ErrWritten) {
			t.Fatalf("Write under a missing directory: %v", err)
		}
		if d.image != nil {
			t.Fatal("an attempt that opened no tmp fixed the bytes")
		}
		path := vaultPath(t)
		if err := d.Write(path, content([]byte("changed"))); err != nil {
			t.Fatalf("Write after an unopened tmp: %v", err)
		}
		file, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := mustOpen(t, p, file, password(t, "a")); string(v.Content()) != "changed" {
			t.Fatalf("content %q", v.Content())
		}
	})
}

// a file that appears after the check of the path and before the link makes
// the link refuse once the tmp is on the drive. The retry writes the same
// bytes, so the drive never holds two versions of one container, and a fill
// that would change the content is refused
func TestRetryWritesTheSameBytes(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		for _, n := range []int{1, 2} {
			hook := &appearing{CryptoProvider: p}
			d, err := Prepare(hook, []Contents{volume(t, "a", []byte("x")), volume(t, "b", []byte("y"))}[:n]...)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			busy := vaultPath(t)
			hook.arm(busy)
			wantErr(t, "a file that appears before the link", d.Write(busy, nil), ErrExists)
			if got, err := os.ReadFile(busy); err != nil || string(got) != appeared {
				t.Fatalf("the file that appeared changed: %q, %v", got, err)
			}
			if _, err := os.Stat(busy + tmpSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("tmp left after a refused link: %v", err)
			}
			tried := bytes.Clone(d.image)
			if len(tried) != FileSize {
				t.Fatal("an attempt that reached the drive fixed no bytes")
			}

			other := vaultPath(t)
			wantErr(t, "another content after the drive", d.Write(other, content([]byte("z"))), errFixed)
			failing := errors.New("fill failed")
			wantErr(t, "a failing fill after the drive", d.Write(other, func(*Identity, []byte) (int, error) { return 0, failing }), failing)
			noFile(t, other)

			path := vaultPath(t)
			if err := d.Write(path, content([]byte("x"))); err != nil {
				t.Fatalf("a retry with the same content: %v", err)
			}
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(file, tried) {
				t.Fatal("the retry wrote another version of the container")
			}
			if v, _ := mustOpen(t, p, file, password(t, "a")); string(v.Content()) != "x" {
				t.Fatalf("content %q", v.Content())
			}
		}
	})
}

const appeared = "appeared before the link"

// makes a file at the armed path at the first AEAD it builds: inside Write
// that is the seal, after the check that the path is free and before the link
type appearing struct {
	jcrypto.CryptoProvider

	mu   sync.Mutex
	path string
}

func (a *appearing) arm(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.path = path
}

func (a *appearing) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	a.mu.Lock()
	path := a.path
	a.path = ""
	a.mu.Unlock()
	if path != "" {
		if err := os.WriteFile(path, []byte(appeared), 0o600); err != nil {
			return nil, err
		}
	}
	return a.CryptoProvider.NewAEAD(key)
}

// a failure after the link leaves the container at the path: the Write is
// ErrWritten with its cause, the key and the buffer of the first volume go at
// once, and no later Write makes a second file. It replaces the steps after
// the link, so it runs alone, before the parallel tests
func TestFailureAfterLink(t *testing.T) {
	injected := errors.New("injected after the link")
	real := settle
	t.Cleanup(func() { settle = real })
	for _, c := range []struct {
		name string
		fail func(tmp, dir string) error
	}{
		{"the directory sync", func(tmp, dir string) error {
			if err := real(tmp, dir); err != nil {
				return err
			}
			return injected
		}},
		{"the tmp removal", func(string, string) error { return injected }},
	} {
		settle = c.fail
		for _, s := range suites {
			t.Run(c.name+"/"+s.String(), func(t *testing.T) {
				p := newSpy(t, cheap{provider(t, s)})
				d, err := Prepare(p, volume(t, "a", []byte("x")))
				if err != nil {
					t.Fatal(err)
				}
				defer d.Close()
				path := vaultPath(t)
				err = d.Write(path, nil)
				wantErr(t, c.name, err, ErrWritten)
				wantErr(t, c.name, err, injected)
				if d.key.Bytes() != nil || d.plain.Bytes() != nil {
					t.Fatal("the key or the buffer of the first volume outlived the link")
				}
				file, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if v, _ := mustOpen(t, p, file, password(t, "a")); string(v.Content()) != "x" {
					t.Fatalf("content %q", v.Content())
				}
				other := vaultPath(t)
				wantErr(t, "a Write after the link", d.Write(other, nil), ErrWritten)
				noFile(t, other)
			})
		}
	}
	settle = real
	dir := t.TempDir()
	if err := settle(filepath.Join(dir, "gone"+tmpSuffix), dir); err != nil {
		t.Fatalf("a tmp that the Clean of another run removed: %v", err)
	}
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
		if _, err := writeTmp(path+tmpSuffix, d.file); err != nil {
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
		if _, err := writeTmp(path+tmpSuffix, []byte("left by a killed creation")); err != nil {
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
