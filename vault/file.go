package vault

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const tmpSuffix = ".tmp"

// removes <path>.tmp, which a creation killed before its link leaves behind;
// one creation per path at a time is assumed, and the blocks of the removed
// file stay on the device
func Clean(path string) error {
	if err := os.Remove(path + tmpSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vault: clean: %w", err)
	}
	return nil
}

// refuses an existing file before a byte reaches the drive; the link still
// refuses one that appears after this check
func vacant(path string) error {
	if err := Clean(path); err != nil {
		return err
	}
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return ErrExists
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

// a hard link never replaces its target, so an existing container is never
// overwritten, and the file appears whole or not at all. linked reports that
// path names the data, whatever the error after the link
func create(path string, data []byte) (linked bool, err error) {
	tmp := path + tmpSuffix
	if err := writeTmp(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("vault: write: %w", err)
	}
	if err := os.Link(tmp, path); err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, fs.ErrExist) {
			return false, ErrExists
		}
		return false, fmt.Errorf("vault: link: %w", err)
	}
	return true, settle(tmp, filepath.Dir(path))
}

// the steps after the link; replaced in tests to fail as a drive fails there.
// A tmp already gone was removed by the Clean of another run
var settle = func(tmp, dir string) error {
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vault: remove %s: %w", tmp, err)
	}
	return syncDir(dir)
}

func writeTmp(tmp string, data []byte) error {
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// reads at most one byte past the size of a container, whatever the file is
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() != FileSize {
		return nil, ErrNotVault
	}
	data, err := io.ReadAll(io.LimitReader(f, FileSize+1))
	if err != nil {
		return nil, fmt.Errorf("vault: read: %w", err)
	}
	if len(data) != FileSize {
		return nil, ErrNotVault
	}
	return data, nil
}
