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

// removes what a creation killed before its link left behind; the blocks of
// the removed file stay on the device
func Clean(path string) error {
	if err := os.Remove(path + tmpSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vault: clean: %w", err)
	}
	return nil
}

// a hard link never replaces its target, so an existing container is never
// overwritten, and the file appears whole or not at all
func create(path string, data []byte) error {
	if err := Clean(path); err != nil {
		return err
	}
	tmp := path + tmpSuffix
	if err := writeTmp(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vault: write: %w", err)
	}
	err := os.Link(tmp, path)
	rmErr := os.Remove(tmp)
	if errors.Is(err, fs.ErrExist) {
		return ErrExists
	}
	if err != nil {
		return fmt.Errorf("vault: link: %w", err)
	}
	if rmErr != nil {
		return fmt.Errorf("vault: remove %s: %w", tmp, rmErr)
	}
	return syncDir(filepath.Dir(path))
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
