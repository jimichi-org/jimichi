//go:build linux

package vault

import (
	"fmt"
	"os"
)

// the new name is durable only once the directory entry is on disk
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("vault: sync %s: %w", dir, err)
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("vault: sync %s: %w", dir, err)
	}
	return nil
}
