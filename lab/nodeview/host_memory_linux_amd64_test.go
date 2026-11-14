//go:build linux && amd64

package nodeview

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHostMemoryLinuxBoundedAggregateRead(t *testing.T) {
	name := filepath.Join(t.TempDir(), "aggregate")
	data := bytes.Repeat([]byte{'1'}, 1<<20)
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readHostMemoryFile(name)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("bounded aggregate read lost bytes")
	}
	if err := os.WriteFile(name, append(data, '1'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHostMemoryFile(name); !errors.Is(err, ErrUnsupported) {
		t.Fatal("oversized aggregate file admitted")
	}
}
