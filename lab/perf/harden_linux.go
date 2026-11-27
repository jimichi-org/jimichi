//go:build linux

package perf

import (
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"golang.org/x/sys/unix"
)

// the child holds relay keys, so it is hardened as cmd/relay is, on both
// levels: prctl and the core limit cost nothing on the cell path
func harden() (dumpable *int, err error) {
	if err := secmem.HardenProcess(); err != nil {
		return nil, err
	}
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	return &d, nil
}
