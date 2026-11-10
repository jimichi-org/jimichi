//go:build linux && amd64

package nodeview

import (
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"golang.org/x/sys/unix"
)

func monotonicNS() int64 {
	var t unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &t) != nil {
		return -1
	}
	return t.Nano()
}
func clockResolution() (int64, error) {
	var t unix.Timespec
	if unix.ClockGetres(unix.CLOCK_MONOTONIC, &t) != nil || t.Nano() <= 0 || t.Nano() >= 10000 {
		return 0, fail(ReasonClock)
	}
	return t.Nano(), nil
}
func protectProcess(bytes int) error {
	if secmem.SetPolicy(secmem.Protected) != nil || secmem.HardenProcess() != nil {
		return fail(ReasonUnsupported)
	}
	var l unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l) != nil || l.Cur < uint64(bytes+1<<20) {
		return fail(ReasonUnsupported)
	}
	p, e := secmem.New(4096)
	if e != nil {
		return fail(ReasonUnsupported)
	}
	defer p.Release()
	if !p.Locked() {
		return fail(ReasonUnsupported)
	}
	_, e = clockResolution()
	return e
}
