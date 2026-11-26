//go:build unix

package scenario

import (
	"syscall"
	"time"
)

// user and system time of the whole process: the core-seconds an open costs
// whatever number of goroutines its stretch runs in
func processCPU() (time.Duration, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), true
}
