//go:build !unix && !windows

package perf

import "time"

func ProcessCPU() (time.Duration, bool) { return 0, false }
