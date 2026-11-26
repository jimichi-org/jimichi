//go:build !unix && !windows

package scenario

import "time"

func processCPU() (time.Duration, bool) { return 0, false }
