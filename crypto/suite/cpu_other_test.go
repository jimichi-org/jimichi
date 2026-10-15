//go:build !unix

package suite_test

import "time"

// no getrusage here: the benchmarks report the wall time alone
func processCPU() (time.Duration, bool) { return 0, false }
