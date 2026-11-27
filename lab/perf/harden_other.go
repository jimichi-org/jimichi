//go:build !linux

package perf

// without prctl there is nothing to harden; such a child is a smoke run
func harden() (dumpable *int, err error) { return nil, nil }
