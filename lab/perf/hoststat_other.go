//go:build !linux

package perf

func HostTimes([]int) (CPUTimes, bool) { return CPUTimes{}, false }

func Virtualized() (bool, bool) { return false, false }
