//go:build !linux

package perf

// Pin, Allowed and Topology need the CPU affinity of linux
func Pin([]int) (bool, error) { return false, ErrNoAffinity }

func Allowed() []int { return nil }

func Topology(int) (Topo, error) { return Topo{}, ErrNoAffinity }

func MasksOK([]int) bool { return false }
