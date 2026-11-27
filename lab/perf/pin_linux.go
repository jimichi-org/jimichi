//go:build linux

package perf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func cpuSet(cpus []int) unix.CPUSet {
	var set unix.CPUSet
	set.Zero()
	for _, c := range cpus {
		set.Set(c)
	}
	return set
}

func threads() ([]int, error) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, err
	}
	tids := make([]int, 0, len(entries))
	for _, e := range entries {
		if tid, err := strconv.Atoi(e.Name()); err == nil {
			tids = append(tids, tid)
		}
	}
	return tids, nil
}

// every thread of the process onto cpus. A thread made later takes the mask of
// the thread that made it, which clone gives on linux; that is checked through
// masksOK at every snapshot, not taken on trust. The pass repeats until it
// changes nothing, since the runtime may start a thread while it runs
func Pin(cpus []int) (bool, error) {
	if len(cpus) == 0 {
		return false, errors.New("perf: no cpu to pin to")
	}
	set := cpuSet(cpus)
	for range 100 {
		tids, err := threads()
		if err != nil {
			return false, err
		}
		changed := false
		for _, tid := range tids {
			var cur unix.CPUSet
			if err := unix.SchedGetaffinity(tid, &cur); err != nil {
				if errors.Is(err, unix.ESRCH) {
					continue
				}
				return false, err
			}
			if cur == set {
				continue
			}
			if err := unix.SchedSetaffinity(tid, &set); err != nil {
				if errors.Is(err, unix.ESRCH) {
					continue
				}
				return false, err
			}
			changed = true
		}
		if !changed {
			return masksOK(cpus), nil
		}
	}
	return masksOK(cpus), nil
}

// whether every thread of the process runs on exactly cpus
func masksOK(cpus []int) bool {
	set := cpuSet(cpus)
	tids, err := threads()
	if err != nil || len(tids) == 0 {
		return false
	}
	for _, tid := range tids {
		var cur unix.CPUSet
		if err := unix.SchedGetaffinity(tid, &cur); err != nil {
			if errors.Is(err, unix.ESRCH) {
				continue
			}
			return false
		}
		if cur != set {
			return false
		}
	}
	return true
}

// the CPUs the calling thread may run on, in order
func Allowed() []int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil
	}
	var out []int
	for c := 0; c < len(set)*64; c++ {
		if set.IsSet(c) {
			out = append(out, c)
		}
	}
	return out
}

// a kernel list such as "0-3,8,10-11"
func parseList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, err
			}
		}
		for c := a; c <= b; c++ {
			out = append(out, c)
		}
	}
	return out, nil
}

func readCPUFile(cpu int, rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/sys/devices/system/cpu", "cpu"+strconv.Itoa(cpu), rel))
	return strings.TrimSpace(string(b)), err
}

// the node takes the first cores CPUs of one L3 group, one per core, from the
// allowed mask without its smallest CPU and that CPU's SMT siblings, which are
// left to the controller and the system. The siblings of the node CPUs go to
// nobody, since they share a core with the node; the load gets the rest
func Topology(cores int) (Topo, error) {
	if cores < 1 {
		return Topo{}, ErrCoresUnavailable
	}
	allowed := Allowed()
	if len(allowed) == 0 {
		return Topo{}, ErrNoAffinity
	}
	virt, _ := Virtualized()
	siblings := map[int][]int{}
	l3 := map[int]string{}
	known := true
	for _, c := range allowed {
		s, err := readCPUFile(c, "topology/thread_siblings_list")
		list, perr := parseList(s)
		if err != nil || perr != nil || len(list) == 0 {
			known = false
			break
		}
		siblings[c] = list
		g, err := readCPUFile(c, "cache/index3/shared_cpu_list")
		if err != nil {
			known = false
			break
		}
		l3[c] = g
	}
	if !known {
		siblings, l3 = map[int][]int{}, map[int]string{}
		for _, c := range allowed {
			siblings[c] = []int{c}
		}
	}
	reserved := map[int]bool{}
	for _, c := range siblings[allowed[0]] {
		reserved[c] = true
	}
	reserved[allowed[0]] = true
	var avail []int
	for _, c := range allowed {
		if !reserved[c] {
			avail = append(avail, c)
		}
	}
	var groups []string
	for _, c := range avail {
		if !slices.Contains(groups, l3[c]) {
			groups = append(groups, l3[c])
		}
	}
	for _, g := range groups {
		var node []int
		taken := map[int]bool{}
		for _, c := range avail {
			if len(node) == cores {
				break
			}
			if l3[c] != g || taken[c] {
				continue
			}
			node = append(node, c)
			for _, s := range siblings[c] {
				taken[s] = true
			}
		}
		if len(node) < cores {
			continue
		}
		var sib, load []int
		for _, c := range avail {
			switch {
			case slices.Contains(node, c):
			case taken[c]:
				sib = append(sib, c)
			default:
				load = append(load, c)
			}
		}
		if len(load) < cores {
			return Topo{}, ErrCoresUnavailable
		}
		return Topo{Node: node, Siblings: sib, Load: load, Known: known && !virt, Virtualized: virt, L3Group: g}, nil
	}
	return Topo{}, ErrCoresUnavailable
}
