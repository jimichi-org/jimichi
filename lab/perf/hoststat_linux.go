//go:build linux

package perf

import (
	"bufio"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// /proc/stat counts in USER_HZ, which the kernel fixes at 100 for user space
// on every architecture it exports the file on
const userHZ = 100

// the columns of /proc/stat summed over the given cpuN lines
func HostTimes(cpus []int) (CPUTimes, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return CPUTimes{}, false
	}
	defer f.Close()
	want := make(map[string]bool, len(cpus))
	for _, c := range cpus {
		want["cpu"+strconv.Itoa(c)] = true
	}
	var t CPUTimes
	found := 0
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 9 || !want[fields[0]] {
			continue
		}
		var v [8]int64
		for i := range v {
			n, err := strconv.ParseInt(fields[i+1], 10, 64)
			if err != nil {
				return CPUTimes{}, false
			}
			v[i] = n
		}
		tick := func(n int64) time.Duration { return time.Duration(n) * time.Second / userHZ }
		// user nice system idle iowait irq softirq steal
		t.User += tick(v[0])
		t.Nice += tick(v[1])
		t.System += tick(v[2])
		t.Irq += tick(v[5])
		t.Softirq += tick(v[6])
		t.Steal += tick(v[7])
		found++
	}
	return t, found == len(want) && lines.Err() == nil
}

// a hypervisor flag in /proc/cpuinfo or a hypervisor type in sysfs; ok is
// false when neither can be read
func Virtualized() (virtualized, ok bool) {
	if b, err := os.ReadFile("/sys/hypervisor/type"); err == nil && strings.TrimSpace(string(b)) != "" {
		return true, true
	}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return false, false
	}
	defer f.Close()
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		key, value, found := strings.Cut(lines.Text(), ":")
		if found && strings.TrimSpace(key) == "flags" {
			return slices.Contains(strings.Fields(value), "hypervisor"), true
		}
	}
	return false, true
}
