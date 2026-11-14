//go:build linux && amd64

package nodeview

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
)

func availableHostMemory() (uint64, error) {
	meminfo, err := readHostMemoryFile("/proc/meminfo")
	if err != nil {
		return 0, ErrUnsupported
	}
	cgroups, groupsErr := readHostMemoryFile("/proc/cgroups")
	membership, membershipErr := readHostMemoryFile("/proc/self/cgroup")
	if errors.Is(groupsErr, fs.ErrNotExist) && errors.Is(membershipErr, fs.ErrNotExist) {
		filesystems, err := readHostMemoryFile("/proc/filesystems")
		if err != nil || !memoryCgroupsAbsent(filesystems) {
			return 0, ErrUnsupported
		}
		return hostMemAvailable(meminfo)
	}
	if groupsErr != nil || membershipErr != nil {
		return 0, ErrUnsupported
	}
	mounts, err := readHostMemoryFile("/proc/self/mountinfo")
	if err != nil {
		return 0, ErrUnsupported
	}
	available, err := availableCgroupMemory(meminfo, cgroups, membership, mounts, readHostMemoryFile)
	if err != nil {
		return 0, ErrUnsupported
	}
	finalMembership, err := readHostMemoryFile("/proc/self/cgroup")
	if err != nil || !bytes.Equal(membership, finalMembership) {
		return 0, ErrUnsupported
	}
	finalMounts, err := readHostMemoryFile("/proc/self/mountinfo")
	if err != nil || !bytes.Equal(mounts, finalMounts) {
		return 0, ErrUnsupported
	}
	return available, nil
}

func readHostMemoryFile(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maximum = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) > maximum {
		return nil, ErrUnsupported
	}
	return data, nil
}
