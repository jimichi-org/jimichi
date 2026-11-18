package nodeview

import (
	"bytes"
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

const cgroupV1Unlimited = uint64(1<<63 - 4096)

type memoryCgroup struct {
	version     int
	hierarchy   uint64
	membership  string
	root, mount string
}

type memoryController struct {
	present, enabled bool
	hierarchy        uint64
}

func memoryCgroupsAbsent(filesystems []byte) bool {
	found := false
	for _, line := range bytes.Split(filesystems, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) > 2 || len(fields) == 2 && string(fields[0]) != "nodev" {
			return false
		}
		kind := string(fields[len(fields)-1])
		if kind == "cgroup" || kind == "cgroup2" {
			return false
		}
		found = true
	}
	return found
}

func hostMemAvailable(data []byte) (uint64, error) {
	var value uint64
	found := false
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 || string(fields[0]) != "MemAvailable:" {
			continue
		}
		if found || len(fields) != 3 || string(fields[2]) != "kB" {
			return 0, ErrUnsupported
		}
		kilobytes, err := memoryDecimal(fields[1])
		if err != nil || kilobytes > ^uint64(0)/1024 {
			return 0, ErrUnsupported
		}
		value, found = kilobytes*1024, true
	}
	if !found {
		return 0, ErrUnsupported
	}
	return value, nil
}

func memoryDecimal(data []byte) (uint64, error) {
	if len(data) == 0 {
		return 0, ErrUnsupported
	}
	for _, digit := range data {
		if digit < '0' || digit > '9' {
			return 0, ErrUnsupported
		}
	}
	value, err := strconv.ParseUint(string(data), 10, 64)
	if err != nil {
		return 0, ErrUnsupported
	}
	return value, nil
}

func parseMemoryController(data []byte) (memoryController, error) {
	var out memoryController
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 || fields[0][0] == '#' {
			continue
		}
		if len(fields) != 4 {
			return memoryController{}, ErrUnsupported
		}
		hierarchy, e1 := memoryDecimal(fields[1])
		_, e2 := memoryDecimal(fields[2])
		enabled, e3 := memoryDecimal(fields[3])
		if e1 != nil || e2 != nil || e3 != nil || enabled > 1 {
			return memoryController{}, ErrUnsupported
		}
		if string(fields[0]) == "memory" {
			if out.present {
				return memoryController{}, ErrUnsupported
			}
			out = memoryController{present: true, enabled: enabled == 1, hierarchy: hierarchy}
		}
	}
	return out, nil
}

func parseMemoryMembership(data []byte) (memoryCgroup, memoryCgroup, error) {
	var v1, v2 memoryCgroup
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || !validMemoryPath(fields[2]) {
			return v1, v2, ErrUnsupported
		}
		hierarchy, err := memoryDecimal([]byte(fields[0]))
		if err != nil || hierarchy == 0 && fields[1] != "" || hierarchy != 0 && fields[1] == "" {
			return v1, v2, ErrUnsupported
		}
		if hierarchy == 0 {
			if v2.version != 0 {
				return v1, v2, ErrUnsupported
			}
			v2 = memoryCgroup{version: 2, membership: fields[2]}
		} else if memoryListContains(fields[1], "memory") {
			if v1.version != 0 {
				return v1, v2, ErrUnsupported
			}
			v1 = memoryCgroup{version: 1, hierarchy: hierarchy, membership: fields[2]}
		}
	}
	return v1, v2, nil
}

func memoryListContains(list, item string) bool {
	for _, element := range strings.Split(list, ",") {
		if element == item {
			return true
		}
	}
	return false
}

func validMemoryPath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\x00\n\r") && path.Clean(value) == value
}

func unescapeMemoryMount(value string) (string, error) {
	var out strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			out.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", ErrUnsupported
		}
		switch value[index+1 : index+4] {
		case "040":
			out.WriteByte(' ')
		case "011":
			out.WriteByte('\t')
		case "012":
			return "", ErrUnsupported
		case "134":
			out.WriteByte('\\')
		default:
			return "", ErrUnsupported
		}
		index += 3
	}
	decoded := out.String()
	if !validMemoryPath(decoded) {
		return "", ErrUnsupported
	}
	return decoded, nil
}

func memoryPathWithin(value, root string) bool {
	return root == "/" || value == root || strings.HasPrefix(value, root+"/")
}

func resolveMemoryMounts(data []byte, group memoryCgroup) ([]memoryCgroup, error) {
	var out []memoryCgroup
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || len(fields) != separator+4 {
			return nil, ErrUnsupported
		}
		for _, numeric := range []string{fields[0], fields[1]} {
			if _, err := memoryDecimal([]byte(numeric)); err != nil {
				return nil, ErrUnsupported
			}
		}
		kind := fields[separator+1]
		if group.version == 2 && kind != "cgroup2" || group.version == 1 && (kind != "cgroup" || !memoryListContains(fields[separator+3], "memory")) {
			continue
		}
		root, e1 := unescapeMemoryMount(fields[3])
		mount, e2 := unescapeMemoryMount(fields[4])
		if e1 != nil || e2 != nil {
			return nil, ErrUnsupported
		}
		if !memoryPathWithin(group.membership, root) {
			continue
		}
		resolved := group
		resolved.root, resolved.mount = root, mount
		out = append(out, resolved)
	}
	if len(out) == 0 {
		return nil, ErrUnsupported
	}
	return out, nil
}

func memoryCgroupDirectory(group memoryCgroup) (string, error) {
	if !validMemoryPath(group.membership) || !validMemoryPath(group.root) || !validMemoryPath(group.mount) || !memoryPathWithin(group.membership, group.root) {
		return "", ErrUnsupported
	}
	relative := strings.TrimPrefix(group.membership, group.root)
	if group.root == "/" {
		relative = group.membership
	}
	directory := path.Join(group.mount, relative)
	if !memoryPathWithin(directory, group.mount) {
		return "", ErrUnsupported
	}
	return directory, nil
}

func memoryScalar(read func(string) ([]byte, error), directory, name string) (uint64, error) {
	data, err := read(path.Join(directory, name))
	if err != nil {
		return 0, err
	}
	return memoryDecimal(bytes.TrimSpace(data))
}

func memoryHierarchyLimit(data []byte) (uint64, error) {
	return memoryStatLimit(data, "hierarchical_memory_limit")
}

func memoryStatLimit(data []byte, key string) (uint64, error) {
	var out uint64
	found := false
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 || string(fields[0]) != key {
			continue
		}
		if found || len(fields) != 2 {
			return 0, ErrUnsupported
		}
		value, err := memoryDecimal(fields[1])
		if err != nil || value > cgroupV1Unlimited {
			return 0, ErrUnsupported
		}
		out, found = value, true
	}
	if !found {
		return 0, ErrUnsupported
	}
	return out, nil
}

func memoryCgroupRootKnown(group memoryCgroup, read func(string) ([]byte, error)) bool {
	if group.version == 2 {
		if group.root != "/" {
			return false
		}
		_, err := read(path.Join(group.mount, "memory.max"))
		if !errors.Is(err, fs.ErrNotExist) {
			return false
		}
		controllers, err := read(path.Join(group.mount, "cgroup.controllers"))
		if err != nil {
			return false
		}
		available := false
		for _, controller := range strings.Fields(string(controllers)) {
			available = available || controller == "memory"
		}
		if !available {
			return false
		}
		// available memory exposes memory.max on every non-root, including kernels predating cgroup.type
		_, err = read(path.Join(group.mount, "cgroup.type"))
		return errors.Is(err, fs.ErrNotExist) && !bytes.Contains(controllers, []byte{0})
	}
	limit, err := memoryScalar(read, group.mount, "memory.limit_in_bytes")
	if err != nil || limit != cgroupV1Unlimited {
		return false
	}
	stat, err := read(path.Join(group.mount, "memory.stat"))
	if err != nil {
		return false
	}
	hierarchical, err := memoryHierarchyLimit(stat)
	// v1 reports the minimum enforcing ancestor limit, including ancestors outside a subtree mount
	if err != nil || hierarchical != cgroupV1Unlimited {
		return false
	}
	memsw, _, enabled, err := memoryV1Memsw(read, group.mount)
	if err != nil || enabled && memsw != cgroupV1Unlimited {
		return false
	}
	if enabled {
		hierarchical, err = memoryStatLimit(stat, "hierarchical_memsw_limit")
		return err == nil && hierarchical == cgroupV1Unlimited
	}
	return true
}

func memoryV1Memsw(read func(string) ([]byte, error), directory string) (uint64, uint64, bool, error) {
	limit, limitErr := memoryScalar(read, directory, "memory.memsw.limit_in_bytes")
	usage, usageErr := memoryScalar(read, directory, "memory.memsw.usage_in_bytes")
	if errors.Is(limitErr, fs.ErrNotExist) && errors.Is(usageErr, fs.ErrNotExist) {
		return 0, 0, false, nil
	}
	if limitErr != nil || usageErr != nil || limit > cgroupV1Unlimited {
		return 0, 0, false, ErrUnsupported
	}
	return limit, usage, true, nil
}

func memoryCgroupHeadroom(group memoryCgroup, available uint64, read func(string) ([]byte, error)) (uint64, error) {
	directory, err := memoryCgroupDirectory(group)
	if err != nil || !memoryCgroupRootKnown(group, read) {
		return 0, ErrUnsupported
	}
	leaf := directory
	memswEnabled := false
	if group.version == 1 {
		_, _, memswEnabled, err = memoryV1Memsw(read, group.mount)
		if err != nil {
			return 0, ErrUnsupported
		}
	}
	for {
		if group.version == 2 {
			limit, err := read(path.Join(directory, "memory.max"))
			if errors.Is(err, fs.ErrNotExist) {
				controllers, err := read(path.Join(directory, "cgroup.controllers"))
				if err != nil {
					return 0, ErrUnsupported
				}
				if directory != group.mount {
					for _, controller := range strings.Fields(string(controllers)) {
						if controller == "memory" {
							return 0, ErrUnsupported
						}
					}
				}
			} else if err != nil {
				return 0, ErrUnsupported
			} else if string(bytes.TrimSpace(limit)) != "max" {
				value, err := memoryDecimal(bytes.TrimSpace(limit))
				if err != nil {
					return 0, ErrUnsupported
				}
				usage, err := memoryScalar(read, directory, "memory.current")
				if err != nil {
					return 0, ErrUnsupported
				}
				available = min(available, memoryRemaining(value, usage))
			}
		} else {
			limit, err := memoryScalar(read, directory, "memory.limit_in_bytes")
			if err != nil || limit > cgroupV1Unlimited {
				return 0, ErrUnsupported
			}
			hierarchical, err := memoryScalar(read, directory, "memory.use_hierarchy")
			if err != nil || hierarchical > 1 {
				return 0, ErrUnsupported
			}
			if limit != cgroupV1Unlimited && (directory == leaf || hierarchical == 1) {
				usage, err := memoryScalar(read, directory, "memory.usage_in_bytes")
				if err != nil {
					return 0, ErrUnsupported
				}
				available = min(available, memoryRemaining(limit, usage))
			}
			memsw, usage, enabled, err := memoryV1Memsw(read, directory)
			if err != nil || enabled != memswEnabled {
				return 0, ErrUnsupported
			}
			if enabled && memsw != cgroupV1Unlimited && (directory == leaf || hierarchical == 1) {
				available = min(available, memoryRemaining(memsw, usage))
			}
		}
		if directory == group.mount {
			break
		}
		directory = path.Dir(directory)
		if !memoryPathWithin(directory, group.mount) {
			return 0, ErrUnsupported
		}
	}
	return available, nil
}

func memoryRemaining(limit, usage uint64) uint64 {
	if usage >= limit {
		return 0
	}
	return limit - usage
}

func availableCgroupMemory(meminfo, controllers, membership, mounts []byte, read func(string) ([]byte, error)) (uint64, error) {
	available, err := hostMemAvailable(meminfo)
	if err != nil {
		return 0, ErrUnsupported
	}
	controller, err := parseMemoryController(controllers)
	if err != nil {
		return 0, ErrUnsupported
	}
	v1, v2, err := parseMemoryMembership(membership)
	if err != nil {
		return 0, ErrUnsupported
	}
	if controller.present && !controller.enabled {
		if v1.version != 0 || controller.hierarchy != 0 {
			return 0, ErrUnsupported
		}
		return available, nil
	}
	group := v2
	if controller.hierarchy != 0 {
		if v1.version == 0 || v1.hierarchy != controller.hierarchy {
			return 0, ErrUnsupported
		}
		group = v1
	} else if v1.version != 0 {
		return 0, ErrUnsupported
	} else if v2.version == 0 {
		// an unexposed default hierarchy cannot contain an active non-root memory cgroup
		return available, nil
	}
	resolved, err := resolveMemoryMounts(mounts, group)
	if err != nil {
		return 0, ErrUnsupported
	}
	found := false
	for _, candidate := range resolved {
		if !memoryCgroupRootKnown(candidate, read) {
			continue
		}
		headroom, err := memoryCgroupHeadroom(candidate, available, read)
		if err == nil {
			available, found = min(available, headroom), true
		}
	}
	if found {
		return available, nil
	}
	return 0, ErrUnsupported
}
