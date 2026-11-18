package nodeview

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func memoryAggregateFixture(t *testing.T, files map[string]string) func(string) ([]byte, error) {
	t.Helper()
	root := t.TempDir()
	for name, value := range files {
		if !validMemoryPath(name) {
			t.Fatalf("invalid aggregate fixture path %q", name)
		}
		local := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(local, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return func(name string) ([]byte, error) {
		if !validMemoryPath(name) {
			return nil, fs.ErrInvalid
		}
		if _, exists := files[name]; !exists {
			return nil, fs.ErrNotExist
		}
		return os.ReadFile(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/"))))
	}
}

func memoryMountFixture(root, mount, kind, options string) string {
	escape := func(value string) string {
		return strings.NewReplacer("\\", "\\134", " ", "\\040", "\t", "\\011").Replace(value)
	}
	return fmt.Sprintf("23 19 0:28 %s %s rw,nosuid - %s cgroup %s\n", escape(root), escape(mount), kind, options)
}

func TestHostMemoryCgroupKnownAnswers(t *testing.T) {
	unlimited := fmt.Sprint(cgroupV1Unlimited)
	for _, test := range []struct {
		name, controller, membership, mounts string
		files                                map[string]string
		want                                 uint64
	}{
		{
			name: "v2-shared-parent", controller: "memory 0 3 1\n", membership: "0::/parent/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files: map[string]string{
				"/aggregate/cgroup.controllers": "cpu memory\n",
				"/aggregate/parent/memory.max":  "1500\n", "/aggregate/parent/memory.current": "1200\n",
				"/aggregate/parent/own/memory.max": "1000\n", "/aggregate/parent/own/memory.current": "100\n",
			},
			want: 300,
		},
		{
			name: "v2-only-controller-absent-from-v1-proc-table", controller: "cpu 0 3 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files: map[string]string{
				"/aggregate/cgroup.controllers": "memory\n",
				"/aggregate/own/memory.max":     "1000\n", "/aggregate/own/memory.current": "100\n",
			},
			want: 900,
		},
		{
			name: "v2-disabled-child-still-counts-shared-parent", controller: "memory 0 3 1\n", membership: "0::/parent/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files: map[string]string{
				"/aggregate/cgroup.controllers": "memory\n",
				"/aggregate/parent/memory.max":  "1500\n", "/aggregate/parent/memory.current": "1200\n",
				"/aggregate/parent/own/cgroup.controllers": "cpu\n",
			},
			want: 300,
		},
		{
			name: "v2-unlimited-is-host-bound", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "memory\n", "/aggregate/own/memory.max": "max\n"},
			want:   1024 * 1024,
		},
		{
			name: "v2-real-root-memory-disabled", controller: "memory 0 1 0\n", membership: "0::/\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "cpu\n"},
			want:   1024 * 1024,
		},
		{
			name: "v2-physical-is-smaller", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "memory\n", "/aggregate/own/memory.max": "2097152\n", "/aggregate/own/memory.current": "1\n"},
			want:   1024 * 1024,
		},
		{
			name: "v2-over-limit-saturates", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "memory\n", "/aggregate/own/memory.max": "1000\n", "/aggregate/own/memory.current": "1001\n"},
			want:   0,
		},
		{
			name: "v1-shared-parent", controller: "memory 5 3 1\n", membership: "5:cpu,memory:/parent/own\n0::/ignored\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup", "rw,cpu,memory"),
			files: map[string]string{
				"/aggregate/memory.limit_in_bytes": unlimited, "/aggregate/memory.use_hierarchy": "1\n",
				"/aggregate/memory.stat":                  "cache 1\nhierarchical_memory_limit " + unlimited + "\n",
				"/aggregate/parent/memory.limit_in_bytes": "1500\n", "/aggregate/parent/memory.usage_in_bytes": "1200\n", "/aggregate/parent/memory.use_hierarchy": "1\n",
				"/aggregate/parent/own/memory.limit_in_bytes": "1000\n", "/aggregate/parent/own/memory.usage_in_bytes": "100\n", "/aggregate/parent/own/memory.use_hierarchy": "1\n",
			},
			want: 300,
		},
		{
			name: "v1-combined-memory-swap-is-tighter", controller: "memory 5 3 1\n", membership: "5:memory:/parent/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup", "rw,memory"),
			files: map[string]string{
				"/aggregate/memory.limit_in_bytes": unlimited, "/aggregate/memory.use_hierarchy": "1",
				"/aggregate/memory.stat":                 "hierarchical_memory_limit " + unlimited + "\nhierarchical_memsw_limit " + unlimited,
				"/aggregate/memory.memsw.limit_in_bytes": unlimited, "/aggregate/memory.memsw.usage_in_bytes": "0",
				"/aggregate/parent/memory.limit_in_bytes": "1500", "/aggregate/parent/memory.usage_in_bytes": "1200", "/aggregate/parent/memory.use_hierarchy": "1",
				"/aggregate/parent/memory.memsw.limit_in_bytes": "2000", "/aggregate/parent/memory.memsw.usage_in_bytes": "1900",
				"/aggregate/parent/own/memory.limit_in_bytes": "1000", "/aggregate/parent/own/memory.usage_in_bytes": "100", "/aggregate/parent/own/memory.use_hierarchy": "1",
				"/aggregate/parent/own/memory.memsw.limit_in_bytes": "1200", "/aggregate/parent/own/memory.memsw.usage_in_bytes": "500",
			},
			want: 100,
		},
		{
			name: "v1-unlimited-subtree-proves-hidden-ancestors-unlimited", controller: "memory 5 4 1\n", membership: "5:memory:/hidden/visible/own\n",
			mounts: memoryMountFixture("/hidden/visible", "/aggregate", "cgroup", "rw,memory"),
			files: map[string]string{
				"/aggregate/memory.limit_in_bytes": unlimited, "/aggregate/memory.use_hierarchy": "1\n",
				"/aggregate/memory.stat":               "hierarchical_memory_limit " + unlimited + "\n",
				"/aggregate/own/memory.limit_in_bytes": "1000\n", "/aggregate/own/memory.usage_in_bytes": "100\n", "/aggregate/own/memory.use_hierarchy": "1\n",
			},
			want: 900,
		},
		{
			name: "no-enabled-memory-controller", controller: "cpu 1 1 1\nmemory 0 1 0\n", membership: "1:cpu:/\n",
			files: map[string]string{}, want: 1024 * 1024,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// host 1024 KiB; parent 1500-1200=300 beats own 1000-100=900
			got, err := availableCgroupMemory([]byte("MemTotal: 2048 kB\nMemAvailable: 1024 kB\n"), []byte(test.controller), []byte(test.membership), []byte(test.mounts), memoryAggregateFixture(t, test.files))
			if err != nil || got != test.want {
				t.Fatalf("headroom %d, want %d, error %v", got, test.want, err)
			}
		})
	}
}

func TestHostMemoryCgroupRejectsUnresolvedBoundary(t *testing.T) {
	unlimited := fmt.Sprint(cgroupV1Unlimited)
	for _, test := range []struct {
		name, controller, membership, mounts string
		files                                map[string]string
	}{
		{
			name: "v2-namespace-root-retains-memory-max", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/memory.max": "4096", "/aggregate/cgroup.controllers": "memory", "/aggregate/cgroup.type": "domain"},
		},
		{
			name: "v2-namespace-root-with-memory-disabled", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "cpu", "/aggregate/cgroup.type": "domain"},
		},
		{
			name: "old-v2-hidden-child-no-type-no-max", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "cpu"},
		},
		{
			name: "old-v2-hidden-child-memory-absent-from-v1-table", controller: "cpu 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "cpu"},
		},
		{
			name: "v2-subtree-hides-ancestors", controller: "memory 0 3 1\n", membership: "0::/parent/own\n",
			mounts: memoryMountFixture("/parent", "/aggregate", "cgroup2", "rw"), files: map[string]string{},
		},
		{
			name: "v1-hidden-finite-ancestor", controller: "memory 5 3 1\n", membership: "5:memory:/parent/own\n",
			mounts: memoryMountFixture("/parent", "/aggregate", "cgroup", "rw,memory"),
			files:  map[string]string{"/aggregate/memory.limit_in_bytes": unlimited, "/aggregate/memory.stat": "hierarchical_memory_limit 4096\n"},
		},
		{
			name: "v1-finite-top-cannot-prove-sibling-usage", controller: "memory 5 3 1\n", membership: "5:memory:/parent/own\n",
			mounts: memoryMountFixture("/parent", "/aggregate", "cgroup", "rw,memory"),
			files:  map[string]string{"/aggregate/memory.limit_in_bytes": "4096", "/aggregate/memory.stat": "hierarchical_memory_limit 4096\n"},
		},
		{
			name: "v1-hidden-finite-memsw-ancestor", controller: "memory 5 3 1\n", membership: "5:memory:/parent/own\n",
			mounts: memoryMountFixture("/parent", "/aggregate", "cgroup", "rw,memory"),
			files: map[string]string{
				"/aggregate/memory.limit_in_bytes":       unlimited,
				"/aggregate/memory.stat":                 "hierarchical_memory_limit " + unlimited + "\nhierarchical_memsw_limit 4096\n",
				"/aggregate/memory.memsw.limit_in_bytes": unlimited, "/aggregate/memory.memsw.usage_in_bytes": "0",
			},
		},
		{
			name: "v1-partial-memsw-interface", controller: "memory 5 3 1\n", membership: "5:memory:/parent/own\n",
			mounts: memoryMountFixture("/parent", "/aggregate", "cgroup", "rw,memory"),
			files: map[string]string{
				"/aggregate/memory.limit_in_bytes": unlimited, "/aggregate/memory.stat": "hierarchical_memory_limit " + unlimited,
				"/aggregate/memory.memsw.limit_in_bytes": unlimited,
			},
		},
		{
			name: "v2-missing-current", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "memory", "/aggregate/own/memory.max": "1000"},
		},
		{
			name: "v2-missing-limit-despite-enabled-controller", controller: "memory 0 2 1\n", membership: "0::/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup2", "rw"),
			files:  map[string]string{"/aggregate/cgroup.controllers": "memory", "/aggregate/own/cgroup.controllers": "memory"},
		},
		{
			name: "memory-controller-hierarchy-mismatch", controller: "memory 5 2 1\n", membership: "4:memory:/own\n", files: map[string]string{},
		},
		{
			name: "no-matching-memory-mount", controller: "memory 5 2 1\n", membership: "5:memory:/own\n",
			mounts: memoryMountFixture("/", "/aggregate", "cgroup", "rw,cpu"), files: map[string]string{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := availableCgroupMemory([]byte("MemAvailable: 1024 kB\n"), []byte(test.controller), []byte(test.membership), []byte(test.mounts), memoryAggregateFixture(t, test.files))
			if got != 0 || !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unresolved effective boundary admitted %d: %v", got, err)
			}
		})
	}
}

func TestHostMemoryCgroupMountResolution(t *testing.T) {
	group := memoryCgroup{version: 2, membership: "/host/visible/own"}
	mounts := memoryMountFixture("/host", "/wrong", "cgroup", "rw,memory") + memoryMountFixture("/host/vis", "/prefix-mismatch", "cgroup2", "rw") + memoryMountFixture("/host/visible", "/aggregate path\tback\\slash", "cgroup2", "rw")
	resolved, err := resolveMemoryMounts([]byte(mounts), group)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolve mount roots: %+v %v", resolved, err)
	}
	directory, err := memoryCgroupDirectory(resolved[0])
	if err != nil || directory != "/aggregate path\tback\\slash/own" {
		t.Fatalf("escaped mount/path resolution %q: %v", directory, err)
	}
	for _, malformed := range []string{
		"23 19 0:28 / /aggregate rw - cgroup2\n",
		"x 19 0:28 / /aggregate rw - cgroup2 cgroup rw\n",
		"23 19 0:28 / /aggregate\\999 rw - cgroup2 cgroup rw\n",
		"23 19 0:28 / /aggregate/../escape rw - cgroup2 cgroup rw\n",
	} {
		if _, err := resolveMemoryMounts([]byte(malformed), group); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("malformed mount accepted: %q", malformed)
		}
	}
	for _, malformed := range []string{"/../own", "/parent/../own", "/own/", "own", "/own\x00suffix"} {
		if validMemoryPath(malformed) {
			t.Fatalf("unsafe membership path accepted: %q", malformed)
		}
	}
}

func TestHostMemoryCgroupParsers(t *testing.T) {
	if !memoryCgroupsAbsent([]byte("nodev\tsysfs\n\text4\n")) {
		t.Fatal("kernel without cgroup filesystem support rejected")
	}
	for _, text := range []string{"", "nodev\tcgroup\n", "nodev\tcgroup2\n", "unknown ext4\n", "nodev sysfs trailing\n"} {
		if memoryCgroupsAbsent([]byte(text)) {
			t.Fatalf("cgroup support absence not established: %q", text)
		}
	}
	for _, test := range []struct {
		text string
		want uint64
	}{
		{"MemAvailable: 1 kB\n", 1024}, {"MemAvailable: 0 kB\n", 0},
		{fmt.Sprintf("MemAvailable: %d kB\n", uint64(math.MaxUint64/1024)), uint64(math.MaxUint64/1024) * 1024},
	} {
		got, err := hostMemAvailable([]byte(test.text))
		if err != nil || got != test.want {
			t.Fatalf("MemAvailable parser: %d, want %d, %v", got, test.want, err)
		}
	}
	for _, text := range []string{"", "MemAvailable: -1 kB\n", "MemAvailable: +1 kB\n", "MemAvailable: 1 MB\n", "MemAvailable: 1 kB\nMemAvailable: 2 kB\n", "MemAvailable: 18446744073709551616 kB\n", fmt.Sprintf("MemAvailable: %d kB\n", uint64(math.MaxUint64/1024)+1)} {
		if _, err := hostMemAvailable([]byte(text)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("invalid/overflowed MemAvailable accepted: %q", text)
		}
	}
	for _, text := range []string{"", "-1", "+1", "1 2", "max", "18446744073709551616"} {
		if _, err := memoryDecimal([]byte(text)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("invalid scalar accepted: %q", text)
		}
	}
	for _, text := range []string{"0:memory:/own\n", "1::/own\n", "0::/own\n0::/other\n", "1:memory:/own\n2:memory:/other\n", "0::/../own\n", "18446744073709551616::/own\n"} {
		if _, _, err := parseMemoryMembership([]byte(text)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("invalid membership accepted: %q", text)
		}
	}
	for _, text := range []string{"memory 0 1 2\n", "memory 0 1 1\nmemory 0 1 1\n", "memory 0 1\n", "memory -1 1 1\n"} {
		if _, err := parseMemoryController([]byte(text)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("invalid controller table accepted: %q", text)
		}
	}
	for _, text := range []string{"", "hierarchical_memory_limit -1\n", "hierarchical_memory_limit 1\nhierarchical_memory_limit 2\n", "hierarchical_memory_limit 18446744073709551615\n"} {
		if _, err := memoryHierarchyLimit([]byte(text)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("invalid hierarchical limit accepted: %q", text)
		}
	}
	if cgroupV1Unlimited != 9223372036854771712 || memoryRemaining(10, 4) != 6 || memoryRemaining(10, 11) != 0 {
		t.Fatal("linux/amd64 unlimited sentinel or saturating subtraction changed")
	}
}

func TestHostMemoryCgroupReadOnlyAndReadErrors(t *testing.T) {
	meminfo, controllers, membership := []byte("MemAvailable: 1024 kB\n"), []byte("memory 0 2 1\n"), []byte("0::/own\n")
	mounts := []byte(memoryMountFixture("/", "/aggregate", "cgroup2", "rw"))
	before := [][]byte{append([]byte(nil), meminfo...), append([]byte(nil), controllers...), append([]byte(nil), membership...), append([]byte(nil), mounts...)}
	reader := memoryAggregateFixture(t, map[string]string{"/aggregate/cgroup.controllers": "memory", "/aggregate/own/memory.max": "1000", "/aggregate/own/memory.current": "100"})
	for _, denied := range []string{"/aggregate/cgroup.controllers", "/aggregate/memory.max", "/aggregate/cgroup.type", "/aggregate/own/memory.current"} {
		wrapped := func(name string) ([]byte, error) {
			if name == denied {
				return nil, fs.ErrPermission
			}
			return reader(name)
		}
		if _, err := availableCgroupMemory(meminfo, controllers, membership, mounts, wrapped); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("inaccessible aggregate accepted: %s", denied)
		}
	}
	if !reflect.DeepEqual(before, [][]byte{meminfo, controllers, membership, mounts}) {
		t.Fatal("aggregate parser mutated source OS text")
	}
}
