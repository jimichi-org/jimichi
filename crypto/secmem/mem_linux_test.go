//go:build linux

package secmem_test

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// these tests are the evidence the threat model cites for key memory, so CI
// must fail where a developer machine may skip
func unavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// what the kernel records for the mapping that holds a buffer: "lo" is locked,
// "dd" is excluded from core dumps
func vmFlags(t *testing.T, addr uintptr) string {
	t.Helper()
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		unavailable(t, "no smaps: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inside := false
	for sc.Scan() {
		line := sc.Text()
		var lo, hi uintptr
		if n, _ := fmt.Sscanf(line, "%x-%x", &lo, &hi); n == 2 && strings.Contains(line, " ") && !strings.HasPrefix(line, "VmFlags") {
			inside = addr >= lo && addr < hi
			continue
		}
		if inside && strings.HasPrefix(line, "VmFlags:") {
			return line
		}
	}
	t.Fatalf("no mapping holds %#x", addr)
	return ""
}

func TestProtectedPagesAreLockedAndUndumpable(t *testing.T) {
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	b, err := secmem.New(32)
	if err != nil {
		unavailable(t, "cannot lock memory here: %v", err)
	}
	defer b.Release()
	flags := vmFlags(t, uintptr(unsafe.Pointer(&b.Bytes()[0])))
	for _, want := range []string{" lo", " dd"} {
		if !strings.Contains(flags, want) {
			t.Fatalf("mapping flags %q lack%s", flags, want)
		}
	}
}

func TestOffHeapWithoutMeasuresIsPlainMapping(t *testing.T) {
	defer func() { _ = secmem.SetPolicy(secmem.Protected) }()
	if err := secmem.SetPolicy(secmem.Policy{OffHeap: true}); err != nil {
		t.Fatal(err)
	}
	b, err := secmem.New(32)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	flags := vmFlags(t, uintptr(unsafe.Pointer(&b.Bytes()[0])))
	if strings.Contains(flags, " lo") || strings.Contains(flags, " dd") {
		t.Fatalf("mapping flags %q show a measure that was switched off", flags)
	}
}

// whatever the size that found no room, the failure names one cause, so a
// node that logs it writes one line for it
func TestLockFailureNamesItsCause(t *testing.T) {
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	var was unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: was.Max}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
			t.Errorf("RLIMIT_MEMLOCK not restored: %v", err)
		}
	})
	for _, size := range []int{32, 64 << 10} {
		b, err := secmem.New(size)
		if err == nil {
			b.Release()
			t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
		}
		if !errors.Is(err, secmem.ErrNotLocked) || errors.Is(err, secmem.ErrNotMapped) {
			t.Fatalf("New(%d) under a zero limit: %v, want %v", size, err, secmem.ErrNotLocked)
		}
	}
}

// half the largest int is past the user address space of a 64-bit process, so
// mmap itself refuses it, before any page is locked
func TestMapFailureNamesItsCause(t *testing.T) {
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	b, err := secmem.New(math.MaxInt / 2)
	if err == nil {
		b.Release()
		t.Skip("the mapping was granted here")
	}
	if !errors.Is(err, secmem.ErrNotMapped) || errors.Is(err, secmem.ErrNotLocked) {
		t.Fatalf("New(MaxInt/2): %v, want %v", err, secmem.ErrNotMapped)
	}
}
