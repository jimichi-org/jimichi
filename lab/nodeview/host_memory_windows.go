//go:build windows

package nodeview

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func availableHostMemory() (uint64, error) {
	var status struct {
		Length, MemoryLoad                                 uint32
		TotalPhys, AvailPhys, TotalPageFile, AvailPageFile uint64
		TotalVirtual, AvailVirtual, AvailExtendedVirtual   uint64
	}
	status.Length = uint32(unsafe.Sizeof(status))
	call := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	result, _, _ := call.Call(uintptr(unsafe.Pointer(&status)))
	if result == 0 {
		return 0, ErrUnsupported
	}
	return status.AvailPhys, nil
}
