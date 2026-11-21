//go:build windows

package lab

import (
	"syscall"
	"unsafe"
)

// diskFreeGB reports free space available to the caller via
// kernel32.GetDiskFreeSpaceExW (lpFreeBytesAvailableToCaller — the Windows
// equivalent of statfs's Bavail), the Windows implementation behind
// diskAvailGB. Zero external dependencies: syscall is stdlib.
func diskFreeGB(path string) (float64, bool) {
	if path == "" {
		path = "."
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var free, total, avail uint64
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
	r1, _, _ := proc.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&free)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&avail)),
	)
	if r1 == 0 {
		return 0, false
	}
	return float64(free) / (1 << 30), true
}
