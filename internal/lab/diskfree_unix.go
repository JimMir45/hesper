//go:build !windows

package lab

import "syscall"

// diskFreeGB reports free space available to the caller via statfs (the
// Bavail blocks — matching what a lab could actually write), the
// non-Windows implementation behind diskAvailGB.
func diskFreeGB(path string) (float64, bool) {
	if path == "" {
		path = "."
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	return float64(uint64(st.Bavail)*uint64(st.Bsize)) / (1 << 30), true
}
