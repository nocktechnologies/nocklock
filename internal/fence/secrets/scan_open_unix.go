//go:build linux || darwin

package secrets

import (
	"golang.org/x/sys/unix"
	"os"
)

// Nonblocking opens prevent a file swapped to a FIFO from hanging preflight.
func openScanFile(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}
