//go:build linux || darwin

package secrets

import (
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Nonblocking opens prevent a file swapped to a FIFO from hanging preflight.
// Open each component relative to its pinned parent descriptor: O_NOFOLLOW on
// only the final component would still follow an intermediate directory symlink.
func openScanFile(root *os.Root, path string) (*os.File, error) {
	if !fs.ValidPath(path) {
		return nil, fs.ErrInvalid
	}
	const flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	f, err := root.OpenFile(".", flags|unix.O_DIRECTORY, 0)
	if err != nil || path == "." {
		return f, err
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		openFlags := flags
		if i < len(parts)-1 {
			openFlags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(f.Fd()), part, openFlags, 0)
		f.Close()
		if err != nil {
			return nil, err
		}
		f = os.NewFile(uintptr(fd), part)
	}
	return f, nil
}
