//go:build unix

package config

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// validateStateDirOwner rejects an audit state directory owned by another user.
// The mode check alone is not enough: a directory another user owns can be
// chmod'd back open at any time, so ownership is the durable property. Mirrors
// validateSigningKeyDirectoryOwner in internal/logging, which guards the signing
// key against the same threat; the check is duplicated rather than shared
// because internal/logging imports this package.
func validateStateDirOwner(info fs.FileInfo) error {
	owner, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("cannot determine directory owner")
	}
	if int(owner) != os.Geteuid() {
		return fmt.Errorf("directory is owned by uid %d, not current uid %d", owner, os.Geteuid())
	}
	return nil
}

// fileOwnerUID returns the owning uid of info and whether it could be
// determined. The config trust walk uses it to compare each path component's
// owner against root and the invoking user.
func fileOwnerUID(info fs.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
