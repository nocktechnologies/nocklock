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
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine directory owner")
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("directory is owned by uid %d, not current uid %d", stat.Uid, os.Geteuid())
	}
	return nil
}
