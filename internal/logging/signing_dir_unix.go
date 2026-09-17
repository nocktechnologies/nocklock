//go:build unix

package logging

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// validateSigningKeyDirectoryOwner confirms that the current effective user
// owns the managed signing-key directory.
func validateSigningKeyDirectoryOwner(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine directory owner")
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("directory is owned by uid %d, not current uid %d", stat.Uid, os.Geteuid())
	}
	return nil
}
