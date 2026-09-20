//go:build !unix

package logging

import "io/fs"

// validateSigningKeyDirectoryOwner has no portable owner-id check outside the
// Unix platforms NockLock supports. The caller still requires a real 0700
// directory and rejects symlinked path components on every platform.
func validateSigningKeyDirectoryOwner(info fs.FileInfo) error {
	return nil
}
