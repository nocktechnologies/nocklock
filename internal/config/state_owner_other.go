//go:build !unix

package config

import "io/fs"

// validateStateDirOwner is a no-op where file ownership is not a uid check.
func validateStateDirOwner(info fs.FileInfo) error {
	return nil
}

// fileOwnerUID cannot read a uid where file ownership is not a uid check, so it
// reports that the owner is undeterminable and the config trust walk skips the
// ownership comparison (the permission check still applies).
func fileOwnerUID(info fs.FileInfo) (uint32, bool) {
	return 0, false
}
