//go:build !unix

package config

import "io/fs"

// validateStateDirOwner is a no-op where file ownership is not a uid check.
func validateStateDirOwner(info fs.FileInfo) error {
	return nil
}
