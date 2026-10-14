//go:build !unix

package config

import "io/fs"

// validateStateDirOwner is a no-op where file ownership is not a uid check.
func validateStateDirOwner(info fs.FileInfo) error {
	return nil
}

// Trusted chain identity lifecycle is unsupported on these platforms. Preserve
// legacy state-directory creation without claiming Unix directory durability.
func syncCreatedStateRootParent(string) error { return nil }
