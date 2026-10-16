//go:build !unix

package config

// checkConfigTrust is a no-op where file ownership and permission bits are not a
// POSIX uid/mode concept. NockLock ships for Linux and macOS (both unix); this
// keeps the package building for other platforms, the same way
// validateStateDirOwner and fileOwnerUID are no-ops there.
func checkConfigTrust(string) error {
	return nil
}
