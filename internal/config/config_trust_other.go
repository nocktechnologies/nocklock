//go:build !unix

package config

// readTrustedConfig reads the config file without a trust walk where file
// ownership and permission bits are not a POSIX uid/mode concept. NockLock ships
// for Linux and macOS (both unix); this keeps the package building for other
// platforms, the same way validateStateDirOwner and fileOwnerUID are no-ops
// there.
func readTrustedConfig(path string) ([]byte, error) {
	return readConfigFile(path)
}
