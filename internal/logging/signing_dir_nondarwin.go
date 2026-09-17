//go:build !darwin

package logging

func isTrustedSigningKeyDirectoryAlias(absDir, resolvedDir string) bool {
	return false
}
