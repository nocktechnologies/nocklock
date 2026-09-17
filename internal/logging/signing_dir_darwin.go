//go:build darwin

package logging

import (
	"os"
	"path/filepath"
	"strings"
)

// isTrustedSigningKeyDirectoryAlias permits macOS's system-owned /var alias
// while rejecting every other symlink component in a signing-key path.
func isTrustedSigningKeyDirectoryAlias(absDir, resolvedDir string) bool {
	const alias = "/var"
	const canonical = "/private/var"
	if absDir != alias && !strings.HasPrefix(absDir, alias+string(filepath.Separator)) {
		return false
	}
	if resolvedDir != canonical+strings.TrimPrefix(absDir, alias) {
		return false
	}
	if target, err := filepath.EvalSymlinks(alias); err != nil || filepath.Clean(target) != canonical {
		return false
	}

	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(absDir, string(filepath.Separator)), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 && current != alias {
			return false
		}
	}
	return true
}
