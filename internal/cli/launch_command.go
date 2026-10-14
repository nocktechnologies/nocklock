package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// resolveChildArgv selects the requested executable using the caller's PATH
// before adding shims that call execve without searching PATH themselves.
// Only argv[0] changes; this selects a path, not a pinned executable inode.
func resolveChildArgv(args []string, prefixes ...[]string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("resolve command: supply an executable to wrap")
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return nil, fmt.Errorf("resolve command %q: %w", args[0], err)
	}
	// Do not let GODEBUG=execerrdot=0 restore implicit CWD selection. Explicit
	// relative paths are intentional; bare names must resolve via absolute PATH.
	if filepath.Base(args[0]) == args[0] && !filepath.IsAbs(path) {
		return nil, fmt.Errorf("resolve command %q: %w", args[0], exec.ErrDot)
	}
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve command %q: get working directory: %w", args[0], err)
		}
		// Preserve symlink/.. semantics: filepath.Abs or Join would clean the
		// spelling and could select a different executable than LookPath checked.
		path = wd + string(os.PathSeparator) + path
	}
	resolved := append([]string(nil), args...)
	resolved[0] = path
	return composeChildArgv(resolved, prefixes...), nil
}
