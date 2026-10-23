package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// ProcessEffectiveConfig merges mandatory credential denies with user policy.
// A grant overlapping a built-in deny is refused on both platforms, including
// when Linux kernel enforcement is disabled. User denies never replace defaults.
func ProcessEffectiveConfig(cfg *config.Config, goos string) (*FenceConfig, error) {
	fc, err := ProcessConfig(cfg.Filesystem)
	if err != nil || fc == nil {
		return fc, err
	}
	builtins := DefaultSensitivePaths()
	if len(builtins) == 0 {
		return nil, fmt.Errorf("cannot resolve built-in credential denies: set HOME to a usable directory")
	}
	// aliases are existing home entries matched by a prefix rule; see PrefixAliasPaths.
	var aliases []string
	if goos == "darwin" {
		home, _ := os.UserHomeDir()
		fc.DenyPrefixes = []string{filepath.Join(home, ".env")}
		agent := cfg.LoginStoreRuntime()
		if agent != "claude-code" {
			fc.DenyPrefixes = append(fc.DenyPrefixes, filepath.Join(home, ".claude"))
		}
		if agent != "codex" {
			builtins = append(builtins, filepath.Join(home, ".codex"))
		}
		// Existing symlink aliases must deny their targets too. Prefix rules still
		// cover names created later; they are not a one-time glob expansion.
		entries, err := os.ReadDir(home)
		if err != nil {
			return nil, fmt.Errorf("cannot enumerate built-in credential aliases: %w", err)
		}
		for _, entry := range entries {
			for _, prefix := range fc.DenyPrefixes {
				if strings.HasPrefix(strings.ToLower(entry.Name()), strings.ToLower(filepath.Base(prefix))) {
					aliases = append(aliases, filepath.Join(home, entry.Name()))
				}
			}
		}
		for i, prefix := range fc.DenyPrefixes {
			// Resolve the parent, not a .env or .claude symlink: the rule must protect
			// the whole family of names even when its bare spelling is a symlink.
			parent, err := resolvePath(filepath.Dir(prefix))
			if err != nil {
				return nil, err
			}
			fc.DenyPrefixes[i] = filepath.Join(parent, filepath.Base(prefix))
		}
	}
	grants := append([]string{fc.Root}, fc.AllowPaths...)
	grants = append(grants, fc.AllowRWPaths...)
	for i, builtin := range append(builtins, aliases...) {
		denied, err := resolvePath(builtin)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve built-in credential deny: %w", err)
		}
		for _, grant := range grants {
			if pathsIntersect(grant, denied, goos == "darwin") {
				return nil, builtinGrantError(grant, denied)
			}
		}
		if !slices.Contains(fc.DenyPaths, denied) {
			fc.DenyPaths = append(fc.DenyPaths, denied)
			if i >= len(builtins) {
				fc.PrefixAliasPaths = append(fc.PrefixAliasPaths, denied)
			}
		}
	}
	for _, prefix := range fc.DenyPrefixes {
		for _, grant := range grants {
			a, p := strings.ToLower(grant), strings.ToLower(prefix)
			if pathContains(a, p) || strings.HasPrefix(a, p) {
				return nil, builtinGrantError(grant, prefix+"*")
			}
		}
	}
	return fc, nil
}

func builtinGrantError(grant, deny string) error {
	return fmt.Errorf("filesystem grant %q overlaps built-in credential deny %q; refusing to start: narrow filesystem.root, allow, or allow_rw", grant, deny)
}

func pathsIntersect(a, b string, fold bool) bool {
	if fold {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	return pathContains(a, b) || pathContains(b, a)
}

func pathContains(parent, path string) bool {
	return path == parent || strings.HasPrefix(path, strings.TrimRight(parent, string(os.PathSeparator))+string(os.PathSeparator))
}
