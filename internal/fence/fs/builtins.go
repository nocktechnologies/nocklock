package fs

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// ProcessEffectiveConfig merges mandatory credential denies with user policy.
// A grant overlapping a built-in deny is refused on both platforms, including
// when Linux kernel enforcement is disabled. User denies never replace defaults.
func ProcessEffectiveConfig(cfg *config.Config, goos string) (*FenceConfig, error) {
	if goos == "darwin" && cfg.Filesystem.ConfineHomeReads && cfg.Filesystem.Root == "" {
		return nil, fmt.Errorf("filesystem.confine_home_reads requires filesystem.root on macOS")
	}
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
		if cfg.Filesystem.ConfineHomeReads {
			account, err := user.LookupId(strconv.Itoa(os.Getuid()))
			if err != nil {
				return nil, fmt.Errorf("cannot resolve invoking UID's passwd home for macOS read confinement: %w", err)
			}
			if !filepath.IsAbs(account.HomeDir) {
				return nil, fmt.Errorf("invoking UID's passwd home is empty or not absolute; refusing macOS read confinement")
			}
			info, err := os.Stat(account.HomeDir)
			if err != nil {
				return nil, fmt.Errorf("cannot access invoking UID's passwd home for macOS read confinement: %v", err)
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("invoking UID's passwd home is not a directory: %q", account.HomeDir)
			}
			fc.HomeReadRoot, err = canonicalizeForProfile(account.HomeDir)
			if err != nil {
				return nil, fmt.Errorf("cannot canonicalize invoking UID's passwd home for macOS read confinement: %w", err)
			}
			// Existing mandatory denies may have been built from an environment
			// HOME. Keep those, and protect the actual passwd home as well.
			builtins = append(builtins, defaultSensitivePathsAt(fc.HomeReadRoot)...)
		}
		home, _ := os.UserHomeDir()
		if home != "" {
			home = filepath.Clean(home)
		}
		homes := []string{home}
		if fc.HomeReadRoot != "" && fc.HomeReadRoot != home {
			homes = append(homes, fc.HomeReadRoot)
		}
		agent := cfg.LoginStoreRuntime()
		for _, dir := range homes {
			fc.DenyPrefixes = append(fc.DenyPrefixes, filepath.Join(dir, ".env"))
			if agent != "claude-code" {
				fc.DenyPrefixes = append(fc.DenyPrefixes, filepath.Join(dir, ".claude"))
			}
			if agent != "codex" {
				builtins = append(builtins, filepath.Join(dir, ".codex"))
			}
		}
		// Existing symlink aliases must deny their targets too. Prefix rules still
		// cover names created later; they are not a one-time glob expansion.
		for _, dir := range homes {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, fmt.Errorf("cannot enumerate built-in credential aliases: %w", err)
			}
			for _, entry := range entries {
				for _, prefix := range fc.DenyPrefixes {
					if filepath.Dir(prefix) == dir && strings.HasPrefix(strings.ToLower(entry.Name()), strings.ToLower(filepath.Base(prefix))) {
						aliases = append(aliases, filepath.Join(dir, entry.Name()))
					}
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
	if goos == "darwin" && cfg.Filesystem.ConfineHomeReads {
		grants = append(grants, fc.ReadAllowPaths...)
	}
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
	err := fmt.Errorf("filesystem grant %q overlaps built-in credential deny %q; refusing to start: narrow filesystem.root, allow, allow_rw, or read_allow", grant, deny)
	if name := filepath.Base(deny); strings.HasPrefix(name, ".claude") || name == ".codex" {
		return fmt.Errorf("%w; an agent login store is exempt only with --profile <preset> or when wrap runs the agent command directly (claude or codex)", err)
	}
	return err
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
