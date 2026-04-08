// Package fs implements filesystem fence configuration processing
// and rule serialization for NockLock.
package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// fieldSep is the Unit Separator character used to delimit fields in
// the serialized fence config passed to the LD_PRELOAD interposer.
const fieldSep = "\x1f"

// FenceConfig holds resolved, absolute filesystem fence paths ready
// for enforcement. All paths have been cleaned, expanded, and (for Root)
// symlink-resolved.
type FenceConfig struct {
	Root       string
	Mode       string
	AllowPaths []string
	DenyPaths  []string
}

// SerializedConfig is the parsed representation of a serialized fence
// rule string, as consumed by the interposer shared library.
type SerializedConfig struct {
	Root       string
	Mode       string // "rw" or "ro"
	SocketPath string
	AllowPaths []string
	DenyPaths  []string
}

// ExpandTilde replaces a leading ~ in path with the user's home directory.
// If path is exactly "~", the home directory is returned.
// If path starts with "~/", the ~ prefix is replaced.
// All other paths are returned unchanged.
func ExpandTilde(path string) (string, error) {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot expand ~: %w", err)
		}
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot expand ~: %w", err)
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// resolvePath expands tilde, converts to absolute, and cleans the path.
// If the path exists on disk, symlinks are resolved so that rules match
// the real paths used by the C interposer's realpath calls.
// The resolved path does not need to exist on disk.
func resolvePath(p string) (string, error) {
	expanded, err := ExpandTilde(p)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path %q: %w", p, err)
	}
	cleaned := filepath.Clean(abs)
	// Resolve symlinks if path exists — the C interposer uses realpath
	// so we must store the real path for rules to match.
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return resolved, nil
	}
	return cleaned, nil
}

// ProcessConfig validates and resolves a FilesystemConfig into a FenceConfig.
// If Root is empty, the fence is disabled and (nil, nil) is returned.
// Root must exist and be a directory; symlinks on Root are resolved.
// Allow and Deny paths are resolved but do not need to exist on disk.
// Mode defaults to "read-write" if empty; only "read-write" and "read-only"
// are valid.
func ProcessConfig(cfg config.FilesystemConfig) (*FenceConfig, error) {
	// Empty root disables the filesystem fence.
	if cfg.Root == "" {
		return nil, nil
	}

	// Validate mode.
	mode := cfg.Mode
	if mode == "" {
		mode = "read-write"
	}
	if mode != "read-write" && mode != "read-only" {
		return nil, fmt.Errorf("invalid filesystem mode %q: must be \"read-write\" or \"read-only\"", mode)
	}

	// Resolve root path.
	rootPath, err := resolvePath(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve root path: %w", err)
	}

	// Root must exist and be a directory.
	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("root path %q does not exist: %w", rootPath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root path %q is not a directory", rootPath)
	}

	// Resolve allow paths.
	allowPaths := make([]string, 0, len(cfg.Allow))
	for _, p := range cfg.Allow {
		resolved, err := resolvePath(p)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve allow path %q: %w", p, err)
		}
		allowPaths = append(allowPaths, resolved)
	}

	// Resolve deny paths.
	denyPaths := make([]string, 0, len(cfg.Deny))
	for _, p := range cfg.Deny {
		resolved, err := resolvePath(p)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve deny path %q: %w", p, err)
		}
		denyPaths = append(denyPaths, resolved)
	}

	// Validate that no resolved path contains the field separator character.
	if err := validateNoSeparator(rootPath, "root"); err != nil {
		return nil, err
	}
	for _, p := range allowPaths {
		if err := validateNoSeparator(p, "allow"); err != nil {
			return nil, err
		}
	}
	for _, p := range denyPaths {
		if err := validateNoSeparator(p, "deny"); err != nil {
			return nil, err
		}
	}

	return &FenceConfig{
		Root:       rootPath,
		Mode:       mode,
		AllowPaths: allowPaths,
		DenyPaths:  denyPaths,
	}, nil
}

// validateNoSeparator checks that a path does not contain the field separator
// character used in NOCKLOCK_FS_ALLOWED serialization.
func validateNoSeparator(path, label string) error {
	if strings.Contains(path, fieldSep) {
		return fmt.Errorf("%s path %q contains reserved separator character (\\x1f)", label, path)
	}
	return nil
}

// Serialize encodes the FenceConfig into a delimited string suitable for
// passing to the LD_PRELOAD interposer via an environment variable.
// The format uses the Unit Separator (\x1f) as delimiter:
//
//	root\x1fmode\x1fsocket\x1f+allow1\x1f+allow2\x1f-deny1\x1f-deny2
//
// Mode is abbreviated: "read-write" becomes "rw", "read-only" becomes "ro".
func (fc *FenceConfig) Serialize(socketPath string) string {
	modeShort := "rw"
	if fc.Mode == "read-only" {
		modeShort = "ro"
	}

	parts := []string{fc.Root, modeShort, socketPath}
	for _, p := range fc.AllowPaths {
		parts = append(parts, "+"+p)
	}
	for _, p := range fc.DenyPaths {
		parts = append(parts, "-"+p)
	}
	return strings.Join(parts, fieldSep)
}

// ParseSerialized decodes a serialized fence config string back into a
// SerializedConfig. Returns an error if fewer than 3 fields are present.
func ParseSerialized(s string) (*SerializedConfig, error) {
	fields := strings.Split(s, fieldSep)
	if len(fields) < 3 {
		return nil, fmt.Errorf("serialized config has %d fields, need at least 3 (root, mode, socket)", len(fields))
	}

	sc := &SerializedConfig{
		Root:       fields[0],
		Mode:       fields[1],
		SocketPath: fields[2],
	}

	for _, f := range fields[3:] {
		if strings.HasPrefix(f, "+") {
			sc.AllowPaths = append(sc.AllowPaths, f[1:])
		} else if strings.HasPrefix(f, "-") {
			sc.DenyPaths = append(sc.DenyPaths, f[1:])
		}
	}

	return sc, nil
}
