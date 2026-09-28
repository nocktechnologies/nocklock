// Package fs implements filesystem fence configuration processing
// and rule serialization for NockLock.
package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// fieldSep is the Unit Separator character used to delimit fields in
// the serialized fence config passed to the LD_PRELOAD interposer.
const fieldSep = "\x1f"

// maxAllowPaths mirrors MAX_PATHS in the interposer's libfence_fs.c
// (internal/fence/fs/interposer/libfence_fs.c; kept in sync by
// TestMaxAllowPathsMatchesInterposerMaxPaths). Past this count in EITHER the
// allow or the deny category, the interposer fails closed (denies every
// path) rather than silently dropping entries.
const maxAllowPaths = 256

// interposerMaxPathFields mirrors "char *fields[MAX_PATHS + 4]" in
// libfence_fs.c: the total slots for the 3 metadata fields (root, mode,
// socket) PLUS every "+allow"/"-deny" field combined, allow and deny sharing
// one budget. Past this many total fields, the interposer's tokenizer stops
// splitting the string and silently drops the remainder — including any
// deny paths that land in the dropped tail, which never reach deny_count's
// own "too many, fail closed" check because that check never sees them.
// CheckInterposerBudget must never let a config reach that combined budget.
const interposerMaxPathFields = maxAllowPaths + 4
const interposerMetadataFields = 3

// selfProcFiles are the specific, read-only /proc/<pid> entries the fence
// grants a wrapped process for its own runtime introspection (e.g. Node's
// process.memoryUsage(), which reads /proc/self/stat). Only these files are
// ever granted — never the /proc/<pid> directory itself, which would also
// expose environ, cmdline, mem, maps and fd to the wrapped process AND to any
// descendant that inherits the Landlock rule. (Verified empirically: Node
// startup also touches /proc/self/exe, maps and cgroup, but tolerates each
// failing to open — it falls back to argv[0] for process.execPath and
// otherwise degrades silently — so none of those need a grant.)
//
// Both the Landlock ruleset (landlockProcSelfAllowPaths in
// internal/cli/wrap.go) and the userspace interposer's allow-list injection
// (allowSelfProcFS in internal/cli/landlock_exec.go) grant exactly this list
// and must stay in sync, so this is the single source of truth for both —
// call SelfProcFiles() rather than duplicating the list.
var selfProcFiles = []string{"stat", "status", "statm"}

// SelfProcFiles returns a copy of the curated /proc/<pid> file list (see
// selfProcFiles); callers get their own slice so they cannot mutate the
// shared source of truth.
func SelfProcFiles() []string {
	return append([]string(nil), selfProcFiles...)
}

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

// resolvePath expands tilde, converts to absolute, and cleans the path. Symlinks
// are resolved so rules match the real paths used by the C interposer's realpath
// calls. For not-yet-existing paths, the deepest existing ancestor is resolved
// and the missing tail is re-appended; this prevents a symlinked parent from
// being swapped after config load to point outside the intended ruleset.
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
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("cannot resolve path %q: %w", p, err)
	}
	tail := []string{filepath.Base(cleaned)}
	for dir := filepath.Dir(cleaned); ; {
		resolved, err := filepath.EvalSymlinks(dir)
		if err == nil {
			parts := append([]string{resolved}, reversePathTail(tail)...)
			return filepath.Join(parts...), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("cannot resolve path ancestor %q for %q: %w", dir, p, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("cannot resolve any existing ancestor for path %q", p)
		}
		tail = append(tail, filepath.Base(dir))
		dir = parent
	}
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

// CheckInterposerBudget validates that fc's allow and deny paths fit within the
// C interposer's field budget (libfence_fs.c MAX_PATHS / fields[] array).
// selfProcReserve is the number of additional allow entries that will be injected
// after config load (the /proc/<pid> self-proc grants from allowSelfProcFS in
// landlock_exec.go). Pass len(SelfProcFiles()) when the __landlock-exec shim
// will engage; pass 0 when it will not (pure userspace-only fence).
//
// This check is deliberately separate from ProcessConfig: ProcessConfig runs
// before wrap.go knows whether the shim will actually engage (that depends on a
// runtime landlock.DetectABI() probe and the syscall fence config, both resolved
// later). Callers in wrap.go invoke this once the shim-engagement decision is
// final.
func CheckInterposerBudget(fc *FenceConfig, selfProcReserve int) error {
	if fc == nil {
		return nil
	}
	if room := maxAllowPaths - selfProcReserve; len(fc.AllowPaths) > room {
		return fmt.Errorf(
			"too many filesystem allow paths (%d): the fence interposer supports at most %d, "+
				"and %d are reserved for the wrapped process's own /proc/<pid> grants (see "+
				"SelfProcFiles); remove entries from [filesystem].allow", len(fc.AllowPaths), maxAllowPaths, selfProcReserve)
	}
	if len(fc.DenyPaths) > maxAllowPaths {
		return fmt.Errorf(
			"too many filesystem deny paths (%d): the fence interposer supports at most %d per category; "+
				"remove entries from [filesystem].deny", len(fc.DenyPaths), maxAllowPaths)
	}
	room := interposerMaxPathFields - interposerMetadataFields - selfProcReserve
	if combined := len(fc.AllowPaths) + len(fc.DenyPaths); combined > room {
		return fmt.Errorf(
			"too many combined filesystem allow (%d) and deny (%d) paths: the fence interposer's "+
				"wire format supports at most %d combined, and %d are reserved for the wrapped "+
				"process's own /proc/<pid> grants (see SelfProcFiles); remove entries from "+
				"[filesystem].allow or [filesystem].deny",
			len(fc.AllowPaths), len(fc.DenyPaths), room+selfProcReserve, selfProcReserve)
	}
	return nil
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

// AppendSerializedAllow returns serialized (a NOCKLOCK_FS_ALLOWED value from
// Serialize) with one extra read-allow path appended in the interposer's wire
// format (fieldSep + "+" + path), keeping the separator framing private to this
// package. Callers use it to add a path known only after config load — see the
// Landlock shim's allowSelfProcFS.
//
// Fails closed on a malformed path: a path containing the reserved separator
// could inject extra allow/deny fields into the policy, so it is refused and
// serialized is returned UNCHANGED (the grant is dropped, never smuggled in) —
// the same invariant ProcessConfig enforces with validateNoSeparator.
func AppendSerializedAllow(serialized, path string) string {
	if strings.Contains(path, fieldSep) {
		return serialized
	}
	return serialized + fieldSep + "+" + path
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

func reversePathTail(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
