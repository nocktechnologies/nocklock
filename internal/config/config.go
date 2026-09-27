// Package config handles TOML configuration parsing and defaults for NockLock.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// ResolveDBPath returns the absolute path to the event log database and the
// project root directory, given a config and the path it was loaded from.
//
// There are two outcomes, and which one applies depends on what is already on
// disk. NockLock never moves an audit chain to change the answer.
//
// LEGACY ROOT — a log already exists at <projectRoot>/.nock/<name>. That file
// stays exactly where it is and keeps being used. An existing audit chain is the
// one thing here that must not be touched by an upgrade: relocating it means
// moving a live SQLite database, its WAL sidecars and its chain anchor
// together, and a half-finished move produces a chain that verifies while
// missing its tail. The cost is that the fence cannot grant the project root for
// creates while the log sits inside it (see fs.FenceConfig.ProtectedRootSubdir),
// which wrap reports on stderr.
//
// NEW ROOT — no legacy log. The log lives in the project's audit state directory
// OUTSIDE the project (AuditStateDir), keeping only the configured filename.
// Nothing NockLock owns is then inside the fence root, which is what lets the
// root be granted so the agent can create and remove files in its own project.
//
// An ABSOLUTE logging.db is returned as written. Validate rejects one that
// points outside the project and its audit state directory, so the check
// happens at config load with a clear error rather than here.
//
// Note that projectRoot (the directory holding .nock/config.toml) and
// filesystem.root need not be the same directory. The choice above is keyed on
// projectRoot because that is what identifies the project; whether the root may
// be granted is decided separately, by asking whether the audit directory
// actually falls inside filesystem.root.
func ResolveDBPath(cfg *Config, configPath string) (dbPath string, projectRoot string, err error) {
	configured := cfg.Logging.DB
	if configured == "" {
		configured = DefaultConfig().Logging.DB
	}
	projectRoot = filepath.Dir(filepath.Dir(configPath))
	if filepath.IsAbs(configured) {
		return configured, projectRoot, nil
	}

	// Only the conventional <projectRoot>/.nock location counts as a legacy log.
	// The default logging.db is now the bare name "events.db", so treating the
	// configured relative path as a candidate would make <projectRoot>/events.db
	// -- plausibly a file the project owns -- look like NockLock's own state.
	legacyDB := filepath.Join(projectRoot, Dir, filepath.Base(configured))
	legacyExists := false
	if info, statErr := os.Lstat(legacyDB); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", projectRoot, fmt.Errorf("refusing to use the event log at %s: path is a symlink", legacyDB)
		}
		legacyExists = true
	}

	// Exactly one authoritative log per root. Two of them is an operator-visible
	// state, not a race, so name the way out instead of picking a side: choosing
	// silently would let a stale or tampered chain shadow the real one.
	//
	// The legacy branch computes the state path WITHOUT creating or validating
	// the directory: a project whose log stays in .nock never writes a byte
	// there, and hard-failing it over the trust checks on a directory it does
	// not use would refuse to run for no reason. Lstat resolves intermediate
	// symlinks itself, so an unresolved path still detects an existing log.
	if legacyExists {
		stateDB, dirErr := AuditStateDir(projectRoot)
		if dirErr == nil {
			stateDB = filepath.Join(stateDB, filepath.Base(configured))
			if _, statErr := os.Lstat(stateDB); statErr == nil {
				return "", projectRoot, fmt.Errorf(
					"two event logs found: %s (inside the project) and %s. "+
						"NockLock will not guess which audit chain is authoritative. "+
						"Verify each one, then move the one you are discarding aside "+
						"(its -wal/-shm sidecars and chain anchor travel with it)",
					legacyDB, stateDB)
			}
		}
		return legacyDB, projectRoot, nil
	}

	stateDir, err := EnsureAuditStateDir(projectRoot)
	if err != nil {
		return "", projectRoot, err
	}
	return filepath.Join(stateDir, filepath.Base(configured)), projectRoot, nil
}

// Config is the top-level NockLock configuration.
type Config struct {
	ProfileName string           `toml:"-"`
	Project     ProjectConfig    `toml:"project"`
	Filesystem  FilesystemConfig `toml:"filesystem"`
	Network     NetworkConfig    `toml:"network"`
	Secrets     SecretsConfig    `toml:"secrets"`
	Syscall     SyscallConfig    `toml:"syscall"`
	Logging     LoggingConfig    `toml:"logging"`
	Cloud       CloudConfig      `toml:"cloud"`
}

// ProjectConfig identifies the project being fenced.
type ProjectConfig struct {
	Name string `toml:"name"`
	Root string `toml:"root"`
}

// FilesystemConfig defines filesystem access boundaries.
type FilesystemConfig struct {
	Root             string   `toml:"root"`
	Mode             string   `toml:"mode"`
	LinuxEnforcement string   `toml:"linux_enforcement"`
	Allow            []string `toml:"allow"`
	AllowRW          []string `toml:"allow_rw"`
	Deny             []string `toml:"deny"`
	// MacOSAllowUnfenced is a temporary macOS-only escape hatch. When true,
	// wrap records a DEGRADED fence state and starts the child only if Seatbelt
	// cannot be applied. It is scheduled for removal in v0.6; false is the
	// secure, fail-closed default.
	MacOSAllowUnfenced bool `toml:"macos_allow_unfenced"`
	// Hardened opts in to the stricter macOS Seatbelt rules (deny
	// mach-priv-host-port, iokit-open, system-socket; tightened /dev). It is a
	// no-op on Linux. Absent/false = no behaviour change.
	Hardened bool `toml:"hardened"`
}

// SyscallConfig defines the syscall-surface fence (Linux seccomp-BPF). It is
// nil-safe: an absent [syscall] table leaves Enforcement empty, which defaults
// to "required" so Linux launches fail closed when seccomp-BPF is unavailable.
type SyscallConfig struct {
	// Enforcement is one of "required", "preferred", or "off". Empty defaults to
	// "required". On non-Linux platforms the syscall fence is always a no-op.
	Enforcement string `toml:"enforcement"`
	// AllowNamespaces, when true, leaves unshare/setns and namespace-creating
	// clone() flags permitted (the rest of the baseline still applies). Default
	// false denies namespace creation.
	AllowNamespaces bool `toml:"allow_namespaces"`
	// SocketFamilies is the allowlist of socket(2) address families the child may
	// create (e.g. "unix", "inet", "inet6"). Empty means no socket restriction.
	SocketFamilies []string `toml:"socket_families"`
	// ExtraDeny appends additional syscall NAMES to deny beyond the baseline.
	// Unknown names are skipped (forward-compat).
	ExtraDeny []string `toml:"extra_deny"`
}

// NetworkConfig defines network egress boundaries.
type NetworkConfig struct {
	Allow              []string `toml:"allow"`
	AllowAll           bool     `toml:"allow_all"`
	AllowPrivateRanges bool     `toml:"allow_private_ranges"`
}

// SecretsConfig defines environment filtering and optional secret preflight checks.
type SecretsConfig struct {
	Pass  []string `toml:"pass"`
	Block []string `toml:"block"`
	// ScanEnv checks values remaining after filtering before the child starts.
	ScanEnv bool `toml:"scan_env"`
	// ScanPaths selects project-relative files/directories for required preflight.
	ScanPaths []string `toml:"scan_paths"`
	// ScanEnvAllow exempts exact environment names from value scanning, never filtering.
	ScanEnvAllow []string `toml:"scan_env_allow"`
}

// LoggingConfig configures local event logging.
type LoggingConfig struct {
	DB    string `toml:"db"`
	Level string `toml:"level"`
}

// CloudConfig configures optional NockCC dashboard sync.
type CloudConfig struct {
	Enabled  bool   `toml:"enabled"`
	APIKey   string `toml:"api_key"`
	Endpoint string `toml:"endpoint"`
}

const (
	// Dir is the NockLock config directory name relative to the project root.
	Dir = ".nock"
	// File is the config file name within Dir.
	File = "config.toml"
)

// FindConfig walks up from the current working directory looking for a
// .nock/config.toml file and returns the first path it finds.
// Returns an error wrapping os.ErrNotExist if no config is found.
func FindConfig() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}
	for {
		candidate := filepath.Join(dir, Dir, File)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding config.
			return "", fmt.Errorf("no %s/%s found in %s or any parent directory: %w", Dir, File, dir, os.ErrNotExist)
		}
		dir = parent
	}
}

// Load reads and parses a TOML config file at the given path.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if err := loadInto(&cfg, path); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadOverlay reads a TOML config file over base, keeping only changes that do
// not widen the fence relative to base.
func LoadOverlay(base Config, path string) (*Config, error) {
	baseCopy := cloneConfig(base)
	overlay := cloneConfig(base)
	fields, err := overlayDefinedFields(path)
	if err != nil {
		return nil, err
	}
	md, err := loadIntoWithMetadata(&overlay, path)
	if err != nil {
		return nil, err
	}
	addMetadataFields(fields, md)
	cfg := restrictOverlay(baseCopy, overlay, fields)
	return &cfg, nil
}

func loadInto(cfg *Config, path string) error {
	_, err := loadIntoWithMetadata(cfg, path)
	return err
}

func loadIntoWithMetadata(cfg *Config, path string) (toml.MetaData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("failed to read config at %s: %w", path, err)
	}

	md, err := toml.Decode(string(data), cfg)
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return toml.MetaData{}, fmt.Errorf("unknown config keys at %s: %v", path, undecoded)
	}

	if errs := Validate(cfg); len(errs) > 0 {
		for _, e := range errs {
			if e.Severity == "error" {
				return toml.MetaData{}, fmt.Errorf("invalid config at %s: %s", path, e.Error())
			}
		}
	}
	if err := validateAuditDBLocation(cfg, path); err != nil {
		return toml.MetaData{}, fmt.Errorf("invalid config at %s: %w", path, err)
	}

	return md, nil
}

// validateAuditDBLocation rejects an absolute logging.db that points outside
// both the project and its audit state directory.
//
// logging.db comes from a file a repository can ship, so an unrestricted
// absolute path would let a hostile checkout aim a SQLite database at any path
// the invoking user can write. Something has always refused those paths; the
// point of doing it HERE is that the operator gets one clear error at config
// load naming the setting, instead of a failure from deep inside the event
// logger at the moment the fence starts.
//
// Relative paths need no check: they are resolved into the audit state
// directory or the project's own .nock, never anywhere else (ResolveDBPath).
func validateAuditDBLocation(cfg *Config, configPath string) error {
	db := strings.TrimSpace(cfg.Logging.DB)
	if db == "" || !filepath.IsAbs(db) {
		return nil
	}
	projectRoot := filepath.Dir(filepath.Dir(configPath))
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		// Fences fail closed: an unresolvable project root means the check
		// cannot be made, not that the path is fine.
		return fmt.Errorf("logging.db %q cannot be checked: the project root %q could not be resolved: %w", db, projectRoot, err)
	}
	if withinDir(absRoot, db) {
		return nil
	}
	stateDir, err := AuditStateDir(absRoot)
	if err == nil && withinDir(stateDir, db) {
		return nil
	}
	return fmt.Errorf(
		"logging.db %q is an absolute path outside both the project (%s) and NockLock's audit state directory. "+
			"Use a relative name such as \"events.db\" to keep the event log in the audit state directory, "+
			"which is where it belongs and where the fenced agent cannot reach it",
		db, absRoot)
}

// withinDir reports whether path is dir or lies beneath it, comparing at
// component boundaries so a sibling named like dir plus a suffix does not match.
func withinDir(dir, path string) bool {
	rel, err := filepath.Rel(resolveExisting(dir), resolveExisting(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// resolveExisting canonicalizes path by resolving symlinks in its deepest
// EXISTING ancestor and re-appending the components that do not exist yet.
//
// Resolving only whole existing paths is not enough, and getting this wrong is a
// macOS-only bug: /tmp, /var and the default TMPDIR are system symlinks into
// /private, so a project directory resolves to /private/var/... while a
// logging.db underneath it that has not been created yet does not resolve at
// all. Comparing one against the other then says the path is outside the project
// when it is plainly inside it.
func resolveExisting(path string) string {
	cleaned := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return resolved
	}
	tail := []string{filepath.Base(cleaned)}
	for dir := filepath.Dir(cleaned); ; {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			parts := append([]string{resolved}, reverseTail(tail)...)
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cleaned
		}
		tail = append(tail, filepath.Base(dir))
		dir = parent
	}
}

func reverseTail(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
