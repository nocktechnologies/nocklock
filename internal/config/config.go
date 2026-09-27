// Package config handles TOML configuration parsing and defaults for NockLock.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// ResolveDBPath returns the absolute path to the event log database and the
// project root directory, given a config and the path it was loaded from.
//
// A RELATIVE logging.db resolves into the project's audit state directory
// OUTSIDE the project (AuditStateDir), keeping only its filename — NOT against
// the project root. An event log inside the fence root cannot be protected from
// the fenced child once the root itself is granted, and the root must be granted
// for the child to create and remove entries in its own project; AuditStateDir
// explains why Landlock offers no third option. Relative is the default and
// covers every config nocklock init writes, so ordinary projects relocate with
// no config change.
//
// An ABSOLUTE logging.db is returned exactly as written, and is the one way to
// override the location. It is not a free-form escape hatch: the event logger
// independently refuses a database that resolves outside both the project and
// its audit state directory (logging.validatePath), so an absolute path is
// useful mainly for pinning the log inside the project — which re-exposes it to
// the fenced child, and which 'nocklock doctor' warns about. That containment
// rule predates this function and is deliberately not relaxed here: logging.db
// comes from a file a repository can ship, so widening it would let a hostile
// checkout aim a SQLite write at any path the user can touch.
//
// A log left inside a project by an older NockLock is moved into the state
// directory on first use (migrateLegacyAuditState), so an existing audit chain
// keeps verifying across the upgrade.
//
// Note that projectRoot (the directory holding .nock/config.toml) and
// filesystem.root need not be the same directory. The relocation is keyed on
// projectRoot because that is what identifies the project; when filesystem.root
// points somewhere else, the state directory is outside both, which is the
// property that matters.
func ResolveDBPath(cfg *Config, configPath string) (dbPath string, projectRoot string, err error) {
	configured := cfg.Logging.DB
	if configured == "" {
		configured = DefaultConfig().Logging.DB
	}
	projectRoot = filepath.Dir(filepath.Dir(configPath))
	if filepath.IsAbs(configured) {
		return configured, projectRoot, nil
	}

	stateDir, err := EnsureAuditStateDir(projectRoot)
	if err != nil {
		return "", projectRoot, err
	}
	dbPath = filepath.Join(stateDir, filepath.Base(configured))

	// Migrate ONLY from the conventional <root>/.nock location. Every config
	// NockLock has ever written put the log there, and restricting the search to
	// that directory is what stops migration from swallowing an unrelated
	// project file: the default logging.db is now the bare name "events.db", so
	// honoring the configured relative path here would make <root>/events.db --
	// plausibly a file the project owns -- a migration candidate and move it out
	// of the repository. A log kept somewhere else by hand stays where it is.
	legacyDB := filepath.Join(projectRoot, Dir, filepath.Base(configured))
	if err := migrateLegacyAuditState(dbPath, legacyDB); err != nil {
		return "", projectRoot, err
	}
	return dbPath, projectRoot, nil
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

	return md, nil
}
