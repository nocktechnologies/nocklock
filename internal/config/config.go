// Package config handles TOML configuration parsing and defaults for NockLock.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// ResolveDBPath returns the absolute path to the event log database
// and the project root directory, given a config and the path it was loaded from.
func ResolveDBPath(cfg *Config, configPath string) (dbPath string, projectRoot string) {
	dbPath = cfg.Logging.DB
	if dbPath == "" {
		dbPath = DefaultConfig().Logging.DB
	}
	projectRoot = filepath.Dir(filepath.Dir(configPath))
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(projectRoot, dbPath)
	}
	return dbPath, projectRoot
}

// Config is the top-level NockLock configuration.
type Config struct {
	Project    ProjectConfig    `toml:"project"`
	Filesystem FilesystemConfig `toml:"filesystem"`
	Network    NetworkConfig    `toml:"network"`
	Secrets    SecretsConfig    `toml:"secrets"`
	Syscall    SyscallConfig    `toml:"syscall"`
	Logging    LoggingConfig    `toml:"logging"`
	Cloud      CloudConfig      `toml:"cloud"`
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
	Deny             []string `toml:"deny"`
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

// SecretsConfig defines environment variable filtering rules.
type SecretsConfig struct {
	Pass  []string `toml:"pass"`
	Block []string `toml:"block"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config at %s: %w", path, err)
	}

	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown config keys at %s: %v", path, undecoded)
	}

	if errs := Validate(&cfg); len(errs) > 0 {
		for _, e := range errs {
			if e.Severity == "error" {
				return nil, fmt.Errorf("invalid config at %s: %s", path, e.Error())
			}
		}
	}

	return &cfg, nil
}
