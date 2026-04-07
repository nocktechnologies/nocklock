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
	Allow []string `toml:"allow"`
	Deny  []string `toml:"deny"`
}

// NetworkConfig defines network egress boundaries.
type NetworkConfig struct {
	Allow    []string `toml:"allow"`
	AllowAll bool     `toml:"allow_all"`
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

	return &cfg, nil
}
