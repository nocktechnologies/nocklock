// Package config handles TOML configuration parsing and defaults for NockLock.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

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

// Load reads and parses a TOML config file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config at %s: %w", path, err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}

	return &cfg, nil
}
