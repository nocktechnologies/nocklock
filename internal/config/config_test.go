package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfig(t *testing.T) {
	tomlContent := `
[project]
name = "test-project"
root = "."

[filesystem]
allow = ["."]
deny = ["~/.ssh/"]

[network]
allow = ["github.com"]
allow_all = false

[secrets]
pass = ["HOME"]
block = ["AWS_*"]

[logging]
db = ".nock/events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
`
	dir := t.TempDir()
	nockDir := filepath.Join(dir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Project.Name != "test-project" {
		t.Errorf("expected project name 'test-project', got %q", cfg.Project.Name)
	}
	if cfg.Network.AllowAll != false {
		t.Error("expected allow_all to be false")
	}
	if len(cfg.Filesystem.Allow) != 1 || cfg.Filesystem.Allow[0] != "." {
		t.Errorf("unexpected filesystem allow: %v", cfg.Filesystem.Allow)
	}
	if len(cfg.Secrets.Block) != 1 || cfg.Secrets.Block[0] != "AWS_*" {
		t.Errorf("unexpected secrets block: %v", cfg.Secrets.Block)
	}
	if cfg.Cloud.Endpoint != "https://cc.nocktechnologies.io/api/fence/events/" {
		t.Errorf("unexpected cloud endpoint: %q", cfg.Cloud.Endpoint)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Project.Root != "." {
		t.Errorf("expected default root '.', got %q", cfg.Project.Root)
	}
	if cfg.Network.AllowAll != false {
		t.Error("expected default allow_all to be false")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected default log level 'info', got %q", cfg.Logging.Level)
	}
	if cfg.Cloud.Enabled != false {
		t.Error("expected cloud to be disabled by default")
	}

	// Verify sensitive dirs are denied by default
	found := false
	for _, d := range cfg.Filesystem.Deny {
		if d == "~/.ssh/" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ~/.ssh/ in default deny list")
	}

	// Verify secret patterns are blocked by default
	found = false
	for _, b := range cfg.Secrets.Block {
		if b == "AWS_*" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected AWS_* in default block list")
	}
}

func TestConfigNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing config, got nil")
	}
}
