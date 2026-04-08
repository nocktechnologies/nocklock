package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
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

func TestConfigInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("not [valid toml !!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
	if cfg != nil {
		t.Error("expected nil config on parse error")
	}
}

func TestFindConfigWalksUp(t *testing.T) {
	root := t.TempDir()
	nockDir := filepath.Join(root, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(DefaultTOML()), 0o644); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(root, "src", "deep", "nested")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(subDir); err != nil {
		t.Fatal(err)
	}

	found, err := FindConfig()
	if err != nil {
		t.Fatalf("FindConfig should find config from subdirectory, got: %v", err)
	}
	// Resolve symlinks for comparison (macOS /var → /private/var).
	resolvedFound, _ := filepath.EvalSymlinks(found)
	resolvedExpected, _ := filepath.EvalSymlinks(configPath)
	if resolvedFound != resolvedExpected {
		t.Errorf("FindConfig returned %q, expected %q", found, configPath)
	}
}

func TestFindConfigNotFound(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	_, err := FindConfig()
	if err == nil {
		t.Fatal("expected error when no config exists")
	}
}

func TestParseConfigWithFilesystemRootAndMode(t *testing.T) {
	tomlContent := `
[project]
name = "test-project"
root = "."

[filesystem]
root = "/home/agent/project"
mode = "read-write"
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

	if cfg.Filesystem.Root != "/home/agent/project" {
		t.Errorf("expected filesystem root '/home/agent/project', got %q", cfg.Filesystem.Root)
	}
	if cfg.Filesystem.Mode != "read-write" {
		t.Errorf("expected filesystem mode 'read-write', got %q", cfg.Filesystem.Mode)
	}
}

func TestDefaultConfigFilesystemRootAndMode(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Filesystem.Root != "." {
		t.Errorf("expected default filesystem root '.', got %q", cfg.Filesystem.Root)
	}
	if cfg.Filesystem.Mode != "read-write" {
		t.Errorf("expected default filesystem mode 'read-write', got %q", cfg.Filesystem.Mode)
	}
}

func TestDefaultTOMLMatchesDefaultConfig(t *testing.T) {
	var parsed Config
	if err := toml.Unmarshal([]byte(DefaultTOML()), &parsed); err != nil {
		t.Fatalf("DefaultTOML is invalid TOML: %v", err)
	}
	expected := DefaultConfig()
	if !reflect.DeepEqual(parsed, expected) {
		t.Error("DefaultTOML() does not produce the same config as DefaultConfig()")
	}
}
