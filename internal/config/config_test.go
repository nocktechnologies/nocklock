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

func TestLoadPartialConfigPreservesSecurityDefaults(t *testing.T) {
	tomlContent := `
[project]
name = "legacy-project"
root = "."

[network]
allow = ["github.com"]
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

	defaults := DefaultConfig()
	if !reflect.DeepEqual(cfg.Secrets.Pass, defaults.Secrets.Pass) {
		t.Fatalf("secrets.pass = %v, want default pass list %v", cfg.Secrets.Pass, defaults.Secrets.Pass)
	}
	if !reflect.DeepEqual(cfg.Secrets.Block, defaults.Secrets.Block) {
		t.Fatalf("secrets.block = %v, want default block list %v", cfg.Secrets.Block, defaults.Secrets.Block)
	}
	if cfg.Filesystem.Root != defaults.Filesystem.Root {
		t.Fatalf("filesystem.root = %q, want default %q", cfg.Filesystem.Root, defaults.Filesystem.Root)
	}
	if cfg.Filesystem.Mode != defaults.Filesystem.Mode {
		t.Fatalf("filesystem.mode = %q, want default %q", cfg.Filesystem.Mode, defaults.Filesystem.Mode)
	}
	if !reflect.DeepEqual(cfg.Filesystem.Deny, defaults.Filesystem.Deny) {
		t.Fatalf("filesystem.deny = %v, want default deny list %v", cfg.Filesystem.Deny, defaults.Filesystem.Deny)
	}
}

func TestLoadProfileCodex(t *testing.T) {
	cfg, err := LoadProfile("codex")
	if err != nil {
		t.Fatalf("LoadProfile(codex): %v", err)
	}
	if cfg.ProfileName != "codex" {
		t.Fatalf("ProfileName = %q, want codex", cfg.ProfileName)
	}
	if !containsString(cfg.Network.Allow, "api.openai.com") {
		t.Fatalf("codex profile should allow api.openai.com, got %v", cfg.Network.Allow)
	}
	if cfg.Network.AllowAll {
		t.Fatal("codex profile must stay default-deny for network")
	}
}

func TestLoadOverlayCanTightenButNotLoosenProfile(t *testing.T) {
	base, err := LoadProfile("codex")
	if err != nil {
		t.Fatalf("LoadProfile(codex): %v", err)
	}

	dir := t.TempDir()
	nockDir := filepath.Join(dir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	tomlContent := `
[network]
allow = ["api.openai.com", "example.com"]
allow_all = true
allow_private_ranges = true

[filesystem]
allow = ["/tmp/", "/"]
deny = ["~/work/private/"]
mode = "read-only"

[secrets]
pass = ["HOME", "OPENAI_API_KEY"]
block = ["NOCKLOCK_TEST_*"]

[syscall]
enforcement = "off"
allow_namespaces = true
socket_families = ["unix", "netlink"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadOverlay(*base, configPath)
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if cfg.ProfileName != "codex" {
		t.Fatalf("ProfileName = %q, want codex", cfg.ProfileName)
	}
	if !reflect.DeepEqual(cfg.Network.Allow, []string{"api.openai.com"}) {
		t.Fatalf("network.allow = %v, want only api.openai.com", cfg.Network.Allow)
	}
	if cfg.Network.AllowAll || cfg.Network.AllowPrivateRanges {
		t.Fatalf("network loosening survived: allow_all=%t private=%t", cfg.Network.AllowAll, cfg.Network.AllowPrivateRanges)
	}
	if !reflect.DeepEqual(cfg.Filesystem.Allow, []string{"/tmp/"}) {
		t.Fatalf("filesystem.allow = %v, want only /tmp/", cfg.Filesystem.Allow)
	}
	if !containsString(cfg.Filesystem.Deny, "~/work/private/") {
		t.Fatalf("filesystem.deny did not add overlay deny: %v", cfg.Filesystem.Deny)
	}
	if cfg.Filesystem.Mode != "read-only" {
		t.Fatalf("filesystem.mode = %q, want read-only", cfg.Filesystem.Mode)
	}
	if !reflect.DeepEqual(cfg.Secrets.Pass, []string{"HOME"}) {
		t.Fatalf("secrets.pass = %v, want only HOME", cfg.Secrets.Pass)
	}
	if !containsString(cfg.Secrets.Block, "NOCKLOCK_TEST_*") {
		t.Fatalf("secrets.block did not add overlay block: %v", cfg.Secrets.Block)
	}
	if cfg.Syscall.Enforcement != "required" || cfg.Syscall.AllowNamespaces {
		t.Fatalf("syscall loosening survived: %+v", cfg.Syscall)
	}
	if !reflect.DeepEqual(cfg.Syscall.SocketFamilies, []string{"unix"}) {
		t.Fatalf("syscall.socket_families = %v, want only unix", cfg.Syscall.SocketFamilies)
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
	if cfg.Filesystem.LinuxEnforcement != "required" {
		t.Errorf("expected default linux_enforcement 'required', got %q", cfg.Filesystem.LinuxEnforcement)
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
	if cfg.Filesystem.LinuxEnforcement != "required" {
		t.Errorf("expected default linux_enforcement 'required', got %q", cfg.Filesystem.LinuxEnforcement)
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

func TestDefaultSyscallConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Syscall.Enforcement != "required" {
		t.Errorf("default syscall.enforcement = %q, want required", cfg.Syscall.Enforcement)
	}
	if cfg.Syscall.AllowNamespaces {
		t.Error("default syscall.allow_namespaces should be false")
	}
	want := []string{"unix", "inet", "inet6"}
	if !reflect.DeepEqual(cfg.Syscall.SocketFamilies, want) {
		t.Errorf("default syscall.socket_families = %v, want %v", cfg.Syscall.SocketFamilies, want)
	}
}

func TestSyscallConfigParsesAndIsOptIn(t *testing.T) {
	// An explicit [syscall] block parses; an ABSENT one leaves the zero value
	// (which the wiring treats as "required" for fail-closed behavior — a minimal
	// config with no [syscall] block must not error).
	const minimal = `
[project]
name = "x"
[filesystem]
root = "."
`
	var cfg Config
	md, err := toml.Decode(minimal, &cfg)
	if err != nil {
		t.Fatalf("decode minimal config: %v", err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		t.Fatalf("unexpected undecoded keys: %v", undec)
	}
	if cfg.Syscall.Enforcement != "" {
		t.Errorf("absent [syscall] should leave Enforcement empty, got %q", cfg.Syscall.Enforcement)
	}
	if len(Validate(&cfg)) != 0 {
		t.Errorf("minimal config with no [syscall] should validate clean: %v", Validate(&cfg))
	}
}

func TestSyscallEnforcementValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Syscall.Enforcement = "bogus"
	errs := Validate(&cfg)
	found := false
	for _, e := range errs {
		if e.Field == "syscall.enforcement" && e.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a syscall.enforcement validation error, got %v", errs)
	}
}

func TestSyscallSocketFamilyValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Syscall.SocketFamilies = []string{"inet", "bogusfamily"}
	errs := Validate(&cfg)
	found := false
	for _, e := range errs {
		if e.Field == "syscall.socket_families" && e.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a syscall.socket_families validation error, got %v", errs)
	}
}
