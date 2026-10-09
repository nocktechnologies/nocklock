package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

func TestLoadAuditForwardOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), Dir, File)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[audit.forward]\nenabled = true\nurl = \"https://cc.nocktechnologies.io\"\napi_key_env = \"NOCKLOCK_FORWARD_KEY\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Audit.Forward.Enabled || cfg.Audit.Forward.APIKeyEnv != "NOCKLOCK_FORWARD_KEY" {
		t.Fatalf("forward opt-in not loaded: %+v", cfg.Audit.Forward)
	}
}

func TestLoadOverlayCannotSelectAnotherOperatorCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), Dir, File)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	contents := "[audit.forward]\nenabled = true\nurl = \"https://cc.nocktechnologies.io\"\napi_key_env = \"AWS_SECRET_ACCESS_KEY\"\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(DefaultConfig(), path); err == nil || !strings.Contains(err.Error(), "audit.forward.api_key_env") {
		t.Fatalf("unsafe profile overlay accepted: %v", err)
	}
}

func TestParseConfig(t *testing.T) {
	tomlContent := `
[project]
name = "test-project"
root = "."

[filesystem]
allow = ["."]
allow_rw = ["~/.claude/"]
deny = ["~/.ssh/"]

[network]
allow = ["github.com"]
allow_all = false
require_enforced = true

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
	if !cfg.Network.RequireEnforced {
		t.Error("expected network.require_enforced to be true")
	}
	if len(cfg.Filesystem.Allow) != 1 || cfg.Filesystem.Allow[0] != "." {
		t.Errorf("unexpected filesystem allow: %v", cfg.Filesystem.Allow)
	}
	if len(cfg.Filesystem.AllowRW) != 1 || cfg.Filesystem.AllowRW[0] != "~/.claude/" {
		t.Errorf("unexpected filesystem allow_rw: %v", cfg.Filesystem.AllowRW)
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

func TestLoadProfileGoose(t *testing.T) {
	cfg, err := LoadProfile("goose")
	if err != nil {
		t.Fatalf("LoadProfile(goose): %v", err)
	}
	if cfg.ProfileName != "goose" {
		t.Fatalf("ProfileName = %q, want goose", cfg.ProfileName)
	}
	for _, host := range []string{"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "api.groq.com", "openrouter.ai"} {
		if !containsString(cfg.Network.Allow, host) {
			t.Fatalf("goose profile should allow %s, got %v", host, cfg.Network.Allow)
		}
	}
	if cfg.Network.AllowAll {
		t.Fatal("goose profile must stay default-deny for network")
	}
	if cfg.Network.AllowPrivateRanges {
		t.Fatal("goose profile must not allow private ranges")
	}
	for _, key := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOSE_PROVIDER", "GOOSE_MODEL", "GOOGLE_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "GOOSE_DISABLE_KEYRING"} {
		if !containsString(cfg.Secrets.Pass, key) {
			t.Fatalf("goose profile should pass %s, got %v", key, cfg.Secrets.Pass)
		}
	}
	if cfg.Filesystem.LinuxEnforcement != "required" {
		t.Fatalf("goose filesystem.linux_enforcement = %q, want required", cfg.Filesystem.LinuxEnforcement)
	}
	if cfg.Syscall.Enforcement != "required" {
		t.Fatalf("goose syscall.enforcement = %q, want required", cfg.Syscall.Enforcement)
	}
}

func TestLoadProfilesValidateEmbeddedPresets(t *testing.T) {
	wantNetwork := map[string][]string{
		"aider":       {"api.anthropic.com", "api.openai.com"},
		"claude-code": {"api.anthropic.com"},
		"codex":       {"api.openai.com"},
		"gemini-cli":  {"generativelanguage.googleapis.com"},
		"goose":       {"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "api.groq.com", "openrouter.ai"},
		"opencode":    {"opencode.ai"},
	}

	profiles := Profiles()
	if len(profiles) != len(wantNetwork) {
		t.Fatalf("Profiles returned %d entries, want %d: %v", len(profiles), len(wantNetwork), profiles)
	}

	for _, profile := range profiles {
		wantHosts, ok := wantNetwork[profile.Name]
		if !ok {
			t.Fatalf("unexpected profile %q", profile.Name)
		}
		cfg, err := LoadProfile(profile.Name)
		if err != nil {
			t.Fatalf("LoadProfile(%s): %v", profile.Name, err)
		}
		if cfg.ProfileName != profile.Name {
			t.Fatalf("%s ProfileName = %q", profile.Name, cfg.ProfileName)
		}
		if cfg.Network.AllowAll || cfg.Network.AllowPrivateRanges {
			t.Fatalf("%s profile widened network: allow_all=%t allow_private_ranges=%t", profile.Name, cfg.Network.AllowAll, cfg.Network.AllowPrivateRanges)
		}
		for _, wantHost := range wantHosts {
			if !containsString(cfg.Network.Allow, wantHost) {
				t.Fatalf("%s profile missing expected host %q: %v", profile.Name, wantHost, cfg.Network.Allow)
			}
		}
		if cfg.Filesystem.LinuxEnforcement != "required" {
			t.Fatalf("%s filesystem.linux_enforcement = %q, want required", profile.Name, cfg.Filesystem.LinuxEnforcement)
		}
		if cfg.Syscall.Enforcement != "required" {
			t.Fatalf("%s syscall.enforcement = %q, want required", profile.Name, cfg.Syscall.Enforcement)
		}
		// No preset may directory-grant the whole /proc or /dev tree: /proc exposes
		// every same-UID process's /proc/<pid>/cmdline (secrets on a command line)
		// and metadata; /dev exposes sibling pty slaves and /dev/shm. The device
		// nodes a child needs are granted individually by baselineDeviceNodes, and
		// no preset needs a whole-directory /proc grant (N10748 round 2). Compare on
		// the cleaned path so an unslashed "/proc" or "/dev" cannot slip past.
		for _, allow := range cfg.Filesystem.Allow {
			switch filepath.Clean(allow) {
			case "/proc", "/dev":
				t.Fatalf("%s profile filesystem.allow must not directory-grant %q (exposes same-UID /proc/<pid> and pty slaves); have %v", profile.Name, allow, cfg.Filesystem.Allow)
			}
		}
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
require_enforced = true

[filesystem]
allow = ["/tmp/", "/"]
allow_rw = ["/tmp/", "/"]
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
	if !cfg.Network.RequireEnforced {
		t.Fatal("network.require_enforced must be allowed to tighten the profile")
	}
	if !reflect.DeepEqual(cfg.Filesystem.Allow, []string{"/tmp/"}) {
		t.Fatalf("filesystem.allow = %v, want only /tmp/", cfg.Filesystem.Allow)
	}
	if len(cfg.Filesystem.AllowRW) != 0 {
		t.Fatalf("filesystem.allow_rw widened profile: %v", cfg.Filesystem.AllowRW)
	}
	if !containsString(cfg.Filesystem.Deny, "~/work/private/") {
		t.Fatalf("filesystem.deny did not add overlay deny: %v", cfg.Filesystem.Deny)
	}
	if cfg.Filesystem.Mode != "read-only" {
		t.Fatalf("filesystem.mode = %q, want read-only", cfg.Filesystem.Mode)
	}
	// Base codex pass now includes OPENAI_API_KEY (the runtime's own key), so an
	// overlay requesting [HOME, OPENAI_API_KEY] tightens to exactly those two.
	if !reflect.DeepEqual(cfg.Secrets.Pass, []string{"HOME", "OPENAI_API_KEY"}) {
		t.Fatalf("secrets.pass = %v, want [HOME OPENAI_API_KEY]", cfg.Secrets.Pass)
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

func TestOverlayCannotTurnOffRequireEnforced(t *testing.T) {
	base := DefaultConfig()
	base.Network.RequireEnforced = true
	overlay := DefaultConfig()
	overlay.Network.RequireEnforced = false
	cfg := restrictOverlay(base, overlay, map[string]bool{"network.require_enforced": true})
	if !cfg.Network.RequireEnforced {
		t.Fatal("overlay disabled network.require_enforced from the base profile")
	}
}

// TestOverlayDisjointInvertedListsFailClosed guards the fail-OPEN edge case where
// an overlay's pass / socket_families list is disjoint from the profile's: a naive
// intersection would be EMPTY, and empty has INVERTED semantics for these two
// fields (pass-everything / no-socket-restriction). The overlay must never loosen
// the fence that way — a disjoint overlay keeps the (restrictive) base.
func TestOverlayDisjointInvertedListsFailClosed(t *testing.T) {
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
	// Both lists are disjoint from the codex profile -> intersection is empty.
	tomlContent := `
[secrets]
pass = ["TOTALLY_UNRELATED_VAR"]

[syscall]
socket_families = ["netlink"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadOverlay(*base, configPath)
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	// pass must NOT collapse to empty (which would pass every non-blocked var).
	if len(cfg.Secrets.Pass) == 0 {
		t.Fatal("secrets.pass collapsed to empty (= pass-all): fence LOOSENED by a disjoint overlay")
	}
	if !reflect.DeepEqual(cfg.Secrets.Pass, base.Secrets.Pass) {
		t.Fatalf("secrets.pass = %v, want fail-closed to base %v", cfg.Secrets.Pass, base.Secrets.Pass)
	}
	// socket_families must NOT collapse to empty (which would lift all socket restriction).
	if len(cfg.Syscall.SocketFamilies) == 0 {
		t.Fatal("syscall.socket_families collapsed to empty (= no restriction): fence LOOSENED")
	}
	if !reflect.DeepEqual(cfg.Syscall.SocketFamilies, base.Syscall.SocketFamilies) {
		t.Fatalf("socket_families = %v, want fail-closed to base %v", cfg.Syscall.SocketFamilies, base.Syscall.SocketFamilies)
	}
	// The audit-log path must stay the profile's — an overlay cannot redirect it.
	if cfg.Logging.DB != base.Logging.DB {
		t.Fatalf("logging.db = %q, want profile path %q (audit redirect must be blocked)", cfg.Logging.DB, base.Logging.DB)
	}
}

// TestLoadRejectsAbsoluteAuditLogOutsideProject: logging.db comes from a file a
// repository can ship, so an absolute path aimed outside the project and the
// audit state directory would let a hostile checkout write a SQLite database
// anywhere the invoking user can. It is refused at config load, where the error
// can name the setting, rather than deep inside the event logger once the fence
// is already starting.
func TestLoadRejectsAbsoluteAuditLogOutsideProject(t *testing.T) {
	dir := t.TempDir()
	nockDir := filepath.Join(dir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	escape := filepath.Join(t.TempDir(), "attacker-controlled.db")
	if err := os.WriteFile(configPath, []byte("[logging]\ndb = \""+escape+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(configPath); err == nil {
		t.Fatal("expected an absolute logging.db outside the project to be rejected")
	} else if !strings.Contains(err.Error(), "logging.db") {
		t.Fatalf("expected an error naming logging.db, got: %v", err)
	}
}

// TestLoadAcceptsAbsoluteAuditLogInsideProject is the matching positive control:
// the restriction is about escaping the project, not about absolute paths.
func TestLoadAcceptsAbsoluteAuditLogInsideProject(t *testing.T) {
	dir := t.TempDir()
	nockDir := filepath.Join(dir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	inside := filepath.Join(dir, "audit", "events.db")
	if err := os.WriteFile(configPath, []byte("[logging]\ndb = \""+inside+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("an absolute logging.db inside the project should load: %v", err)
	}
	if cfg.Logging.DB != inside {
		t.Fatalf("logging.db = %q, want %q", cfg.Logging.DB, inside)
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
	if cfg.Network.RequireEnforced {
		t.Error("expected network.require_enforced to default false")
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
	if cfg.Filesystem.MacOSAllowUnfenced {
		t.Error("expected removed macos_allow_unfenced to default false")
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

func TestFindConfigPreservesSymlinkedConfigLeaf(t *testing.T) {
	root := t.TempDir()
	sharedConfig := filepath.Join(root, "shared-config.toml")
	if err := os.WriteFile(sharedConfig, []byte(DefaultTOML()), 0o644); err != nil {
		t.Fatal(err)
	}

	stateDirs := make([]string, 0, 2)
	for _, name := range []string{"project-a", "project-b"} {
		project := filepath.Join(root, name)
		configDir := filepath.Join(project, Dir)
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(sharedConfig, filepath.Join(configDir, File)); err != nil {
			t.Fatalf("create symlinked config for %s: %v", project, err)
		}
		t.Chdir(project)

		found, err := FindConfig()
		if err != nil {
			t.Fatalf("FindConfig from %s: %v", project, err)
		}
		resolvedProject, err := filepath.EvalSymlinks(project)
		if err != nil {
			t.Fatalf("resolve project %s: %v", project, err)
		}
		expected := filepath.Join(resolvedProject, Dir, File)
		if found != expected {
			t.Fatalf("FindConfig from %s returned %q, want project-local path %q", project, found, expected)
		}

		dbPath, _, err := ResolveDBPath(&Config{}, found)
		if err != nil {
			t.Fatalf("ResolveDBPath for %s: %v", project, err)
		}
		stateDirs = append(stateDirs, filepath.Dir(dbPath))
	}

	if stateDirs[0] == stateDirs[1] {
		t.Fatalf("ResolveDBPath returned one shared state directory: %q", stateDirs[0])
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

func TestDefaultConfigSystemPathsAreReadOnly(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Filesystem.AllowRW) != 0 {
		t.Fatalf("default must not grant writes outside root: %v", cfg.Filesystem.AllowRW)
	}
	for _, want := range []string{"/usr/", "/bin/", "/lib/", "/lib64/", "/etc/ld.so.cache", "/etc/ssl/certs/", "/etc/pki/tls/certs/", "/etc/pki/ca-trust/extracted/"} {
		if !slices.Contains(cfg.Filesystem.Allow, want) {
			t.Errorf("default filesystem.allow missing system read path %q", want)
		}
		if slices.Contains(cfg.Filesystem.AllowRW, want) {
			t.Errorf("system path %q must not be writable", want)
		}
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

const v05FilesystemTOML = `
[filesystem]
root = "."
mode = "read-write"
linux_enforcement = "required"
# TEMPORARY macOS v0.5 compatibility escape hatch.
macos_allow_unfenced = false
`

// A config written by `nocklock init` in v0.5 carries macos_allow_unfenced =
// false. The loader rejects unknown keys, so deleting the field would break
// every such config; this is the negative control for that trap.
func TestLoadV05ConfigWithMacOSAllowUnfencedFalse(t *testing.T) {
	path := writeTempConfig(t, v05FilesystemTOML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("v0.5 config with macos_allow_unfenced = false must still load: %v", err)
	}
	if cfg.Filesystem.MacOSAllowUnfenced {
		t.Fatal("macos_allow_unfenced = false loaded as true")
	}
}

func TestLoadRejectsMacOSAllowUnfencedTrue(t *testing.T) {
	toml := strings.Replace(v05FilesystemTOML, "macos_allow_unfenced = false", "macos_allow_unfenced = true", 1)
	path := writeTempConfig(t, toml)

	_, err := Load(path)
	if err == nil {
		t.Fatal("macos_allow_unfenced = true must fail to load")
	}
	for _, want := range []string{"macos_allow_unfenced was removed in v0.6.0", "always refuses to start unfenced on macOS", "restore sandbox-exec or remove the key"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}

	base := DefaultConfig()
	if _, err := LoadOverlay(base, path); err == nil {
		t.Fatal("overlay setting macos_allow_unfenced = true must fail to load")
	}
}

func TestDefaultTOMLOmitsMacOSAllowUnfenced(t *testing.T) {
	if strings.Contains(DefaultTOML(), "macos_allow_unfenced") {
		t.Fatal("DefaultTOML must not write the removed macos_allow_unfenced key")
	}
	path := writeTempConfig(t, DefaultTOML())
	if _, err := Load(path); err != nil {
		t.Fatalf("DefaultTOML must load: %v", err)
	}
}

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nocklock.toml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateMacOSAllowUnfencedTrueIsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.MacOSAllowUnfenced = true
	for _, e := range Validate(&cfg) {
		if e.Field == "filesystem.macos_allow_unfenced" && e.Severity == "error" {
			return
		}
	}
	t.Fatal("Validate must report filesystem.macos_allow_unfenced = true as an error")
}

func writeLookbackConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadParsesLookbackRules(t *testing.T) {
	path := writeLookbackConfig(t, `
[[network.lookback]]
name   = "probe-then-silence"
on     = "file_blocked"
within = "10m"
then   = "deny_egress"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []LookbackRule{{Name: "probe-then-silence", On: "file_blocked", Within: "10m", Then: "deny_egress"}}
	if !reflect.DeepEqual(cfg.Network.Lookback, want) {
		t.Fatalf("Lookback = %+v, want %+v", cfg.Network.Lookback, want)
	}
	if got := cfg.Network.Lookback[0].WithinDuration(); got != 10*time.Minute {
		t.Fatalf("WithinDuration = %v, want 10m", got)
	}

	if _, err := Load(writeLookbackConfig(t, "[[network.lookback]]\nname = \"x\"\non = \"config.digest\"\nthen = \"deny_egress\"\n")); err == nil {
		t.Fatal("Load accepted a rule whose trigger can never fire")
	}
}

func TestOverlayAddsLookbackRulesButNeverDropsOrDuplicatesBase(t *testing.T) {
	base := DefaultConfig()
	base.Network.Lookback = []LookbackRule{{Name: "base", On: "file_blocked", Within: "10m", Then: "deny_egress"}}

	// An overlay that names no rules keeps the base's, once.
	none, err := LoadOverlay(base, writeLookbackConfig(t, "[network]\nallow_all = false\n"))
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if !reflect.DeepEqual(none.Network.Lookback, base.Network.Lookback) {
		t.Fatalf("overlay without rules changed them: %+v", none.Network.Lookback)
	}

	// An overlay rule is added after the base's, and decoding it must not
	// write through into the base's rule.
	added, err := LoadOverlay(base, writeLookbackConfig(t, "[[network.lookback]]\nname = \"extra\"\non = \"file_blocked\"\nthen = \"deny_egress\"\n"))
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if len(added.Network.Lookback) != 2 || added.Network.Lookback[0].Name != "base" || added.Network.Lookback[0].Within != "10m" || added.Network.Lookback[1].Name != "extra" || added.Network.Lookback[1].Within != "" {
		t.Fatalf("merged rules = %+v, want base then extra with no inherited fields", added.Network.Lookback)
	}
	if base.Network.Lookback[0].Name != "base" || base.Network.Lookback[0].Within != "10m" {
		t.Fatalf("overlay modified the base's rule: %+v", base.Network.Lookback)
	}
}
