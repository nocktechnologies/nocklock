package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
)

func TestExpandTilde_HomePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot determine home dir: %v", err)
	}
	got, err := ExpandTilde("~/.ssh")
	if err != nil {
		t.Fatalf("ExpandTilde(~/.ssh) error: %v", err)
	}
	want := filepath.Join(home, ".ssh")
	if got != want {
		t.Errorf("ExpandTilde(~/.ssh) = %q, want %q", got, want)
	}
}

func TestExpandTilde_AbsolutePath(t *testing.T) {
	got, err := ExpandTilde("/usr/lib")
	if err != nil {
		t.Fatalf("ExpandTilde(/usr/lib) error: %v", err)
	}
	if got != "/usr/lib" {
		t.Errorf("ExpandTilde(/usr/lib) = %q, want /usr/lib", got)
	}
}

func TestExpandTilde_TildeOnly(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot determine home dir: %v", err)
	}
	got, err := ExpandTilde("~")
	if err != nil {
		t.Fatalf("ExpandTilde(~) error: %v", err)
	}
	if got != home {
		t.Errorf("ExpandTilde(~) = %q, want %q", got, home)
	}
}

func TestProcessConfig_Valid(t *testing.T) {
	// Create a temp dir to use as root.
	root := t.TempDir()

	cfg := config.FilesystemConfig{
		Root:  root,
		Mode:  "read-write",
		Allow: []string{root},
		Deny:  []string{"~/.aws"},
	}

	fc, err := ProcessConfig(cfg)
	if err != nil {
		t.Fatalf("ProcessConfig error: %v", err)
	}
	if fc == nil {
		t.Fatal("ProcessConfig returned nil for valid config")
	}

	// Root should be resolved (absolute, cleaned, symlinks resolved).
	resolved, _ := filepath.EvalSymlinks(root)
	if fc.Root != resolved {
		t.Errorf("Root = %q, want %q", fc.Root, resolved)
	}

	if fc.Mode != "read-write" {
		t.Errorf("Mode = %q, want read-write", fc.Mode)
	}

	if len(fc.AllowPaths) != 1 {
		t.Fatalf("expected 1 allow path, got %d", len(fc.AllowPaths))
	}

	if len(fc.DenyPaths) != 1 {
		t.Fatalf("expected 1 deny path, got %d", len(fc.DenyPaths))
	}

	// Deny path should have tilde expanded.
	home, _ := os.UserHomeDir()
	wantDeny := filepath.Clean(filepath.Join(home, ".aws"))
	if fc.DenyPaths[0] != wantDeny {
		t.Errorf("DenyPaths[0] = %q, want %q", fc.DenyPaths[0], wantDeny)
	}
}

func TestProcessConfig_InvalidMode(t *testing.T) {
	root := t.TempDir()
	cfg := config.FilesystemConfig{
		Root: root,
		Mode: "execute",
	}
	_, err := ProcessConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid mode 'execute'")
	}
	if !strings.Contains(err.Error(), "execute") {
		t.Errorf("error should mention invalid mode, got: %v", err)
	}
}

func TestProcessConfig_MissingRoot(t *testing.T) {
	cfg := config.FilesystemConfig{
		Root: "/nonexistent/path/that/does/not/exist",
		Mode: "read-write",
	}
	_, err := ProcessConfig(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent root")
	}
}

func TestProcessConfig_EmptyRootDisablesFence(t *testing.T) {
	cfg := config.FilesystemConfig{
		Root: "",
		Mode: "read-write",
	}
	fc, err := ProcessConfig(cfg)
	if err != nil {
		t.Fatalf("expected no error for empty root, got: %v", err)
	}
	if fc != nil {
		t.Errorf("expected nil FenceConfig for empty root, got %+v", fc)
	}
}

func TestProcessConfig_DefaultMode(t *testing.T) {
	root := t.TempDir()
	cfg := config.FilesystemConfig{
		Root: root,
		Mode: "",
	}
	fc, err := ProcessConfig(cfg)
	if err != nil {
		t.Fatalf("ProcessConfig error: %v", err)
	}
	if fc.Mode != "read-write" {
		t.Errorf("expected default mode 'read-write', got %q", fc.Mode)
	}
}

func TestProcessConfig_SymlinkedRoot(t *testing.T) {
	// Create a real directory.
	realDir := t.TempDir()

	// Create a symlink to it.
	parent := t.TempDir()
	linkPath := filepath.Join(parent, "linked-root")
	if err := os.Symlink(realDir, linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	fsCfg := config.FilesystemConfig{
		Root: linkPath,
		Mode: "read-write",
	}

	fc, err := ProcessConfig(fsCfg)
	if err != nil {
		t.Fatalf("ProcessConfig failed: %v", err)
	}

	// Root should be resolved to the real path, not the symlink.
	if fc.Root == linkPath {
		t.Errorf("Root should be resolved through symlink, got symlink path %q", fc.Root)
	}
	// Resolve realDir too, since on macOS /var -> /private/var.
	resolvedReal, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("failed to resolve real dir: %v", err)
	}
	if fc.Root != resolvedReal {
		t.Errorf("Root = %q, want real path %q", fc.Root, resolvedReal)
	}
}

// --- Task 3: Rule Serialization Tests ---

func TestSerialize_RoundTrip(t *testing.T) {
	fc := &FenceConfig{
		Root:       "/home/user/project",
		Mode:       "read-write",
		AllowPaths: []string{"/tmp", "/home/user/.claude"},
		DenyPaths:  []string{"/home/user/.ssh", "/home/user/.aws"},
	}

	serialized := fc.Serialize("/tmp/nock.sock")

	parsed, err := ParseSerialized(serialized)
	if err != nil {
		t.Fatalf("ParseSerialized error: %v", err)
	}

	if parsed.Root != fc.Root {
		t.Errorf("Root = %q, want %q", parsed.Root, fc.Root)
	}
	if parsed.Mode != "rw" {
		t.Errorf("Mode = %q, want 'rw'", parsed.Mode)
	}
	if parsed.SocketPath != "/tmp/nock.sock" {
		t.Errorf("SocketPath = %q, want /tmp/nock.sock", parsed.SocketPath)
	}
	if len(parsed.AllowPaths) != 2 {
		t.Fatalf("expected 2 allow paths, got %d", len(parsed.AllowPaths))
	}
	if parsed.AllowPaths[0] != "/tmp" || parsed.AllowPaths[1] != "/home/user/.claude" {
		t.Errorf("AllowPaths = %v, want [/tmp /home/user/.claude]", parsed.AllowPaths)
	}
	if len(parsed.DenyPaths) != 2 {
		t.Fatalf("expected 2 deny paths, got %d", len(parsed.DenyPaths))
	}
	if parsed.DenyPaths[0] != "/home/user/.ssh" || parsed.DenyPaths[1] != "/home/user/.aws" {
		t.Errorf("DenyPaths = %v, want [/home/user/.ssh /home/user/.aws]", parsed.DenyPaths)
	}
}

func TestSerialize_ReadOnlyMode(t *testing.T) {
	fc := &FenceConfig{
		Root:       "/home/user/project",
		Mode:       "read-only",
		AllowPaths: []string{"/tmp"},
		DenyPaths:  []string{"/home/user/.ssh"},
	}

	serialized := fc.Serialize("/tmp/nock.sock")
	parsed, err := ParseSerialized(serialized)
	if err != nil {
		t.Fatalf("ParseSerialized error: %v", err)
	}
	if parsed.Mode != "ro" {
		t.Errorf("Mode = %q, want 'ro'", parsed.Mode)
	}
}

func TestParseSerialized_TooFewFields(t *testing.T) {
	// Only 2 fields, need at least 3.
	_, err := ParseSerialized("root" + fieldSep + "rw")
	if err == nil {
		t.Fatal("expected error for fewer than 3 fields")
	}
}
