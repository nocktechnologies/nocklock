package fs

import (
	"fmt"
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

// paths returns n distinct, resolvable paths under root for cap-boundary
// tests: ProcessConfig resolves every allow/deny entry, so each needs to be a
// real, distinguishable filesystem path rather than an arbitrary string.
func paths(root string, n int, prefix string) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = filepath.Join(root, fmt.Sprintf("%s%d", prefix, i))
	}
	return out
}

// TestCheckInterposerBudget_AllowPathCapWithShim is the boundary test for
// #10757's thread 2: the interposer's libfence_fs.c fails closed (denies
// everything) once its allow_count ALONE reaches MAX_PATHS (256), and the
// __landlock-exec shim injects one allow entry per SelfProcFiles() AFTER
// config load (see allowSelfProcFS in internal/cli/landlock_exec.go). A user
// config with exactly 256 allow paths used to trip the interposer's cap at
// runtime once the self-proc entries were appended — a silent full deny-all.
// CheckInterposerBudget must reject at wrap time when the shim engages.
func TestCheckInterposerBudget_AllowPathCapWithShim(t *testing.T) {
	reserve := len(SelfProcFiles())
	room := maxAllowPaths - reserve

	fc := &FenceConfig{Root: "/root", Mode: "read-write", AllowPaths: fakePaths(room)}
	if err := CheckInterposerBudget(fc, reserve); err != nil {
		t.Fatalf("CheckInterposerBudget with %d allow paths (exactly the reserved cap) should succeed: %v", room, err)
	}

	fc.AllowPaths = fakePaths(room + 1)
	if err := CheckInterposerBudget(fc, reserve); err == nil {
		t.Fatalf("CheckInterposerBudget with %d allow paths (one past the reserved cap) should fail closed with a config error", room+1)
	}
}

// TestCheckInterposerBudget_CombinedCapWithShim proves the cap covers allow
// and deny TOGETHER. libfence_fs.c's wire-format tokenizer shares ONE field
// budget between both categories; past that budget it silently drops the tail.
func TestCheckInterposerBudget_CombinedCapWithShim(t *testing.T) {
	reserve := len(SelfProcFiles())
	room := interposerMaxPathFields - interposerMetadataFields - reserve

	fc := &FenceConfig{
		Root:       "/root",
		Mode:       "read-write",
		AllowPaths: fakePaths(room - 2),
		DenyPaths:  fakePaths(2),
	}
	if err := CheckInterposerBudget(fc, reserve); err != nil {
		t.Fatalf("CheckInterposerBudget with %d allow + %d deny (exactly the combined cap) should succeed: %v",
			len(fc.AllowPaths), len(fc.DenyPaths), err)
	}

	fc.DenyPaths = fakePaths(3)
	if err := CheckInterposerBudget(fc, reserve); err == nil {
		t.Fatalf("CheckInterposerBudget with %d allow + %d deny (one past the combined cap) should fail closed, "+
			"even though neither list alone reaches maxAllowPaths", len(fc.AllowPaths), len(fc.DenyPaths))
	}
}

// TestCheckInterposerBudget_UserspaceOnly verifies the acceptance criterion
// for N10815: when the __landlock-exec shim does NOT engage (pure userspace
// interposer), no headroom is reserved and the user gets the full interposer
// budget (up to maxAllowPaths = 256 combined allow+deny paths).
func TestCheckInterposerBudget_UserspaceOnly(t *testing.T) {
	fc := &FenceConfig{
		Root:       "/root",
		Mode:       "read-write",
		AllowPaths: fakePaths(maxAllowPaths),
	}
	if err := CheckInterposerBudget(fc, 0); err != nil {
		t.Fatalf("userspace-only fence with %d allow paths (the full interposer budget) must succeed: %v", maxAllowPaths, err)
	}

	fc.AllowPaths = fakePaths(maxAllowPaths + 1)
	if err := CheckInterposerBudget(fc, 0); err == nil {
		t.Fatalf("userspace-only fence with %d allow paths (one past the interposer budget) must still fail closed", maxAllowPaths+1)
	}

	combined := interposerMaxPathFields - interposerMetadataFields
	fc = &FenceConfig{
		Root:       "/root",
		Mode:       "read-write",
		AllowPaths: fakePaths(combined - 2),
		DenyPaths:  fakePaths(2),
	}
	if err := CheckInterposerBudget(fc, 0); err != nil {
		t.Fatalf("userspace-only fence with %d combined paths (exactly the combined budget) must succeed: %v", combined, err)
	}

	fc.DenyPaths = fakePaths(3)
	if err := CheckInterposerBudget(fc, 0); err == nil {
		t.Fatalf("userspace-only fence with %d combined paths (one past the combined budget) must still fail closed", combined+1)
	}
}

// TestCheckInterposerBudget_NilConfig verifies no panic on a nil FenceConfig.
func TestCheckInterposerBudget_NilConfig(t *testing.T) {
	if err := CheckInterposerBudget(nil, 3); err != nil {
		t.Fatalf("nil FenceConfig should not error: %v", err)
	}
}

// fakePaths returns n synthetic paths for budget tests. These are not real
// filesystem paths — CheckInterposerBudget operates on already-resolved
// FenceConfig, so no resolution is needed.
func fakePaths(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("/p/%d", i)
	}
	return out
}

// TestProcessConfig_NoCapOnConfig verifies that ProcessConfig itself no longer
// rejects high-path-count configs (the budget check moved to
// CheckInterposerBudget, called post-ABI-detection in wrap.go).
func TestProcessConfig_NoCapOnConfig(t *testing.T) {
	root := t.TempDir()
	cfg := config.FilesystemConfig{Root: root, Allow: paths(root, maxAllowPaths, "f")}
	if _, err := ProcessConfig(cfg); err != nil {
		t.Fatalf("ProcessConfig must not reject %d allow paths (budget is checked later): %v", maxAllowPaths, err)
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

func TestProcessConfig_NonexistentAllowPathResolvesSymlinkedAncestor(t *testing.T) {
	base := t.TempDir()
	realAllow := filepath.Join(base, "real-allow")
	if err := os.Mkdir(realAllow, 0o755); err != nil {
		t.Fatal(err)
	}
	linkAllow := filepath.Join(base, "link-allow")
	if err := os.Symlink(realAllow, linkAllow); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	resolvedAllow, err := filepath.EvalSymlinks(realAllow)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	fc, err := ProcessConfig(config.FilesystemConfig{
		Root:  root,
		Mode:  "read-write",
		Allow: []string{filepath.Join(linkAllow, "future", "file.txt")},
	})
	if err != nil {
		t.Fatalf("ProcessConfig: %v", err)
	}
	want := filepath.Join(resolvedAllow, "future", "file.txt")
	if len(fc.AllowPaths) != 1 || fc.AllowPaths[0] != want {
		t.Fatalf("AllowPaths = %v, want [%q]", fc.AllowPaths, want)
	}
	if strings.Contains(fc.AllowPaths[0], linkAllow) {
		t.Fatalf("allow path kept symlinked ancestor %q, creating a ruleset TOCTOU: %v", linkAllow, fc.AllowPaths)
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

func TestAppendSerializedAllow_AppendsReadAllowField(t *testing.T) {
	fc := &FenceConfig{Root: "/root", Mode: "read-write", AllowPaths: []string{"/tmp"}}
	base := fc.Serialize("/sock")

	got := AppendSerializedAllow(base, "/proc/123")

	sc, err := ParseSerialized(got)
	if err != nil {
		t.Fatalf("re-parse appended policy: %v", err)
	}
	found := false
	for _, p := range sc.AllowPaths {
		if p == "/proc/123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("appended allow path /proc/123 not present after round-trip; allow=%v", sc.AllowPaths)
	}
}

// TestAppendSerializedAllow_RefusesSeparatorInjection is the fail-closed negative
// control: a path carrying the reserved field separator must not smuggle extra
// allow/deny fields into the serialized policy. The grant is dropped, not injected.
func TestAppendSerializedAllow_RefusesSeparatorInjection(t *testing.T) {
	fc := &FenceConfig{Root: "/root", Mode: "read-write"}
	base := fc.Serialize("/sock")

	injected := "/proc/1" + fieldSep + "-/etc"
	got := AppendSerializedAllow(base, injected)

	if got != base {
		t.Fatalf("separator-bearing path must be refused (returned unchanged), got %q", got)
	}
	sc, err := ParseSerialized(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, d := range sc.DenyPaths {
		if d == "/etc" {
			t.Fatalf("injected deny field /etc leaked into policy: deny=%v", sc.DenyPaths)
		}
	}
}
