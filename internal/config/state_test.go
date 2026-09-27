package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolvedTempDir returns a t.TempDir() with symlinks resolved. Every state-dir
// test needs this: on macOS the temp root lives under /var/folders/..., and /var
// is a system symlink into /private, so comparing an unresolved t.TempDir()
// against a path NockLock resolved would fail there while passing on Linux.
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

func TestEnsureAuditStateDirCreatesPrivateDirs(t *testing.T) {
	base := resolvedTempDir(t)
	t.Setenv("XDG_STATE_HOME", base)

	dir, err := EnsureAuditStateDir(resolvedTempDir(t))
	if err != nil {
		t.Fatalf("EnsureAuditStateDir: %v", err)
	}
	if !strings.HasPrefix(dir, base+string(os.PathSeparator)) {
		t.Fatalf("audit state dir %q is not under the configured state root %q", dir, base)
	}
	// Every directory NockLock created must be 0700, not just the leaf.
	for d := dir; d != base; d = filepath.Dir(d) {
		info, err := os.Lstat(d)
		if err != nil {
			t.Fatalf("lstat %s: %v", d, err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("%s mode = %04o, want 0700", d, perm)
		}
	}
}

// TestEnsureAuditStateDirRejectsWritableAncestor is the parent-trust negative
// control. Validating only the leaf is not enough: whoever can write a parent can
// rename the leaf away and substitute their own directory, and no mode on the
// event log prevents that.
func TestEnsureAuditStateDirRejectsWritableAncestor(t *testing.T) {
	base := resolvedTempDir(t)
	t.Setenv("XDG_STATE_HOME", base)
	// "nocklock" is the intermediate directory NockLock owns, one level above
	// the per-project dir. Make it group- and world-writable.
	ancestor := filepath.Join(base, "nocklock")
	if err := os.Mkdir(ancestor, 0o777); err != nil {
		t.Fatalf("mkdir ancestor: %v", err)
	}
	if err := os.Chmod(ancestor, 0o777); err != nil {
		t.Fatalf("chmod ancestor: %v", err)
	}

	if _, err := EnsureAuditStateDir(resolvedTempDir(t)); err == nil {
		t.Fatal("expected a group/world-writable ancestor of the audit state dir to be refused")
	} else if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected a writable-directory error, got: %v", err)
	}
}

// TestEnsureAuditStateDirRejectsSymlinkComponent: a symlink among the
// directories NockLock owns would hand the audit trail to whatever it points at,
// so those components are Lstat'd rather than followed. Symlinks ABOVE the state
// root stay allowed — /tmp and /var are system links into /private on macOS.
func TestEnsureAuditStateDirRejectsSymlinkComponent(t *testing.T) {
	base := resolvedTempDir(t)
	t.Setenv("XDG_STATE_HOME", base)
	elsewhere := resolvedTempDir(t)
	if err := os.Symlink(elsewhere, filepath.Join(base, "nocklock")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	if _, err := EnsureAuditStateDir(resolvedTempDir(t)); err == nil {
		t.Fatal("expected a symlinked component of the audit state dir to be refused")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected a symlink error, got: %v", err)
	}
}

// TestEnsureAuditStateDirAcceptsSymlinkedStateRoot is the positive control for
// the rule above, and the reason it is written that way: the macOS default
// TMPDIR reaches its real location through a system symlink, so a blanket
// no-symlinks rule would reject ordinary machines.
func TestEnsureAuditStateDirAcceptsSymlinkedStateRoot(t *testing.T) {
	real := resolvedTempDir(t)
	link := filepath.Join(resolvedTempDir(t), "state-link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", link)

	dir, err := EnsureAuditStateDir(resolvedTempDir(t))
	if err != nil {
		t.Fatalf("a symlinked state root should be accepted: %v", err)
	}
	if !strings.HasPrefix(dir, real+string(os.PathSeparator)) {
		t.Fatalf("audit state dir %q was not resolved through the symlinked root to %q", dir, real)
	}
}

func TestAuditStateDirSeparatesProjects(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", resolvedTempDir(t))
	a, err := AuditStateDir(resolvedTempDir(t))
	if err != nil {
		t.Fatalf("AuditStateDir: %v", err)
	}
	b, err := AuditStateDir(resolvedTempDir(t))
	if err != nil {
		t.Fatalf("AuditStateDir: %v", err)
	}
	if a == b {
		t.Fatalf("two projects share one audit state dir: %q", a)
	}
}
