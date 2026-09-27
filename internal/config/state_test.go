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

// trustedStateRoot returns a resolved temp dir chmod'd 0700, standing in for a
// state root (XDG_STATE_HOME or ~/.local/state) an operator actually trusts.
// t.TempDir() itself is not good enough here: its per-call leaf is created
// with os.Mkdir(dir, 0777), so under a permissive umask (e.g. 002, common with
// user-private-group setups) it comes back group-writable, which would trip
// validateStateRootBase for reasons that have nothing to do with what the test
// is checking.
func trustedStateRoot(t *testing.T) string {
	t.Helper()
	dir := resolvedTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod state root: %v", err)
	}
	return dir
}

func TestEnsureAuditStateDirCreatesPrivateDirs(t *testing.T) {
	base := trustedStateRoot(t)
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
	base := trustedStateRoot(t)
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
	base := trustedStateRoot(t)
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
	real := trustedStateRoot(t)
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

// TestResolveDBPathKeepsUsingItsFirstResolvedStateRoot proves that resolving a
// symlinked state root cannot race the candidate scan against the final audit
// directory construction. A second resolution after this seam retargets the
// link would return a path under stateRootB instead of the existing chain under
// stateRootA.
func TestResolveDBPathKeepsUsingItsFirstResolvedStateRoot(t *testing.T) {
	projectRoot := resolvedTempDir(t)
	configPath := filepath.Join(projectRoot, Dir, File)
	stateRootA := trustedStateRoot(t)
	stateRootB := trustedStateRoot(t)
	stateLink := filepath.Join(resolvedTempDir(t), "state-link")
	if err := os.Symlink(stateRootA, stateLink); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", stateLink)

	stateDirA := filepath.Join(stateRootA, "nocklock", projectStateKey(projectRoot))
	if err := os.MkdirAll(stateDirA, 0o700); err != nil {
		t.Fatalf("mkdir state directory: %v", err)
	}
	for _, dir := range []string{filepath.Join(stateRootA, "nocklock"), stateDirA} {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatalf("chmod state directory %s: %v", dir, err)
		}
	}
	want := filepath.Join(stateDirA, DefaultConfig().Logging.DB)
	if err := os.WriteFile(want, []byte("existing chain"), 0o600); err != nil {
		t.Fatalf("write existing chain: %v", err)
	}

	originalEval := evalAuditStateRoot
	calls := 0
	evalAuditStateRoot = func(base string) (string, error) {
		calls++
		resolved, err := originalEval(base)
		if err != nil || calls != 1 {
			return resolved, err
		}
		if err := os.Remove(stateLink); err != nil {
			return "", err
		}
		if err := os.Symlink(stateRootB, stateLink); err != nil {
			return "", err
		}
		return resolved, nil
	}
	t.Cleanup(func() { evalAuditStateRoot = originalEval })

	cfg := DefaultConfig()
	got, _, err := ResolveDBPath(&cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if got != want {
		t.Fatalf("event log = %q, want existing chain under first resolved state root %q", got, want)
	}
	if calls != 1 {
		t.Fatalf("state root resolved %d times, want once", calls)
	}
}

// TestEnsureAuditStateDirRejectsGroupWritableStateRoot: the configured state
// root itself (XDG_STATE_HOME, or the ~/.local/state fallback) must be
// trusted before NockLock creates anything beneath it, same as any other
// ancestor -- a group-writable base lets another member of the group rename
// away a component NockLock owns and substitute their own directory.
func TestEnsureAuditStateDirRejectsGroupWritableStateRoot(t *testing.T) {
	base := trustedStateRoot(t)
	if err := os.Chmod(base, 0o770); err != nil {
		t.Fatalf("chmod base: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", base)

	if _, err := EnsureAuditStateDir(resolvedTempDir(t)); err == nil {
		t.Fatal("expected a group-writable state root to be refused")
	} else if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected a writable-directory error, got: %v", err)
	}
}

// TestEnsureAuditStateDirRejectsWorldWritableStateRoot is the other half of
// the same rule: the world-write bit is just as dangerous as the group-write
// one.
func TestEnsureAuditStateDirRejectsWorldWritableStateRoot(t *testing.T) {
	base := trustedStateRoot(t)
	if err := os.Chmod(base, 0o707); err != nil {
		t.Fatalf("chmod base: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", base)

	if _, err := EnsureAuditStateDir(resolvedTempDir(t)); err == nil {
		t.Fatal("expected a world-writable state root to be refused")
	} else if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected a writable-directory error, got: %v", err)
	}
}

// TestEnsureAuditStateDirRejectsForeignOwnedStateRoot only exercises the
// ownership half of the check when the test can actually produce a
// foreign-owned directory, which needs chown privileges this process rarely
// has outside a root-run CI job. Everywhere else it documents the requirement
// via a loud skip reason instead of silently doing nothing.
func TestEnsureAuditStateDirRejectsForeignOwnedStateRoot(t *testing.T) {
	base := trustedStateRoot(t)
	const otherUID = 65534 // "nobody" on most systems, and never this test's own uid
	if err := os.Chown(base, otherUID, -1); err != nil {
		t.Skipf("cannot chown %s to a foreign uid without privileges (expected outside a root-run CI job): %v", base, err)
	}
	t.Setenv("XDG_STATE_HOME", base)

	if _, err := EnsureAuditStateDir(resolvedTempDir(t)); err == nil {
		t.Fatal("expected a foreign-owned state root to be refused")
	} else if !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("expected an ownership error, got: %v", err)
	}
}

// TestEnsureAuditStateDirAcceptsDefaultStateRoot: with XDG_STATE_HOME unset,
// the ~/.local/state fallback must still pass for the common case -- a
// freshly created or ordinarily permissioned home directory is not group- or
// world-writable and is owned by the current user.
func TestEnsureAuditStateDirAcceptsDefaultStateRoot(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", trustedStateRoot(t))

	if _, err := EnsureAuditStateDir(resolvedTempDir(t)); err != nil {
		t.Fatalf("a default, untampered state root should be accepted: %v", err)
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

// TestRelativeXDGStateHomeIsIgnored: a relative XDG_STATE_HOME resolves against
// the working directory, which for a fenced run is the project itself — so
// honoring ".state" would build the supposedly external audit state inside the
// writable fence root. The XDG spec requires an absolute path; a relative one is
// ignored in favour of the home directory.
func TestRelativeXDGStateHomeIsIgnored(t *testing.T) {
	project := resolvedTempDir(t)
	t.Setenv("XDG_STATE_HOME", ".state")
	t.Setenv("HOME", resolvedTempDir(t))
	t.Chdir(project)

	dir, err := AuditStateDir(project)
	if err != nil {
		t.Fatalf("AuditStateDir: %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("audit state dir %q is not absolute", dir)
	}
	if rel, relErr := filepath.Rel(project, dir); relErr == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("audit state dir %q landed inside the project %q", dir, project)
	}
}

// TestLoadRejectsAuditLogDirectlyInProjectRoot: the fence protects an in-project
// audit trail by withholding the grant on the root and granting each child
// except the audit directory. With the log in the root itself there is nothing
// to skip, so this is refused at config load rather than failing later while
// building the ruleset.
func TestLoadRejectsAuditLogDirectlyInProjectRoot(t *testing.T) {
	project := resolvedTempDir(t)
	nockDir := filepath.Join(project, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	rootLevel := filepath.Join(project, "events.db")
	if err := os.WriteFile(configPath, []byte("[logging]\ndb = \""+rootLevel+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(configPath); err == nil {
		t.Fatal("expected an audit log directly in the project root to be rejected")
	} else if !strings.Contains(err.Error(), "directly in") {
		t.Fatalf("expected a root-level audit log error, got: %v", err)
	}
}

// TestLoadAcceptsAuditLogInProjectSubdirectory is the positive control: a
// subdirectory of the project is protectable, so it still loads.
func TestLoadAcceptsAuditLogInProjectSubdirectory(t *testing.T) {
	project := resolvedTempDir(t)
	nockDir := filepath.Join(project, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	nested := filepath.Join(nockDir, "events.db")
	if err := os.WriteFile(configPath, []byte("[logging]\ndb = \""+nested+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(configPath); err != nil {
		t.Fatalf("an audit log in a project subdirectory should load: %v", err)
	}
}
