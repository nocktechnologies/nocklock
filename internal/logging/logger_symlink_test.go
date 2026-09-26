//go:build unix

package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurity_SymlinkedDBPathRejected verifies the N8614 fix: a repository
// that commits .nock/events.db as a symlink pointing to a file OUTSIDE the
// project must be rejected. NewLogger must NOT follow the symlink, chmod the
// target, or let SQLite write to (corrupt) it.
func TestSecurity_SymlinkedDBPathRejected(t *testing.T) {
	root := t.TempDir()

	// A sensitive file outside the project, with distinctive contents and
	// permissions we can prove are untouched.
	outsideDir := t.TempDir()
	target := filepath.Join(outsideDir, "victim.txt")
	const original = "do not touch me"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}

	// The malicious audit-log path: .nock/events.db is a symlink to the victim.
	nockDir := filepath.Join(root, ".nock")
	if err := os.MkdirAll(nockDir, 0o700); err != nil {
		t.Fatalf("mkdir .nock: %v", err)
	}
	dbPath := filepath.Join(nockDir, "events.db")
	if err := os.Symlink(target, dbPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	l, err := NewLogger(dbPath, root)
	if err == nil {
		if l != nil {
			l.Close()
		}
		t.Fatal("expected NewLogger to reject symlinked DB path, got nil error")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected a symlink-related error, got: %v", err)
	}

	// The symlink itself must still be a symlink (not replaced with a real DB).
	if fi, lerr := os.Lstat(dbPath); lerr != nil {
		t.Fatalf("lstat dbPath after rejection: %v", lerr)
	} else if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink was replaced by a real file — fix followed/clobbered it")
	}

	// The victim file outside the project must be byte-for-byte and
	// permission-for-permission untouched.
	after, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target after rejection: %v", err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Errorf("target permissions changed: before %o after %o (symlink was followed and chmod'd)",
			before.Mode().Perm(), after.Mode().Perm())
	}
	if after.Size() != before.Size() {
		t.Errorf("target size changed: before %d after %d (symlink was followed and written)",
			before.Size(), after.Size())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target after rejection: %v", err)
	}
	if string(got) != original {
		t.Errorf("target contents changed: %q — symlink was followed and corrupted", string(got))
	}
}

// TestSecurity_NormalDBPathStillWorks is the positive control for the N8614
// fix: a normal (non-symlink) .nock/events.db must still create, open, and log
// exactly as before.
func TestSecurity_NormalDBPathStillWorks(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, ".nock", "events.db")

	l, err := NewLogger(dbPath, root)
	if err != nil {
		t.Fatalf("NewLogger on normal path failed: %v", err)
	}
	defer l.Close()

	// File exists, is a regular file, and has 0600 perms.
	fi, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatalf("lstat created DB: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("created DB is a symlink, expected a regular file")
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("created DB is not a regular file: mode %v", fi.Mode())
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("created DB perms: got %o, want 600", fi.Mode().Perm())
	}

	// Logging works end-to-end.
	evt := sampleEvent(EventSecretBlocked, "secret", "API_KEY", true, "sess-normal")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log on normal path failed: %v", err)
	}
	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query on normal path failed: %v", err)
	}
	if len(events) != 1 || events[0].Detail != "API_KEY" {
		t.Fatalf("expected 1 event with detail API_KEY, got %+v", events)
	}
}

// TestSecurity_SymlinkSwapAfterCreateRejected covers the case where a real DB
// exists on first run and is later replaced by a symlink pointing outside the
// project (e.g. a compromised checkout). Reopening must reject it.
func TestSecurity_SymlinkSwapAfterCreateRejected(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, ".nock", "events.db")

	l, err := NewLogger(dbPath, root)
	if err != nil {
		t.Fatalf("first NewLogger failed: %v", err)
	}
	l.Close()

	// Replace the real DB with a symlink to an outside file.
	outsideDir := t.TempDir()
	target := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Remove(dbPath); err != nil {
		t.Fatalf("remove real DB: %v", err)
	}
	if err := os.Symlink(target, dbPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := NewLogger(dbPath, root); err == nil {
		t.Fatal("expected reopen of symlinked DB to be rejected, got nil error")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error on reopen, got: %v", err)
	}
}

// TestSecurity_SymlinkedAncestorWithMissingTailRejected is the negative control
// for validatePath's deepest-existing-ancestor resolution: an intermediate
// directory that is a symlink OUT of the project must be rejected even when the
// components below it (and the DB file itself) do not exist yet — so the final
// Lstat/O_NOFOLLOW guard never gets a path to inspect. Resolving only the
// existing ancestor is what catches the escape; leaving the DB path unresolved
// would let it through and then create the audit tree through the symlink.
func TestSecurity_SymlinkedAncestorWithMissingTailRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	// root/link -> outside (an existing symlinked ancestor); the DB lives at a
	// path BELOW it whose intermediate dir and file do not exist yet.
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	dbPath := filepath.Join(root, "link", "sub", "events.db")

	l, err := NewLogger(dbPath, root)
	if err == nil {
		if l != nil {
			l.Close()
		}
		t.Fatal("expected NewLogger to reject a DB path reached through a symlinked ancestor")
	}
	if !strings.Contains(err.Error(), "resolves outside project root") {
		t.Errorf("expected outside-root rejection, got: %v", err)
	}

	// The escape must not have been created through the symlink.
	if _, serr := os.Stat(filepath.Join(outside, "sub")); serr == nil {
		t.Error("audit tree was created through the symlinked ancestor — the escape was followed")
	}
}

// TestSecurity_DanglingSymlinkAncestorRejected covers a symlinked ancestor whose
// target does not exist yet: EvalSymlinks reports the missing target as "does not
// exist", so a naive walk would step over the symlink as if it were a plain
// not-yet-created directory and admit an out-of-root DB path. The Lstat check
// must catch that the symlink entry itself is present and fail closed — before
// MkdirAll/OpenFile ever run, closing the TOCTOU window where the target could
// be created between the check and the write.
func TestSecurity_DanglingSymlinkAncestorRejected(t *testing.T) {
	root := t.TempDir()

	// .nock is a symlink to a path OUTSIDE the project that does not exist.
	target := filepath.Join(t.TempDir(), "not-created-yet")
	if err := os.Symlink(target, filepath.Join(root, ".nock")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	dbPath := filepath.Join(root, ".nock", "events.db")

	l, err := NewLogger(dbPath, root)
	if err == nil {
		if l != nil {
			l.Close()
		}
		t.Fatal("expected NewLogger to reject a DB path under a dangling symlinked ancestor")
	}
	if !strings.Contains(err.Error(), "cannot canonicalize DB path") {
		t.Errorf("expected fail-closed canonicalization error, got: %v", err)
	}

	// The escape target must not have been created through the symlink.
	if _, serr := os.Stat(target); serr == nil {
		t.Error("escape target was created through the dangling symlink — the symlink was followed")
	}
}

// TestSecurity_UnresolvableAncestorFailsClosed is the negative control for the
// non-ENOENT branch of validatePath's ancestor resolution: an ancestor that
// cannot be canonicalized (here a symlink loop → ELOOP, not "does not exist")
// must fail closed rather than fall back to the raw path frame, which is where a
// symlinked ancestor could otherwise escape the root undetected.
func TestSecurity_UnresolvableAncestorFailsClosed(t *testing.T) {
	root := t.TempDir()

	// A self-referential symlink: EvalSymlinks(root/loop) returns ELOOP, which is
	// not os.ErrNotExist, so the walk must refuse rather than treat it as absent.
	if err := os.Symlink("loop", filepath.Join(root, "loop")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	dbPath := filepath.Join(root, "loop", "events.db")

	l, err := NewLogger(dbPath, root)
	if err == nil {
		if l != nil {
			l.Close()
		}
		t.Fatal("expected NewLogger to reject a DB path under an unresolvable (looping) ancestor")
	}
	if !strings.Contains(err.Error(), "cannot canonicalize DB path") {
		t.Errorf("expected fail-closed canonicalization error, got: %v", err)
	}
}
