package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// AuditStateDir returns the directory holding NockLock's own audit state for the
// project rooted at projectRoot: the event log and its SQLite sidecars, the
// chain anchor, and the per-session egress decision logs. It is created 0700 on
// first use and named for a SHA-256 prefix of the project root's real path, so
// two projects never share audit state.
//
// The directory deliberately sits OUTSIDE the project, under
// $XDG_STATE_HOME/nocklock/ (or ~/.local/state/nocklock/). That is a security
// requirement, not a filesystem convention.
//
// Landlock grants a path hierarchy, and a rule on a subdirectory cannot narrow a
// grant on an ancestor: the kernel walks upward from the accessed file and
// allows the access as soon as ANY ancestor rule grants it
// (security/landlock/fs.c, is_access_to_paths_allowed). Stacking a second
// ruleset layer does not help either, because every layer must grant the
// creation right on the root for a create in the root to succeed. So the moment
// the fence root itself is granted — which is what lets the fenced child create
// and remove entries directly in it — everything underneath the root becomes
// writable, including anything NockLock keeps there. Holding the audit state
// outside the root is what makes "the child can write in its project" and "the
// child cannot touch its own audit trail" true at the same time.
//
// This mirrors logging.DefaultSigningKeyPath, which already keeps the Ed25519
// signing key under $XDG_CONFIG_HOME for the same reason.
func AuditStateDir(projectRoot string) (string, error) {
	dir, err := AuditStateDirPath(projectRoot)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create the audit state directory %s: %w", dir, err)
	}
	// A pre-existing directory keeps whatever mode it already had, so verify it
	// rather than trusting MkdirAll. A group- or world-writable audit directory
	// lets another local user replace the event log wholesale, which no
	// per-file mode on events.db can prevent. Fail closed.
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("cannot stat the audit state directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("refusing to use the audit state directory %s: not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("refusing to use the audit state directory %s: mode %04o is group- or world-accessible; run 'chmod 700 %s'", dir, perm, dir)
	}
	return dir, nil
}

// AuditStateDirPath computes the audit state directory for projectRoot WITHOUT
// creating or validating it. Use it where the location is only being compared
// against — notably the event logger's containment check, which must not have
// the side effect of creating a directory. Use AuditStateDir to obtain a
// directory that is ready to write to.
func AuditStateDirPath(projectRoot string) (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot resolve the home directory for the audit state directory: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "nocklock", projectStateKey(projectRoot)), nil
}

// projectStateKey names a project's audit state directory: a SHA-256 prefix of
// the project root's real path. Symlinks are resolved first so the same project
// reached through a symlink maps to one directory; a path that cannot be
// resolved falls back to its lexical form.
func projectStateKey(projectRoot string) string {
	real := filepath.Clean(projectRoot)
	if resolved, err := filepath.EvalSymlinks(real); err == nil {
		real = resolved
	}
	sum := sha256.Sum256([]byte(real))
	return hex.EncodeToString(sum[:])[:16]
}
