package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

var evalAuditStateRoot = filepath.EvalSymlinks

// EnsureAuditStateDir returns the directory holding NockLock's own audit state
// for the project rooted at projectRoot: the event log and its SQLite sidecars,
// the chain anchor, and the per-session egress decision logs. It is created
// 0700 on first use and named for a SHA-256 prefix of the project root's real
// path, so two projects never share audit state.
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
func EnsureAuditStateDir(projectRoot string) (string, error) {
	base, owned, checkBase := auditStateLayout(projectRoot)
	base, err := resolveAuditStateRoot(base)
	if err != nil {
		return "", err
	}
	return ensureAuditStateDirAt(base, owned, checkBase)
}

// resolveAuditStateRoot creates the non-NockLock-owned state root when needed
// and resolves its symlinks before any NockLock-owned component is constructed
// beneath it.
func resolveAuditStateRoot(base string) (string, error) {
	// The base may not exist yet ($XDG_STATE_HOME on a fresh account, or
	// ~/.local/state). Create it with ordinary directory permissions: it is not
	// NockLock's directory and forcing 0700 on a user's ~/.local would be
	// overreach.
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("cannot create the audit state root %s: %w", base, err)
	}
	// Resolve the state ROOT once, and only here. Symlinks above the root are
	// the platform's business: on macOS /tmp, /var and the default TMPDIR
	// (/var/folders/...) are system links into /private, so refusing symlink
	// components outright would reject ordinary paths. Everything NockLock
	// creates BELOW the resolved root is held to the strict rule instead.
	dir, err := evalAuditStateRoot(base)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the audit state root %s: %w", base, err)
	}
	return dir, nil
}

// ensureAuditStateDirAt creates and validates NockLock-owned components below
// an already-resolved audit state root.
func ensureAuditStateDirAt(dir string, owned []string, checkBase bool) (string, error) {
	// The configured state root (XDG_STATE_HOME, or the ~/.local/state
	// fallback) is never NockLock's own directory, so it is never created 0700
	// like the components below it -- but a chain anchored under a base
	// another user can write is not trustworthy either: whoever can write the
	// base can rename a component away and substitute their own directory,
	// exactly the threat ensureTrustedDir guards against one level down. The
	// /var/tmp fallback below is deliberately exempt: it is a shared 1777
	// system directory by design, and the per-uid component under it (part of
	// owned, walked by ensureTrustedDir just below) is what NockLock actually
	// trusts there.
	if checkBase {
		if err := validateStateRootBase(dir); err != nil {
			return "", err
		}
	}
	for _, component := range owned {
		dir = filepath.Join(dir, component)
		if err := ensureTrustedDir(dir); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// ensureTrustedDir creates dir 0700 if it is missing and, either way, verifies
// that NockLock can trust it: a real directory, not a symlink, owned by the
// current user, and not group- or world-writable.
//
// Checking only the leaf is not enough, which is why the caller walks every
// component it owns. A trusted directory reached through an untrusted parent is
// not trusted: whoever can write the parent can rename the leaf away and put
// their own directory there, and no mode on the event log prevents it. Lstat
// rather than Stat so a symlink is caught instead of followed — a symlink here
// would hand the audit trail to whatever it points at.
func ensureTrustedDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("cannot create the audit state directory %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("cannot stat the audit state directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use the audit state directory %s: path is a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use the audit state directory %s: not a directory", dir)
	}
	if err := checkDirPermissions(dir, info); err != nil {
		return fmt.Errorf("refusing to use the audit state directory %s: %w", dir, err)
	}
	return nil
}

// checkDirPermissions requires info to describe a directory NockLock can
// trust: not group- or world-writable, and owned by the current user. Shared
// by ensureTrustedDir (a directory NockLock creates and owns) and
// validateStateRootBase (a directory NockLock only reaches through, whose
// symlink-ness and directory-ness the caller has already confirmed another
// way) -- the mode and ownership rule is the same either way, only the
// wrapping error and its suggested fix differ per caller.
//
// Group/world WRITE is the one mode bit that matters: it is what lets another
// user replace the event log or swap the directory. Read access is not ideal
// but does not compromise the chain, and being strict about it breaks
// inherited 0750 layouts for no security gain. The two checks name their own
// fix, since group/world-write is fixed with chmod while a foreign owner
// needs chown (or root) -- chmod cannot change ownership.
func checkDirPermissions(dir string, info fs.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("mode %04o is group- or world-writable; run 'chmod go-w %s'", perm, dir)
	}
	if err := validateStateDirOwner(info); err != nil {
		return fmt.Errorf("%w; chown the directory to the current user", err)
	}
	return nil
}

// AuditStateDir computes the audit state directory for projectRoot WITHOUT
// creating or validating it. Use it where the location is only being compared
// against — notably the event logger's containment check, which must not have
// the side effect of creating a directory. Use EnsureAuditStateDir to obtain a
// directory that is ready to write to.
func AuditStateDir(projectRoot string) (string, error) {
	base, owned, _ := auditStateLayout(projectRoot)
	return filepath.Join(base, filepath.Join(owned...)), nil
}

// validateStateRootBase requires the configured state root -- XDG_STATE_HOME,
// or the ~/.local/state fallback -- to be owned by the current user and not
// group- or world-writable before NockLock creates or trusts anything beneath
// it. Unlike ensureTrustedDir's components, NockLock does not own this
// directory: fixing it (or repointing NockLock elsewhere) is the operator's
// job, not something NockLock does on its own.
//
// The caller has already run this exact path through os.MkdirAll (confirming
// it exists as a directory) and filepath.EvalSymlinks (resolving it), so
// unlike ensureTrustedDir's components this cannot be a symlink or a
// non-directory; only the mode and the owner remain to check.
func validateStateRootBase(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("cannot stat the state root %s: %w", dir, err)
	}
	if err := checkDirPermissions(dir, info); err != nil {
		return fmt.Errorf("refusing to use the state root %s: %w, or point NockLock at a different one via XDG_STATE_HOME", dir, err)
	}
	return nil
}

// auditStateLayout splits the audit state location into a BASE that NockLock only
// reaches through, and the components BELOW it that NockLock owns and therefore
// validates strictly (see ensureTrustedDir). Ownership is the reason for the
// split: $XDG_STATE_HOME and ~/.local/state belong to the user's wider setup and
// /var/tmp is a 1777 system directory, so holding any of them to "0700, owned by
// me" would reject perfectly normal machines.
//
// The /var/tmp fallback exists because wrap REFUSES TO START when the event log
// cannot be opened, and a home directory is not guaranteed: containers with no
// passwd entry for the uid, and CI steps that run with HOME unset, both reach
// it. Those environments needed no home directory before the audit state moved
// out of the project, so erroring here would break them. The per-uid directory
// under /var/tmp is NockLock's own, so it is one of the validated components
// rather than part of the base.
//
// It is /var/tmp rather than /tmp deliberately: /tmp is granted by the shipped
// presets, and an audit state directory inside a Landlock-granted tree makes its
// own deny unenforceable and aborts rule generation. /var/tmp also survives a
// reboot on most systems, which /tmp does not.
// checkBase reports whether the base directory itself must pass
// validateStateRootBase: true for XDG_STATE_HOME and the ~/.local/state
// fallback, both of which are expected to be a normal user-owned directory;
// false for the /var/tmp fallback, which is a shared 1777 system directory by
// design and is never held to that rule (see EnsureAuditStateDir).
func auditStateLayout(projectRoot string) (base string, owned []string, checkBase bool) {
	key := projectStateKey(projectRoot)
	// A RELATIVE XDG_STATE_HOME is ignored, not honored. The XDG spec requires
	// an absolute path, and a relative one resolves against the working
	// directory -- which for a fenced run is the project itself, so a value like
	// ".state" would build the supposedly external audit state INSIDE the
	// writable fence root. Falling back to the home directory keeps the trail
	// out of the project; a caller that wants a specific location can still set
	// an absolute path.
	if x := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(x) {
		return x, []string{"nocklock", key}, true
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "state"), []string{"nocklock", key}, true
	}
	return "/var/tmp", []string{fmt.Sprintf("nocklock-state-%d", os.Geteuid()), "nocklock", key}, false
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
