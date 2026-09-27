package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// migrateLegacyAuditState relocates a pre-existing in-project audit trail to
// newDB's directory, once, on first use after the upgrade that moved audit state
// out of the fence root (see AuditStateDir).
//
// It MOVES rather than copies on purpose. A compat read that left the old file
// in place would defeat the relocation entirely: the whole point is that no
// audit state remains inside the fence root, because the root is now granted to
// the fenced child and a Landlock rule cannot carve a protected hole out of a
// granted tree.
//
// If both a legacy log and a relocated log exist, this refuses to run rather
// than pick one: silently choosing between two audit chains would let a tampered
// log shadow the real one.
func migrateLegacyAuditState(newDB, legacyDB string) error {
	info, err := os.Lstat(legacyDB)
	if err != nil {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to migrate the event log at %s: path is a symlink", legacyDB)
	}
	if _, err := os.Lstat(newDB); err == nil {
		// Name a recovery step the operator can actually take. Every audit
		// command resolves through here, so telling them to run one of those
		// commands would just reproduce this error.
		return fmt.Errorf(
			"two event logs found: %s (legacy, inside the project) and %s (current). "+
				"NockLock will not guess which audit chain is authoritative. "+
				"Move one aside (its -wal/-shm sidecars and chain-anchor.json travel with it), "+
				"then rerun: with a single log in place the usual commands work again",
			legacyDB, newDB)
	}
	return moveAuditArtifacts(legacyDB, newDB)
}

// moveAuditArtifacts moves the event log, its SQLite sidecars and the chain
// anchor that sits beside it. The anchor must travel with the log or
// 'nocklock verify --against-anchor' loses the baseline it compares against.
func moveAuditArtifacts(legacyDB, newDB string) error {
	// The logger runs in WAL mode (PRAGMA journal_mode=WAL), so committed rows
	// can still live in events.db-wal: moving the main file without its SQLite
	// sidecars silently drops the tail of the hash chain.
	//
	// Order matters. The sidecars and the anchor move FIRST and the main file
	// LAST, so the main file's presence is the marker for "not migrated yet".
	// If a move fails part way (a cross-device copy running out of space, say),
	// the legacy main file is still there, the next run retries, and the
	// already-moved pieces are simply skipped. Moving the main file first would
	// make the next run see nothing to migrate and silently adopt a chain
	// truncated to its last checkpoint.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := moveIfPresent(legacyDB+suffix, newDB+suffix); err != nil {
			return err
		}
	}
	// Keep this name in step with logging.DefaultAnchorPath, which computes the
	// same <db-dir>/chain-anchor.json. It is repeated rather than called because
	// internal/logging imports this package, so the dependency cannot run the
	// other way. Renaming the anchor there without changing it here would still
	// compile and would silently stop migrating anchors.
	const anchorName = "chain-anchor.json"
	if err := moveIfPresent(
		filepath.Join(filepath.Dir(legacyDB), anchorName),
		filepath.Join(filepath.Dir(newDB), anchorName),
	); err != nil {
		return err
	}
	return moveIfPresent(legacyDB, newDB)
}

// moveIfPresent moves src to dst when src exists, leaving a missing src alone.
func moveIfPresent(src, dst string) error {
	if _, err := os.Lstat(src); err != nil {
		return nil
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Rename fails across filesystems (EXDEV), and the project and
	// $XDG_STATE_HOME routinely sit on different mounts. Fall back to a
	// durable copy; the original is removed only once the copy is on disk.
	if err := copyFileSynced(src, dst); err != nil {
		return fmt.Errorf("migrate audit state %s -> %s: %w", src, dst, err)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("migrate audit state: copied %s to %s but could not remove the original: %w", src, dst, err)
	}
	return nil
}

// copyFileSynced copies src to a fresh 0600 dst and fsyncs it, so a crash
// mid-migration cannot leave a truncated audit log as the only surviving copy.
func copyFileSynced(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
