package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/internal/ocsf"
	"github.com/nocktechnologies/nocklock/internal/version"
)

// exportAfterChecks, when set by a test, runs between the verify --audit checks
// and the export read, where a concurrent writer can append.
var exportAfterChecks func()

// exportMaxBytes caps the in-memory export. A test lowers it.
var exportMaxBytes = 256 << 20

var errExportTooLarge = errors.New("export exceeds 256 MiB; NockLock v0.15 builds the export in memory")

// cappedBuffer is an in-memory buffer that refuses a write that would take it
// past exportMaxBytes, so an oversized export fails before anything is
// published. Write is its only way in.
type cappedBuffer struct{ b bytes.Buffer }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.b.Len()+len(p) > exportMaxBytes {
		return 0, errExportTooLarge
	}
	return c.b.Write(p)
}

// Bytes returns the buffered export.
func (c *cappedBuffer) Bytes() []byte { return c.b.Bytes() }

// runAuditExport implements verify --export ocsf. It runs the verify --audit
// checks first, printing their report to stderr, and refuses to write anything
// unless they pass. The rows are then read in the same read transaction as a
// second chain verification (logging.ReadVerifiedChain), and the export is
// refused unless that chain ends at the same head as the one the checks
// covered, so the export is exactly the log those checks passed. The export is
// built in memory, refused past exportMaxBytes, and published only once
// complete: with --out by rename inside the --out directory opened before the
// checks, otherwise to stdout.
func runAuditExport(ctx context.Context, stdout, stderr io.Writer, format, outPath, pubFlag string, requireClosed bool) error {
	if format != "ocsf" {
		return fmt.Errorf("unsupported --export format %q: the supported format is ocsf", format)
	}
	refuse := func(err error) error {
		fmt.Fprintln(stderr, "EXPORT: REFUSED — nothing was written")
		return err
	}
	root, name, err := openOutDir(outPath)
	if err != nil {
		return refuse(err)
	}
	if root != nil {
		defer root.Close()
	}
	var buf cappedBuffer
	var trailer ocsf.Trailer
	err = verifyAuditLog(ctx, stderr, pubFlag, requireClosed, func(logger *logging.Logger, dbPath, projectRoot string, pub ed25519.PublicKey, checked *logging.ChainVerifyResult) error {
		if root != nil {
			if err := refuseProtectedOut(root, name, outPath, dbPath, projectRoot); err != nil {
				return err
			}
		}
		if exportAfterChecks != nil {
			exportAfterChecks()
		}
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		walkCtx, cancelWalk := anchorCLIWalkContext(ctx)
		defer cancelWalk()
		result, head, err := logger.ReadVerifiedChain(walkCtx, pub, pubFlag != "", func(r logging.ChainRow) error {
			ev, err := ocsf.FromRow(r, version.Version)
			if err != nil {
				return err
			}
			return enc.Encode(ev)
		})
		if errors.Is(err, logging.ErrVerifyInterrupted) {
			return err
		}
		if err != nil {
			return fmt.Errorf("export: %w; re-run verify --audit", err)
		}
		if result.HeadHash != checked.HeadHash {
			return fmt.Errorf("export: the audit log changed after the checks above (chain head %s, now %s); re-run the export", checked.HeadHash, result.HeadHash)
		}

		trailer = ocsf.Trailer{
			Verdict:     "CONSISTENT",
			RowCount:    result.EntriesVerified,
			GenesisHash: logging.ChainGenesisHashHex,
			ChainHead:   result.HeadHash,
		}
		if result.SigState == "authentic" {
			signedBytes, err := head.CanonicalBytes()
			if err != nil {
				return fmt.Errorf("export: chain head: %w", err)
			}
			trailer.Verdict = "AUTHENTIC"
			trailer.UnsignedThroughID = result.UnsignedThroughID
			trailer.HeadSig = head.Sig
			trailer.HeadSignedBytes = base64.StdEncoding.EncodeToString(signedBytes)
			trailer.PublicKey = logging.EncodePublicKey(pub)
			trailer.KeyFingerprint = logging.PublicKeyFingerprint(pub)
		}
		if err := enc.Encode(ocsf.TrailerEvent(trailer, version.Version, time.Now())); err != nil {
			return fmt.Errorf("export: %w", err)
		}
		return nil
	})
	if errors.Is(err, errExportTooLarge) {
		return refuse(errExportTooLarge)
	}
	if err != nil {
		return refuse(err)
	}

	dest := "stdout"
	if outPath == "" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintln(stderr, "EXPORT: INCOMPLETE — stdout may hold a partial export with no trailer; discard it")
			return fmt.Errorf("export: write stdout: %w", err)
		}
	} else {
		if err := publishExport(root, name, outPath, buf.Bytes()); err != nil {
			return refuse(err)
		}
		dest = outPath
	}
	fmt.Fprintf(stderr, "EXPORT: OCSF %s, %d row event(s) and 1 trailer written to %s (%s)\n", ocsf.Version, trailer.RowCount, dest, trailer.Verdict)
	return nil
}

// openOutDir opens the directory that will hold --out, before the checks. The
// protected-file check (refuseProtectedOut) and the publish both go through
// the returned root, so swapping a symlink in the --out path during the export
// cannot redirect the rename. An empty outPath (stdout) returns a nil root.
func openOutDir(outPath string) (*os.Root, string, error) {
	if outPath == "" {
		return nil, "", nil
	}
	abs, err := filepath.Abs(outPath)
	if err != nil {
		return nil, "", fmt.Errorf("export: --out %s: %w", outPath, err)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, "", fmt.Errorf("export: --out %s: its directory must exist: %w", outPath, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", fmt.Errorf("export: --out %s: %w", outPath, err)
	}
	return root, filepath.Base(abs), nil
}

// refuseProtectedOut errors when name in root is, by directory and name or by
// file identity, a file the export must not replace: the audit database it
// read (dbPath, as opened, not resolved again), its SQLite sidecars, its chain
// anchor, the managed signing key or a trusted chain identity file. Names
// compare case-insensitively, failing closed on case-insensitive filesystems.
func refuseProtectedOut(root *os.Root, name, outPath, dbPath, projectRoot string) error {
	protected := []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal", logging.DefaultAnchorPath(dbPath)}
	if keyPath, err := logging.DefaultSigningKeyPath(); err == nil {
		protected = append(protected, keyPath)
	}
	if stateDir, err := config.AuditStateDir(projectRoot); err == nil {
		for _, n := range []string{logging.ChainIdentityFileName, logging.ChainIdentityLockName, logging.AnchorRegistrationFileName} {
			protected = append(protected, filepath.Join(stateDir, n))
		}
	}
	dirInfo, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("export: --out %s: %w", outPath, err)
	}
	// The rename replaces name itself, never a symlink's target, so following
	// a symlink here only refuses a path that reads as the protected file.
	target, targetErr := os.Stat(filepath.Join(root.Name(), name))
	for _, p := range protected {
		pDir, err := os.Stat(filepath.Dir(p))
		sameName := err == nil && os.SameFile(pDir, dirInfo) && strings.EqualFold(filepath.Base(p), name)
		pInfo, err := os.Stat(p)
		sameFile := err == nil && targetErr == nil && os.SameFile(pInfo, target)
		if sameName || sameFile {
			return fmt.Errorf("export: --out %s is %s, which the export must not replace; choose another path", outPath, p)
		}
	}
	return nil
}

// publishExport writes data to a temporary file in root, syncs it, and renames
// it onto name, so a reader never sees a partial export. The file is created
// 0600: it holds the audit log.
func publishExport(root *os.Root, name, outPath string, data []byte) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("export: %w", err)
	}
	tmpName := "." + name + ".tmp-" + hex.EncodeToString(suffix[:])
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("export: create a temporary file next to %s: %w", outPath, err)
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmpName, name)
	}
	if err != nil {
		root.Remove(tmpName)
		return fmt.Errorf("export: write %s: %w", outPath, err)
	}
	return nil
}
