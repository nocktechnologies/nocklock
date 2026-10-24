package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/internal/ocsf"
	"github.com/nocktechnologies/nocklock/internal/version"
)

// exportAfterChecks, when set by a test, runs between the verify --audit checks
// and the export read, where a concurrent writer can append.
var exportAfterChecks func()

// runAuditExport implements verify --export ocsf. It runs the verify --audit
// checks first, printing their report to stderr, and refuses to write anything
// unless they pass. The rows are then read in the same read transaction as a
// second chain verification (logging.ReadVerifiedChain), and the export is
// refused unless that chain ends at the same head as the one the checks
// covered, so the export is exactly the log those checks passed. The export is
// built in memory and published only once complete: with --out by rename,
// otherwise to stdout.
func runAuditExport(ctx context.Context, stdout, stderr io.Writer, format, outPath, pubFlag string, requireClosed bool) error {
	if format != "ocsf" {
		return fmt.Errorf("unsupported --export format %q: the supported format is ocsf", format)
	}
	refuse := func(err error) error {
		fmt.Fprintln(stderr, "EXPORT: REFUSED — nothing was written")
		return err
	}
	if err := refuseProtectedOut(outPath); err != nil {
		return refuse(err)
	}
	var buf bytes.Buffer
	var trailer ocsf.Trailer
	err := verifyAuditLog(ctx, stderr, pubFlag, requireClosed, func(logger *logging.Logger, pub ed25519.PublicKey, checked *logging.ChainVerifyResult) error {
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
		if err := publishExport(outPath, buf.Bytes()); err != nil {
			return refuse(err)
		}
		dest = outPath
	}
	fmt.Fprintf(stderr, "EXPORT: OCSF %s, %d row event(s) and 1 trailer written to %s (%s)\n", ocsf.Version, trailer.RowCount, dest, trailer.Verdict)
	return nil
}

// refuseProtectedOut errors when outPath, after symlinks, names the audit
// database, one of its SQLite sidecars, or the managed signing key: publishing
// the export by rename would replace the log or key it was read from. An empty
// outPath (stdout) passes.
func refuseProtectedOut(outPath string) error {
	if outPath == "" {
		return nil
	}
	dbPath, _, err := resolveAuditDBPath()
	if err != nil {
		return err
	}
	protected := []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal"}
	if keyPath, err := logging.DefaultSigningKeyPath(); err == nil {
		protected = append(protected, keyPath)
	}
	out := absResolved(outPath)
	for _, p := range protected {
		if rp := absResolved(p); rp == out || sameExistingFile(rp, out) {
			return fmt.Errorf("export: --out %s is %s, which the export must not replace; choose another path", outPath, p)
		}
	}
	return nil
}

// absResolved returns p made absolute with the symlinks in its existing
// prefix resolved.
func absResolved(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return resolveExistingPrefix(p)
}

// sameExistingFile reports whether a and b both exist and are the same file.
func sameExistingFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

// publishExport writes data to a temporary file beside outPath, syncs it, and
// renames it onto outPath, so a reader never sees a partial export. The file
// is created 0600: it holds the audit log.
func publishExport(outPath string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(outPath), "."+filepath.Base(outPath)+".tmp-*")
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
		err = os.Rename(tmp.Name(), outPath)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("export: write %s: %w", outPath, err)
	}
	return nil
}
