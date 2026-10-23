package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/internal/ocsf"
	"github.com/nocktechnologies/nocklock/internal/version"
)

// runAuditExport implements verify --export ocsf. It runs the verify --audit
// checks first, printing their report to stderr, and refuses to write anything
// unless they pass. It then re-reads the chain in one read transaction and
// requires that snapshot to be the chain just verified (same head, row count,
// hash links and signatures) before the export is published: with --out the
// file appears only by rename after the last line, and without it nothing
// reaches stdout until the whole export is built.
func runAuditExport(ctx context.Context, stdout, stderr io.Writer, format, outPath, pubFlag string, requireClosed bool) error {
	if format != "ocsf" {
		return fmt.Errorf("unsupported --export format %q: the supported format is ocsf", format)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	refuse := func(err error) error {
		fmt.Fprintln(stderr, "EXPORT: REFUSED — nothing was written")
		return err
	}
	result, pub, err := verifyAuditLog(ctx, stderr, pubFlag, requireClosed)
	if err != nil {
		return refuse(err)
	}

	dbPath, projectRoot, err := resolveAuditDBPath()
	if err != nil {
		return refuse(err)
	}
	logger, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		return refuse(fmt.Errorf("failed to open event log: %w", err))
	}
	defer logger.Close()

	var buf bytes.Buffer
	var tmp *os.File
	var dst io.Writer = &buf
	if outPath != "" {
		tmp, err = os.CreateTemp(filepath.Dir(outPath), "."+filepath.Base(outPath)+".tmp-*")
		if err != nil {
			return refuse(fmt.Errorf("create export file next to %s: %w", outPath, err))
		}
		defer func() {
			if tmp != nil {
				tmp.Close()
				os.Remove(tmp.Name())
			}
		}()
		dst = bufio.NewWriter(tmp)
	}
	enc := json.NewEncoder(dst)
	enc.SetEscapeHTML(false)

	prev := logging.ChainGenesisHashHex
	walked, signed := 0, 0
	head, found, err := logger.ReadChain(ctx, func(r logging.ChainRow) error {
		cb := logging.CanonicalBytes(r.ID, r.Timestamp, r.EventType, r.Category, r.Detail, r.Blocked != 0, r.SessionID)
		hash, herr := logging.ChainEntryFromCanonical(cb, r.PrevHash)
		if r.PrevHash != prev || herr != nil || hash != r.EntryHash {
			return fmt.Errorf("entry %d does not chain in the export snapshot", r.ID)
		}
		if r.EntrySig != "" {
			signed++
			if pub != nil && !logging.VerifyRowSig(pub, cb, r.EntrySig) {
				return fmt.Errorf("entry %d signature does not verify in the export snapshot", r.ID)
			}
		}
		prev = r.EntryHash
		walked++
		ev, err := ocsf.FromRow(r, version.Version)
		if err != nil {
			return err
		}
		return enc.Encode(ev)
	})
	if err != nil {
		return refuse(fmt.Errorf("export: %w", err))
	}
	if !found {
		return refuse(fmt.Errorf("export: the audit log has no chain head to anchor the export"))
	}
	if head.Hash != result.HeadHash || head.RowCount != result.EntriesVerified ||
		prev != result.HeadHash || walked != result.EntriesVerified || signed != result.SignedEntries {
		return refuse(fmt.Errorf("export: the audit log changed between verification and export (verified %d rows to %s, read %d rows to %s); re-run the export", result.EntriesVerified, result.HeadHash, walked, prev))
	}

	trailer := ocsf.Trailer{
		Verdict:     "CONSISTENT",
		RowCount:    head.RowCount,
		GenesisHash: logging.ChainGenesisHashHex,
		ChainHead:   head.Hash,
	}
	if result.SigState == "authentic" {
		signedBytes, err := head.CanonicalBytes()
		if err != nil {
			return refuse(fmt.Errorf("export: chain head: %w", err))
		}
		trailer.Verdict = "AUTHENTIC"
		trailer.HeadSig = head.Sig
		trailer.HeadSignedBytes = base64.StdEncoding.EncodeToString(signedBytes)
		trailer.PublicKey = logging.EncodePublicKey(pub)
		trailer.KeyFingerprint = logging.PublicKeyFingerprint(pub)
	}
	if err := enc.Encode(ocsf.TrailerEvent(trailer, version.Version, time.Now())); err != nil {
		return refuse(fmt.Errorf("export: %w", err))
	}

	if tmp == nil {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("export: write stdout: %w", err)
		}
	} else {
		if err := publishExport(tmp, dst.(*bufio.Writer), outPath); err != nil {
			return refuse(err)
		}
		tmp = nil
	}
	dest := "stdout"
	if outPath != "" {
		dest = outPath
	}
	fmt.Fprintf(stderr, "EXPORT: OCSF %s, %d row event(s) and 1 trailer written to %s (%s)\n", ocsf.Version, walked, dest, trailer.Verdict)
	return nil
}

// publishExport flushes, syncs and closes the temporary export file, then
// renames it onto outPath, so a reader never sees a partial export.
func publishExport(tmp *os.File, w *bufio.Writer, outPath string) error {
	if err := w.Flush(); err != nil {
		return fmt.Errorf("export: write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("export: sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("export: close %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), outPath); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("export: publish %s: %w", outPath, err)
	}
	return nil
}
