package cli

import (
	"bytes"
	"context"
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

// runAuditExport implements verify --export ocsf. It runs the verify --audit
// checks first, printing their report to stderr, and refuses to write anything
// unless they pass. The rows are then read in the same read transaction as a
// second chain verification (logging.ReadVerifiedChain), so the export is
// exactly the chain that verdict covers. The export is built in memory and
// published only once complete: with --out by rename, otherwise to stdout.
func runAuditExport(ctx context.Context, stdout, stderr io.Writer, format, outPath, pubFlag string, requireClosed bool) error {
	if format != "ocsf" {
		return fmt.Errorf("unsupported --export format %q: the supported format is ocsf", format)
	}
	refuse := func(err error) error {
		fmt.Fprintln(stderr, "EXPORT: REFUSED — nothing was written")
		return err
	}
	logger, pub, err := verifyAuditLog(ctx, stderr, pubFlag, requireClosed)
	if err != nil {
		return refuse(err)
	}
	defer logger.Close()

	var buf bytes.Buffer
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
		return refuse(err)
	}
	if err != nil {
		return refuse(fmt.Errorf("export: %w; re-run verify --audit", err))
	}

	trailer := ocsf.Trailer{
		Verdict:     "CONSISTENT",
		RowCount:    result.EntriesVerified,
		GenesisHash: logging.ChainGenesisHashHex,
		ChainHead:   result.HeadHash,
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

	dest := "stdout"
	if outPath == "" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("export: write stdout: %w", err)
		}
	} else {
		if err := publishExport(outPath, buf.Bytes()); err != nil {
			return refuse(err)
		}
		dest = outPath
	}
	fmt.Fprintf(stderr, "EXPORT: OCSF %s, %d row event(s) and 1 trailer written to %s (%s)\n", ocsf.Version, result.EntriesVerified, dest, trailer.Verdict)
	return nil
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
