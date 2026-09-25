// Package receipt verifies one session's NockLock audit chain offline, read
// only, with nothing but the Ed25519 public key. It is the public seam other
// modules (for example nockguard) import: internal/logging cannot be imported
// from outside this module, so this package exposes a narrow read-only API and
// delegates every chain primitive (canonical bytes, hash link, row signature)
// to internal/logging. There is one implementation of the chain; this package
// only walks it.
package receipt

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/logging"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Verdicts. Exactly one is set on every Result; only VerdictIntact is success.
const (
	// VerdictIntact: every row in the DB links and hashes correctly, and every
	// row of the session carries a signature that verifies under the key.
	VerdictIntact = "INTACT"
	// VerdictTampered: a hash or link breaks anywhere in the DB (in or outside
	// the session), or a session row's signature does not verify under the key.
	VerdictTampered = "TAMPERED"
	// VerdictUnsigned: the chain is consistent but a session row has no
	// signature, so its authorship cannot be proven.
	VerdictUnsigned = "UNSIGNED"
	// VerdictNoRows: the chain is consistent but the session has no rows.
	VerdictNoRows = "NO_ROWS"
	// VerdictUnverifiable: the input could not be read or the key is unusable.
	VerdictUnverifiable = "UNVERIFIABLE"
)

// RowResult is the per-row outcome for one row of the requested session.
type RowResult struct {
	ID     int64  // events.id
	LinkOK bool   // prev_hash equals the previous row's entry_hash (genesis for the first row)
	HashOK bool   // entry_hash equals SHA-256(canonical || prev_hash)
	Signed bool   // entry_sig is non-empty
	SigOK  bool   // entry_sig verifies under the supplied key
	Reason string // first failure on this row, empty when the row is clean
}

// Result is the outcome of VerifySession.
type Result struct {
	Verdict     string      // one of the Verdict constants; only INTACT is success
	SessionID   string      // the session that was requested
	KeyID       string      // hex(sha256(pub)), empty when the key was unusable
	RowsChecked int         // rows of the session that were examined
	FirstBadRow int64       // events.id of the row behind the verdict, 0 if none
	Reason      string      // why the verdict is not INTACT
	Rows        []RowResult // per-row outcomes for the session's rows, in id order
}

// VerifySession verifies the audit chain in the NockLock SQLite log at dbPath
// and reports on the rows of sessionID, using only the Ed25519 public key pub.
//
// The DB is opened read only (mode=ro, query_only); it is never created,
// written, or migrated. The whole chain is walked in id order, because the
// hash link spans sessions: every row must satisfy entry_hash ==
// SHA-256(canonical || prev_hash) and prev_hash == the previous row's
// entry_hash, with the first row anchored at the genesis hash. Every row of
// sessionID must also carry an entry_sig that verifies under pub. A valid
// signature does not excuse a broken link: the signature covers the canonical
// bytes only, not prev_hash.
//
// Verdict precedence, fail closed: TAMPERED (any hash or link break) >
// NO_ROWS > UNSIGNED > TAMPERED (session signature failure) > INTACT.
//
// Callers must treat Verdict == VerdictIntact as the only success. The error is
// diagnostic: it is non-nil for a nil or short key, an empty sessionID, or a DB
// that cannot be read, and in each of those cases Verdict is UNVERIFIABLE.
func VerifySession(dbPath string, pub ed25519.PublicKey, sessionID string) (Result, error) {
	res := Result{Verdict: VerdictUnverifiable, SessionID: sessionID}
	fail := func(err error) (Result, error) {
		res.Verdict = VerdictUnverifiable
		res.Reason = err.Error()
		res.Rows = nil
		res.RowsChecked = 0
		res.FirstBadRow = 0
		return res, err
	}

	if len(pub) != ed25519.PublicKeySize {
		return fail(fmt.Errorf("receipt: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub)))
	}
	res.KeyID = logging.PublicKeyFingerprint(pub)
	if sessionID == "" {
		return fail(errors.New("receipt: session id is empty"))
	}

	db, absPath, preOpen, err := openReadOnly(dbPath)
	if err != nil {
		return fail(err)
	}
	defer db.Close()

	// One read transaction gives a consistent snapshot even while a writer is
	// appending to the log.
	tx, err := db.Begin()
	if err != nil {
		return fail(fmt.Errorf("receipt: begin read transaction on %s: %w", dbPath, err))
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		"SELECT id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash, entry_sig FROM events ORDER BY id ASC",
	)
	if err != nil {
		return fail(fmt.Errorf("receipt: read events from %s: %w", dbPath, err))
	}
	defer rows.Close()

	var (
		chainBadID     int64 // first hash/link break anywhere in the DB
		chainBadReason string
		unsignedID     int64 // first unsigned session row
		sigBadID       int64 // first session row whose signature fails
		sigBadReason   string
	)
	prevHashHex := logging.ChainGenesisHashHex
	for rows.Next() {
		var id int64
		var ts, et, cat, detail, sid, storedPrev, storedEntry, storedSig string
		var blocked int
		if err := rows.Scan(&id, &ts, &et, &cat, &detail, &blocked, &sid, &storedPrev, &storedEntry, &storedSig); err != nil {
			return fail(fmt.Errorf("receipt: scan events row: %w", err))
		}

		var rowReason string
		linkOK := storedPrev == prevHashHex
		if !linkOK {
			rowReason = fmt.Sprintf("entry %d: prev_hash mismatch (expected %s, got %s)", id, prevHashHex, storedPrev)
		}
		cb := logging.CanonicalBytes(id, ts, et, cat, detail, blocked != 0, sid)
		// The recompute uses the row's own stored prev_hash, so a forged link
		// is reported as a link break even when the row is self-consistent.
		expected, herr := logging.ChainEntryFromCanonical(cb, storedPrev)
		hashOK := herr == nil && expected == storedEntry
		if !hashOK && rowReason == "" {
			if herr != nil {
				rowReason = fmt.Sprintf("entry %d: cannot compute hash: %v", id, herr)
			} else {
				rowReason = fmt.Sprintf("entry %d: entry_hash mismatch (expected %s, got %s)", id, expected, storedEntry)
			}
		}
		if (!linkOK || !hashOK) && chainBadID == 0 {
			chainBadID = id
			chainBadReason = rowReason
			if sid != sessionID {
				chainBadReason += " (outside the requested session; the hash link spans sessions)"
			}
		}

		if sid == sessionID {
			rr := RowResult{ID: id, LinkOK: linkOK, HashOK: hashOK, Signed: storedSig != ""}
			if rr.Signed {
				rr.SigOK = logging.VerifyRowSig(pub, cb, storedSig)
				if !rr.SigOK {
					msg := fmt.Sprintf("entry %d: signature does not verify under key %s", id, res.KeyID)
					if rowReason == "" {
						rowReason = msg
					}
					if sigBadID == 0 {
						sigBadID, sigBadReason = id, msg
					}
				}
			} else {
				if rowReason == "" {
					rowReason = fmt.Sprintf("entry %d: no signature", id)
				}
				if unsignedID == 0 {
					unsignedID = id
				}
			}
			rr.Reason = rowReason
			res.Rows = append(res.Rows, rr)
		}

		// Advance on the stored hash, as VerifyChain does; a break was already
		// recorded above and decides the verdict.
		prevHashHex = storedEntry
	}
	if err := rows.Err(); err != nil {
		return fail(fmt.Errorf("receipt: iterate events: %w", err))
	}
	res.RowsChecked = len(res.Rows)

	post, err := os.Lstat(absPath)
	if err != nil {
		return fail(fmt.Errorf("receipt: re-check audit log %s after read: %w", absPath, err))
	}
	if err := checkSameFile(absPath, preOpen, post); err != nil {
		return fail(err)
	}

	switch {
	case chainBadID != 0:
		res.Verdict, res.FirstBadRow, res.Reason = VerdictTampered, chainBadID, chainBadReason
	case res.RowsChecked == 0:
		res.Verdict, res.Reason = VerdictNoRows, fmt.Sprintf("no rows for session %q", sessionID)
	case unsignedID != 0:
		res.Verdict, res.FirstBadRow = VerdictUnsigned, unsignedID
		res.Reason = fmt.Sprintf("entry %d of session %q carries no signature", unsignedID, sessionID)
	case sigBadID != 0:
		res.Verdict, res.FirstBadRow, res.Reason = VerdictTampered, sigBadID, sigBadReason
	default:
		res.Verdict, res.Reason = VerdictIntact, ""
	}
	return res, nil
}

// beforeSQLiteOpen is a test seam for deterministic path-swap regression tests.
var beforeSQLiteOpen = func() {}

// openReadOnly opens an existing SQLite file read only. It refuses a missing,
// symlinked, or non-regular path up front: sql.Open is lazy, and SQLite must
// never be handed a path it could create. It returns the absolute path and the
// pre-open FileInfo so the caller can bind the check to the file it read (see
// checkSameFile).
func openReadOnly(dbPath string) (*sql.DB, string, os.FileInfo, error) {
	if dbPath == "" {
		return nil, "", nil, errors.New("receipt: DB path is empty")
	}
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, "", nil, fmt.Errorf("receipt: resolve DB path %s: %w", dbPath, err)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, "", nil, fmt.Errorf("receipt: cannot read audit log %s: %w", abs, err)
	}
	if err := requireRegular(abs, fi); err != nil {
		return nil, "", nil, err
	}

	// mode=ro opens without write access and without create; query_only is a
	// second guard. On a WAL-mode log SQLite may create the -shm index next to
	// the DB; it holds no rows. The main file and any -wal are never written.
	beforeSQLiteOpen()
	u := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro&_pragma=query_only(1)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, "", nil, fmt.Errorf("receipt: open audit log %s read only: %w", abs, err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, "", nil, fmt.Errorf("receipt: open audit log %s read only: %w", abs, err)
	}
	return db, abs, fi, nil
}

// requireRegular rejects a symlink or any non-regular file.
func requireRegular(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("receipt: refusing audit log %s: path is a symlink", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("receipt: refusing audit log %s: not a regular file", path)
	}
	return nil
}

// checkSameFile binds the pre-open check to the file that was read: after the
// rows are read, the path must still be a regular, non-symlink file and the
// same file (os.SameFile) as the pre-open Lstat. This catches a path swapped
// between the Lstat and the open.
//
// Residual: a swap and swap-back entirely inside the window is not caught
// here. It is still bound cryptographically: the rows that were read must
// hash-chain from genesis and verify under the caller's key for the caller's
// session id, so a swapped-in file can only yield INTACT if it is itself a
// valid log signed by that key for that session.
func checkSameFile(path string, pre, post os.FileInfo) error {
	if err := requireRegular(path, post); err != nil {
		return fmt.Errorf("%w (after read)", err)
	}
	if !os.SameFile(pre, post) {
		return fmt.Errorf("receipt: audit log %s changed identity between the pre-open check and the read", path)
	}
	return nil
}
