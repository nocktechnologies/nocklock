// External chain-head anchor (N10647, audit-log v1 follow-on). The signed
// hash chain in logger.go/signing.go proves a log is internally consistent and
// (with the key) authentic, but its head signature was valid AT THE TIME it was
// written: an attacker who restores an earlier, legitimately-signed snapshot of
// the whole database — or, on a host that verifies hash-only because it lacks
// the key, truncates the tail and rewrites chain_head in lockstep — presents a
// SHORTER chain that still verifies. That residual gap is exactly what the v1
// spec and the README name as "external head anchoring."
//
// An anchor is a small, signed record of {row_count, head_hash} captured at a
// point in time and stored OUTSIDE events.db (a future NockCC push consumes the
// wrap-teardown file). `verify --against-anchor` then detects any local chain
// that has FEWER rows than the anchor attests (truncation / rollback) or that
// does not reproduce the anchored head hash at the anchored count (tamper) —
// even when the local signed verify reads AUTHENTIC, because the anchor pins the
// count the signed head cannot.
//
// Honest limit: chain-anchor.json lives in the same trust boundary as
// events.db, so a file-access attacker can delete it or swap an older valid
// anchor alongside a matching db rollback. Its value is as the OFF-BOX push
// hook; once the head is pinned somewhere the agent cannot reach, rollback
// becomes observable.
package logging

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AnchorVersion is the current anchor record version. It maps 1:1 to the
// anchorSigVersion domain-separation byte below; a future version bumps both.
const AnchorVersion = 1

// anchorSigVersion is the leading domain-separation byte for anchor canonical
// bytes. Row canonical bytes lead with 0x01 (canonicalBytes) and the chain_head
// with 0x03 (headSigVersion); the anchor leads with 0x05 so a row or head
// signature can never be replayed as an anchor signature, and vice versa. Like
// those two, this single byte is both the version and the domain tag: it equals
// AnchorVersion 1.
const anchorSigVersion byte = 0x05

// Anchor is the external chain-head anchor record. It is emitted as compact
// JSON. AgentID is the signing public-key fingerprint (hex SHA-256 of the
// Ed25519 public key) — the SAME identity the audit log records in
// chain_head.signing_pubkey_fingerprint, so an anchor is bound to the key that
// produced the head it attests.
type Anchor struct {
	Version   int    `json:"version"`
	AgentID   string `json:"agent_id"`
	HeadHash  string `json:"head_hash"`
	RowCount  int    `json:"row_count"`
	CreatedAt string `json:"created_at"`
	Sig       string `json:"sig"`
}

// AnchorVerifyResult is the outcome of verifying a local chain against an anchor.
type AnchorVerifyResult struct {
	// OK is true only when the anchor is authentic AND the local chain has at
	// least the anchored row count AND reproduces the anchored head hash at that
	// count (a chain that has GROWN past the anchor is OK).
	OK bool

	// Classification is one of: "ok", "truncation", "tampered", "forged",
	// "identity_mismatch", "no_key". It never conflates an authentic-anchor
	// truncation (an attack signal) with a bad/forged anchor.
	Classification string
	Reason         string

	AnchorRowCount int
	LocalRowCount  int
	AnchorHeadHash string
	// LocalHeadAtAnchor is the cumulative chain hash recomputed from the local
	// rows at the anchored row count (set when the local chain reaches it).
	LocalHeadAtAnchor string

	// PrunedAfterAnchor is true when the local chain_head records a prune whose
	// timestamp is after the anchor's created_at: a legitimate compaction, not
	// necessarily an attack. Surfaced as a NOTE so a prune is not misread.
	PrunedAfterAnchor bool
}

// anchorCanonicalBytes returns the deterministic bytes signed for an anchor.
// Layout, in order:
//
//	anchorSigVersion            1 byte  (0x05; version-and-domain, = AnchorVersion 1)
//	lp(agent_id)                u32be length + UTF-8 bytes
//	head_hash                   32 raw bytes, decoded from 64 lowercase hex chars
//	row_count                   u64be
//	lp(created_at)              u32be length + UTF-8 bytes
//
// where lp = a uint32 big-endian byte length followed by the field's unmodified
// UTF-8 bytes. head_hash is decoded to its 32 bytes (rejected otherwise) rather
// than signed as hex text, mirroring headCanonicalBytes. The JSON `version`
// field is bound by the leading byte, not re-encoded; verify rejects a version
// other than AnchorVersion before checking the signature.
func anchorCanonicalBytes(a *Anchor) ([]byte, error) {
	hb, err := hex.DecodeString(a.HeadHash)
	if err != nil {
		return nil, fmt.Errorf("invalid anchor head_hash hex: %w", err)
	}
	if len(hb) != 32 {
		return nil, fmt.Errorf("anchor head_hash must be 32 bytes, got %d", len(hb))
	}
	if a.RowCount < 0 {
		return nil, fmt.Errorf("anchor row_count must be non-negative, got %d", a.RowCount)
	}
	buf := make([]byte, 0, 1+4+len(a.AgentID)+32+8+4+len(a.CreatedAt))
	buf = append(buf, anchorSigVersion)
	buf = anchorAppendLP(buf, a.AgentID)
	buf = append(buf, hb...)
	var cnt [8]byte
	binary.BigEndian.PutUint64(cnt[:], uint64(a.RowCount))
	buf = append(buf, cnt[:]...)
	buf = anchorAppendLP(buf, a.CreatedAt)
	return buf, nil
}

// anchorAppendLP appends a uint32 big-endian length prefix and the string's
// UTF-8 bytes.
func anchorAppendLP(buf []byte, s string) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(s)))
	buf = append(buf, length[:]...)
	return append(buf, s...)
}

// EmitAnchor reads the current chain_head and returns a signed anchor record.
// It requires a signing key (open the log WithSigning); an unsigned log cannot
// produce an authenticatable anchor, so this fails closed rather than emitting
// an unsigned record that verify could never trust.
func (l *Logger) EmitAnchor() (*Anchor, error) {
	if l.signer == nil {
		return nil, errors.New("anchor emission requires a signing key: open the audit log with signing enabled")
	}

	tx, err := l.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin anchor transaction: %w", err)
	}
	defer tx.Rollback()
	if err := initChainHeadIfNeeded(tx); err != nil {
		return nil, fmt.Errorf("failed to initialize chain_head for anchor: %w", err)
	}

	var headHash string
	var rowCount int
	if err := tx.QueryRow("SELECT entry_hash, row_count FROM chain_head WHERE id = 1").Scan(&headHash, &rowCount); err != nil {
		return nil, fmt.Errorf("failed to read chain_head for anchor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit anchor transaction: %w", err)
	}

	a := &Anchor{
		Version:   AnchorVersion,
		AgentID:   publicKeyFingerprint(l.signer.pub),
		HeadHash:  headHash,
		RowCount:  rowCount,
		CreatedAt: formatTimestampForChain(time.Now()),
	}
	cb, err := anchorCanonicalBytes(a)
	if err != nil {
		return nil, fmt.Errorf("failed to encode anchor canonical bytes: %w", err)
	}
	a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(l.signer.priv, cb))
	return a, nil
}

// EmitAnchorToFile emits an anchor and writes it as compact JSON to path, 0600,
// via a temp file + rename so a crash cannot leave a torn anchor. wrap teardown
// performs the same two steps (EmitAnchor + WriteAnchor) itself because it also
// needs the anchor object for the off-box push.
func (l *Logger) EmitAnchorToFile(path string) error {
	a, err := l.EmitAnchor()
	if err != nil {
		return err
	}
	return WriteAnchor(path, a)
}

// DefaultAnchorPath returns the default anchor path next to the event DB:
// <db-dir>/chain-anchor.json. wrap writes it on teardown as the off-box push
// hook (a future NockCC push consumes it).
func DefaultAnchorPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "chain-anchor.json")
}

// MarshalAnchor renders an anchor as compact JSON (no trailing newline).
func MarshalAnchor(a *Anchor) ([]byte, error) {
	return json.Marshal(a)
}

// WriteAnchor writes an anchor as compact JSON to path, mode 0600, atomically
// (temp file in the same directory + rename).
func WriteAnchor(path string, a *Anchor) error {
	data, err := MarshalAnchor(a)
	if err != nil {
		return fmt.Errorf("failed to marshal anchor: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".chain-anchor-*.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create anchor temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("failed to set anchor file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("failed to write anchor: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("failed to close anchor temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("failed to finalize anchor at %s: %w", path, err)
	}
	return nil
}

// ReadAnchor reads and decodes an anchor JSON file.
func ReadAnchor(path string) (*Anchor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := UnmarshalAnchor(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse anchor file %s: %w", path, err)
	}
	return a, nil
}

// UnmarshalAnchor decodes an anchor from its JSON encoding. It is the single
// decode path for every anchor source (a local file, or one fetched from the
// off-box store), so a remote anchor is parsed exactly like a local one; the
// authenticity and chain checks live in VerifyAgainstAnchor.
func UnmarshalAnchor(data []byte) (*Anchor, error) {
	var a Anchor
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// SigningPublicKey returns the Ed25519 public key this logger signs with, or
// nil when the log was opened without signing.
func (l *Logger) SigningPublicKey() ed25519.PublicKey {
	if l.signer == nil {
		return nil
	}
	return l.signer.pub
}

// VerifyAgainstAnchor checks the local chain against an anchor, using pub to
// authenticate the anchor's own signature. The checks run in order:
//
//	(0) the anchor record version is understood;
//	(a) pub is present, its fingerprint matches the anchor's agent_id, and the
//	    anchor's Ed25519 signature verifies (a bad/forged anchor is FORGED,
//	    never mistaken for a truncated local chain);
//	(b) the local chain has at least the anchored row count (fewer = TRUNCATION,
//	    the rollback/tail-truncation signal); and
//	(c) the local chain reproduces the anchored head hash at the anchored count
//	    (mismatch = TAMPERED).
//
// A local chain that has GROWN past the anchor (more rows, anchored head
// reproduced at the anchored count) is OK.
func (l *Logger) VerifyAgainstAnchor(a *Anchor, pub ed25519.PublicKey) (*AnchorVerifyResult, error) {
	res := &AnchorVerifyResult{
		AnchorRowCount: a.RowCount,
		AnchorHeadHash: a.HeadHash,
	}

	// (0) Version — reject before any signature work so a future format is a
	// clear refusal, not a silent verify failure.
	if a.Version != AnchorVersion {
		res.Classification = "forged"
		res.Reason = fmt.Sprintf("unsupported anchor version %d (this build understands version %d)", a.Version, AnchorVersion)
		return res, nil
	}

	// (a) Authenticate the anchor itself.
	if pub == nil {
		res.Classification = "no_key"
		res.Reason = "no public key available to authenticate the anchor (supply --ed25519-pub or run on the signing host)"
		return res, nil
	}
	if a.AgentID != publicKeyFingerprint(pub) {
		res.Classification = "identity_mismatch"
		res.Reason = fmt.Sprintf("anchor attests signing identity %s but the supplied key is %s", a.AgentID, publicKeyFingerprint(pub))
		return res, nil
	}
	cb, err := anchorCanonicalBytes(a)
	if err != nil {
		res.Classification = "forged"
		res.Reason = fmt.Sprintf("malformed anchor: %v", err)
		return res, nil
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		res.Classification = "forged"
		res.Reason = "anchor signature is not a valid Ed25519 signature encoding"
		return res, nil
	}
	if !ed25519.Verify(pub, cb, sig) {
		res.Classification = "forged"
		res.Reason = "anchor signature does not verify against the supplied key"
		return res, nil
	}

	// The anchor is authentic. Walk the local chain, recomputing the cumulative
	// hash from each row's canonical bytes (not trusting the stored hashes, so a
	// tampered row is caught even if its stored hash was rewritten in lockstep).
	tx, err := l.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin anchor verification transaction: %w", err)
	}
	defer tx.Rollback()

	// Read the local prune boundary so a legitimate compaction after the anchor
	// can be surfaced rather than misread as an attack.
	var prunedAtStr *string
	if err := tx.QueryRow("SELECT pruned_at FROM chain_head WHERE id = 1").Scan(&prunedAtStr); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to read chain_head prune boundary: %w", err)
	}
	if prunedAtStr != nil {
		if pruned, perr := time.Parse(time.RFC3339, *prunedAtStr); perr == nil {
			if created, cerr := time.Parse(time.RFC3339, a.CreatedAt); cerr == nil && pruned.After(created) {
				res.PrunedAfterAnchor = true
			}
		}
	}

	rows, err := tx.Query(
		"SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events ORDER BY id ASC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query events for anchor verification: %w", err)
	}
	defer rows.Close()

	prevHashHex := chainGenesisHashHex
	headAtAnchor := ""
	if a.RowCount == 0 {
		headAtAnchor = chainGenesisHashHex
	}
	total := 0
	for rows.Next() {
		var id int64
		var ts, et, cat, detail, sid string
		var blocked int
		if err := rows.Scan(&id, &ts, &et, &cat, &detail, &blocked, &sid); err != nil {
			return nil, fmt.Errorf("failed to scan event row: %w", err)
		}
		entryHash, err := chainEntry(id, ts, EventType(et), cat, detail, blocked != 0, sid, prevHashHex)
		if err != nil {
			return nil, fmt.Errorf("failed to recompute chain hash for row %d: %w", id, err)
		}
		prevHashHex = entryHash
		total++
		if total == a.RowCount {
			headAtAnchor = entryHash
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating events during anchor verification: %w", err)
	}
	res.LocalRowCount = total
	res.LocalHeadAtAnchor = headAtAnchor

	// (b) Truncation / rollback: the local chain has fewer rows than the anchor.
	if total < a.RowCount {
		res.Classification = "truncation"
		res.Reason = fmt.Sprintf("truncation detected: anchor attests %d rows, local has %d", a.RowCount, total)
		return res, nil
	}

	// (c) Tamper: the local chain does not reproduce the anchored head hash at
	// the anchored count.
	if headAtAnchor != a.HeadHash {
		res.Classification = "tampered"
		res.Reason = fmt.Sprintf("tamper detected: local chain does not reproduce the anchored head hash at %d rows (anchored %s, local %s)", a.RowCount, a.HeadHash, headAtAnchor)
		return res, nil
	}

	res.OK = true
	res.Classification = "ok"
	if total == a.RowCount {
		res.Reason = fmt.Sprintf("local chain reproduces the anchored head at %d rows", a.RowCount)
	} else {
		res.Reason = fmt.Sprintf("local chain reproduces the anchored head at %d rows and has grown to %d", a.RowCount, total)
	}
	return res, nil
}
