// Signed verification receipt (Step 2 of docs/design/anchor-verification-profile.md,
// option C). A full signed-chain verification costs one Ed25519 verify per row —
// about 97% of the walk — and is re-paid in full on every anchor emission even
// when nothing changed. A receipt caches the result of one complete verification
// as a key-signed attestation of a VERIFIED PREFIX, so a later run re-proves the
// prefix bytes are byte-identical (hash + rolling digest, no signatures) and
// verifies signatures only for rows after the prefix. It never weakens the
// verdict: any change to a prefix byte, signature, link, key or adoption marker
// makes the digest or a hash mismatch and falls back to the full walk, and the
// head is always re-checked in full.
package logging

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// verifyReceiptSigVersion is the leading domain-separation byte for a verify
// receipt signature. Row canonical bytes lead with 0x01 (canonicalBytes),
// chain_head with 0x03 (headSigVersion), anchor v1 with 0x05 (anchorSigVersion)
// and anchor v2 with 0x06 (anchorV2SigVersion); a receipt leads with 0x07 so a
// row, head or anchor signature can never be replayed as a receipt signature,
// and vice versa. Like those, this single byte is both the version and the
// domain tag: it equals VerifyReceiptVersion.
const verifyReceiptSigVersion byte = 0x07

// VerifyReceiptVersion is the current verify-receipt record version. An unknown
// version is ignored (a full walk), so an older binary safely skips a newer
// receipt and a newer binary safely skips an older one.
const VerifyReceiptVersion = 1

// verifyReceiptWriteTimeout bounds the short, separate transaction that records
// a receipt after the read snapshot ends. It is deliberately brief and the write
// is best-effort: a live Logger append holds the single SQLite write lock, so a
// contending receipt write is cancelled by this deadline and skipped rather than
// delaying the append. Tests shorten it.
var verifyReceiptWriteTimeout = 2 * time.Second

// verifyReceiptDisableRead is a test-only seam (mirrors verifyRowHook). When
// true, verification ignores any verify_receipt and runs the full walk. It lets
// the differential oracle (negative control 18) compute the receipt-free verdict
// on the very same database that carries a receipt, so the two can be compared
// field by field. Never set in production.
var verifyReceiptDisableRead bool

// verifyReceiptSkipDigestCheck is a test-only seam (mirrors verifyRowHook). When
// true, the prefix rescan TRUSTS the receipt's prefix without re-verifying it: it
// skips both the per-row entry_hash recompute-and-compare and the rolling-digest
// (D), head-hash and count comparison to the receipt. It exists only for the
// mutation control (negative control 19): flipping it must make the prefix tamper
// controls (content edit, keyless re-chain, signature strip, and the differential
// property test) diverge from the full-walk verdict, proving the controls bite.
// Never set in production.
var verifyReceiptSkipDigestCheck bool

// verifyReceipt is the single verify_receipt row: a key-signed attestation that
// every row through ThroughID was linked, hashed and signature-checked under the
// audit key within one read snapshot. It attests a VERIFIED PREFIX, not an
// authentic chain — reaching the snapshot head and a clean head signature is a
// separate gate that only anchor emission requires.
type verifyReceipt struct {
	Version           int
	KeyFingerprint    string  // hex SHA-256 of the signing public key
	SignedGenesisAt   *string // chain_head.signed_genesis_at the receipt was written under (NULL before adoption)
	UnsignedThroughID *int64  // chain_head.unsigned_through_id the receipt was written under
	ThroughID         int64   // id of the last verified prefix row
	ThroughCount      int64   // number of verified prefix rows (through ThroughID)
	ThroughHeadHash   string  // cumulative entry_hash at ThroughID (hex)
	Digest            []byte  // rolling D over the prefix (see verifyRollingDigest)
	Sig               string  // base64 Ed25519 signature over verifyReceiptCanonicalBytes
}

// verifyReceiptDigestSeed is D_0, the rolling-digest seed before any row is
// folded. The signature's domain byte separates the digest from every other
// construction, so a 32-byte zero seed is sufficient.
func verifyReceiptDigestSeed() []byte { return make([]byte, sha256.Size) }

// verifyRollingDigest folds one row into the rolling digest:
// D_i = SHA-256(D_{i-1} || entry_hash_i || entry_sig_i), over the STORED column
// bytes (hex entry_hash, base64 entry_sig; empty entry_sig for pre-adoption
// rows). It binds entry_sig, which the hash chain does not cover, so a signature
// edit or strip on an otherwise-consistent prefix changes D and forces a full
// walk.
func verifyRollingDigest(prev []byte, storedEntryHash, storedSig string) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write([]byte(storedEntryHash))
	h.Write([]byte(storedSig))
	return h.Sum(nil)
}

// verifyReceiptCanonicalBytes returns the deterministic bytes signed for a
// receipt, in the order the design fixes:
//
//	verifyReceiptSigVersion     1 byte  (0x07; version-and-domain)
//	key_fingerprint             32 raw bytes (decoded from 64 hex chars)
//	signed_genesis_at           optional string (NULL-vs-value preserving)
//	unsigned_through_id         optional int64  (NULL-vs-value preserving)
//	through_id                  u64be
//	through_count               u64be
//	through_head_hash           32 raw bytes (decoded from 64 hex chars)
//	D                           32 raw bytes
//
// The optional fields reuse the chain_head canonical encoding so a NULL adoption
// marker is distinct from an empty or zero one.
func verifyReceiptCanonicalBytes(r *verifyReceipt) ([]byte, error) {
	fp, err := hex.DecodeString(r.KeyFingerprint)
	if err != nil || len(fp) != sha256.Size {
		return nil, errors.New("verify receipt key fingerprint must be 32 bytes of hex")
	}
	hh, err := hex.DecodeString(r.ThroughHeadHash)
	if err != nil || len(hh) != sha256.Size {
		return nil, errors.New("verify receipt through_head_hash must be 32 bytes of hex")
	}
	if len(r.Digest) != sha256.Size {
		return nil, errors.New("verify receipt digest must be 32 bytes")
	}
	if r.ThroughID < 0 || r.ThroughCount < 0 {
		return nil, errors.New("verify receipt through_id and through_count must be non-negative")
	}
	buf := make([]byte, 0, 1+sha256.Size+(1+4)+(1+8)+8+8+sha256.Size+sha256.Size)
	buf = append(buf, verifyReceiptSigVersion)
	buf = append(buf, fp...)
	buf = appendHeadOptionalString(buf, r.SignedGenesisAt)
	buf = appendHeadOptionalInt64(buf, r.UnsignedThroughID)
	var n8 [8]byte
	binary.BigEndian.PutUint64(n8[:], uint64(r.ThroughID))
	buf = append(buf, n8[:]...)
	binary.BigEndian.PutUint64(n8[:], uint64(r.ThroughCount))
	buf = append(buf, n8[:]...)
	buf = append(buf, hh...)
	buf = append(buf, r.Digest...)
	return buf, nil
}

// signVerifyReceipt returns the base64 Ed25519 signature over the receipt's
// canonical bytes.
func signVerifyReceipt(s *signer, r *verifyReceipt) (string, error) {
	cb, err := verifyReceiptCanonicalBytes(r)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, cb)), nil
}

// verifyReceiptSig reports whether the receipt signature verifies under pub. It
// reuses verifyRowSig for the base64-decode, length guard and Ed25519 verify.
func verifyReceiptSig(pub ed25519.PublicKey, r *verifyReceipt) bool {
	cb, err := verifyReceiptCanonicalBytes(r)
	if err != nil {
		return false
	}
	return verifyRowSig(pub, cb, r.Sig)
}

// loadVerifyReceipt reads the single verify_receipt row inside tx. It returns
// (nil, nil) for a missing row, an absent table (older schema), or any unreadable
// value: all are treated as "no receipt", so verification falls back to a full
// walk. A receipt is never trusted here — validVerifyReceiptFor authenticates it.
func loadVerifyReceipt(tx *sql.Tx) (*verifyReceipt, error) {
	var r verifyReceipt
	var digestHex string
	err := tx.QueryRow(
		"SELECT version, key_fingerprint, signed_genesis_at, unsigned_through_id, through_id, through_count, through_head_hash, digest, sig FROM verify_receipt WHERE id = 1",
	).Scan(&r.Version, &r.KeyFingerprint, &r.SignedGenesisAt, &r.UnsignedThroughID, &r.ThroughID, &r.ThroughCount, &r.ThroughHeadHash, &digestHex, &r.Sig)
	if err != nil {
		// No row, no table, or a corrupt value: ignore and walk fully. This is a
		// performance event, never an integrity one (receipt loss costs one walk).
		return nil, nil
	}
	d, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, nil
	}
	r.Digest = d
	return &r, nil
}

// validVerifyReceiptFor reports whether r may be used to skip prefix signature
// checks: a nil receipt or a nil key (hash-only verification) never qualifies;
// the version must be known; the fingerprint must equal the key's; the bound
// adoption metadata must equal the current head's; and the signature must verify
// under the key. Anything else leaves the receipt unused and runs the full walk.
func validVerifyReceiptFor(r *verifyReceipt, pub ed25519.PublicKey, head chainHeadRecord) bool {
	if r == nil || pub == nil {
		return false
	}
	if r.Version != VerifyReceiptVersion {
		return false
	}
	if r.KeyFingerprint != publicKeyFingerprint(pub) {
		return false
	}
	if !optEqual(r.SignedGenesisAt, head.meta.signedGenesisAt) {
		return false
	}
	if !optEqual(r.UnsignedThroughID, head.meta.unsignedThroughID) {
		return false
	}
	return verifyReceiptSig(pub, r)
}

// verifyProgress carries the verified prefix a verification run proved, so a key
// holder can record it as a receipt after the read snapshot ends. It is NEVER a
// verdict: an interrupted walk returns ErrVerifyInterrupted and no
// ChainVerifyResult, but still hands back the prefix it proved here. All fields
// describe rows actually verified under the key this run (or a receipt prefix
// re-proven byte-identical this run), never rows merely scanned.
type verifyProgress struct {
	throughID         int64
	throughCount      int64
	throughHeadHash   string
	digest            []byte
	signedGenesisAt   *string
	unsignedThroughID *int64
}

// advanceTo records a newly verified prefix boundary. digest may be aliased
// rather than copied because verifyRollingDigest returns a fresh slice on every
// fold and the walk never mutates one in place.
func (p *verifyProgress) advanceTo(id, count int64, headHash string, digest []byte) {
	p.throughID = id
	p.throughCount = count
	p.throughHeadHash = headHash
	p.digest = digest
}

// verifyReceiptUpsertSQL writes (or replaces) the single verify_receipt row. It
// is the one source of truth for the row's column order, shared by the
// production writer and the test receipt-restore helper so a schema change
// cannot drift between them. The digest is hex-encoded before binding.
const verifyReceiptUpsertSQL = "INSERT OR REPLACE INTO verify_receipt (id, version, key_fingerprint, signed_genesis_at, unsigned_through_id, through_id, through_count, through_head_hash, digest, sig) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

// writeVerifyReceipt records prog as a signed verify_receipt, best-effort. It is
// a no-op unless this Logger holds the signing key whose public half is pub, so a
// public-key-only verifier never writes. The write uses its own short,
// separately-bounded transaction — never the verification walk's context, which
// may already be cancelled — and is skipped on SQLITE_BUSY, a read-only database,
// or any other error. A receipt write is not a fence decision, so the audit-row
// invariant does not apply (see docs/design/anchor-verification-profile.md).
func (l *Logger) writeVerifyReceipt(pub ed25519.PublicKey, prog *verifyProgress) {
	if l.signer == nil || prog == nil || prog.throughCount <= 0 {
		return
	}
	// A public-key-only verifier (a different or nil key) never writes a receipt.
	if !l.signer.pub.Equal(pub) {
		return
	}
	r := &verifyReceipt{
		Version:           VerifyReceiptVersion,
		KeyFingerprint:    publicKeyFingerprint(l.signer.pub),
		SignedGenesisAt:   prog.signedGenesisAt,
		UnsignedThroughID: prog.unsignedThroughID,
		ThroughID:         prog.throughID,
		ThroughCount:      prog.throughCount,
		ThroughHeadHash:   prog.throughHeadHash,
		Digest:            prog.digest,
	}
	sig, err := signVerifyReceipt(l.signer, r)
	if err != nil {
		return
	}
	r.Sig = sig

	if l.writeDSN == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), verifyReceiptWriteTimeout)
	defer cancel()

	// Write on a dedicated throwaway connection, not this Logger's single pooled
	// connection, so the write never contends with (or blocks) a concurrent append
	// at the Go pool layer, and its busy-timeout change can never leak to a later
	// append. busy_timeout=0 turns a held write lock (a live append in another
	// process) into an immediate SQLITE_BUSY the caller skips, rather than waiting
	// out the global 5 s timeout. mode=rw never creates the database, so a read-only
	// copy or a missing file simply fails to open and the write is skipped.
	wdb, err := sql.Open("sqlite", l.writeDSN)
	if err != nil {
		return
	}
	defer wdb.Close()
	wdb.SetMaxOpenConns(1)
	if _, err := wdb.ExecContext(ctx, "PRAGMA busy_timeout=0"); err != nil {
		return
	}
	tx, err := wdb.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	if _, err := tx.ExecContext(ctx, verifyReceiptUpsertSQL,
		r.Version, r.KeyFingerprint, r.SignedGenesisAt, r.UnsignedThroughID, r.ThroughID, r.ThroughCount, r.ThroughHeadHash, hex.EncodeToString(r.Digest), r.Sig,
	); err != nil {
		_ = tx.Rollback()
		return
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
	}
}

// optEqual reports whether two optional values are both nil or both present and
// equal — the NULL-vs-value distinction the receipt must preserve when matching
// its bound adoption metadata against the current head.
func optEqual[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
