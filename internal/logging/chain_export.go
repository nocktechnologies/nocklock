package logging

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
)

// Exported wrappers over the audit-chain primitives, so the public read-only
// verifier (pkg/receipt) checks rows with the exact code the writer and
// VerifyChain use. These are thin delegations, not copies: there is one
// implementation of the canonical encoding, the hash link, and the row
// signature check, and it lives in logger.go and signing.go.

// ChainGenesisHashHex is the prev_hash of the first row in an intact chain
// (the hex SHA-256 of the empty input). Prune re-anchors the first surviving
// row to it, so it holds after pruning too.
const ChainGenesisHashHex = chainGenesisHashHex

// CanonicalBytes returns the canonical byte encoding of one events row, the
// bytes both the entry_hash and the entry_sig cover. ts must be the stored
// timestamp string exactly as written, not a re-formatted value.
func CanonicalBytes(id int64, ts string, eventType, category, detail string, blocked bool, sessionID string) []byte {
	return canonicalBytes(id, ts, EventType(eventType), category, detail, blocked, sessionID)
}

// ChainEntryFromCanonical returns the hex entry_hash for a row, computed as
// SHA-256(canonical || prev_hash). It errors when prevHashHex is not 32 bytes
// of hex.
func ChainEntryFromCanonical(canonical []byte, prevHashHex string) (string, error) {
	return chainEntryFromCanonical(canonical, prevHashHex)
}

// VerifyRowSig reports whether sigB64 is a valid base64 Ed25519 signature by
// pub over a row's canonical bytes. A malformed signature is false, never an
// error.
func VerifyRowSig(pub ed25519.PublicKey, canonical []byte, sigB64 string) bool {
	return verifyRowSig(pub, canonical, sigB64)
}

// ChainHead is the stored chain_head record: the signed tail anchor that
// commits to the last row's entry_hash and the total row count. Its signature
// (domain byte 0x03) also covers pruning, signing-adoption, and public-key
// metadata, which travel with the value unexported so a caller cannot verify a
// head against metadata other than what was stored.
type ChainHead struct {
	Hash     string // entry_hash of the last row (genesis for an empty chain)
	RowCount int    // number of rows the head anchors
	Sig      string // base64 Ed25519 head signature, empty when unsigned

	meta headSignatureMetadata
}

// chainHeadColumns are the chain_head columns readChainHeadRecord selects.
var chainHeadColumns = []string{
	"entry_hash", "row_count", "migrated_at", "legacy_through_id", "pruned_at",
	"pruned_count", "head_sig", "signed_genesis_at", "unsigned_through_id",
	"signing_pubkey_fingerprint",
}

// ReadChainHead reads the chain_head record inside tx with the same reader
// nocklock verify uses. found is false, with a nil error, when the log has no
// head to read: no chain_head table, a table from a schema that predates the
// signed head (missing columns), or no head row. It never writes, so it is
// safe on a read-only connection.
func ReadChainHead(tx *sql.Tx) (head ChainHead, found bool, err error) {
	rows, err := tx.Query("SELECT name FROM pragma_table_info('chain_head')")
	if err != nil {
		return ChainHead{}, false, fmt.Errorf("inspect chain_head schema: %w", err)
	}
	cols := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return ChainHead{}, false, fmt.Errorf("inspect chain_head schema: %w", err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ChainHead{}, false, fmt.Errorf("inspect chain_head schema: %w", err)
	}
	rows.Close()
	for _, c := range chainHeadColumns {
		if !cols[c] {
			return ChainHead{}, false, nil
		}
	}

	rec, err := readChainHeadRecord(tx)
	if errors.Is(err, sql.ErrNoRows) {
		return ChainHead{}, false, nil
	}
	if err != nil {
		return ChainHead{}, false, fmt.Errorf("read chain_head: %w", err)
	}
	return ChainHead{Hash: rec.hash, RowCount: rec.rowCount, Sig: rec.sig, meta: rec.meta}, true, nil
}

// CanonicalBytes returns the domain-separated bytes the head signature covers
// (see headCanonicalBytes). It errors when the stored hash or public-key
// fingerprint is malformed.
func (h ChainHead) CanonicalBytes() ([]byte, error) {
	return headCanonicalBytes(h.Hash, h.RowCount, h.meta)
}

// VerifySig reports whether the head's signature verifies under pub, with the
// same check nocklock verify applies. An empty or malformed signature is false.
func (h ChainHead) VerifySig(pub ed25519.PublicKey) bool {
	return verifyHeadSig(pub, h.Hash, h.RowCount, h.meta, h.Sig)
}
