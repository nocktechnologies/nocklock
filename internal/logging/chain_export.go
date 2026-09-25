package logging

import "crypto/ed25519"

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
