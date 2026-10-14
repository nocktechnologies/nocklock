package logging

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// AnchorV2Version identifies the opt-in, chain-bound record format. EmitAnchor
// and all existing CLI and network paths still use AnchorVersion (v1).
const AnchorV2Version = 2

const anchorV2SigVersion byte = 0x06

// ErrAnchorIdentityMismatch means a record's key fingerprint differs from the
// supplied key, or an authenticated record differs from the trusted expected
// pair. It must not become a row-count verdict.
var ErrAnchorIdentityMismatch = errors.New("anchor identity mismatch")

// AnchorV2 is a signed chain-head record with an independent chain identity.
// AgentID is the SHA-256 fingerprint of the signing public key. ChainID,
// HeadHash, and LegacyAnchorDigest are 32-byte values in lowercase hex.
// LegacyAnchorDigest is all zeroes for a fresh chain, or the fixed snapshot
// digest of an explicitly selected v1 migration witness. A record alone does
// not prove migration, enrollment, or the relationship between two chain heads.
// RowCount is uint64; JSON consumers must preserve integers without rounding.
// CreatedAt is UTC RFC3339 with zero to nine fractional digits, signed verbatim.
// This type does not create, persist, enroll, or select a chain identity.
type AnchorV2 struct {
	Version            int    `json:"version"`
	AgentID            string `json:"agent_id"`
	ChainID            string `json:"chain_id"`
	HeadHash           string `json:"head_hash"`
	RowCount           uint64 `json:"row_count"`
	CreatedAt          string `json:"created_at"`
	LegacyAnchorDigest string `json:"legacy_anchor_digest"`
	Sig                string `json:"sig"`
}

// AnchorV2CanonicalBytes returns the bytes to sign with Ed25519 after validating
// every signed field (Sig is ignored). Layout: 0x06 || lp(agent_id) || chain_id
// (32 decoded bytes) || head_hash (32 decoded bytes) || row_count (u64be) ||
// lp(created_at) || legacy_anchor_digest (32 decoded bytes). lp is a u32be byte
// length followed by unmodified UTF-8 bytes. Version is bound by the domain byte.
func AnchorV2CanonicalBytes(a *AnchorV2) ([]byte, error) {
	if a == nil {
		return nil, errors.New("anchor v2 record is required")
	}
	if a.Version != AnchorV2Version {
		return nil, fmt.Errorf("unsupported anchor v2 version %d: require version 2", a.Version)
	}
	if _, err := anchorHex32("agent_id", a.AgentID); err != nil {
		return nil, err
	}
	chain, err := anchorHex32("chain_id", a.ChainID)
	if err != nil {
		return nil, err
	}
	head, err := anchorHex32("head_hash", a.HeadHash)
	if err != nil {
		return nil, err
	}
	legacy, err := anchorHex32("legacy_anchor_digest", a.LegacyAnchorDigest)
	if err != nil {
		return nil, err
	}
	if err := anchorTimestamp(a.CreatedAt); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 1+4+64+32+32+8+4+len(a.CreatedAt)+32)
	buf = append(buf, anchorV2SigVersion)
	buf = anchorAppendLP(buf, a.AgentID)
	buf = append(buf, chain...)
	buf = append(buf, head...)
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], a.RowCount)
	buf = append(buf, count[:]...)
	buf = anchorAppendLP(buf, a.CreatedAt)
	return append(buf, legacy...), nil
}

// MarshalAnchorV2 returns compact JSON in struct field order with a padded
// standard-base64 signature. It validates encoding, not authenticity; callers
// must authenticate with VerifyAnchorV2 before trusting the record.
func MarshalAnchorV2(a *AnchorV2) ([]byte, error) {
	if _, err := AnchorV2CanonicalBytes(a); err != nil {
		return nil, err
	}
	sig, err := anchorSignature(a.Sig)
	if err != nil {
		return nil, err
	}
	copy := *a
	copy.Sig = base64.StdEncoding.EncodeToString(sig)
	return json.Marshal(&copy)
}

// UnmarshalAnchorV2 decodes exactly one v2 JSON object. Unknown, duplicate,
// missing, null, or differently cased fields are rejected, as are invalid field
// encodings. Whitespace and field order are transport-only. Authentication and
// expected-pair checks remain mandatory via VerifyAnchorV2.
func UnmarshalAnchorV2(data []byte) (*AnchorV2, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("anchor v2 JSON must be valid UTF-8")
	}
	var a AnchorV2
	fields := map[string]any{
		"version": &a.Version, "agent_id": &a.AgentID, "chain_id": &a.ChainID,
		"head_hash": &a.HeadHash, "row_count": &a.RowCount, "created_at": &a.CreatedAt,
		"legacy_anchor_digest": &a.LegacyAnchorDigest, "sig": &a.Sig,
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("anchor v2 JSON must be an object")
	}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid anchor v2 JSON field: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("anchor v2 JSON field name must be a string")
		}
		target, ok := fields[name]
		if !ok {
			return nil, fmt.Errorf("unknown or duplicate anchor v2 field %q", name)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("invalid anchor v2 field %q: %w", name, err)
		}
		if bytes.Equal(raw, []byte("null")) {
			return nil, fmt.Errorf("anchor v2 field %q must not be null", name)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return nil, fmt.Errorf("invalid anchor v2 field %q: %w", name, err)
		}
		delete(fields, name)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("invalid anchor v2 JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("anchor v2 JSON must contain exactly one object")
	}
	if len(fields) != 0 {
		return nil, errors.New("anchor v2 JSON requires all eight record fields")
	}
	if _, err := MarshalAnchorV2(&a); err != nil {
		return nil, err
	}
	return &a, nil
}

// VerifyAnchorV2 authenticates the record and requires its signed identity to
// match the caller's trusted expected pair. Neither expected ID may be empty.
// It makes no chain-continuity or row-count verdict and does not enroll a chain.
func VerifyAnchorV2(a *AnchorV2, pub ed25519.PublicKey, expectedAgentID, expectedChainID string) error {
	cb, err := AnchorV2CanonicalBytes(a)
	if err != nil {
		return err
	}
	if _, err := verifyAnchorRecord(a.AgentID, a.Sig, cb, pub); err != nil {
		return err
	}
	if _, err := anchorHex32("expected agent_id", expectedAgentID); err != nil {
		return err
	}
	if _, err := anchorHex32("expected chain_id", expectedChainID); err != nil {
		return err
	}
	if a.AgentID != expectedAgentID || a.ChainID != expectedChainID {
		return fmt.Errorf("%w: signed pair differs from the trusted expected pair", ErrAnchorIdentityMismatch)
	}
	return nil
}

// AnchorV2SnapshotDigest authenticates an expected v2 record and returns its
// lowercase SHA-256 snapshot digest: "nocklock-anchor-snapshot-v2\x00" followed
// by canonical signed bytes and the decoded 64-byte signature. JSON formatting
// and accepted base64 spelling do not affect this digest.
func AnchorV2SnapshotDigest(a *AnchorV2, pub ed25519.PublicKey, expectedAgentID, expectedChainID string) (string, error) {
	if err := VerifyAnchorV2(a, pub, expectedAgentID, expectedChainID); err != nil {
		return "", err
	}
	cb, _ := AnchorV2CanonicalBytes(a) // Validated above; no state or I/O involved.
	sig, _ := anchorSignature(a.Sig)
	return anchorSnapshotDigest("nocklock-anchor-snapshot-v2\x00", cb, sig), nil
}

// LegacyAnchorSnapshotDigest authenticates a v1 record and returns its migration
// witness digest using the v1 snapshot domain and unchanged v1 signed encoding.
// IDs and hashes must be canonical lowercase hex. It does not establish project
// ownership or migrate a chain; callers must separately verify the chosen local
// chain reproduces this legacy head. Existing v1 readers/verifiers are unchanged.
func LegacyAnchorSnapshotDigest(a *Anchor, pub ed25519.PublicKey) (string, error) {
	if a == nil || a.Version != AnchorVersion {
		return "", errors.New("legacy anchor snapshot requires a version 1 record")
	}
	if _, err := anchorHex32("agent_id", a.AgentID); err != nil {
		return "", err
	}
	if _, err := anchorHex32("head_hash", a.HeadHash); err != nil {
		return "", err
	}
	if err := anchorTimestamp(a.CreatedAt); err != nil {
		return "", err
	}
	cb, err := anchorCanonicalBytes(a)
	if err != nil {
		return "", err
	}
	sig, err := verifyAnchorRecord(a.AgentID, a.Sig, cb, pub)
	if err != nil {
		return "", err
	}
	return anchorSnapshotDigest("nocklock-anchor-snapshot-v1\x00", cb, sig), nil
}

func anchorHex32(name, value string) ([]byte, error) {
	if len(value) != 64 || strings.ToLower(value) != value {
		return nil, fmt.Errorf("anchor %s must be 64 lowercase hexadecimal characters", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("anchor %s must be 64 lowercase hexadecimal characters", name)
	}
	return decoded, nil
}

func anchorTimestamp(value string) error {
	if len(value) < 20 || len(value) == 21 || len(value) > 30 {
		return errors.New("anchor created_at must be UTC RFC3339 with at most nine fractional digits")
	}
	layout := "2006-01-02T15:04:05"
	if len(value) > 20 {
		layout += "." + strings.Repeat("0", len(value)-21)
	}
	layout += "Z"
	parsed, err := time.Parse(layout, value)
	if err != nil || parsed.Format(layout) != value {
		return errors.New("anchor created_at must be UTC RFC3339 with at most nine fractional digits")
	}
	return nil
}

func anchorSignature(value string) ([]byte, error) {
	// Accept padded/unpadded standard base64 and CR/LF transport wrapping, but
	// reject nonzero padding bits. MarshalAnchorV2 always writes one spelling.
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", "")
	var sig []byte
	var err error
	switch len(value) {
	case 88:
		sig, err = base64.StdEncoding.Strict().DecodeString(value)
	case 86:
		sig, err = base64.RawStdEncoding.Strict().DecodeString(value)
	default:
		return nil, errors.New("anchor sig must encode a 64-byte Ed25519 signature in standard base64")
	}
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("anchor sig must encode a 64-byte Ed25519 signature in standard base64")
	}
	return sig, nil
}

func verifyAnchorRecord(agentID, signature string, cb []byte, pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("anchor verification requires a 32-byte Ed25519 public key")
	}
	if publicKeyFingerprint(pub) != agentID {
		return nil, fmt.Errorf("%w: agent_id does not match the supplied public key", ErrAnchorIdentityMismatch)
	}
	sig, err := anchorSignature(signature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, cb, sig) {
		return nil, errors.New("anchor signature does not verify against the supplied public key")
	}
	return sig, nil
}

func anchorSnapshotDigest(domain string, cb, sig []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(cb)
	h.Write(sig)
	return hex.EncodeToString(h.Sum(nil))
}
