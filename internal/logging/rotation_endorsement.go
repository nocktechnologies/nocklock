package logging

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const rotationDomain = "nocklock-rotation-endorsement-v1\x00"
const rotationDigestDomain = "nocklock-rotation-endorsement-digest-v1\x00"
const rotationUseDomain = "nocklock-rotation-acceptance-v1\x00"

// Rotation verification failure classes are stable errors for errors.Is.
var (
	ErrRotationRootMismatch     = errors.New("rotation lineage root mismatch: supply the independently trusted first-key fingerprint")
	ErrRotationIdentityMismatch = errors.New("rotation identity mismatch: check the retiring key and old chain")
	ErrRotationTailMismatch     = errors.New("rotation tail/count mismatch or truncation: preserve and investigate the old tail")
	ErrRotationReplay           = errors.New("rotation replay: endorsement names a different successor or new chain")
	ErrRotationMissing          = errors.New("rotation endorsement missing: supply the transition bundle")
	ErrRotationUnused           = errors.New("rotation endorsement unused: successor acceptance is required")
	ErrRotationBadSignature     = errors.New("rotation signature invalid: preserve and investigate the bundle")
	ErrRotationMalformed        = errors.New("rotation encoding malformed: supply a canonical version 1 bundle")
)

// RotationEndorsement is a separate record, never an AnchorV2 extension.
// All byte strings are lowercase hex; signatures use standard base64. An empty
// Acceptance explicitly represents an unused endorsement. OldPublicKey is
// authenticated against the caller's trusted old ChainIdentity.AgentID.
type RotationEndorsement struct {
	Version            int    `json:"version"`
	LineageRoot        string `json:"lineage_root"`
	OldChainID         string `json:"old_chain_id"`
	NewChainID         string `json:"new_chain_id"`
	HeadHash           string `json:"head_hash"`
	RowCount           uint64 `json:"row_count"`
	SuccessorPublicKey string `json:"successor_public_key"`
	OldPublicKey       string `json:"old_public_key"`
	Sig                string `json:"sig"`
	Acceptance         string `json:"acceptance"`
}

// RotationEndorsementCanonicalBytes validates signed fields and returns domain,
// version byte 1, root, old chain, new chain, tail, u64be count, successor key,
// and retiring key, in that order. All byte strings occupy exactly 32 bytes.
func RotationEndorsementCanonicalBytes(r *RotationEndorsement) ([]byte, error) {
	if r == nil || r.Version != 1 {
		return nil, ErrRotationMalformed
	}
	b := append([]byte(rotationDomain), byte(1))
	for _, s := range []string{r.LineageRoot, r.OldChainID, r.NewChainID, r.HeadHash} {
		v, e := anchorHex32("rotation field", s)
		if e != nil {
			return nil, fmt.Errorf("%w: %v", ErrRotationMalformed, e)
		}
		b = append(b, v...)
	}
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], r.RowCount)
	b = append(b, count[:]...)
	for _, s := range []string{r.SuccessorPublicKey, r.OldPublicKey} {
		v, e := anchorHex32("rotation key", s)
		if e != nil {
			return nil, fmt.Errorf("%w: %v", ErrRotationMalformed, e)
		}
		b = append(b, v...)
	}
	return b, nil
}

func rotationSignatures(r *RotationEndorsement) (sig, acceptance []byte, err error) {
	sig, err = anchorSignature(r.Sig)
	if err == nil && r.Acceptance != "" {
		acceptance, err = anchorSignature(r.Acceptance)
	}
	if err != nil {
		err = fmt.Errorf("%w: %v", ErrRotationMalformed, err)
	}
	return
}

// MarshalRotationEndorsement emits compact JSON with normalized signatures.
// It checks encoding only; VerifyRotationEndorsement must authenticate it.
func MarshalRotationEndorsement(r *RotationEndorsement) ([]byte, error) {
	if _, err := RotationEndorsementCanonicalBytes(r); err != nil {
		return nil, err
	}
	sig, use, err := rotationSignatures(r)
	if err != nil {
		return nil, err
	}
	c := *r
	c.Sig = base64.StdEncoding.EncodeToString(sig)
	if use != nil {
		c.Acceptance = base64.StdEncoding.EncodeToString(use)
	}
	return json.Marshal(&c)
}

// UnmarshalRotationEndorsement rejects unknown, duplicate, missing, differently
// cased or null fields, malformed UTF-8, invalid encodings and trailing data.
// Empty input is a missing endorsement; an empty acceptance is unused.
func UnmarshalRotationEndorsement(data []byte) (*RotationEndorsement, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrRotationMissing
	}
	if !utf8.Valid(data) {
		return nil, ErrRotationMalformed
	}
	var r RotationEndorsement
	fields := map[string]any{
		"version": &r.Version, "lineage_root": &r.LineageRoot,
		"old_chain_id": &r.OldChainID, "new_chain_id": &r.NewChainID,
		"head_hash": &r.HeadHash, "row_count": &r.RowCount,
		"successor_public_key": &r.SuccessorPublicKey, "old_public_key": &r.OldPublicKey,
		"sig": &r.Sig, "acceptance": &r.Acceptance,
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if tok, e := d.Token(); e != nil || tok != json.Delim('{') {
		return nil, ErrRotationMalformed
	}
	for d.More() {
		tok, e := d.Token()
		if e != nil {
			return nil, ErrRotationMalformed
		}
		name, ok := tok.(string)
		if !ok {
			return nil, ErrRotationMalformed
		}
		target, ok := fields[name]
		if !ok {
			return nil, ErrRotationMalformed
		}
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil || bytes.Equal(raw, []byte("null")) {
			return nil, ErrRotationMalformed
		}
		if e = json.Unmarshal(raw, target); e != nil {
			return nil, ErrRotationMalformed
		}
		delete(fields, name)
	}
	if tok, e := d.Token(); e != nil || tok != json.Delim('}') {
		return nil, ErrRotationMalformed
	}
	if _, e := d.Token(); e != io.EOF || len(fields) != 0 {
		return nil, ErrRotationMalformed
	}
	if _, e := MarshalRotationEndorsement(&r); e != nil {
		return nil, e
	}
	return &r, nil
}

func rotationDigest(cb, sig []byte) string {
	return anchorSnapshotDigest(rotationDigestDomain, cb, sig)
}
func rotationAcceptanceBytes(digest string) []byte {
	raw, _ := hex.DecodeString(digest)
	return append([]byte(rotationUseDomain), raw...)
}

// VerifyRotationEndorsement authenticates both signatures before making any
// tail/count verdict. root is the independently pinned first-key fingerprint,
// not a value inferred from either chain or this bundle. old and next must be
// trusted ChainIdentity records; their agent IDs authenticate the supplied keys.
// No store is read, no state is changed, and repeat verification of the exact
// same transition is idempotent. This does not prove enrollment or key switching.
func VerifyRotationEndorsement(r *RotationEndorsement, root string, old, next *ChainIdentity, head string, count uint64, successor ed25519.PublicKey) error {
	if r == nil {
		return ErrRotationMissing
	}
	cb, err := RotationEndorsementCanonicalBytes(r)
	if err != nil {
		return err
	}
	sig, use, err := rotationSignatures(r)
	if err != nil {
		return err
	}
	retiring, _ := hex.DecodeString(r.OldPublicKey)
	if _, err = verifyAnchorRecord(publicKeyFingerprint(retiring), r.Sig, cb, retiring); err != nil {
		return ErrRotationBadSignature
	}
	nextKey, _ := hex.DecodeString(r.SuccessorPublicKey)
	if len(use) == 0 {
		return ErrRotationUnused
	}
	if !ed25519.Verify(nextKey, rotationAcceptanceBytes(rotationDigest(cb, sig)), use) {
		return ErrRotationBadSignature
	}
	if _, err = anchorHex32("trusted root", root); err != nil {
		return ErrRotationMalformed
	}
	if _, err = anchorHex32("expected tail", head); err != nil {
		return ErrRotationMalformed
	}
	if old == nil || next == nil || len(successor) != ed25519.PublicKeySize {
		return ErrRotationMalformed
	}
	if validateChainIdentity(old) != nil || validateChainIdentity(next) != nil {
		return ErrRotationMalformed
	}
	if r.LineageRoot != root {
		return ErrRotationRootMismatch
	}
	if old.AgentID != publicKeyFingerprint(retiring) || old.ChainID != r.OldChainID {
		return ErrRotationIdentityMismatch
	}
	if next.AgentID != publicKeyFingerprint(successor) || r.SuccessorPublicKey != hex.EncodeToString(successor) || next.ChainID != r.NewChainID {
		return ErrRotationReplay
	}
	if r.OldChainID == r.NewChainID {
		return ErrRotationIdentityMismatch
	}
	if r.HeadHash != head || r.RowCount != count {
		return ErrRotationTailMismatch
	}
	return nil
}
