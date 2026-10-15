package logging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// AnchorV2VerifyResult keeps remote counts unsigned and exact through reporting.
// A valid signed record for another pair is never classified as truncation.
type AnchorV2VerifyResult struct {
	OK                bool
	Classification    string
	Reason            string
	AnchorRowCount    uint64
	LocalRowCount     uint64
	AnchorHeadHash    string
	LocalHeadAtAnchor string
}

// EmitAnchorV2 signs a verified local head with the existing trusted identity.
// It never initializes identity and refuses incomplete or mismatched stores.
func (l *Logger) EmitAnchorV2() (*AnchorV2, error) {
	return l.EmitAnchorV2Context(context.Background())
}

// EmitAnchorV2Context is EmitAnchorV2 with ctx bounding both identity-lock
// acquisition and the verification walk.
func (l *Logger) EmitAnchorV2Context(ctx context.Context) (*AnchorV2, error) {
	return l.EmitAnchorV2Walk(ctx, ctx)
}

// EmitAnchorV2Walk is EmitAnchorV2 with separate deadlines: lockCtx bounds
// identity-lock acquisition and walkCtx bounds the verification walk. The
// identity lock is held for the whole walk (Prune and registration take the
// same lock); an interrupted walk returns ErrVerifyInterrupted and releases it
// on return.
func (l *Logger) EmitAnchorV2Walk(lockCtx, walkCtx context.Context) (*AnchorV2, error) {
	store, err := l.lockChainIdentityStoreContext(lockCtx)
	if err != nil {
		return nil, err
	}
	defer store.close()
	id, err := l.readChainIdentityLocked(store)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, ErrChainIdentityMissing
	}
	return l.emitAnchorV2Locked(walkCtx, id)
}

func (l *Logger) emitAnchorV2Locked(ctx context.Context, id *ChainIdentity) (*AnchorV2, error) {
	if l.signer == nil {
		return nil, errors.New("v2 anchor emission requires the original audit signing key")
	}
	verified, err := l.VerifyChainSignedContext(ctx, l.signer.pub, true)
	if err != nil {
		return nil, err
	}
	if !verified.Intact || verified.SigState != "authentic" {
		return nil, fmt.Errorf("refusing to anchor an unauthentic local chain: %s %s", verified.BrokenReason, verified.SigBrokenReason)
	}
	// The verification result is the authenticated head from one DB snapshot;
	// do not re-read chain_head after its transaction ends.
	a := &AnchorV2{Version: AnchorV2Version, AgentID: id.AgentID, ChainID: id.ChainID,
		HeadHash: verified.HeadHash, RowCount: uint64(verified.EntriesVerified),
		CreatedAt: formatTimestampForChain(time.Now()), LegacyAnchorDigest: id.LegacyAnchorDigest}
	canonical, err := AnchorV2CanonicalBytes(a)
	if err != nil {
		return nil, err
	}
	a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(l.signer.priv, canonical))
	return a, nil
}

// VerifyAgainstAnchorV2 authenticates the expected pair and immutable witness,
// then verifies the local signed chain and head at the anchored count. It never
// converts an unbounded remote uint64 count into a platform-sized int.
func (l *Logger) VerifyAgainstAnchorV2(a *AnchorV2, pub ed25519.PublicKey) (*AnchorV2VerifyResult, error) {
	return l.VerifyAgainstAnchorV2Context(context.Background(), a, pub)
}

// VerifyAgainstAnchorV2Context is VerifyAgainstAnchorV2 with ctx bounding both
// identity-lock acquisition and the verification walk.
func (l *Logger) VerifyAgainstAnchorV2Context(ctx context.Context, a *AnchorV2, pub ed25519.PublicKey) (*AnchorV2VerifyResult, error) {
	return l.VerifyAgainstAnchorV2Walk(ctx, ctx, a, pub)
}

// VerifyAgainstAnchorV2Walk is VerifyAgainstAnchorV2 with separate deadlines for
// identity-lock acquisition (lockCtx) and the verification walk (walkCtx). An
// interrupted walk returns ErrVerifyInterrupted, never a classification.
func (l *Logger) VerifyAgainstAnchorV2Walk(lockCtx, walkCtx context.Context, a *AnchorV2, pub ed25519.PublicKey) (*AnchorV2VerifyResult, error) {
	store, err := l.lockChainIdentityStoreContext(lockCtx)
	if err != nil {
		return nil, err
	}
	defer store.close()
	id, err := l.readChainIdentityLocked(store)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, ErrChainIdentityMissing
	}
	return l.verifyAgainstAnchorV2Locked(walkCtx, a, pub, id)
}

func (l *Logger) verifyAgainstAnchorV2Locked(ctx context.Context, a *AnchorV2, pub ed25519.PublicKey, id *ChainIdentity) (*AnchorV2VerifyResult, error) {
	r := &AnchorV2VerifyResult{}
	if a != nil {
		r.AnchorRowCount, r.AnchorHeadHash = a.RowCount, a.HeadHash
	}
	if pub == nil {
		r.Classification = "no_key"
		r.Reason = "no public key available to authenticate the anchor (supply --ed25519-pub or run on the signing host)"
		return r, nil
	}
	if err := VerifyAnchorV2(a, pub, id.AgentID, id.ChainID); err != nil {
		r.Classification, r.Reason = "forged", err.Error()
		if errors.Is(err, ErrAnchorIdentityMismatch) {
			r.Classification = "identity_mismatch"
		}
		return r, nil
	}
	if a.LegacyAnchorDigest != id.LegacyAnchorDigest {
		r.Classification, r.Reason = "identity_mismatch", "signed legacy witness differs from the trusted identity"
		return r, nil
	}
	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var actual uint64
	if err := tx.QueryRow("SELECT COUNT(*) FROM events").Scan(&actual); err != nil {
		return nil, err
	}
	r.LocalRowCount = actual
	if actual < a.RowCount {
		r.Classification, r.Reason = "truncation", fmt.Sprintf("truncation detected: anchor attests %d rows, local has %d", a.RowCount, actual)
		return r, nil
	}
	// A public-key-only verify --against-anchor / push preflight reads and uses any
	// receipt here but never writes one (it holds no signing key); the anchor emit
	// path, which does hold the key, maintains the receipt via verifyChain.
	verified, _, _, err := verifyChainInTransaction(ctx, tx, pub, true)
	if err != nil {
		return nil, err
	}
	if !verified.Intact || verified.SigState != "authentic" {
		r.Classification, r.Reason = "tampered", "local signed chain failed verification: "+verified.BrokenReason+" "+verified.SigBrokenReason
		return r, nil
	}
	head := chainGenesisHashHex
	if a.RowCount > 0 {
		// Bounded by an actual local count before conversion; SQLite OFFSET
		// accepts int64 and events cannot exceed SQLite's signed row capacity.
		if err := tx.QueryRow("SELECT entry_hash FROM events ORDER BY id ASC LIMIT 1 OFFSET ?", int64(a.RowCount-1)).Scan(&head); err != nil {
			return nil, err
		}
	}
	r.LocalHeadAtAnchor = head
	if head != a.HeadHash {
		r.Classification, r.Reason = "tampered", fmt.Sprintf("local chain does not reproduce the anchored head at %d rows", a.RowCount)
		return r, nil
	}
	r.OK, r.Classification = true, "ok"
	r.Reason = fmt.Sprintf("local signed chain reproduces the anchored head at %d rows (local has %d)", a.RowCount, actual)
	return r, nil
}

// WriteAnchorV2 atomically writes a validated v2 transport record, mode 0600.
func WriteAnchorV2(path string, a *AnchorV2) error {
	data, err := MarshalAnchorV2(a)
	if err != nil {
		return err
	}
	return writeAnchorData(path, data)
}

// ReadAnchorV2 decodes a local v2 anchor; callers must authenticate it and its
// expected identity before trusting any field.
func ReadAnchorV2(path string) (*AnchorV2, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return UnmarshalAnchorV2(data)
}

// AnchorRegistrationFileName retains the exact original signed request outside
// the rollbackable DB. Retrying must not regenerate its timestamp or signature.
const AnchorRegistrationFileName = "anchor-registration.json"

// AnchorRegistrationRequest is the durable original v2 registration. Mode is
// fresh, acknowledge_no_legacy_history, or migrate. Legacy exists only for
// migration and is the authenticated immutable witness, never inferred history.
type AnchorRegistrationRequest struct {
	Version int       `json:"version"`
	Mode    string    `json:"mode"`
	Anchor  *AnchorV2 `json:"anchor"`
	Legacy  *Anchor   `json:"legacy,omitempty"`
}

// RegisterAnchorV2 prepares and durably retains one original request under the
// identity/prune lock, then persists pending before calling send. send must use
// a bounded deadline and authenticate the server's exact registration digest
// and original mode (including already-exists); it returns its signed latest
// anchor. A verified matching local prefix is required before enrollment.
// Neither send nor its callees may recursively take this chain's identity lock.
func (l *Logger) RegisterAnchorV2(mode string, legacy *Anchor, send func(AnchorRegistrationRequest) (*AnchorV2, error)) (*ChainIdentity, error) {
	return l.RegisterAnchorV2Context(context.Background(), mode, legacy, send)
}

// RegisterAnchorV2Context is RegisterAnchorV2 with cancellable identity-lock acquisition.
// Local verification and durable writes remain synchronous and unbounded: an
// interruption after the remote accepted the pin would leave enrollment pending
// for a pin that exists, so ctx bounds only the lock wait and send, which must respect it.
func (l *Logger) RegisterAnchorV2Context(ctx context.Context, mode string, legacy *Anchor, send func(AnchorRegistrationRequest) (*AnchorV2, error)) (*ChainIdentity, error) {
	if l.signer == nil || send == nil {
		return nil, errors.New("v2 registration requires the original signing key and a confirmation callback")
	}
	store, err := l.lockChainIdentityStoreContext(ctx)
	if err != nil {
		return nil, err
	}
	defer store.close()
	id, err := l.readChainIdentityLocked(store)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, ErrChainIdentityMissing
	}
	if err := validateRegistrationMode(mode, legacy, id, l.signer.pub); err != nil {
		return nil, err
	}
	if id.RegistrationState == ChainRegistrationEnrolled {
		return id, nil
	}
	data, err := store.readData(AnchorRegistrationFileName, 16384)
	if err != nil {
		return nil, err
	}
	var request AnchorRegistrationRequest
	if data == nil {
		if id.RegistrationState != ChainRegistrationNone {
			return nil, errors.New("pending registration has lost its original request; restore trusted state, never regenerate it or clear the remote pin")
		}
		anchor, err := l.emitAnchorV2Locked(context.Background(), id)
		if err != nil {
			return nil, err
		}
		request = AnchorRegistrationRequest{Version: 1, Mode: mode, Anchor: anchor, Legacy: legacy}
	} else {
		if err := json.Unmarshal(data, &request); err != nil {
			return nil, fmt.Errorf("invalid original registration: %w", err)
		}
		canonical, err := json.Marshal(&request)
		if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) || request.Version != 1 || request.Mode != mode {
			return nil, errors.New("original registration is malformed or its mode differs; restore the original request and retry with its original mode")
		}
	}
	if err := validateRegistrationMode(request.Mode, request.Legacy, id, l.signer.pub); err != nil {
		return nil, err
	}
	if request.Legacy != nil {
		result, err := l.VerifyAgainstAnchor(request.Legacy, l.signer.pub)
		if err != nil {
			return nil, err
		}
		if !result.OK {
			return nil, fmt.Errorf("legacy migration prefix refused: %s", result.Reason)
		}
	}
	// Verify inside the same lock as prune, on every retry. A prior candidate
	// cannot be pinned after a none-state prune rewrote its signed chain.
	result, err := l.verifyAgainstAnchorV2Locked(context.Background(), request.Anchor, l.signer.pub, id)
	if err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("registration preflight refused: %s", result.Reason)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if data == nil {
		encoded, err := json.Marshal(&request)
		if err != nil {
			return nil, err
		}
		if err := store.writeData(AnchorRegistrationFileName, encoded); err != nil {
			return nil, err
		}
	}
	// If the original request's rename succeeded but directory sync failed,
	// its file data was already synced. On retry the pending rewrite below
	// syncs their shared directory and ancestors before send, making the exact
	// retained request entry durable without regenerating its signed snapshot.
	return l.registerChainIdentityLocked(ctx, store, id, func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
		stored, err := send(request)
		if err != nil {
			return nil, err
		}
		if stored == nil || stored.RowCount < request.Anchor.RowCount || (stored.RowCount == request.Anchor.RowCount && stored.HeadHash != request.Anchor.HeadHash) {
			return nil, errors.New("registration confirmation is older than or conflicts with the original signed request")
		}
		checked, err := l.verifyAgainstAnchorV2Locked(context.Background(), stored, l.signer.pub, id)
		if err != nil {
			return nil, err
		}
		if !checked.OK {
			return nil, fmt.Errorf("registration confirmation refused: %s", checked.Reason)
		}
		return &ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
	})
}

func validateRegistrationMode(mode string, legacy *Anchor, id *ChainIdentity, pub ed25519.PublicKey) error {
	switch mode {
	case "fresh", "acknowledge_no_legacy_history":
		if legacy != nil || id.LegacyAnchorDigest != strings.Repeat("0", 64) {
			return errors.New("fresh registration cannot claim legacy history; use explicit migration")
		}
	case "migrate":
		digest, err := LegacyAnchorSnapshotDigest(legacy, pub)
		if err != nil {
			return err
		}
		if digest != id.LegacyAnchorDigest {
			return errors.New("legacy witness differs from the trusted chain identity; do not replace it")
		}
	default:
		return errors.New("invalid registration mode; use fresh, acknowledge_no_legacy_history, or migrate")
	}
	return nil
}
