package anchorclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// ErrAnchorConflict means a conditional v2 operation did not advance the pin.
var ErrAnchorConflict = errors.New("anchor store refused the conditional update")

// ErrNoLegacyHistory means an upgraded store explicitly reported no v1 pin.
// A generic HTTP 404 from an older store is not this confirmation.
var ErrNoLegacyHistory = errors.New("the v2 store has no retained legacy anchor for this key")

// V2Result contains authenticated stored state returned by a v2 transition.
// The caller must still compare the anchor with its local signed chain.
type V2Result struct {
	Anchor             *logging.AnchorV2
	RegistrationDigest string
	Code               string
}

type v2Envelope struct {
	Success bool `json:"success"`
	Data    struct {
		Code               string          `json:"code"`
		AgentID            string          `json:"agent_id"`
		ChainID            string          `json:"chain_id"`
		LegacyDigest       string          `json:"legacy_anchor_digest"`
		SnapshotDigest     string          `json:"snapshot_digest"`
		RegistrationDigest string          `json:"registration_digest"`
		Anchor             json.RawMessage `json:"anchor"`
	} `json:"data"`
}

func canonicalDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func checkV2Pair(agentID, chainID string, pub ed25519.PublicKey) error {
	if !canonicalDigest(agentID) || !canonicalDigest(chainID) || len(pub) != ed25519.PublicKeySize || logging.PublicKeyFingerprint(pub) != agentID {
		return fmt.Errorf("anchor v2 requires the trusted local chain ID and matching signing public key")
	}
	return nil
}

func requestV2(ctx context.Context, baseURL, token, method, path string, body []byte) (int, []byte, error) {
	base, err := ValidateBaseURL(baseURL)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, base+"/api/nocklock/anchors/v2/"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("anchor v2 request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	setAuth(req, token)
	status, data, err := do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("anchor v2: %w", redactErr(err, token))
	}
	return status, data, nil
}

func v2StatusError(status int, data []byte, token string) error {
	switch status {
	case http.StatusNotFound:
		return fmt.Errorf("%w: v2 endpoint or stream unavailable; upgrade the store or explicitly enroll the project (no v1 fallback)", ErrNoRemoteAnchor)
	case http.StatusMethodNotAllowed, http.StatusNotImplemented, http.StatusUpgradeRequired:
		return fmt.Errorf("anchor v2 requires an upgraded store (HTTP %d); no v1 fallback is permitted", status)
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrAnchorConflict, errorBodyText(data, token))
	default:
		return fmt.Errorf("anchor v2: server returned HTTP %d: %s", status, errorBodyText(data, token))
	}
}

// FetchLatestV2 fetches and authenticates only the expected signed pair. Missing
// or unsupported v2 routes fail; this function never calls a v1 endpoint.
func FetchLatestV2(ctx context.Context, baseURL, token, agentID, chainID string, pub ed25519.PublicKey) (*logging.AnchorV2, error) {
	if err := checkV2Pair(agentID, chainID, pub); err != nil {
		return nil, err
	}
	status, data, err := requestV2(ctx, baseURL, token, http.MethodGet, agentID+"/"+chainID+"/latest/", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, v2StatusError(status, data, token)
	}
	a, err := logging.UnmarshalAnchorV2(data)
	if err != nil {
		return nil, fmt.Errorf("invalid remote v2 anchor: %w", redactErr(err, token))
	}
	if err := logging.VerifyAnchorV2(a, pub, agentID, chainID); err != nil {
		return nil, redactErr(err, token)
	}
	return a, nil
}

// FetchLegacyForMigration reads a v1 snapshot only from the migration-only v2
// route and authenticates it. It is never a remote-verification fallback.
func FetchLegacyForMigration(ctx context.Context, baseURL, token, agentID string, pub ed25519.PublicKey) (*logging.Anchor, error) {
	if err := checkV2Pair(agentID, strings.Repeat("0", 64), pub); err != nil {
		return nil, err
	}
	status, data, err := requestV2(ctx, baseURL, token, http.MethodGet, agentID+"/legacy/", nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		var reply v2Envelope
		if json.Unmarshal(data, &reply) == nil && reply.Data.Code == "legacy_missing" {
			return nil, ErrNoLegacyHistory
		}
	}
	if status != http.StatusOK {
		return nil, v2StatusError(status, data, token)
	}
	a, err := logging.UnmarshalAnchor(data)
	if err != nil {
		return nil, fmt.Errorf("invalid legacy migration anchor: %w", redactErr(err, token))
	}
	if _, err := logging.LegacyAnchorSnapshotDigest(a, pub); err != nil {
		return nil, redactErr(err, token)
	}
	return a, nil
}

// RegisterV2 conditionally creates a new remote pin. An already_exists response
// is accepted only for this exact original signed registration and expected pair.
// The caller durably marks registration pending before calling this function.
func RegisterV2(ctx context.Context, baseURL, token string, a *logging.AnchorV2, pub ed25519.PublicKey, acknowledgeNoLegacy bool) (*V2Result, error) {
	mode := "fresh"
	if acknowledgeNoLegacy {
		mode = "acknowledge_no_legacy_history"
	}
	if a == nil || a.LegacyAnchorDigest != strings.Repeat("0", 64) {
		return nil, fmt.Errorf("fresh v2 registration requires a zero legacy digest; use explicit migration")
	}
	return transitionV2(ctx, baseURL, token, "register/", a, pub, "mode", mode)
}

// PushV2 updates an existing pin with an authenticated previous-snapshot CAS.
// The caller verifies both candidate and remote heads against the local chain.
func PushV2(ctx context.Context, baseURL, token string, a *logging.AnchorV2, pub ed25519.PublicKey, expectedPrevious string) (*V2Result, error) {
	if !canonicalDigest(expectedPrevious) {
		return nil, fmt.Errorf("v2 push requires a canonical previous snapshot digest")
	}
	return transitionV2(ctx, baseURL, token, "", a, pub, "expected_previous", expectedPrevious)
}

// MigrateV2 explicitly assigns retained legacy history to a verified pair. The
// caller proves the local chain reproduces the legacy head before this request.
func MigrateV2(ctx context.Context, baseURL, token string, a *logging.AnchorV2, pub ed25519.PublicKey, expectedLegacy string) (*V2Result, error) {
	if !canonicalDigest(expectedLegacy) || expectedLegacy == strings.Repeat("0", 64) || a == nil || a.LegacyAnchorDigest != expectedLegacy {
		return nil, fmt.Errorf("v2 migration requires the authenticated legacy snapshot digest in both request and signed anchor")
	}
	return transitionV2(ctx, baseURL, token, "migrate/", a, pub, "expected_legacy", expectedLegacy)
}

func transitionV2(ctx context.Context, baseURL, token, path string, a *logging.AnchorV2, pub ed25519.PublicKey, field, value string) (*V2Result, error) {
	if a == nil {
		return nil, fmt.Errorf("anchor v2: no candidate")
	}
	candidateDigest, err := logging.AnchorV2SnapshotDigest(a, pub, a.AgentID, a.ChainID)
	if err != nil {
		return nil, fmt.Errorf("anchor v2 candidate: %w", err)
	}
	body, err := json.Marshal(map[string]any{"anchor": a, "pubkey": base64.StdEncoding.EncodeToString(pub), field: value})
	if err != nil {
		return nil, err
	}
	status, data, err := requestV2(ctx, baseURL, token, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	var reply v2Envelope
	if err := json.Unmarshal(data, &reply); err != nil {
		if status != 200 && status != 201 {
			return nil, v2StatusError(status, data, token)
		}
		return nil, fmt.Errorf("anchor v2: invalid stored-state response")
	}
	alreadyRegistered := path == "register/" && status == 409 && reply.Data.Code == "already_exists"
	validStatus := (status == 200 || status == 201) && reply.Success
	validCode := (path == "" && (reply.Data.Code == "stored" || reply.Data.Code == "already_stored")) ||
		(path == "register/" && reply.Data.Code == "registered") ||
		(path == "migrate/" && (reply.Data.Code == "registered" || reply.Data.Code == "already_migrated"))
	if !(validStatus && validCode) && !alreadyRegistered {
		return nil, v2StatusError(status, data, token)
	}
	stored, err := logging.UnmarshalAnchorV2(reply.Data.Anchor)
	if err != nil {
		return nil, fmt.Errorf("anchor v2: invalid stored anchor: %w", redactErr(err, token))
	}
	digest, err := logging.AnchorV2SnapshotDigest(stored, pub, a.AgentID, a.ChainID)
	if err != nil {
		return nil, fmt.Errorf("anchor v2: stored anchor authentication failed: %w", redactErr(err, token))
	}
	if stored.LegacyAnchorDigest != a.LegacyAnchorDigest || reply.Data.AgentID != a.AgentID || reply.Data.ChainID != a.ChainID ||
		reply.Data.LegacyDigest != a.LegacyAnchorDigest || reply.Data.SnapshotDigest != digest || !canonicalDigest(reply.Data.RegistrationDigest) {
		return nil, fmt.Errorf("anchor v2: stored identity or snapshot metadata mismatch")
	}
	if path != "" && reply.Data.RegistrationDigest != candidateDigest {
		return nil, fmt.Errorf("anchor v2: response does not confirm this exact original registration")
	}
	if path != "" && (stored.RowCount < a.RowCount || (stored.RowCount == a.RowCount && stored.HeadHash != a.HeadHash)) {
		return nil, fmt.Errorf("anchor v2: stored confirmation rolls back or conflicts with the original registration")
	}
	if path == "" && (stored.RowCount != a.RowCount || stored.HeadHash != a.HeadHash) {
		return nil, fmt.Errorf("anchor v2: response does not confirm the submitted head")
	}
	return &V2Result{Anchor: stored, RegistrationDigest: reply.Data.RegistrationDigest, Code: reply.Data.Code}, nil
}
