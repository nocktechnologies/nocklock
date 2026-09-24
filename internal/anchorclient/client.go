// Package anchorclient pushes external chain-head anchors off-box and fetches
// the latest one back (N10647 Inc.3b, client half). The anchor itself is
// produced and verified by internal/logging; this package only moves it.
//
// Server contract (the NockCC endpoint ships separately):
//
//	POST {base}/api/nocklock/anchors/
//	     body {"anchor": <anchor object>, "pubkey": "<base64 std, 32-byte Ed25519 key>"}
//	     2xx = stored; 409 = refused because row_count would regress below the
//	     latest stored anchor for that agent_id (the server-side monotonic check
//	     is what makes a local rollback observable).
//	GET  {base}/api/nocklock/anchors/{agent_id}/latest/
//	     200 = the latest anchor JSON; 404 = no anchor stored for that agent.
//
// The bearer token is sent only in the Authorization header. It never appears
// in a returned error or a log line, and redirects are not followed, so the
// token cannot be replayed to a different origin.
package anchorclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// EnvURL and EnvToken are the only configuration inputs. The token is read from
// the environment only: never from a config file or a flag.
const (
	EnvURL   = "NOCKLOCK_ANCHOR_URL"
	EnvToken = "NOCKLOCK_ANCHOR_TOKEN"
)

// MaxResponseBytes caps every response body read.
const MaxResponseBytes = 64 << 10

// maxErrorBodyBytes caps the server body text carried in an error.
const maxErrorBodyBytes = 512

// ErrAnchorRegression is returned (wrapped) when the server refuses a push with
// 409 because the anchor's row_count is below the latest stored anchor.
var ErrAnchorRegression = errors.New("anchor store refused a row_count regression")

// ErrNoRemoteAnchor is returned (wrapped) when the server has no anchor stored
// for the requested agent_id (404).
var ErrNoRemoteAnchor = errors.New("no remote anchor stored for this agent")

// httpClient never follows redirects: a 3xx is surfaced as a non-2xx error
// rather than re-sending the request (and its bearer token) elsewhere.
var httpClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// ValidateBaseURL accepts an https:// URL, or an http:// URL whose host is a
// loopback name (127.0.0.1, ::1, localhost) for tests and local development.
// Userinfo, query strings, and fragments are rejected. It returns the base with
// any trailing slash removed.
func ValidateBaseURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("anchor URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid anchor URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid anchor URL: missing host")
	}
	if u.User != nil {
		return "", fmt.Errorf("invalid anchor URL: credentials in the URL are not allowed (use %s)", EnvToken)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid anchor URL: query strings and fragments are not allowed")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(host) {
			return "", fmt.Errorf("invalid anchor URL: http:// is only allowed for loopback hosts (127.0.0.1, ::1, localhost); use https://")
		}
	default:
		return "", fmt.Errorf("invalid anchor URL: scheme must be https (got %q)", u.Scheme)
	}
	return strings.TrimRight(raw, "/"), nil
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

type pushBody struct {
	Anchor *logging.Anchor `json:"anchor"`
	Pubkey string          `json:"pubkey"`
}

// Push stores a on the anchor server. pub is the Ed25519 key the anchor is
// signed with, sent so the server can authenticate the anchor and bind it to
// agent_id. 2xx is success; 409 wraps ErrAnchorRegression; any other status is
// an error carrying the status code. The caller owns the timeout via ctx.
func Push(ctx context.Context, baseURL, token string, a *logging.Anchor, pub ed25519.PublicKey) error {
	if a == nil {
		return fmt.Errorf("anchor push: no anchor")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("anchor push: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	base, err := ValidateBaseURL(baseURL)
	if err != nil {
		return err
	}
	body, err := json.Marshal(pushBody{Anchor: a, Pubkey: base64.StdEncoding.EncodeToString(pub)})
	if err != nil {
		return fmt.Errorf("anchor push: marshal body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/nocklock/anchors/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("anchor push: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	setAuth(req, token)

	status, respBody, err := do(req)
	if err != nil {
		return fmt.Errorf("anchor push: %w", redactErr(err, token))
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrAnchorRegression, errorBodyText(respBody, token))
	default:
		return fmt.Errorf("anchor push: server returned HTTP %d: %s", status, errorBodyText(respBody, token))
	}
}

// FetchLatest returns the latest anchor stored for agentID. 404 wraps
// ErrNoRemoteAnchor. The anchor is decoded with logging.UnmarshalAnchor, the
// same path a local anchor file takes; authenticating it is the caller's job
// (VerifyAgainstAnchor).
func FetchLatest(ctx context.Context, baseURL, token, agentID string) (*logging.Anchor, error) {
	if agentID == "" {
		return nil, fmt.Errorf("anchor fetch: empty agent_id")
	}
	base, err := ValidateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/nocklock/anchors/"+url.PathEscape(agentID)+"/latest/", nil)
	if err != nil {
		return nil, fmt.Errorf("anchor fetch: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	setAuth(req, token)

	status, respBody, err := do(req)
	if err != nil {
		return nil, fmt.Errorf("anchor fetch: %w", redactErr(err, token))
	}
	switch {
	case status == http.StatusNotFound:
		return nil, fmt.Errorf("%w (agent_id %s)", ErrNoRemoteAnchor, agentID)
	case status < 200 || status >= 300:
		return nil, fmt.Errorf("anchor fetch: server returned HTTP %d: %s", status, errorBodyText(respBody, token))
	}
	a, err := logging.UnmarshalAnchor(respBody)
	if err != nil {
		return nil, fmt.Errorf("anchor fetch: invalid anchor JSON from server: %w", err)
	}
	return a, nil
}

func setAuth(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// do sends req and reads at most MaxResponseBytes of the body; a larger body is
// an error rather than a silently truncated read.
func do(req *http.Request) (int, []byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read response body: %w", err)
	}
	if len(data) > MaxResponseBytes {
		return 0, nil, fmt.Errorf("response body exceeds %d bytes (HTTP %d)", MaxResponseBytes, resp.StatusCode)
	}
	return resp.StatusCode, data, nil
}

// errorBodyText renders server body text for an error: scrubbed of the token
// should a server echo it, then truncated to maxErrorBodyBytes.
func errorBodyText(body []byte, token string) string {
	s := string(body)
	if token != "" {
		s = strings.ReplaceAll(s, token, "[redacted]")
	}
	if len(s) > maxErrorBodyBytes {
		s = s[:maxErrorBodyBytes] + "...(truncated)"
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty body)"
	}
	return s
}

// redactErr scrubs the token from a transport error's text. The token only
// travels in a header, so it should never be present, but this keeps the
// no-token-in-errors guarantee independent of the transport's error format.
func redactErr(err error, token string) error {
	if token == "" || !strings.Contains(err.Error(), token) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "[redacted]"))
}
