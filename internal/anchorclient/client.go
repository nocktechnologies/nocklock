// Package anchorclient provides the shared HTTP transport for authenticated
// v2 anchor registration, migration, and conditional updates (client_v2.go).
//
// The bearer token is sent only in the Authorization header. It never appears
// in a returned error or a log line, and redirects are not followed, so the
// token cannot be replayed to a different origin.
package anchorclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
