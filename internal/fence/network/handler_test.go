package network

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// isAllowedTests covers the pure domain-matching logic.
var isAllowedTests = []struct {
	name      string
	allowList []string
	allowAll  bool
	hostname  string
	want      bool
}{
	{
		name:      "exact match",
		allowList: []string{"github.com"},
		hostname:  "github.com",
		want:      true,
	},
	{
		name:      "subdomain of allowed apex",
		allowList: []string{"github.com"},
		hostname:  "api.github.com",
		want:      true,
	},
	{
		name:      "deep subdomain of allowed apex",
		allowList: []string{"github.com"},
		hostname:  "objects.githubusercontent.com",
		want:      false, // not a direct subdomain of github.com
	},
	{
		name:      "wildcard entry matches subdomain",
		allowList: []string{"*.example.com"},
		hostname:  "sub.example.com",
		want:      true,
	},
	{
		name:      "wildcard entry does NOT match apex",
		allowList: []string{"*.example.com"},
		hostname:  "example.com",
		want:      false,
	},
	{
		name:      "case insensitive hostname",
		allowList: []string{"GitHub.COM"},
		hostname:  "github.com",
		want:      true,
	},
	{
		name:      "port stripped before matching",
		allowList: []string{"github.com"},
		hostname:  "github.com:443",
		want:      true,
	},
	{
		name:      "allow_all bypasses check",
		allowList: []string{},
		allowAll:  true,
		hostname:  "evil.com",
		want:      true,
	},
	{
		name:      "empty allowlist blocks everything",
		allowList: []string{},
		hostname:  "github.com",
		want:      false,
	},
	{
		name:      "raw IPv4 address blocked",
		allowList: []string{"github.com"},
		hostname:  "203.0.113.42",
		want:      false,
	},
	{
		name:      "raw IPv6 address blocked",
		allowList: []string{"github.com"},
		hostname:  "2001:db8::1",
		want:      false,
	},
	{
		name:      "not in allowlist",
		allowList: []string{"github.com"},
		hostname:  "evil-exfil.com",
		want:      false,
	},
	{
		name:      "multiple entries, second matches",
		allowList: []string{"github.com", "api.anthropic.com"},
		hostname:  "api.anthropic.com",
		want:      true,
	},
}

func TestIsAllowed(t *testing.T) {
	for _, tc := range isAllowedTests {
		t.Run(tc.name, func(t *testing.T) {
			p := &ProxyServer{allowList: tc.allowList, allowAll: tc.allowAll}
			got := p.isAllowed(tc.hostname)
			if got != tc.want {
				t.Errorf("isAllowed(%q) = %v, want %v (allowList=%v, allowAll=%v)",
					tc.hostname, got, tc.want, tc.allowList, tc.allowAll)
			}
		})
	}
}

// TestServeHTTP_BlockedDomain checks that the HTTP handler returns 403 for blocked domains.
func TestServeHTTP_BlockedDomain(t *testing.T) {
	p := &ProxyServer{allowList: []string{"allowed.com"}}

	// Build a fake outbound request to a blocked host.
	req := httptest.NewRequest(http.MethodGet, "http://blocked.com/path", nil)
	req.RequestURI = "http://blocked.com/path"
	req.Host = "blocked.com"
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if string(body) == "" {
		t.Error("expected non-empty body for blocked request")
	}
}

// TestServeHTTP_NockLockIdentifierInBlockedBody verifies the NockLock identifier appears.
func TestServeHTTP_NockLockIdentifierInBlockedBody(t *testing.T) {
	p := &ProxyServer{allowList: []string{}}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RequestURI = "http://example.com/"
	req.Host = "example.com"
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "NockLock") {
		t.Errorf("expected body to contain 'NockLock', got: %q", string(body))
	}
}
