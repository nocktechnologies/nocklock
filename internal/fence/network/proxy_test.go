package network

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

func makeProxy(allowList []string) *ProxyServer {
	return NewProxyServer(config.NetworkConfig{Allow: allowList}, nil, "test-session")
}

// TestProxyStartsAndBindsToLocalhost verifies the proxy binds to 127.0.0.1.
func TestProxyStartsAndBindsToLocalhost(t *testing.T) {
	p := makeProxy([]string{"example.com"})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer p.Stop()

	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("expected addr to start with 127.0.0.1:, got %q", addr)
	}
}

// TestProxyBindsToRandomPort verifies the port is not hardcoded (> 1024).
func TestProxyBindsToRandomPort(t *testing.T) {
	p := makeProxy([]string{"example.com"})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer p.Stop()

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("could not parse addr %q: %v", addr, err)
	}
	// Port must be non-zero.
	if portStr == "0" || portStr == "" {
		t.Errorf("expected a real port, got %q", portStr)
	}
}

// TestProxyStopsCleanly verifies Stop() does not error.
func TestProxyStopsCleanly(t *testing.T) {
	p := makeProxy(nil)
	if _, err := p.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

// TestProxyStopIdempotent verifies double Stop() does not panic or error.
func TestProxyStopIdempotent(t *testing.T) {
	p := makeProxy(nil)
	if _, err := p.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	_ = p.Stop()
	if err := p.Stop(); err != nil {
		t.Errorf("second Stop() error: %v", err)
	}
}

// TestProxyOnlyListensOnLocalhost verifies the proxy is not bound to 0.0.0.0.
func TestProxyOnlyListensOnLocalhost(t *testing.T) {
	p := makeProxy(nil)
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer p.Stop()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("could not parse addr %q: %v", addr, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("proxy must bind to 127.0.0.1 only, got %q", host)
	}
}

// TestProxyAddrEmptyBeforeStart verifies Addr() returns "" before Start().
func TestProxyAddrEmptyBeforeStart(t *testing.T) {
	p := makeProxy(nil)
	if p.Addr() != "" {
		t.Errorf("Addr() before Start() should be empty, got %q", p.Addr())
	}
}

// TestProxyAddrAfterStart verifies Addr() returns the bound address after Start().
func TestProxyAddrAfterStart(t *testing.T) {
	p := makeProxy(nil)
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer p.Stop()

	if p.Addr() != addr {
		t.Errorf("Addr() = %q, want %q", p.Addr(), addr)
	}
}

// TestProxyTwoInstancesBindDifferentPorts ensures random port assignment works for concurrent proxies.
func TestProxyTwoInstancesBindDifferentPorts(t *testing.T) {
	p1 := makeProxy(nil)
	addr1, err := p1.Start()
	if err != nil {
		t.Fatalf("p1 Start() error: %v", err)
	}
	defer p1.Stop()

	p2 := makeProxy(nil)
	addr2, err := p2.Start()
	if err != nil {
		t.Fatalf("p2 Start() error: %v", err)
	}
	defer p2.Stop()

	if addr1 == addr2 {
		t.Errorf("two proxy instances bound to the same address: %q", addr1)
	}
}

func TestProxyStartFailsWhenPortUnavailable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := makeProxy(nil)
	p.listenAddr = ln.Addr().String()

	if _, err := p.Start(); err == nil {
		t.Fatal("Start() should fail when the configured proxy port is unavailable")
	}
}

func TestProxyDialFailsClosedWhenDegraded(t *testing.T) {
	p := makeProxy([]string{"example.com"})
	p.dialFunc = func(context.Context, string, string) (net.Conn, error) {
		server, client := net.Pipe()
		_ = server.Close()
		return client, nil
	}

	p.MarkDegraded("watchdog failure")

	conn, err := p.dial(t.Context(), "tcp", "example.com:443")
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("dial should fail closed when the proxy is degraded")
	}
	if !strings.Contains(err.Error(), "degraded") {
		t.Fatalf("dial error should mention degraded state, got %v", err)
	}
}

// TestIsBlockedIP covers the SSRF prevention helper.
func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},             // loopback
		{"::1", true},                   // IPv6 loopback
		{"10.0.0.1", true},              // RFC-1918
		{"172.16.5.5", true},            // RFC-1918
		{"192.168.1.1", true},           // RFC-1918
		{"169.254.10.1", true},          // link-local
		{"100.64.0.1", true},            // CGNAT
		{"0.0.0.0", true},               // unspecified
		{"224.0.0.1", true},             // multicast
		{"ff02::1", true},               // IPv6 link-local multicast
		{"8.8.8.8", false},              // public
		{"2001:4860:4860::8888", false}, // public IPv6
		// 198.51.100.0/24 is TEST-NET-2 (documentation range, not routable in production,
		// but not in any standard blocked range so safeDial allows it).
		{"198.51.100.1", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("invalid test IP: %q", tc.ip)
		}
		got := isBlockedIP(ip, false)
		if got != tc.blocked {
			t.Errorf("isBlockedIP(%q, allowPrivateRanges=false) = %v, want %v", tc.ip, got, tc.blocked)
		}
	}
}

// TestSafeDialBlocksLoopback verifies safeDial refuses loopback addresses.
func TestSafeDialBlocksLoopback(t *testing.T) {
	// Start a real server on localhost to confirm the refusal is about IP, not connectivity.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	defer ln.Close()

	_, err = safeDial(t.Context(), "tcp", ln.Addr().String())
	if err == nil {
		t.Error("safeDial should have refused loopback address, but succeeded")
	}
}

// TestProxyBlockedRequestReturns403 is an end-to-end HTTP test through the proxy.
func TestProxyBlockedRequestReturns403(t *testing.T) {
	p := makeProxy([]string{"allowed.com"})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer p.Stop()

	// Use the proxy to send a request to a blocked domain.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(r *http.Request) (*url.URL, error) {
				return url.Parse("http://" + addr)
			},
		},
	}
	resp, err := client.Get("http://blocked.com/test")
	if err != nil {
		// http.Client may return an error for 4xx responses depending on redirect
		// handling. Only fail on unexpected errors (non-HTTP errors).
		if resp == nil {
			t.Fatalf("proxy request failed with no response: %v", err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxyHealthEndpointReady(t *testing.T) {
	p := makeProxy(nil)
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer p.Stop()

	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get("http://" + addr + ProxyHealthPath)
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestWaitForProxyReadySucceeds(t *testing.T) {
	p := makeProxy([]string{"example.com"})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer p.Stop()

	if err := WaitForProxyReady(t.Context(), addr, time.Second); err != nil {
		t.Fatalf("WaitForProxyReady() error: %v", err)
	}
}

func TestWaitForProxyReadyFailsClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if err := WaitForProxyReady(t.Context(), addr, 75*time.Millisecond); err == nil {
		t.Fatal("WaitForProxyReady() should fail for a closed port")
	}
}

func TestCachedSafeDialLogsDNSRebind(t *testing.T) {
	projectRoot := t.TempDir()
	logger, err := logging.NewLogger(filepath.Join(projectRoot, ".nock", "events.db"), "")
	if err != nil {
		t.Fatalf("NewLogger() error: %v", err)
	}
	defer logger.Close()

	callCount := 0
	resolver := func(_ context.Context, _ string) ([]string, error) {
		callCount++
		if callCount == 1 {
			return []string{"93.184.216.34"}, nil
		}
		return []string{"192.168.1.20"}, nil
	}

	p := NewProxyServer(config.NetworkConfig{Allow: []string{"target.com"}}, logger, "sess-dns-rebind")
	p.dnsCache = newDNSCacheWithResolver(resolver)

	if _, err := p.dnsCache.LookupOrResolve(t.Context(), "target.com"); err != nil {
		t.Fatalf("initial lookup should pin: %v", err)
	}
	_, err = p.cachedSafeDial(t.Context(), "tcp", "target.com:443")
	if err == nil {
		t.Fatal("cachedSafeDial should block rebinding")
	}

	blocked := true
	events, err := logger.Query(logging.QueryOptions{
		Blocked:   &blocked,
		SessionID: stringPtr("sess-dns-rebind"),
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 blocked event, got %d: %+v", len(events), events)
	}
	if events[0].EventType != logging.EventNetworkBlocked {
		t.Fatalf("event type = %s, want %s", events[0].EventType, logging.EventNetworkBlocked)
	}
	if !strings.Contains(events[0].Detail, "dns_rebind host=target.com") {
		t.Fatalf("event detail should mention dns_rebind, got %q", events[0].Detail)
	}
}

func stringPtr(s string) *string {
	return &s
}
