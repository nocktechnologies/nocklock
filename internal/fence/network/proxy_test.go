package network

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
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
		got := isBlockedIP(ip)
		if got != tc.blocked {
			t.Errorf("isBlockedIP(%q) = %v, want %v", tc.ip, got, tc.blocked)
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
