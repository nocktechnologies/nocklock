package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unsafeDial is a test-only dialer that allows loopback connections.
// This bypasses safeDial's SSRF protection so tests can use local TCP servers.
func unsafeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// dialProxy returns a raw TCP connection to the proxy and issues a CONNECT request.
// It returns the raw connection (for the caller to use as a tunnel) and the proxy response.
func dialCONNECT(t *testing.T, proxyAddr, targetHost string) (net.Conn, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("could not connect to proxy: %v", err)
	}

	req, _ := http.NewRequest(http.MethodConnect, "http://"+proxyAddr, nil)
	req.Host = targetHost
	if err := req.Write(conn); err != nil {
		conn.Close()
		t.Fatalf("could not write CONNECT request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		t.Fatalf("could not read CONNECT response: %v", err)
	}
	return conn, resp
}

// TestCONNECTAllowedReturns200 verifies allowed CONNECT returns 200.
func TestCONNECTAllowedReturns200(t *testing.T) {
	// Start a dummy TCP server on localhost to accept the tunnel connection.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start target: %v", err)
	}
	defer target.Close()
	_, targetPort, _ := net.SplitHostPort(target.Addr().String())

	go func() {
		c, _ := target.Accept()
		if c != nil {
			c.Close()
		}
	}()

	// Use "localhost" in the allowlist. Inject unsafeDial so the proxy can connect
	// back to our local target (safeDial blocks loopback by design).
	p := makeProxy([]string{"localhost"})
	p.dialFunc = unsafeDial
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("proxy Start() error: %v", err)
	}
	defer p.Stop()

	conn, resp := dialCONNECT(t, addr, "localhost:"+targetPort)
	defer conn.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestCONNECTBlockedReturns403 verifies that CONNECT to a blocked host returns 403.
func TestCONNECTBlockedReturns403(t *testing.T) {
	p := makeProxy([]string{"allowed.com"})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("proxy Start() error: %v", err)
	}
	defer p.Stop()

	conn, resp := dialCONNECT(t, addr, "blocked.com:443")
	defer conn.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestCONNECTBlockedBodyContainsNockLock verifies the response body on block.
func TestCONNECTBlockedBodyContainsNockLock(t *testing.T) {
	p := makeProxy([]string{})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("proxy Start() error: %v", err)
	}
	defer p.Stop()

	conn, resp := dialCONNECT(t, addr, "evil.com:443")
	defer conn.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "NockLock") {
		t.Errorf("expected body to contain 'NockLock', got: %q", string(body))
	}
}

// TestCONNECTRawIPBlocked verifies raw IP CONNECT requests are blocked.
func TestCONNECTRawIPBlocked(t *testing.T) {
	p := makeProxy([]string{"github.com"})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("proxy Start() error: %v", err)
	}
	defer p.Stop()

	conn, resp := dialCONNECT(t, addr, "203.0.113.42:443")
	defer conn.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for raw IP, got %d", resp.StatusCode)
	}
}

// TestHandleConnect_BlockedCases verifies all block conditions via httptest.ResponseRecorder.
// (The recorder cannot hijack, so only 403 responses — which return before hijack — can be
// fully verified here. Allowed-host tunnelling is covered by TestCONNECTAllowedReturns200.)
func TestHandleConnect_BlockedCases(t *testing.T) {
	cases := []struct {
		name      string
		allowList []string
		host      string
	}{
		{"blocked host not in allowlist", []string{"allowed.com"}, "evil.com:443"},
		{"raw IP blocked", []string{"github.com"}, "1.2.3.4:443"},
		{"empty allowlist blocks everything", nil, "any.com:443"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &ProxyServer{allowList: tc.allowList}

			req, _ := http.NewRequest(http.MethodConnect, "http://proxy", nil)
			req.Host = tc.host
			req.RequestURI = tc.host

			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("host %q: expected 403, got %d", tc.host, w.Code)
			}
		})
	}
}

// TestHandleConnect_AllowedDoesNotReturn403 verifies that an allowed CONNECT host
// does not get a 403. The dial is stubbed so no real network access occurs.
// The recorder can't hijack so the final response is 500 (hijack unsupported),
// but the critical assertion is that the allowlist check does not return 403.
func TestHandleConnect_AllowedDoesNotReturn403(t *testing.T) {
	p := &ProxyServer{
		allowList: []string{"example.com"},
		// Stub the dialer so this test never touches the real network.
		dialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("test stub: no real dialing")
		},
	}

	req, _ := http.NewRequest(http.MethodConnect, "http://proxy", nil)
	req.Host = "example.com:443"
	req.RequestURI = "example.com:443"

	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Errorf("allowed host 'example.com' should not get 403, got %d", w.Code)
	}
}
