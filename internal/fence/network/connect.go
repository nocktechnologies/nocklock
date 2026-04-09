package network

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// handleConnect handles HTTP CONNECT tunnel requests for HTTPS.
// It checks the destination hostname against the allowlist, hijacks the connection
// if allowed, and pipes bytes bidirectionally without inspecting the encrypted payload.
//
// Security properties:
//   - No MITM: the proxy never reads or writes the encrypted payload.
//   - Hostname-only inspection: only the CONNECT request host is checked.
//   - Post-DNS IP validation: the safe dialer blocks loopback/private IP SSRF.
//   - Both copy goroutines are joined before returning; connections are closed when
//     either direction finishes so the other goroutine is not left blocked.
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}

	if !p.isAllowed(r.Host) {
		p.logEvent(logging.EventNetworkBlocked, r.Method, host, true)
		http.Error(w, "NockLock: domain not in allowlist", http.StatusForbidden)
		return
	}

	// Dial the destination before hijacking so we can respond with 502 cleanly on failure.
	// p.dial defaults to safeDial, which validates the resolved IP is not loopback/private.
	upstream, err := p.dial(r.Context(), "tcp", r.Host)
	if err != nil {
		p.logEvent(logging.EventNetworkError, r.Method, host, false)
		// Return a generic error — do not leak the resolved IP or internal details.
		http.Error(w, "NockLock: could not connect to upstream", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	p.logEvent(logging.EventNetworkPassed, r.Method, host, false)

	// Hijack the client connection so we can pipe raw bytes.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "NockLock: proxy does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Signal the client that the tunnel is established.
	if _, err := fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// Apply an absolute session deadline to both ends.
	// Note: SetDeadline sets an absolute deadline, not an idle timeout.
	// Connections active for longer than 5 minutes will be terminated.
	// This is acceptable for AI agent workloads; adjust if needed.
	sessionDeadline := time.Now().Add(5 * time.Minute)
	_ = clientConn.SetDeadline(sessionDeadline)
	_ = upstream.SetDeadline(sessionDeadline)

	// Pipe bytes bidirectionally.
	// When one direction finishes, close that connection so the other goroutine's
	// blocked read/write is unblocked rather than waiting until the session deadline.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, clientConn) //nolint:errcheck
		upstream.Close()              // Unblock the upstream → clientConn goroutine.
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upstream) //nolint:errcheck
		clientConn.Close()            // Unblock the clientConn → upstream goroutine.
		done <- struct{}{}
	}()
	// Wait for both directions to complete.
	<-done
	<-done
}
