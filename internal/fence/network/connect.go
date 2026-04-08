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

	// Dial the destination before hijacking so we can 502 cleanly on failure.
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	upstream, err := dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		p.logEvent(logging.EventNetworkError, r.Method, host, false)
		http.Error(w, fmt.Sprintf("NockLock: could not connect to %s: %v", r.Host, err), http.StatusBadGateway)
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

	// Apply idle timeout to both ends to bound resource usage.
	idleDeadline := time.Now().Add(5 * time.Minute)
	_ = clientConn.SetDeadline(idleDeadline)
	_ = upstream.SetDeadline(idleDeadline)

	// Pipe bytes bidirectionally. Both goroutines close when either side closes.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, clientConn) //nolint:errcheck
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upstream) //nolint:errcheck
		done <- struct{}{}
	}()
	<-done
}
