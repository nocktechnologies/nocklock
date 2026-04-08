// Package network implements a local HTTP/HTTPS proxy for NockLock's network fence.
// The proxy inspects only the destination hostname — it never decrypts HTTPS payloads.
package network

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// isAllowed reports whether the given hostname is permitted by the proxy's allowlist.
//
// Rules:
//   - Port suffix is stripped before matching.
//   - If allowAll is true, all hostnames are permitted.
//   - Raw IP addresses (v4 or v6) are always blocked (fail closed).
//   - An exact allowlist entry "github.com" permits "github.com" and "*.github.com".
//   - A wildcard entry "*.example.com" permits "sub.example.com" but not "example.com".
//   - Matching is case-insensitive.
//   - An empty allowlist blocks everything (correct fail-closed behaviour).
func (p *ProxyServer) isAllowed(hostname string) bool {
	if p.allowAll {
		return true
	}

	// Strip port.
	host := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	// Block raw IP addresses.
	if net.ParseIP(host) != nil {
		return false
	}

	for _, entry := range p.allowList {
		entry = strings.ToLower(entry)

		if strings.HasPrefix(entry, "*.") {
			// Wildcard entry: matches subdomain only, not the apex.
			suffix := entry[1:] // e.g. ".example.com"
			if strings.HasSuffix(host, suffix) {
				return true
			}
		} else {
			// Apex entry: matches exact hostname or any direct-or-deep subdomain.
			if host == entry || strings.HasSuffix(host, "."+entry) {
				return true
			}
		}
	}
	return false
}

// ServeHTTP handles incoming proxy requests. CONNECT requests are routed to
// handleConnect; all other methods are handled as forward-proxy requests.
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}

	if !p.isAllowed(host) {
		p.logEvent(logging.EventNetworkBlocked, r.Method, host, true)
		http.Error(w, "NockLock: domain not in allowlist", http.StatusForbidden)
		return
	}

	p.logEvent(logging.EventNetworkPassed, r.Method, host, false)
	p.forwardHTTP(w, r)
}

// forwardHTTP proxies a plain HTTP request to the destination.
func (p *ProxyServer) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	// Ensure the request URL is absolute so the reverse proxy can dial the target.
	if !r.URL.IsAbs() {
		scheme := "http"
		target := &url.URL{
			Scheme:   scheme,
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
		r.URL = target
	}

	// Remove hop-by-hop headers before forwarding.
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Te")
	r.Header.Del("Trailers")
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Upgrade")

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Director is a no-op; the URL is already absolute.
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, fmt.Sprintf("NockLock: proxy error: %v", err), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

// logEvent writes a network event if a logger is attached.
func (p *ProxyServer) logEvent(eventType logging.EventType, method, host string, blocked bool) {
	if p.logger == nil {
		return
	}
	_ = p.logger.Log(logging.Event{
		Timestamp: time.Now(),
		EventType: eventType,
		Category:  "network",
		Detail:    fmt.Sprintf("method=%s host=%s", method, host),
		Blocked:   blocked,
		SessionID: p.sessionID,
	})
}
