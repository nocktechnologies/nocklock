package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// cgnat is the IANA Shared Address Space (RFC 6598) — 100.64.0.0/10.
// Carrier-grade NAT addresses are not routable on the public internet and
// must not be reachable via the proxy to prevent SSRF.
var cgnat = &net.IPNet{
	IP:   net.ParseIP("100.64.0.0").To4(),
	Mask: net.CIDRMask(10, 32),
}

// isBlockedIP reports whether ip should never be dialed by the proxy.
// Blocks loopback, unspecified (0.0.0.0/::), link-local unicast, multicast,
// RFC-1918 private ranges, and CGNAT (100.64.0.0/10).
func isBlockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		if cgnat.Contains(ip4) {
			return true
		}
	}
	return ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate()
}

// safeDial resolves addr, rejects loopback/private IPs (SSRF prevention),
// and dials the first safe address. It matches the http.Transport.DialContext signature.
func safeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("NockLock: invalid address %q: %w", addr, err)
	}

	// Resolve the hostname inside the timeout context.
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("NockLock: DNS lookup failed for %q: %w", host, err)
	}

	for _, rawIP := range ips {
		ip := net.ParseIP(rawIP)
		if ip == nil {
			continue
		}
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("NockLock: resolved address %s is in a blocked range", rawIP)
		}
		conn, dialErr := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(
			ctx, network, net.JoinHostPort(rawIP, port),
		)
		if dialErr == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("NockLock: could not connect to %q: all resolved addresses failed", host)
}

// DialFunc matches the signature expected by http.Transport.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ProxyServer is a local HTTP/HTTPS proxy that enforces the network allowlist.
// It binds exclusively to 127.0.0.1 on a randomly assigned port.
type ProxyServer struct {
	listener  net.Listener
	allowList []string
	allowAll  bool
	logger    *logging.Logger
	sessionID string
	server    *http.Server
	transport *http.Transport
	// dialFunc is used by handleConnect to establish upstream connections.
	// Defaults to safeDial which validates resolved IPs. Overridable in tests.
	dialFunc DialFunc
}

// NewProxyServer creates a ProxyServer from a NetworkConfig.
func NewProxyServer(cfg config.NetworkConfig, logger *logging.Logger, sessionID string) *ProxyServer {
	p := &ProxyServer{
		allowList: cfg.Allow,
		allowAll:  cfg.AllowAll,
		logger:    logger,
		sessionID: sessionID,
		dialFunc:  safeDial,
	}
	// Shared transport with:
	//   - No proxy chaining (Proxy: nil) — prevents ambient HTTP_PROXY from re-routing traffic.
	//   - Safe dial via closure so tests can override p.dialFunc.
	//   - Explicit connection limits to prevent resource exhaustion.
	p.transport = &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.dial(ctx, network, addr)
		},
		// Connection pool limits.
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return p
}

// Start binds to 127.0.0.1:0 (OS assigns the port) and begins serving.
// Returns the bound address as "127.0.0.1:PORT".
func (p *ProxyServer) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("network fence: failed to bind proxy: %w", err)
	}
	p.listener = ln

	p.server = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	go p.server.Serve(ln) //nolint:errcheck // Serve returns ErrServerClosed on Stop()

	addr := ln.Addr().String()
	if p.logger != nil {
		_ = p.logger.Log(logging.Event{
			Timestamp: time.Now(),
			EventType: logging.EventProxyStart,
			Category:  "network",
			Detail:    fmt.Sprintf("addr=%s", addr),
			Blocked:   false,
			SessionID: p.sessionID,
		})
	}
	return addr, nil
}

// Stop shuts down the proxy server gracefully.
// After Stop returns, Addr() returns "" and the server will not accept new connections.
func (p *ProxyServer) Stop() error {
	if p.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := p.server.Shutdown(ctx)

	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}

	// Clear server and listener so Addr() returns "" and Stop() is idempotent.
	p.server = nil
	p.listener = nil

	if p.logger != nil {
		_ = p.logger.Log(logging.Event{
			Timestamp: time.Now(),
			EventType: logging.EventProxyStop,
			Category:  "network",
			Detail:    "proxy stopped",
			Blocked:   false,
			SessionID: p.sessionID,
		})
	}
	return err
}

// dial dials addr using p.dialFunc, falling back to safeDial if unset.
func (p *ProxyServer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.dialFunc != nil {
		return p.dialFunc(ctx, network, addr)
	}
	return safeDial(ctx, network, addr)
}

// Addr returns the bound address, or empty string if not started.
func (p *ProxyServer) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}
