package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// ProxyServer is a local HTTP/HTTPS proxy that enforces the network allowlist.
// It binds exclusively to 127.0.0.1 on a randomly assigned port.
type ProxyServer struct {
	listener  net.Listener
	allowList []string
	allowAll  bool
	logger    *logging.Logger
	sessionID string
	server    *http.Server
}

// NewProxyServer creates a ProxyServer from a NetworkConfig.
func NewProxyServer(cfg config.NetworkConfig, logger *logging.Logger, sessionID string) *ProxyServer {
	return &ProxyServer{
		allowList: cfg.Allow,
		allowAll:  cfg.AllowAll,
		logger:    logger,
		sessionID: sessionID,
	}
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
func (p *ProxyServer) Stop() error {
	if p.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := p.server.Shutdown(ctx)

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

// Addr returns the bound address, or empty string if not started.
func (p *ProxyServer) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}
