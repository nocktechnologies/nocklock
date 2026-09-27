package network

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdogHealthyProxyDoesNotFire(t *testing.T) {
	p := makeProxy(nil)
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer p.Stop()

	var fired atomic.Bool
	onFailure := func() { fired.Store(true) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewProxyWatchdog(addr, 20*time.Millisecond, 2, onFailure)
	w.Start(ctx)

	// Wait a few intervals — watchdog must not fire.
	time.Sleep(120 * time.Millisecond)

	if fired.Load() {
		t.Error("watchdog fired on healthy proxy")
	}
}

func TestWatchdogDetectsProxyFailure(t *testing.T) {
	p := makeProxy(nil)
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}

	var fired atomic.Bool
	onFailure := func() { fired.Store(true) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewProxyWatchdog(addr, 20*time.Millisecond, 2, onFailure)
	w.Start(ctx)

	// Give the watchdog a moment to start, then kill the proxy.
	time.Sleep(10 * time.Millisecond)
	_ = p.Stop()

	// Wait for N consecutive failures + interval buffer.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if fired.Load() {
			return // pass
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("watchdog did not fire after proxy failure")
}

func TestUnixWatchdogDetectsProxyFailure(t *testing.T) {
	p := makeProxy(nil)
	dir, err := os.MkdirTemp("/tmp", "nlproxy-watchdog-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	socketPath := filepath.Join(dir, "proxy.sock")
	if _, err := p.StartUnix(socketPath, "127.0.0.1:41234"); err != nil {
		t.Fatalf("failed to start unix proxy: %v", err)
	}

	var fired atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewUnixProxyWatchdog(socketPath, 20*time.Millisecond, 2, func() {
		fired.Store(true)
	})
	w.Start(ctx)

	time.Sleep(10 * time.Millisecond)
	_ = p.Stop()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if fired.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("unix watchdog did not fire after proxy failure")
}

func TestWatchdogTriggersFailClosedAfterThreshold(t *testing.T) {
	p := makeProxy(nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var fired atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewProxyWatchdog(addr, 10*time.Millisecond, 2, func() {
		p.MarkDegraded("watchdog failure")
		fired.Store(true)
		cancel()
	})
	w.Start(ctx)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if fired.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !fired.Load() {
		t.Fatal("watchdog did not invoke onFailure after the failure threshold")
	}

	p.dialFunc = func(context.Context, string, string) (net.Conn, error) {
		server, client := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	if _, err := p.dial(t.Context(), "tcp", "example.com:443"); err == nil {
		t.Fatal("proxy should refuse dials after watchdog marks it degraded")
	}
}

func TestWatchdogStopsOnContextCancel(t *testing.T) {
	p := makeProxy(nil)
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer p.Stop()

	var fired atomic.Bool
	onFailure := func() { fired.Store(true) }

	ctx, cancel := context.WithCancel(context.Background())

	w := NewProxyWatchdog(addr, 20*time.Millisecond, 2, onFailure)
	w.Start(ctx)

	// Cancel the context.
	cancel()
	time.Sleep(80 * time.Millisecond)

	// Close the listener after cancel — watchdog should be stopped and not fire.
	_ = p.Stop()
	time.Sleep(80 * time.Millisecond)

	if fired.Load() {
		t.Error("watchdog fired after context was cancelled")
	}
}

func TestWatchdogProbeRejectsRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case ProxyHealthPath:
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/ok":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "http://")
	w := NewProxyWatchdog(addr, 20*time.Millisecond, 1, func() {})

	if w.probe(context.Background()) {
		t.Fatal("watchdog probe should not follow redirects to a healthy endpoint")
	}
}

func TestWatchdogProbeUsesContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "http://")
	w := NewProxyWatchdog(addr, 20*time.Millisecond, 1, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if w.probe(ctx) {
		t.Fatal("watchdog probe should fail when the context is already canceled")
	}
}
