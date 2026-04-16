package network

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdogHealthyProxyDoesNotFire(t *testing.T) {
	// Start a real TCP listener to represent a healthy proxy.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	var fired atomic.Bool
	onFailure := func() { fired.Store(true) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewProxyWatchdog(ln.Addr().String(), 20*time.Millisecond, 2, onFailure)
	w.Start(ctx)

	// Wait a few intervals — watchdog must not fire.
	time.Sleep(120 * time.Millisecond)

	if fired.Load() {
		t.Error("watchdog fired on healthy proxy")
	}
}

func TestWatchdogDetectsProxyFailure(t *testing.T) {
	// Start a listener, then close it to simulate proxy crash.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	addr := ln.Addr().String()

	var fired atomic.Bool
	onFailure := func() { fired.Store(true) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewProxyWatchdog(addr, 20*time.Millisecond, 2, onFailure)
	w.Start(ctx)

	// Give the watchdog a moment to start, then kill the proxy.
	time.Sleep(10 * time.Millisecond)
	ln.Close()

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

func TestWatchdogStopsOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	var fired atomic.Bool
	onFailure := func() { fired.Store(true) }

	ctx, cancel := context.WithCancel(context.Background())

	w := NewProxyWatchdog(ln.Addr().String(), 20*time.Millisecond, 2, onFailure)
	w.Start(ctx)

	// Cancel the context.
	cancel()
	time.Sleep(80 * time.Millisecond)

	// Close the listener after cancel — watchdog should be stopped and not fire.
	ln.Close()
	time.Sleep(80 * time.Millisecond)

	if fired.Load() {
		t.Error("watchdog fired after context was cancelled")
	}
}
