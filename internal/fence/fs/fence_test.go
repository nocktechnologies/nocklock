package fs

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- Task 4: OS Detection and Event Type Tests ---

func TestIsSupported(t *testing.T) {
	got := IsSupported()
	want := runtime.GOOS == "linux"
	if got != want {
		t.Errorf("IsSupported() = %v, want %v (GOOS=%s)", got, want, runtime.GOOS)
	}
}

func TestUnsupportedError(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("test only runs on non-Linux platforms")
	}
	err := CheckSupported()
	if err == nil {
		t.Fatal("expected error on non-Linux OS, got nil")
	}
	// Error should mention the current OS.
	if got := err.Error(); !strings.Contains(got, runtime.GOOS) {
		t.Errorf("error should mention %s, got: %s", runtime.GOOS, got)
	}
	// Error should mention macOS support coming soon.
	if got := err.Error(); !strings.Contains(got, "macOS support coming soon") {
		t.Errorf("error should mention macOS support, got: %s", got)
	}
}

func TestFenceEvent_UnmarshalJSON(t *testing.T) {
	raw := `{"type":"fs","action":"blocked","path":"/home/user/.ssh/id_rsa","operation":"open","reason":"denied path","timestamp":"2026-04-07T22:30:00Z"}`
	var event FenceEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if event.Type != "fs" {
		t.Errorf("Type = %q, want %q", event.Type, "fs")
	}
	if event.Action != "blocked" {
		t.Errorf("Action = %q, want %q", event.Action, "blocked")
	}
	if event.Path != "/home/user/.ssh/id_rsa" {
		t.Errorf("Path = %q, want %q", event.Path, "/home/user/.ssh/id_rsa")
	}
	if event.Operation != "open" {
		t.Errorf("Operation = %q, want %q", event.Operation, "open")
	}
	if event.Reason != "denied path" {
		t.Errorf("Reason = %q, want %q", event.Reason, "denied path")
	}
	if event.Timestamp != "2026-04-07T22:30:00Z" {
		t.Errorf("Timestamp = %q, want %q", event.Timestamp, "2026-04-07T22:30:00Z")
	}
}

// --- Task 5: Go Fence Wrapper Tests ---

func TestNewFence_CreatesSocket(t *testing.T) {
	if !IsSupported() {
		t.Skip("filesystem fence not supported on " + runtime.GOOS)
	}

	cfg := &FenceConfig{
		Root:       "/tmp",
		Mode:       "read-write",
		AllowPaths: []string{"/tmp"},
		DenyPaths:  []string{"/etc/shadow"},
	}

	fence, err := NewFence(cfg, "/usr/lib/libfence_fs.so")
	if err != nil {
		t.Fatalf("NewFence error: %v", err)
	}
	defer fence.Close()

	// Verify socket file exists.
	if fence.SocketPath == "" {
		t.Fatal("SocketPath is empty")
	}
	info, err := os.Stat(fence.SocketPath)
	if err != nil {
		t.Fatalf("socket file does not exist: %v", err)
	}
	// On Linux, Unix domain sockets have ModeSocket set.
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("expected socket file, got mode %v", info.Mode())
	}
}

func TestFence_EnvVars(t *testing.T) {
	if !IsSupported() {
		t.Skip("filesystem fence not supported on " + runtime.GOOS)
	}

	cfg := &FenceConfig{
		Root:       "/home/user/project",
		Mode:       "read-write",
		AllowPaths: []string{"/tmp"},
		DenyPaths:  []string{"/home/user/.ssh"},
	}

	fence, err := NewFence(cfg, "/usr/lib/libfence_fs.so")
	if err != nil {
		t.Fatalf("NewFence error: %v", err)
	}
	defer fence.Close()

	envVars := fence.EnvVars()

	var foundPreload, foundAllowed bool
	for _, env := range envVars {
		if strings.HasPrefix(env, "LD_PRELOAD=") {
			foundPreload = true
			if env != "LD_PRELOAD=/usr/lib/libfence_fs.so" {
				t.Errorf("LD_PRELOAD = %q, want LD_PRELOAD=/usr/lib/libfence_fs.so", env)
			}
		}
		if strings.HasPrefix(env, "NOCKLOCK_FS_ALLOWED=") {
			foundAllowed = true
		}
	}
	if !foundPreload {
		t.Error("LD_PRELOAD not found in env vars")
	}
	if !foundAllowed {
		t.Error("NOCKLOCK_FS_ALLOWED not found in env vars")
	}
}

func TestFence_ListenReceivesEvents(t *testing.T) {
	if !IsSupported() {
		t.Skip("filesystem fence not supported on " + runtime.GOOS)
	}

	cfg := &FenceConfig{
		Root:       "/tmp",
		Mode:       "read-write",
		AllowPaths: []string{"/tmp"},
		DenyPaths:  []string{"/etc/shadow"},
	}

	fence, err := NewFence(cfg, "/usr/lib/libfence_fs.so")
	if err != nil {
		t.Fatalf("NewFence error: %v", err)
	}
	defer fence.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := fence.Listen(ctx)

	// Connect to the socket and send a JSON event.
	conn, err := net.Dial("unix", fence.SocketPath)
	if err != nil {
		t.Fatalf("dial socket error: %v", err)
	}

	eventJSON := `{"type":"fs","action":"blocked","path":"/etc/shadow","operation":"open","reason":"denied path","timestamp":"2026-04-07T22:30:00Z"}` + "\n"
	if _, err := conn.Write([]byte(eventJSON)); err != nil {
		t.Fatalf("write error: %v", err)
	}
	conn.Close()

	// Read event from channel with timeout.
	select {
	case event := <-ch:
		if event.Type != "fs" {
			t.Errorf("Type = %q, want %q", event.Type, "fs")
		}
		if event.Action != "blocked" {
			t.Errorf("Action = %q, want %q", event.Action, "blocked")
		}
		if event.Path != "/etc/shadow" {
			t.Errorf("Path = %q, want %q", event.Path, "/etc/shadow")
		}
		if event.Operation != "open" {
			t.Errorf("Operation = %q, want %q", event.Operation, "open")
		}
		if event.Reason != "denied path" {
			t.Errorf("Reason = %q, want %q", event.Reason, "denied path")
		}
		if event.Timestamp != "2026-04-07T22:30:00Z" {
			t.Errorf("Timestamp = %q, want %q", event.Timestamp, "2026-04-07T22:30:00Z")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}
