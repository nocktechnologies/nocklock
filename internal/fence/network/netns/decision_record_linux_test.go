//go:build linux

package netns

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type observedReadConn struct {
	net.Conn
	readStarted chan struct{}
	once        sync.Once
}

func (c *observedReadConn) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.readStarted) })
	return c.Conn.Read(b)
}

func TestShutdownDuringTLSHelloDoesNotRecordDeny(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOCKLOCK_TRANSPARENT_DENY_LOG", filepath.Join(t.TempDir(), "denies.log"))
	client, peer := net.Pipe()
	defer peer.Close()
	observed := &observedReadConn{Conn: client, readStarted: make(chan struct{})}
	p := &transparentProxy{decisionLog: f, active: map[net.Conn]net.Conn{observed: nil}}
	p.connWG.Add(1)
	go func() {
		defer p.connWG.Done()
		p.handleTLS(observed)
	}()
	select {
	case <-observed.readStarted:
	case <-time.After(time.Second):
		t.Fatal("TLS handler did not start reading")
	}
	p.shutdown()
	rows, err := os.ReadFile(path)
	if err != nil || len(rows) != 0 {
		t.Fatalf("shutdown decision rows = %q, %v", rows, err)
	}
	if rows, err := os.ReadFile(os.Getenv("NOCKLOCK_TRANSPARENT_DENY_LOG")); err == nil && len(rows) != 0 {
		t.Fatalf("shutdown deny rows = %q", rows)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestMalformedTLSHelloStillRecordsDeny(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	p := &transparentProxy{decisionLog: f}
	done := make(chan struct{})
	go func() { p.handleTLS(client); close(done) }()
	if _, err := peer.Write([]byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("malformed TLS handler did not return")
	}
	rows, err := os.ReadFile(path)
	if err != nil || string(rows) != "deny\ttls\t\t443\tdisallowed_sni\n" {
		t.Fatalf("malformed TLS decision rows = %q, %v", rows, err)
	}
}

func TestShutdownDrainsIdleTunnelAndRecordsBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer peer.Close()
	defer upstreamPeer.Close()
	p := &transparentProxy{decisionLog: f, active: map[net.Conn]net.Conn{client: upstream}}
	p.connWG.Add(1)
	go func() {
		defer p.connWG.Done()
		var sent int64
		defer p.recordBytesOut("tls", "allowed.test", "443", &sent)
		sent = pipeConnections(client, upstream)
	}()
	go func() { _, _ = peer.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(upstreamPeer, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("upstream read = %q, %v", buf, err)
	}
	done := make(chan struct{})
	go func() { p.shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle tunnel held sidecar shutdown open")
	}
	rows, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(rows), "bytes\ttls\tallowed.test\t443\t5\n") {
		t.Fatalf("byte report = %q, %v", rows, err)
	}
}

func TestPipeConnectionsCountsOnlyUpstreamDirection(t *testing.T) {
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = upstream.SetDeadline(time.Now().Add(time.Second))
	done := make(chan int64, 1)
	go func() { done <- pipeConnections(client, upstream) }()
	go func() { _, _ = clientPeer.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(upstreamPeer, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("upstream read = %q, %v", buf, err)
	}
	go func() { _, _ = upstreamPeer.Write([]byte("reply")) }()
	if _, err := io.ReadFull(clientPeer, buf); err != nil || string(buf) != "reply" {
		t.Fatalf("client read = %q, %v", buf, err)
	}
	_ = clientPeer.Close()
	_ = upstreamPeer.Close()
	if n := <-done; n != 5 {
		t.Fatalf("upstream bytes = %d, want 5", n)
	}
}

// These tests exercise the transparent proxy's recordDecision in isolation with
// plain file I/O — no root, no netns, no proxy sockets. They assert the
// fail-closed contract (F1): a lost or corruptible decision record is an error
// the caller must treat as a denial.

func TestRecordDecisionWritesFullLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open decision log: %v", err)
	}
	p := &transparentProxy{decisionLog: f}

	if err := p.recordDecision("allow", "tls", "example.com", "443", "allowlisted"); err != nil {
		t.Fatalf("recordDecision(allow) returned error: %v", err)
	}
	if err := p.recordDecision("deny", "http", "blocked.test", "80", "disallowed_host"); err != nil {
		t.Fatalf("recordDecision(deny) returned error: %v", err)
	}
	_ = f.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read decision log: %v", err)
	}
	want := "allow\ttls\texample.com\t443\tallowlisted\n" +
		"deny\thttp\tblocked.test\t80\tdisallowed_host\n"
	if string(got) != want {
		t.Errorf("decision log contents = %q, want %q", got, want)
	}
}

func TestRecordDecisionNilLogIsNoop(t *testing.T) {
	p := &transparentProxy{} // decisionLog nil => DecisionLogPath was empty
	if err := p.recordDecision("allow", "tls", "example.com", "443", "allowlisted"); err != nil {
		t.Errorf("recordDecision with nil log should be a no-op returning nil, got %v", err)
	}
}

func TestRecordDecisionFailsClosedOnWriteError(t *testing.T) {
	// A read-only fd makes Write fail (EBADF). The allow path must see this error
	// and refuse the connection rather than proceed with a lost receipt.
	path := filepath.Join(t.TempDir(), "decisions.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create decision log: %v", err)
	}
	ro, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer ro.Close()
	p := &transparentProxy{decisionLog: ro}

	if err := p.recordDecision("allow", "tls", "example.com", "443", "allowlisted"); err == nil {
		t.Fatal("recordDecision returned nil on a failed write; expected fail-closed error")
	}
}

func TestRecordDecisionSanitizesControlChars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open decision log: %v", err)
	}
	p := &transparentProxy{decisionLog: f}

	// A host carrying a tab/newline could otherwise forge a second record.
	// recordDecision now SANITIZES the delimiters to '?' so the deny is still
	// recorded (not dropped) as exactly one well-formed line — and returns no error.
	if err := p.recordDecision("deny", "http", "evil.example\nallow\ttls\tx", "80", "disallowed_host"); err != nil {
		t.Fatalf("recordDecision should sanitize, not error, on a control-char field: %v", err)
	}
	_ = f.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read decision log: %v", err)
	}
	// Exactly one record (one trailing newline), no raw control chars from the host.
	want := "deny\thttp\tevil.example?allow?tls?x\t80\tdisallowed_host\n"
	if string(got) != want {
		t.Errorf("sanitized record = %q, want %q", got, want)
	}
}
