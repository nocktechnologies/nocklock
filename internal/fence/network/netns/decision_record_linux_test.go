//go:build linux

package netns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestRecordDecisionRejectsControlChars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open decision log: %v", err)
	}
	defer f.Close()
	p := &transparentProxy{decisionLog: f}

	// A host carrying a newline could forge a second record; recordDecision must
	// refuse rather than write it.
	if err := p.recordDecision("allow", "tls", "evil.example\nallow\ttls\tx", "443", "allowlisted"); err == nil {
		t.Fatal("recordDecision accepted a field with a newline; expected refusal")
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "evil.example") {
		t.Errorf("a rejected record must not be written; log = %q", got)
	}
}
