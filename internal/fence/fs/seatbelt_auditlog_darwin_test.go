//go:build darwin

package fs

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The audit-log tamper fix denies the audit directory to the fenced child. This
// proves the enforcement end to end on real macOS: a child under the fence must
// NOT be able to WRITE to (i.e. corrupt or truncate) a fenced events.db, while
// writing elsewhere still works. Read-denial is covered by the sibling test;
// this one specifically exercises WRITE, which is the audit-tamper threat.
func TestSeatbeltDeniesWriteToFencedAuditLog(t *testing.T) {
	if err := EnsureSandboxExecAvailable(); err != nil {
		t.Skipf("sandbox-exec unavailable: %v", err)
	}

	base := t.TempDir()
	auditDir := filepath.Join(base, ".nock")
	allowedDir := filepath.Join(base, "project")
	if err := os.Mkdir(auditDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(allowedDir, 0700); err != nil {
		t.Fatal(err)
	}
	auditFile := filepath.Join(auditDir, "events.db")
	if err := os.WriteFile(auditFile, []byte("original audit trail"), 0600); err != nil {
		t.Fatal(err)
	}
	allowedFile := filepath.Join(allowedDir, "ok.txt")

	profile, err := GenerateProfile([]string{auditDir})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	pf, err := WriteProfile(profile)
	if err != nil {
		t.Fatalf("WriteProfile: %v", err)
	}
	defer os.Remove(pf)

	write := func(target string) error {
		argv, werr := WrapArgv(pf, []string{"/bin/sh", "-c", "echo tampered > " + target})
		if werr != nil {
			t.Fatalf("WrapArgv: %v", werr)
		}
		return exec.Command(argv[0], argv[1:]...).Run()
	}

	// Writing to an allowed path under the fence must still work.
	if err := write(allowedFile); err != nil {
		t.Errorf("write to allowed path failed under fence: %v", err)
	}

	// Writing to the fenced audit log must be DENIED, and the original content
	// must be untouched (the redirect's truncating open is what gets blocked).
	if err := write(auditFile); err == nil {
		t.Error("FENCE FAILED OPEN: child wrote to the fenced audit log")
	}
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original audit trail" {
		t.Errorf("audit log was modified under fence: %q", data)
	}
}
