package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

func writeExec(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestFingerprintExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable semantics")
	}
	dir := t.TempDir()
	bin := writeExec(t, dir, "agent", "\x7fELFnot-really", 0o755)
	script := writeExec(t, dir, "tool.sh", "#!/bin/sh\necho hi\n", 0o755)
	env := writeExec(t, dir, "env", "launcher-bytes", 0o755)
	t.Setenv("PATH", dir)

	tests := []struct {
		name, cmd, status, kind, hash, path string
	}{
		{"absolute path", bin, execHashed, "", sum("\x7fELFnot-really"), bin},
		{"bare name via PATH", "agent", execHashed, "", sum("\x7fELFnot-really"), bin},
		{"script hashes the script file only", script, execHashed, "script", sum("#!/bin/sh\necho hi\n"), script},
		{"launcher is labelled, not passed off as the agent", "env", execHashed, "launcher", sum("launcher-bytes"), env},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := fingerprintExecutable(tt.cmd)
			if fp.Status != tt.status || fp.Kind != tt.kind || fp.SHA256 != tt.hash || fp.Path != tt.path {
				t.Fatalf("got %+v, want status=%s kind=%q hash=%s path=%s", fp, tt.status, tt.kind, tt.hash, tt.path)
			}
		})
	}

	// Negative control: different bytes give a different digest.
	if a, b := fingerprintExecutable(bin), fingerprintExecutable(script); a.SHA256 == b.SHA256 {
		t.Fatal("distinct files produced the same digest")
	}

	t.Run("unresolved", func(t *testing.T) {
		fp := fingerprintExecutable("no-such-command-xyz")
		if fp.Status != execUnresolved || fp.SHA256 != "" {
			t.Fatalf("got %+v", fp)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads everything")
		}
		p := writeExec(t, dir, "execonly", "secret", 0o111)
		fp := fingerprintExecutable(p)
		if fp.Status != execUnreadable || fp.SHA256 != "" || fp.Path != p {
			t.Fatalf("got %+v", fp)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		p := writeExec(t, dir, "huge", "", 0o755)
		if err := os.Truncate(p, maxFingerprintBytes+1); err != nil {
			t.Skipf("cannot create sparse file: %v", err)
		}
		fp := fingerprintExecutable(p)
		if fp.Status != execOversized || fp.SHA256 != "" {
			t.Fatalf("got %+v", fp)
		}
		// Negative control: a file exactly at the cap is still hashed.
		q := writeExec(t, dir, "atcap", "", 0o755)
		if err := os.Truncate(q, maxFingerprintBytes); err != nil {
			t.Skipf("cannot create sparse file: %v", err)
		}
		if fp := fingerprintExecutable(q); fp.Status != execHashed {
			t.Fatalf("at-cap file: got %+v", fp)
		}
	})
	t.Run("fifo is not read", func(t *testing.T) {
		p := filepath.Join(dir, "fifo")
		if err := syscall.Mkfifo(p, 0o755); err != nil {
			t.Skip(err)
		}
		fp := fingerprintExecutable(p)
		if fp.Status != execNotRegular || fp.SHA256 != "" {
			t.Fatalf("got %+v", fp)
		}
	})
}

func TestExecFingerprintDetail(t *testing.T) {
	d := execFingerprint{Path: "/a b/x", SHA256: "ab", Status: execHashed, Kind: "script"}.Detail()
	want := ` exec_status=hashed exec_path="/a b/x" exec_sha256=ab exec_kind=script`
	if d != want {
		t.Fatalf("got %q, want %q", d, want)
	}
	if got := (execFingerprint{Status: execUnresolved}).Detail(); strings.Contains(got, "exec_path") {
		t.Fatalf("unresolved detail carries a path: %q", got)
	}
}

// The wrap start row fingerprints the requested command, not NockLock's own
// binary or any shim placed in front of it (same call site for plain, netns,
// Landlock and Seatbelt launches).
func TestWrapStartRowFingerprintsRequestedCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wrap launches a POSIX command")
	}
	project := t.TempDir()
	writeTestConfig(t, project, plainLaunchTOML(t))
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("NOCKLOCK_ANCHOR_URL", "")
	t.Setenv("NOCKLOCK_ANCHOR_TOKEN", "")
	body := "#!/bin/sh\nexit 0\n"
	script := writeExec(t, t.TempDir(), "agent.sh", body, 0o755)

	if stderr, err := runWrapCapturingStderr(t, []string{"--", script}); err != nil {
		t.Fatalf("wrap: %v\n%s", err, stderr)
	}
	detail := startDetail(t, project)
	for _, want := range []string{" exec_status=hashed", " exec_sha256=" + sum(body), " exec_kind=script"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("start detail %q missing %q", detail, want)
		}
	}
	if self, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(self); err == nil && strings.Contains(detail, sum(string(data))) {
			t.Fatal("start row recorded NockLock's own digest")
		}
	}
}

func startDetail(t *testing.T, project string) string {
	t.Helper()
	logger, err := logging.NewLogger(resolvedAuditDB(t, project), project)
	if err != nil {
		t.Fatalf("open audit DB: %v", err)
	}
	defer logger.Close()
	start := logging.EventSessionStart
	events, err := logger.Query(logging.QueryOptions{EventType: &start, Limit: 10, ByID: true})
	if err != nil || len(events) != 1 {
		t.Fatalf("session-start rows = %d, err = %v", len(events), err)
	}
	return events[0].Detail
}
