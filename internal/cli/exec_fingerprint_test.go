package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// newWrapTestProject sets up a project directory with a plain (no shim)
// launch config and the env vars a wrap test needs, mirroring the isolation
// plainLaunchTOML documents.
func newWrapTestProject(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	writeTestConfig(t, project, plainLaunchTOML(t))
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("NOCKLOCK_ANCHOR_URL", "")
	t.Setenv("NOCKLOCK_ANCHOR_TOKEN", "")
	return project
}

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
		{"script hashes the script file only", script, execHashed, "script", sum("#!/bin/sh\necho hi\n"), script},
		{"launcher is labelled, not passed off as the agent", env, execHashed, "launcher", sum("launcher-bytes"), env},
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

	t.Run("nonexistent path is unreadable, not resolved", func(t *testing.T) {
		// fingerprintExecutable takes an already-resolved path; resolution
		// failures (execUnresolved) are the caller's concern (wrap.go), not
		// this function's.
		fp := fingerprintExecutable(filepath.Join(dir, "no-such-command-xyz"))
		if fp.Status != execUnreadable || fp.SHA256 != "" {
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
	project := newWrapTestProject(t)
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

// A command name crafted to look like a trailing key=value field must not be
// able to plant a second exec_sha256 field ahead of the real one.
func TestWrapStartRowQuotesCommandAgainstFingerprintSpoofing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wrap launches a POSIX command")
	}
	project := newWrapTestProject(t)
	body := "#!/bin/sh\nexit 0\n"
	script := writeExec(t, t.TempDir(), "agent exec_sha256=deadbeef", body, 0o755)

	if stderr, err := runWrapCapturingStderr(t, []string{"--", script}); err != nil {
		t.Fatalf("wrap: %v\n%s", err, stderr)
	}
	detail := startDetail(t, project)
	fields := mustParseDetailFields(t, detail)
	if want := sum(body); fields["exec_sha256"] != want {
		t.Fatalf("exec_sha256 field = %q, want the real digest %q (detail=%q)", fields["exec_sha256"], want, detail)
	}
	if fields["command"] != script {
		t.Fatalf("command field = %q, want %q", fields["command"], script)
	}
}

// Negative control: proves the test above actually exercises the attack.
// Reconstructing the pre-fix detail shape (a bare, unquoted command directly
// ahead of the fingerprint fields, with no "command=" wrapper) and running it
// through the same parser the fixed form passes: the unquoted form is
// rejected as ambiguous (two "exec_sha256" fields), where the quoted,
// labelled form above parses to exactly one.
func TestSessionStartDetailNegativeControlUnquotedCommandIsSpoofable(t *testing.T) {
	fp := execFingerprint{Path: "/bin/real", SHA256: "realdigest", Status: execHashed}
	unquoted := "agent exec_sha256=deadbeef" + fp.Detail()
	if _, err := parseDetailFields(unquoted); err == nil {
		t.Fatal("negative control is broken: unquoted command should produce an ambiguous duplicate exec_sha256 field")
	}
}

// exec_fingerprint.go must hash the exact path wrap.go exec's, not resolve
// the command a second time. Run via a bare PATH-resolved name (not an
// explicit path) so the resolution step is actually exercised.
func TestWrapStartRowFingerprintsResolvedPathOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wrap launches a POSIX command")
	}
	project := newWrapTestProject(t)

	binDir := t.TempDir()
	scriptPath := writeExec(t, binDir, "agent", "#!/bin/sh\nprintf '%s' \"$0\" > resolved-path\n", 0o755)
	t.Setenv("PATH", binDir)

	if stderr, err := runWrapCapturingStderr(t, []string{"--", "agent"}); err != nil {
		t.Fatalf("wrap: %v\n%s", err, stderr)
	}
	execd, err := os.ReadFile(filepath.Join(project, "resolved-path"))
	if err != nil {
		t.Fatalf("read exec'd-path marker: %v", err)
	}
	detail := startDetail(t, project)
	fields := mustParseDetailFields(t, detail)
	if fields["exec_path"] != string(execd) {
		t.Fatalf("fingerprinted exec_path=%q, exec'd path=%q (detail=%q)", fields["exec_path"], execd, detail)
	}
	if fields["exec_path"] != scriptPath {
		t.Fatalf("fingerprinted exec_path=%q, want resolved script path %q", fields["exec_path"], scriptPath)
	}
}

// An unresolvable command still gets a signed start row (status unresolved,
// no path) before the launch fails.
func TestWrapStartRowRecordsUnresolvedCommandThenFailsLaunch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX PATH resolution")
	}
	project := newWrapTestProject(t)
	t.Setenv("PATH", t.TempDir()) // empty: nothing resolves

	if _, err := runWrapCapturingStderr(t, []string{"--", "no-such-command-xyz"}); err == nil {
		t.Fatal("wrap unexpectedly launched an unresolvable command")
	}
	detail := startDetail(t, project)
	if !strings.Contains(detail, "exec_status=unresolved") || strings.Contains(detail, "exec_path") {
		t.Fatalf("start detail = %q, want unresolved status without a path", detail)
	}
}

// detailFieldRE matches one key=value field in a session_start detail
// string, where value is either a double-quoted (strconv.Quote / %q) string
// or a single bare token.
var detailFieldRE = regexp.MustCompile(`(\S+?)=("(?:[^"\\]|\\.)*"|\S+)`)

// parseDetailFields tokenizes a session_start detail string into key=value
// fields, respecting quoted values so a quoted field's content is never
// split into extra fields. It errors on a duplicate key, since the signed
// row depends on each field appearing exactly once.
func parseDetailFields(detail string) (map[string]string, error) {
	fields := map[string]string{}
	for _, m := range detailFieldRE.FindAllStringSubmatch(detail, -1) {
		key, raw := m[1], m[2]
		value := raw
		if strings.HasPrefix(raw, `"`) {
			unq, err := strconv.Unquote(raw)
			if err != nil {
				return nil, fmt.Errorf("unquote %q: %w", raw, err)
			}
			value = unq
		}
		if _, dup := fields[key]; dup {
			return nil, fmt.Errorf("duplicate field %q in detail %q", key, detail)
		}
		fields[key] = value
	}
	return fields, nil
}

func mustParseDetailFields(t *testing.T, detail string) map[string]string {
	t.Helper()
	fields, err := parseDetailFields(detail)
	if err != nil {
		t.Fatalf("parse detail %q: %v", detail, err)
	}
	return fields
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
