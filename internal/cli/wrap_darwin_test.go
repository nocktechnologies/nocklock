//go:build darwin

package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

// TestWrapMacOSFilesystemFenceRecordsOneEngagedState proves the wrap command,
// not merely the component helper, records precisely one filesystem-fence
// state after a Seatbelt profile is accepted and before its child runs.
func TestWrapMacOSFilesystemFenceRecordsOneEngagedState(t *testing.T) {
	requireSandboxExecForWrap(t)

	project := t.TempDir()
	policy := strings.Replace(config.DefaultTOML(), "allow_all = false", "allow_all = true", 1)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/true"}); err != nil {
		t.Fatalf("wrap should launch an allowed command under Seatbelt: %v", err)
	}

	// The event log lives in the audit state directory outside the project
	// (config.AuditStateDir), so resolve it the way the CLI does.
	dbPath := resolvedAuditDB(t, project)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer db.Close()

	states := macOSFilesystemFenceStates(t, db)
	if len(states) != 1 {
		t.Fatalf("expected exactly one macOS filesystem fence state, got %d: %q", len(states), states)
	}
	if !strings.Contains(states[0], "ENGAGED") || !strings.Contains(states[0], "Seatbelt root-write confinement applied") {
		t.Fatalf("expected an engaged Seatbelt state record, got %q", states[0])
	}
}

// TestWrapMacOSFilesystemFenceConfinesWritesToRoot proves nocklock wrap wires
// the root-write profile into the launched child, rather than merely generating
// a valid SBPL string. The targets live under the home directory because the
// profile intentionally permits the system temp directory used by t.TempDir.
func TestWrapMacOSFilesystemFenceConfinesWritesToRoot(t *testing.T) {
	requireSandboxExecForWrap(t)

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Fatalf("UserHomeDir: %v", err)
	}
	base, err := os.MkdirTemp(home, ".nocklock-wrap-")
	if err != nil {
		t.Fatalf("create home test directory: %v", err)
	}
	defer os.RemoveAll(base)
	project := filepath.Join(base, "project")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{project, outside} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}

	policy := strings.Replace(config.DefaultTOML(), "allow_all = false", "allow_all = true", 1)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	insideFile := filepath.Join(project, "inside.txt")
	outsideFile := filepath.Join(outside, "outside.txt")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err = wrapCmd.RunE(cmd, []string{
		"--", "/bin/sh", "-c", `printf inside > "$1"; printf outside > "$2"`, "sh", insideFile, outsideFile,
	})
	if err == nil {
		t.Fatal("FENCE FAILED OPEN: write outside filesystem.root succeeded")
	}
	if got, readErr := os.ReadFile(insideFile); readErr != nil || string(got) != "inside" {
		t.Fatalf("inside-root write = %q, %v; want inside, nil", got, readErr)
	}
	if _, statErr := os.Stat(outsideFile); !os.IsNotExist(statErr) {
		t.Fatalf("outside-root target exists after denied wrap write: %v", statErr)
	}
}

// TestWrapMacOSFilesystemFenceDeniesAuditStateTampering proves a fenced child
// cannot truncate or rename the event database, active WAL sidecar, or chain
// anchor. The unfenced parent must still write a complete, signed audit trail
// for both the denied attempts and a subsequent ordinary wrapped command.
func TestWrapMacOSFilesystemFenceDeniesAuditStateTampering(t *testing.T) {
	requireSandboxExecForWrap(t)

	project := t.TempDir()
	policy := strings.Replace(config.DefaultTOML(), "allow_all = false", "allow_all = true", 1)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	runWrap := func(args ...string) error {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		return wrapCmd.RunE(cmd, append([]string{"--"}, args...))
	}
	if err := runWrap("/usr/bin/true"); err != nil {
		t.Fatalf("initial wrapped command failed: %v", err)
	}

	dbPath := resolvedAuditDB(t, project)
	anchorPath := logging.DefaultAnchorPath(dbPath)
	if _, err := os.Stat(anchorPath); err != nil {
		t.Fatalf("initial wrapped session did not write chain anchor: %v", err)
	}

	// Keep a parent-owned connection open so SQLite retains a real WAL sidecar
	// while the fenced child attempts to damage it.
	parentLogger, err := logging.NewLogger(dbPath, project, signingLoggerOpts()...)
	if err != nil {
		t.Fatalf("open parent audit logger: %v", err)
	}
	configPath, err := config.FindConfig()
	if err != nil {
		_ = parentLogger.Close()
		t.Fatalf("find project config: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		_ = parentLogger.Close()
		t.Fatalf("load project config: %v", err)
	}
	const tamperTestSession = "audit-state-tamper-test"
	if err := recordConfigDigest(parentLogger, cfg, configPath, dbPath, tamperTestSession, resolvedNetworkFenceMode(WrapFlags{}), io.Discard); err != nil {
		_ = parentLogger.Close()
		t.Fatalf("write config digest for parent audit event: %v", err)
	}
	if err := parentLogger.Log(logging.Event{
		EventType: logging.EventSessionStart,
		Category:  "session",
		Detail:    "start audit-state tamper fixture",
		SessionID: tamperTestSession,
	}); err != nil {
		_ = parentLogger.Close()
		t.Fatalf("write session start for parent audit event: %v", err)
	}
	if err := parentLogger.Log(logging.Event{
		EventType: logging.EventFilePassed,
		Category:  "filesystem",
		Detail:    "prepare WAL tamper test",
		SessionID: tamperTestSession,
	}); err != nil {
		_ = parentLogger.Close()
		t.Fatalf("write parent audit event: %v", err)
	}
	walPath := dbPath + "-wal"
	if _, err := os.Stat(walPath); err != nil {
		_ = parentLogger.Close()
		t.Fatalf("active audit WAL is missing before child tamper attempt: %v", err)
	}

	// Each pathname is passed as an argument, never interpolated into the shell
	// source. A successful truncate or rename makes the child exit non-zero;
	// denied operations are intentionally handled so all six attempts run.
	tamperScript := `status=0
for target in "$@"; do
  if : > "$target"; then status=1; fi
  if mv "$target" "$target.renamed"; then status=1; fi
done
exit "$status"`
	if err := runWrap("/bin/sh", "-c", tamperScript, "sh", dbPath, walPath, anchorPath); err != nil {
		_ = parentLogger.Close()
		t.Fatalf("FENCE FAILED OPEN: audit-state truncate or rename succeeded: %v", err)
	}
	for _, path := range []string{dbPath, walPath, anchorPath} {
		if _, err := os.Stat(path); err != nil {
			_ = parentLogger.Close()
			t.Fatalf("audit state target %s changed after denied child tamper attempt: %v", path, err)
		}
		if _, err := os.Stat(path + ".renamed"); !os.IsNotExist(err) {
			_ = parentLogger.Close()
			t.Fatalf("FENCE FAILED OPEN: child renamed audit state target %s: %v", path, err)
		}
	}
	if err := parentLogger.Close(); err != nil {
		t.Fatalf("close parent audit logger: %v", err)
	}

	normalFile := filepath.Join(project, "normal-wrapped-command")
	if err := runWrap("/usr/bin/touch", normalFile); err != nil {
		t.Fatalf("normal wrapped command failed after denied tamper attempts: %v", err)
	}
	if _, err := os.Stat(normalFile); err != nil {
		t.Fatalf("normal wrapped command did not create its project file: %v", err)
	}

	// This is the handler behind `nocklock verify --audit`; it checks both the
	// hash chain and the local managed signing key.
	var verifyOut bytes.Buffer
	if err := runAuditVerify(context.Background(), &verifyOut, ""); err != nil {
		t.Fatalf("nocklock verify --audit did not pass after wrapped session: %v\n%s", err, verifyOut.String())
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open verified audit log: %v", err)
	}
	defer db.Close()
	var successfulSessions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type = 'session_end' AND detail = 'exit_code=0'`).Scan(&successfulSessions); err != nil {
		t.Fatalf("count successful wrapped sessions: %v", err)
	}
	if successfulSessions < 3 {
		t.Fatalf("successful wrapped sessions = %d, want at least 3", successfulSessions)
	}
}

// TestWrapMacOSFilesystemFenceRefusesBeforeLaunchingChild proves a missing
// Seatbelt backend does not start the child under the default fail-closed
// policy, and records precisely one refusal state instead.
func TestWrapMacOSFilesystemFenceRefusesBeforeLaunchingChild(t *testing.T) {
	project := t.TempDir()
	writeTestConfig(t, project, config.DefaultTOML())
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	oldEnsure := ensureSandboxExecAvailable
	ensureSandboxExecAvailable = func() error { return errors.New("sandbox-exec unavailable") }
	t.Cleanup(func() { ensureSandboxExecAvailable = oldEnsure })

	marker := filepath.Join(project, "child-ran")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/touch", marker})
	if err == nil {
		t.Fatal("wrap started the child despite an unavailable Seatbelt backend")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("fail-closed wrap ran the child: stat marker = %v", statErr)
	}

	// The event log lives in the audit state directory outside the project
	// (config.AuditStateDir), so resolve it the way the CLI does.
	dbPath := resolvedAuditDB(t, project)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer db.Close()

	states := macOSFilesystemFenceStates(t, db)
	if len(states) != 1 || !strings.Contains(states[0], "REFUSED-TO-START") {
		t.Fatalf("expected exactly one refusal state, got %q", states)
	}
}

func macOSFilesystemFenceStates(t *testing.T, db *sql.DB) []string {
	t.Helper()

	rows, err := db.Query(`SELECT detail FROM events WHERE event_type = 'filesystem_fence_state' AND detail LIKE 'macOS filesystem-fence %'`)
	if err != nil {
		t.Fatalf("query fence state: %v", err)
	}
	defer rows.Close()

	var states []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("scan fence state: %v", err)
		}
		states = append(states, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate fence state: %v", err)
	}
	return states
}

func requireSandboxExecForWrap(t *testing.T) {
	t.Helper()
	if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
		if os.Getenv("NOCKLOCK_SANDBOX_REQUIRE") == "1" {
			t.Fatalf("sandbox-exec unavailable: %v; NOCKLOCK_SANDBOX_REQUIRE=1 forbids skipping", err)
		}
		t.Skipf("sandbox-exec unavailable: %v", err)
	}
}

// denialLogProject prepares an allow_all project whose HOME is a temp directory
// holding a default-denied ~/.ssh secret, and returns the project, the secret
// path, and a runner for wrapped commands.
func denialLogProject(t *testing.T) (project, secret string, run func(args ...string) error) {
	t.Helper()
	requireSandboxExecForWrap(t)
	home := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		home = resolved
	}
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret = filepath.Join(home, ".ssh", "id_nocklock_test")
	if err := os.WriteFile(secret, []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	project = t.TempDir()
	policy := strings.Replace(config.DefaultTOML(), "allow_all = false", "allow_all = true", 1)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	run = func(args ...string) error {
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		return wrapCmd.RunE(cmd, append([]string{"--"}, args...))
	}
	return project, secret, run
}

func wantExitCode(t *testing.T, err error, want int) {
	t.Helper()
	var ec *exitCodeError
	if want == 0 {
		if err != nil {
			t.Fatalf("wrapped command failed: %v", err)
		}
		return
	}
	if !errors.As(err, &ec) || ec.code != want {
		t.Fatalf("wrap error = %v, want exit code %d", err, want)
	}
}

// TestWrapMacOSDenialLogRecordsFileBlockedRow is the end-to-end proof for the
// unified-log tailer: a wrapped command reads a denied path and exactly one
// signed EventFileBlocked row naming it lands in the session's audit chain,
// while the command's own exit code passes through untouched.
func TestWrapMacOSDenialLogRecordsFileBlockedRow(t *testing.T) {
	project, secret, run := denialLogProject(t)

	err := run("/bin/sh", "-c", `cat "$1" >/dev/null 2>&1; exit 7`, "sh", secret)
	wantExitCode(t, err, 7)

	db, err := sql.Open("sqlite", resolvedAuditDB(t, project))
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer db.Close()

	var sessionID string
	if err := db.QueryRow(`SELECT session_id FROM events WHERE event_type = 'session_end'`).Scan(&sessionID); err != nil {
		t.Fatalf("session_end row: %v", err)
	}
	rows, err := db.Query(`SELECT category, detail, blocked, session_id FROM events WHERE event_type = 'file_blocked'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var category, detail, session string
		var blocked int
		if err := rows.Scan(&category, &detail, &blocked, &session); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(detail, secret) {
			details = append(details, detail)
		}
		if category != "filesystem" || blocked != 1 || session != sessionID {
			t.Errorf("denial row = category %q blocked %d session %q; want filesystem/1/%q", category, blocked, session, sessionID)
		}
	}
	// Other file_blocked rows may exist: every process also trips the fence's
	// base write deny on /dev/dtracehelper at startup. The denied secret must
	// appear exactly once.
	if len(details) != 1 || details[0] != "file-read-data "+secret {
		t.Fatalf("want exactly one file_blocked row %q, got %q", "file-read-data "+secret, details)
	}

	var verifyOut bytes.Buffer
	if err := runAuditVerify(context.Background(), &verifyOut, ""); err != nil {
		t.Fatalf("audit chain with denial row does not verify: %v\n%s", err, verifyOut.String())
	}
}

// TestWrapMacOSDenialLogIgnoresOtherSessions is the negative control: a denial
// carrying another session's tag, replayed through the same tailer, is not
// written to this session's chain.
func TestWrapMacOSDenialLogIgnoresOtherSessions(t *testing.T) {
	project, _, run := denialLogProject(t)

	foreign := `{"eventMessage":"Sandbox: cat(1) deny(1) file-read-data /Users/other/.ssh/id_ed25519\nnocklock:some-other-session"}`
	old := denialLogArgv
	denialLogArgv = func() []string {
		return []string{"/bin/sh", "-c", `printf '%s\n' "$1"; exec /bin/sleep 30`, "sh", foreign}
	}
	t.Cleanup(func() { denialLogArgv = old })

	wantExitCode(t, run("/usr/bin/true"), 0)

	db, err := sql.Open("sqlite", resolvedAuditDB(t, project))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type = 'file_blocked'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a denial tagged for another session was logged: %d file_blocked rows", n)
	}
}

// TestWrapMacOSDenialLogFailureIsOneWarning proves a unified-log stream that
// cannot start never fails or reroutes the run: the command's exit code is
// preserved and exactly one warning row is written.
func TestWrapMacOSDenialLogFailureIsOneWarning(t *testing.T) {
	project, secret, run := denialLogProject(t)

	old := denialLogArgv
	denialLogArgv = func() []string { return []string{filepath.Join(t.TempDir(), "no-such-log")} }
	t.Cleanup(func() { denialLogArgv = old })

	wantExitCode(t, run("/bin/sh", "-c", `cat "$1" >/dev/null 2>&1; exit 7`, "sh", secret), 7)

	db, err := sql.Open("sqlite", resolvedAuditDB(t, project))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var warnings, denials int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type = 'file_passed' AND detail LIKE 'macOS denial log (best-effort):%'`).Scan(&warnings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type = 'file_blocked'`).Scan(&denials); err != nil {
		t.Fatal(err)
	}
	if warnings != 1 || denials != 0 {
		t.Fatalf("want 1 warning and 0 denial rows, got %d and %d", warnings, denials)
	}
}

// TestWrapMacOSDenialLogSilentStreamDoesNotDelayRun proves the tailer's bounded
// attach and drain windows: a stream that never produces output costs the run
// at most those two windows, and the run still succeeds with one warning row
// recording that the stream never attached.
func TestWrapMacOSDenialLogSilentStreamDoesNotDelayRun(t *testing.T) {
	project, _, run := denialLogProject(t)

	old := denialLogArgv
	denialLogArgv = func() []string { return []string{"/bin/sleep", "60"} }
	t.Cleanup(func() { denialLogArgv = old })

	start := time.Now()
	wantExitCode(t, run("/usr/bin/true"), 0)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("a silent denial stream held the run for %v", elapsed)
	}

	db, err := sql.Open("sqlite", resolvedAuditDB(t, project))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var warnings int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE detail LIKE 'macOS denial log (best-effort):%'`).Scan(&warnings); err != nil {
		t.Fatal(err)
	}
	if warnings != 1 {
		t.Fatalf("silent stream produced %d warning rows, want 1", warnings)
	}
}

func macOSSyscallHardeningEvents(t *testing.T, project string) int {
	t.Helper()
	db, err := sql.Open("sqlite", resolvedAuditDB(t, project))
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE category = 'syscall' AND detail LIKE 'macOS hardened SBPL%'`).Scan(&n); err != nil {
		t.Fatalf("query syscall events: %v", err)
	}
	return n
}

func runDarwinWrap(t *testing.T, project, toml string, args ...string) error {
	t.Helper()
	writeTestConfig(t, project, toml)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	return wrapCmd.RunE(cmd, append([]string{"--"}, args...))
}

// TestWrapMacOSSyscallEnforcementMatchesDoctor pins wrap's macOS syscall
// behaviour to the same rule doctor reports (macOSSyscallHardening): the
// default config (enforcement = "required", hardened unset) applies the
// hardened SBPL rules and says so, "required" without a Seatbelt profile to
// carry them refuses, and "off" applies nothing.
func TestWrapMacOSSyscallEnforcementMatchesDoctor(t *testing.T) {
	requireSandboxExecForWrap(t)

	t.Run("default config applies hardened rules", func(t *testing.T) {
		project := t.TempDir()
		if err := runDarwinWrap(t, project, doctorTestTOML(true), "/usr/bin/true"); err != nil {
			t.Fatalf("default config must wrap under hardened SBPL: %v", err)
		}
		if n := macOSSyscallHardeningEvents(t, project); n != 1 {
			t.Fatalf("hardened-SBPL audit events = %d, want 1", n)
		}
	})
	t.Run("required without filesystem.root refuses", func(t *testing.T) {
		project := t.TempDir()
		toml := strings.Replace(dryRunTestTOML(), "allow_all = false", "allow_all = true", 1)
		err := runDarwinWrap(t, project, toml, "/usr/bin/true")
		if err == nil || !strings.Contains(err.Error(), "syscall fence cannot be enforced (fail-closed)") {
			t.Fatalf("wrap err = %v, want the syscall fail-closed refusal", err)
		}
	})
	t.Run("off applies no hardening", func(t *testing.T) {
		project := t.TempDir()
		toml := strings.Replace(doctorTestTOML(true), "\nenforcement = \"required\"", "\nenforcement = \"off\"", 1)
		if !strings.Contains(toml, "\nenforcement = \"off\"") {
			t.Fatal("test premise: [syscall] enforcement was not switched off")
		}
		if err := runDarwinWrap(t, project, toml, "/usr/bin/true"); err != nil {
			t.Fatalf("syscall off must wrap: %v", err)
		}
		if n := macOSSyscallHardeningEvents(t, project); n != 0 {
			t.Fatalf("hardened-SBPL audit events = %d with enforcement off, want 0", n)
		}
	})
}

// TestWrapMacOSClaudeCodePresetRunsUnderHardenedRules proves the hardened SBPL
// rules that "required" now applies do not break ordinary tools under the
// claude-code preset: shell, /dev/null and pty-style writes, directory reads.
func TestWrapMacOSClaudeCodePresetRunsUnderHardenedRules(t *testing.T) {
	requireSandboxExecForWrap(t)
	body, err := config.ProfileTOML("claude-code")
	if err != nil {
		t.Fatalf("claude-code preset: %v", err)
	}
	project := t.TempDir()
	err = runDarwinWrap(t, project, body,
		"/bin/sh", "-c", `echo ok >/dev/null && /bin/ls /usr/bin >/dev/null && /usr/bin/true`)
	if err != nil {
		t.Fatalf("claude-code preset must run ordinary tools under hardened SBPL: %v", err)
	}
	if n := macOSSyscallHardeningEvents(t, project); n != 1 {
		t.Fatalf("hardened-SBPL audit events = %d, want 1 (preset enforces syscall)", n)
	}
}
