//go:build darwin

package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

// TestSBPLDeniesProjectRootAuditSidecars checks the actual Seatbelt policy for
// a root-level logging.db. The first child tries to create each absent sidecar;
// the second tries to overwrite, remove, and rename existing sidecar files.
func TestSBPLDeniesProjectRootAuditSidecars(t *testing.T) {
	if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
		if os.Getenv("NOCKLOCK_SANDBOX_REQUIRE") == "1" {
			t.Fatalf("sandbox-exec unavailable: %v; NOCKLOCK_SANDBOX_REQUIRE=1 forbids skipping", err)
		}
		t.Skipf("sandbox-exec unavailable: %v", err)
	}

	project, dbPath := rootAuditFixture(t)
	sidecars := auditSidecarPaths(t, dbPath)
	sensitive := auditDenyPaths(dbPath, project)
	profile, _, err := fsfence.GenerateWriteConfinementProfile(sensitive, project, "read-write", false)
	if err != nil {
		t.Fatalf("generate root-audit SBPL profile: %v", err)
	}
	profilePath, err := fsfence.WriteProfile(profile)
	if err != nil {
		t.Fatalf("write root-audit SBPL profile: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(profilePath) })
	run := func(script string, args ...string) string {
		t.Helper()
		argv := []string{"-f", profilePath, "/bin/sh", "-c", script, "audit-sidecar-probe"}
		argv = append(argv, args...)
		out, err := exec.Command("sandbox-exec", argv...).CombinedOutput()
		if err != nil {
			t.Fatalf("SBPL probe failed: %v\n%s", err, out)
		}
		return string(out)
	}

	createScript := `status=0
for target do
  if (set -C; : > "$target") 2>/dev/null; then
    printf 'CREATED %s\n' "$target"
    status=1
  else
    printf 'DENIED create %s\n' "$target"
  fi
done
exit "$status"`
	createOut := run(createScript, sidecars...)
	for _, path := range sidecars {
		if !strings.Contains(createOut, "DENIED create "+path) {
			t.Errorf("SBPL did not prove create denial for %q; output:\n%s", path, createOut)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("child created audit sidecar %q: %v", path, err)
		}
	}

	for _, path := range sidecars {
		if err := os.WriteFile(path, []byte("audit-fixture"), 0o600); err != nil {
			t.Fatalf("create audit sidecar fixture %q: %v", path, err)
		}
	}
	mutateScript := `status=0
for target do
  if : > "$target" 2>/dev/null; then
    printf 'OVERWRITE_ALLOWED %s\n' "$target"
    status=1
  fi
  if /bin/rm "$target" 2>/dev/null; then
    printf 'REMOVE_ALLOWED %s\n' "$target"
    status=1
  fi
  if /bin/mv "$target" "$target.renamed" 2>/dev/null; then
    printf 'RENAME_ALLOWED %s\n' "$target"
    status=1
  fi
done
exit "$status"`
	if out := run(mutateScript, sidecars...); strings.Contains(out, "_ALLOWED ") {
		t.Fatalf("SBPL permitted an audit sidecar mutation:\n%s", out)
	}
	for _, path := range sidecars {
		if got, err := os.ReadFile(path); err != nil || string(got) != "audit-fixture" {
			t.Fatalf("sidecar %q changed after child mutation attempts: %q, %v", path, got, err)
		}
		if _, err := os.Lstat(path + ".renamed"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("child renamed audit sidecar %q: %v", path, err)
		}
	}

	control := filepath.Join(project, "ordinary-root-file")
	controlOut := run(`: > "$1" && printf 'CONTROL_ALLOWED\n'`, control)
	if !strings.Contains(controlOut, "CONTROL_ALLOWED") {
		t.Fatalf("SBPL denied an ordinary project-root write:\n%s", controlOut)
	}
}

// TestWrapMacOSFilesystemFenceRecordsOneEngagedState proves the wrap command,
// not merely the component helper, records precisely one filesystem-fence
// state after a Seatbelt profile is accepted and before its child runs.
func TestWrapMacOSFilesystemFenceRecordsOneEngagedState(t *testing.T) {
	if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
		if os.Getenv("NOCKLOCK_SANDBOX_REQUIRE") == "1" {
			t.Fatalf("sandbox-exec unavailable: %v; NOCKLOCK_SANDBOX_REQUIRE=1 forbids skipping", err)
		}
		t.Skipf("sandbox-exec unavailable: %v", err)
	}

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
	if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
		if os.Getenv("NOCKLOCK_SANDBOX_REQUIRE") == "1" {
			t.Fatalf("sandbox-exec unavailable: %v; NOCKLOCK_SANDBOX_REQUIRE=1 forbids skipping", err)
		}
		t.Skipf("sandbox-exec unavailable: %v", err)
	}

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
	if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
		if os.Getenv("NOCKLOCK_SANDBOX_REQUIRE") == "1" {
			t.Fatalf("sandbox-exec unavailable: %v; NOCKLOCK_SANDBOX_REQUIRE=1 forbids skipping", err)
		}
		t.Skipf("sandbox-exec unavailable: %v", err)
	}

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

// TestWrapMacOSFilesystemFenceOptOutRecordsDegraded proves the temporary,
// explicit compatibility opt-out is loud and audited before it starts an
// unfenced child when Seatbelt cannot be applied.
func TestWrapMacOSFilesystemFenceOptOutRecordsDegraded(t *testing.T) {
	project := t.TempDir()
	policy := strings.Replace(config.DefaultTOML(), "macos_allow_unfenced = false", "macos_allow_unfenced = true", 1)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	oldEnsure := ensureSandboxExecAvailable
	ensureSandboxExecAvailable = func() error { return errors.New("sandbox-exec unavailable") }
	t.Cleanup(func() { ensureSandboxExecAvailable = oldEnsure })

	marker := filepath.Join(project, "child-ran")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/touch", marker}); err != nil {
		t.Fatalf("explicit macOS compatibility opt-out should start the child: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("opt-out child did not run: %v", err)
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
	if len(states) != 1 || !strings.Contains(states[0], "DEGRADED") || !strings.Contains(states[0], "macos_allow_unfenced=true") {
		t.Fatalf("expected exactly one explicit degraded state, got %q", states)
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
