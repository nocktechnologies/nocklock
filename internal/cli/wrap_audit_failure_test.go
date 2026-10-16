package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

const auditFailTestSecret = "NOCKLOCK_AUDIT_FAIL_TEST_VAR"

// installAuditWriteFailure creates the audit log at db and installs a trigger
// that aborts every insert of eventType, so the logger's write genuinely fails
// the way it would on a full disk or a locked database.
func installAuditWriteFailure(t *testing.T, projectRoot, db string, eventType logging.EventType) {
	t.Helper()
	logger, err := logging.NewLogger(db, projectRoot)
	if err != nil {
		t.Fatalf("create audit log: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close audit log: %v", err)
	}
	conn, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer conn.Close()
	stmt := fmt.Sprintf(`CREATE TRIGGER fail_audit_write BEFORE INSERT ON events
WHEN NEW.event_type = '%s'
BEGIN SELECT RAISE(ABORT, 'simulated audit write failure'); END;`, eventType)
	if _, err := conn.Exec(stmt); err != nil {
		t.Fatalf("install failing trigger: %v", err)
	}
}

// runWrapWithFailingAudit runs wrap like runWrapWithAuditDB, with a secret
// fence that blocks auditFailTestSecret, and returns the child marker path,
// wrap's stderr and its error.
func runWrapWithFailingAudit(t *testing.T, projectRoot, db string) (string, string, error) {
	t.Helper()
	contents := fmt.Sprintf(`[filesystem]
root = ""

[network]
allow_all = true

[syscall]
enforcement = "off"

[secrets]
block = [%q]

[logging]
db = %q
`, auditFailTestSecret, db)
	writeTestConfig(t, projectRoot, contents)
	withWorkingDir(t, projectRoot)
	child, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "child-launched")
	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetErr(&stderr)
	err = wrapCmd.RunE(cmd, []string{
		"--", child, "-test.run=^TestWrapChildLaunchMarker$", wrapChildMarkerArg + marker,
	})
	return marker, stderr.String(), err
}

// auditEventCounts counts the audit rows by event type, and by "type/detail"
// for rows whose detail is auditFailTestSecret.
func auditEventCounts(t *testing.T, projectRoot, db string) map[string]int {
	t.Helper()
	logger, err := logging.NewLogger(db, projectRoot)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer logger.Close()
	rows, err := logger.Query(logging.QueryOptions{ByID: true, Limit: 10000})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[string(r.EventType)]++
		if r.Detail == auditFailTestSecret {
			counts[string(r.EventType)+"/"+r.Detail]++
		}
	}
	return counts
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()
	var exitErr *exitCodeError
	if !errors.As(err, &exitErr) || exitErr.code != want {
		t.Fatalf("wrap error = %v, want exit code %d", err, want)
	}
}

// A session_end that cannot be written must fail the run (exit 2) and say why,
// even though the child exited 0; the run is left without a signed close. The
// control run with a writable log still exits 0 with session_end and close.
func TestWrapFailsWhenSessionEndCannotBeWritten(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))

	t.Run("writable log", func(t *testing.T) {
		projectRoot := resolvedTempDir(t)
		db := filepath.Join(projectRoot, "fresh", ".nock", "events.db")
		marker, stderr, err := runWrapWithFailingAudit(t, projectRoot, db)
		if err != nil {
			t.Fatalf("wrap error = %v, want nil; stderr:\n%s", err, stderr)
		}
		assertChildMarker(t, marker)
		counts := auditEventCounts(t, projectRoot, db)
		if counts["session_end"] != 1 || counts["session_close"] != 1 {
			t.Fatalf("event counts = %v, want one session_end and one session_close", counts)
		}
	})

	t.Run("session_end write fails", func(t *testing.T) {
		projectRoot := resolvedTempDir(t)
		db := filepath.Join(projectRoot, "fresh", ".nock", "events.db")
		installAuditWriteFailure(t, projectRoot, db, logging.EventSessionEnd)
		marker, stderr, err := runWrapWithFailingAudit(t, projectRoot, db)
		assertExitCode(t, err, 2)
		assertChildMarker(t, marker)
		if !strings.Contains(stderr, "NockLock: fatal: failed to record session_end") ||
			!strings.Contains(stderr, "simulated audit write failure") {
			t.Fatalf("stderr does not name the session_end failure:\n%s", stderr)
		}
		if counts := auditEventCounts(t, projectRoot, db); counts["session_close"] != 0 {
			t.Fatalf("event counts = %v, want no session_close after a failed session_end", counts)
		}
	})
}

// A blocked-secret batch that cannot be written must refuse to launch the child
// (exit 2) and say why. The control run records the blocked secret.
func TestWrapRefusesWhenBlockedSecretsCannotBeWritten(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))
	t.Setenv(auditFailTestSecret, "not-for-the-child")

	t.Run("writable log", func(t *testing.T) {
		projectRoot := resolvedTempDir(t)
		db := filepath.Join(projectRoot, "fresh", ".nock", "events.db")
		marker, stderr, err := runWrapWithFailingAudit(t, projectRoot, db)
		if err != nil {
			t.Fatalf("wrap error = %v, want nil; stderr:\n%s", err, stderr)
		}
		assertChildMarker(t, marker)
		if counts := auditEventCounts(t, projectRoot, db); counts["secret_blocked/"+auditFailTestSecret] != 1 {
			t.Fatalf("event counts = %v, want one secret_blocked row for %s", counts, auditFailTestSecret)
		}
	})

	t.Run("secret_blocked write fails", func(t *testing.T) {
		projectRoot := resolvedTempDir(t)
		db := filepath.Join(projectRoot, "fresh", ".nock", "events.db")
		installAuditWriteFailure(t, projectRoot, db, logging.EventSecretBlocked)
		marker, stderr, err := runWrapWithFailingAudit(t, projectRoot, db)
		assertExitCode(t, err, 2)
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Fatalf("child launch marker exists or could not be checked (%v); wrap must refuse before launching the child", statErr)
		}
		if !strings.Contains(stderr, "blocked environment variable(s) in the audit log") ||
			!strings.Contains(stderr, "simulated audit write failure") {
			t.Fatalf("stderr does not name the blocked-secret write failure:\n%s", stderr)
		}
	})
}

// The recorder fails the session on the first failed blocked-event write only:
// it cancels the child once, keeps the first error, and leaves successful and
// non-blocked writes alone.
func TestAuditRecorderFailsClosedOnBlockedWrite(t *testing.T) {
	writeErr := errors.New("disk full")
	newRecorder := func(fail bool) (*auditRecorder, *bytes.Buffer, *int) {
		var stderr bytes.Buffer
		cancels := 0
		r := &auditRecorder{
			log: func(logging.Event) error {
				if fail {
					return writeErr
				}
				return nil
			},
			sessionID: "s1",
			stderr:    &stderr,
			cancel:    func() { cancels++ },
		}
		return r, &stderr, &cancels
	}

	r, stderr, cancels := newRecorder(false)
	r.record(logging.EventFileBlocked, "filesystem", "denied", true)
	if r.failure() != nil || *cancels != 0 || stderr.Len() != 0 {
		t.Fatalf("successful write: failure=%v cancels=%d stderr=%q, want none", r.failure(), *cancels, stderr)
	}

	r, stderr, cancels = newRecorder(true)
	r.record(logging.EventFilePassed, "filesystem", "best-effort warning", false)
	if r.failure() != nil || *cancels != 0 {
		t.Fatalf("failed non-blocked write: failure=%v cancels=%d, want none", r.failure(), *cancels)
	}
	r.record(logging.EventFileBlocked, "filesystem", "denied", true)
	r.record(logging.EventNetworkError, "network", "denied", true)
	if !errors.Is(r.failure(), writeErr) || *cancels != 1 {
		t.Fatalf("failed blocked writes: failure=%v cancels=%d, want %v and one cancel", r.failure(), *cancels, writeErr)
	}
	if got := strings.Count(stderr.String(), "NockLock: fatal:"); got != 1 ||
		!strings.Contains(stderr.String(), "file_blocked") || !strings.Contains(stderr.String(), "disk full") {
		t.Fatalf("stderr = %q, want one fatal line naming the event and error", stderr)
	}
}

// Concurrent writers (fs events, denial tailer, proxy watchdog) record one
// failure and cancel once; run under -race.
func TestAuditRecorderConcurrentFailures(t *testing.T) {
	var cancels int
	var mu sync.Mutex
	r := &auditRecorder{
		log:       func(logging.Event) error { return errors.New("locked") },
		sessionID: "s1",
		stderr:    &bytes.Buffer{},
		cancel:    func() { mu.Lock(); cancels++; mu.Unlock() },
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.record(logging.EventFileBlocked, "filesystem", "denied", true)
		}()
	}
	wg.Wait()
	if r.failure() == nil || cancels != 1 {
		t.Fatalf("failure=%v cancels=%d, want an error and one cancel", r.failure(), cancels)
	}
}
