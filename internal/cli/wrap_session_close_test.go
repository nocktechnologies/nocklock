package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// TestWrapWritesSignedSessionCloseAfterSessionEnd is the run-lifecycle
// differential: it uses only the pre-existing Query API and event-type strings,
// so it compiles on the base commit (0dfbafc5) where it FAILS — no session_close
// row is ever written there — and passes with the teardown change. A clean wrap
// run must end with a signed session_close whose id is after the session_end row,
// under the same session id.
func TestWrapWritesSignedSessionCloseAfterSessionEnd(t *testing.T) {
	projectRoot := resolvedTempDir(t)
	db := filepath.Join(projectRoot, "fresh", ".nock", "events.db")
	marker, err := runWrapWithAuditDB(t, projectRoot, db)
	assertWrapChildLaunched(t, marker, err)

	logger, err := logging.NewLogger(db, projectRoot)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer logger.Close()
	rows, err := logger.Query(logging.QueryOptions{ByID: true, Limit: 10000})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}

	var endID, closeID int64
	var endSID, closeSID string
	for _, r := range rows {
		switch r.EventType {
		case "session_end":
			endID, endSID = r.ID, r.SessionID
		case "session_close":
			closeID, closeSID = r.ID, r.SessionID
		}
	}
	if endID == 0 {
		t.Fatal("no session_end row written")
	}
	if closeID == 0 {
		t.Fatal("no session_close row written: teardown did not write the run's signed close")
	}
	if closeID <= endID {
		t.Fatalf("session_close id %d must come after session_end id %d (close is the run's last row)", closeID, endID)
	}
	if closeSID != endSID {
		t.Fatalf("session_close session %q != session_end session %q", closeSID, endSID)
	}
}

// TestWrapRunVerifiesClosed confirms the verifier reports the wrapped run as
// closed and still prints the limited-coverage notice.
func TestWrapRunVerifiesClosed(t *testing.T) {
	projectRoot := resolvedTempDir(t)
	db := filepath.Join(projectRoot, "fresh", ".nock", "events.db")
	marker, err := runWrapWithAuditDB(t, projectRoot, db)
	assertWrapChildLaunched(t, marker, err)

	logger, err := logging.NewLogger(db, projectRoot)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer logger.Close()
	runs, err := logger.VerifyRuns(context.Background())
	if err != nil {
		t.Fatalf("VerifyRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].Status != logging.RunClosed {
		t.Fatalf("wrapped run statuses = %+v, want exactly one closed run", runs)
	}
}

// TestCloseRunEligible covers the teardown decision that gates the signed close,
// including the drain-deadline skip and the failed-session_end skip.
func TestCloseRunEligible(t *testing.T) {
	cases := []struct {
		name                                            string
		started, drainExceeded, endFailed, ended, wantE bool
	}{
		{"clean close", true, false, false, true, true},
		{"never started", false, false, false, true, false},
		{"drain deadline exceeded", true, true, false, true, false},
		{"session_end failed", true, false, true, true, false},
		{"session_end never landed", true, false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := closeRunEligible(tc.started, tc.drainExceeded, tc.endFailed, tc.ended); got != tc.wantE {
				t.Fatalf("closeRunEligible = %v, want %v", got, tc.wantE)
			}
		})
	}
}

// TestRunLifecycleResultExitMapping checks the verify command's exit mapping:
// close_mismatch and rows_after_close are failures; a bare unclosed run is not,
// but it is surfaced for the coverage notice.
func TestRunLifecycleResultExitMapping(t *testing.T) {
	var out bytes.Buffer
	failed, unclosed := writeRunLifecycleResult(&out, []logging.RunStatus{
		{SessionID: "ok", Status: logging.RunClosed},
		{SessionID: "gone", Status: logging.RunUnclosed},
		{SessionID: "bad", Status: logging.RunCloseMismatch, Reason: "root differs"},
	})
	if !failed {
		t.Fatal("a close_mismatch run must mark the verification failed")
	}
	if len(unclosed) != 1 || unclosed[0] != "gone" {
		t.Fatalf("unclosed runs = %v, want [gone]", unclosed)
	}
	if !strings.Contains(out.String(), "RUN bad: CLOSE_MISMATCH") {
		t.Fatalf("close_mismatch not reported:\n%s", out.String())
	}

	var out2 bytes.Buffer
	failed2, unclosed2 := writeRunLifecycleResult(&out2, []logging.RunStatus{
		{SessionID: "a", Status: logging.RunUnclosed},
	})
	if failed2 {
		t.Fatal("a bare unclosed run must not fail verification on its own")
	}
	if len(unclosed2) != 1 {
		t.Fatalf("unclosed = %v, want one", unclosed2)
	}
}

// TestRequireClosedFailsUnclosedRun verifies that --require-closed escalates a
// neutral unclosed run to a failure, that the default does not, and that the
// coverage notice names the run either way.
func TestRequireClosedFailsUnclosedRun(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedUnclosedRun(t, dbPath, keyPath, "run-unclosed")

	// Default: neutral unclosed run, overall success, but named in the notice.
	var out bytes.Buffer
	if err := runAuditVerify(context.Background(), &out, "", false); err != nil {
		t.Fatalf("default verify of an unclosed run should succeed, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "run-unclosed") || !strings.Contains(out.String(), "no signed session_close") {
		t.Fatalf("coverage notice must name the unclosed run:\n%s", out.String())
	}

	// --require-closed: the same run now fails verification.
	var out2 bytes.Buffer
	err := runAuditVerify(context.Background(), &out2, "", true)
	var exit *exitCodeError
	if !errors.As(err, &exit) || exit.code != 1 {
		t.Fatalf("--require-closed should fail an unclosed run with exit 1, got %v\n%s", err, out2.String())
	}
}

// seedUnclosedRun writes a signed lifecycle run (session_start with lifecycle=1,
// a row, session_end) with no session_close, mirroring an interrupted writer.
func seedUnclosedRun(t *testing.T, dbPath, keyPath, sid string) {
	t.Helper()
	l, err := logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("seed logger: %v", err)
	}
	defer l.Close()
	start := sessionStartDetail("agent", execFingerprint{Status: execUnresolved}, "")
	if err := l.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: start, EgressLevel: "OFF", SessionID: sid}); err != nil {
		t.Fatalf("seed session_start: %v", err)
	}
	if err := l.Log(logging.Event{EventType: logging.EventNetworkPassed, Category: "network", Detail: "egress level=OFF", SessionID: sid}); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	if err := l.Log(logging.Event{EventType: logging.EventSessionEnd, Category: "session", Detail: "exit_code=0", SessionID: sid}); err != nil {
		t.Fatalf("seed session_end: %v", err)
	}
}
