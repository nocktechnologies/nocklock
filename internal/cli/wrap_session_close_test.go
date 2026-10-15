package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// TestWrapRunVerifiesClosed confirms VerifyRuns reports the wrapped run as
// closed. The COVERAGE: LIMITED notice is asserted separately in
// TestRequireClosedFailsUnclosedRun, which drives runAuditVerify's output.
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

// TestRunIntegrityFailurePrintsVerdictLine confirms a lifecycle tamper
// (rows_after_close) fails verify --audit with exit 1 and ends with an explicit
// AUDIT: RUN INTEGRITY FAILURE line, so the earlier AUDIT: AUTHENTIC line (the
// chain is genuinely intact) cannot be read as the overall verdict.
func TestRunIntegrityFailurePrintsVerdictLine(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedRowsAfterCloseRun(t, dbPath, keyPath, "run-tampered")

	var out bytes.Buffer
	err := runAuditVerify(context.Background(), &out, "", false)
	var exit *exitCodeError
	if !errors.As(err, &exit) || exit.code != 1 {
		t.Fatalf("a rows_after_close run must fail verify with exit 1, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "AUDIT: RUN INTEGRITY FAILURE") {
		t.Fatalf("missing AUDIT: RUN INTEGRITY FAILURE verdict line:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "RUN run-tampered: ROWS_AFTER_CLOSE") {
		t.Fatalf("missing per-run failure line:\n%s", out.String())
	}
}

// seedRowsAfterCloseRun writes a signed closed run and then appends one more row
// under the same session_id, so the run reads rows_after_close.
func seedRowsAfterCloseRun(t *testing.T, dbPath, keyPath, sid string) {
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
	if err := l.Log(logging.Event{EventType: logging.EventSessionEnd, Category: "session", Detail: "exit_code=0", SessionID: sid}); err != nil {
		t.Fatalf("seed session_end: %v", err)
	}
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	if err := l.Log(logging.Event{EventType: logging.EventNetworkPassed, Category: "network", Detail: "egress level=OFF", SessionID: sid}); err != nil {
		t.Fatalf("seed post-close row: %v", err)
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

// TestSanitizeSessionID checks a crafted session id cannot inject a newline or a
// terminal escape into a notice line, and is truncated.
func TestSanitizeSessionID(t *testing.T) {
	cases := map[string]string{
		"":                          "(empty)",
		"550e8400-e29b-41d4-a716-0": "550e8400-e29b-41d4-a716-0",
		"line1\nline2":              "line1?line2",
		"esc\x1b[31mred":            "esc?[31mred",
		strings.Repeat("x", 100):    strings.Repeat("x", 64) + "…",
	}
	for in, want := range cases {
		if got := sanitizeSessionID(in); got != want {
			t.Errorf("sanitizeSessionID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCoverageNoticeCapsUnclosedList confirms the COVERAGE notice reports the
// exact unclosed count but caps the inline id list.
func TestCoverageNoticeCapsUnclosedList(t *testing.T) {
	var ids []string
	for i := 0; i < maxListedUnclosedRuns+5; i++ {
		ids = append(ids, fmt.Sprintf("sid-%02d", i))
	}
	var out bytes.Buffer
	writeVerificationCoverage(&out, ids)
	s := out.String()
	if !strings.Contains(s, fmt.Sprintf("%d run(s) have no signed session_close", len(ids))) {
		t.Fatalf("exact unclosed count not reported:\n%s", s)
	}
	if !strings.Contains(s, "… and 5 more") {
		t.Fatalf("inline id list not capped:\n%s", s)
	}
	if strings.Contains(s, "sid-24") {
		t.Fatalf("capped id should not appear inline:\n%s", s)
	}
}
