package cli

import (
	"path/filepath"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// fakeDecisionSink records every event the reader would sign into the audit log,
// so the test asserts exactly what logger.Log() receives — without a real DB,
// signing key, root, or netns.
type fakeDecisionSink struct {
	events []logging.Event
}

func (f *fakeDecisionSink) Log(e logging.Event) error {
	f.events = append(f.events, e)
	return nil
}

// TestDecisionLogScanner exercises wrap's decision-log READER in isolation: it
// feeds allow, deny, and a partial-line-then-completed case, and asserts the
// scanner logs one correctly-mapped event per COMPLETE record and NEVER on a
// partial (unterminated) line.
func TestDecisionLogScanner(t *testing.T) {
	const sessionID = "session-abc-123"
	sink := &fakeDecisionSink{}
	scanner := newDecisionLogScanner(sink, sessionID)

	// Chunk 1: one complete allow line, one complete deny line, and a trailing
	// PARTIAL line (no terminator). Only the two complete records must log.
	scanner.Feed([]byte("allow\ttls\texample.com\t443\tallowlisted\n" +
		"deny\thttp\tblocked.test\t80\tdisallowed_host\n" +
		"allow\ttls\tpartial.example"))

	if len(sink.events) != 2 {
		t.Fatalf("after chunk 1: expected 2 logged events (partial line must NOT log), got %d: %+v", len(sink.events), sink.events)
	}

	// Assert the ALLOW row: EventNetworkPassed, not blocked, mapped Detail and SessionID.
	got := sink.events[0]
	if got.EventType != logging.EventNetworkPassed {
		t.Errorf("allow row EventType = %q, want %q", got.EventType, logging.EventNetworkPassed)
	}
	if got.Blocked {
		t.Errorf("allow row Blocked = true, want false")
	}
	if got.Category != "network" {
		t.Errorf("allow row Category = %q, want %q", got.Category, "network")
	}
	if want := "method=tls host=example.com:443 rule=allowlisted"; got.Detail != want {
		t.Errorf("allow row Detail = %q, want %q", got.Detail, want)
	}
	if got.SessionID != sessionID {
		t.Errorf("allow row SessionID = %q, want %q", got.SessionID, sessionID)
	}

	// Assert the DENY row: EventNetworkBlocked, blocked=true, mapped Detail.
	got = sink.events[1]
	if got.EventType != logging.EventNetworkBlocked {
		t.Errorf("deny row EventType = %q, want %q", got.EventType, logging.EventNetworkBlocked)
	}
	if !got.Blocked {
		t.Errorf("deny row Blocked = false, want true")
	}
	if want := "method=http host=blocked.test:80 rule=disallowed_host"; got.Detail != want {
		t.Errorf("deny row Detail = %q, want %q", got.Detail, want)
	}
	if got.SessionID != sessionID {
		t.Errorf("deny row SessionID = %q, want %q", got.SessionID, sessionID)
	}

	// Chunk 2: completes the partial line from chunk 1. It must NOW log exactly
	// one more event — the record split across the two feeds, reassembled.
	scanner.Feed([]byte("\t443\tallowlisted\n"))
	if len(sink.events) != 3 {
		t.Fatalf("after chunk 2: expected 3 total events (partial completed), got %d", len(sink.events))
	}
	got = sink.events[2]
	if got.EventType != logging.EventNetworkPassed {
		t.Errorf("completed row EventType = %q, want %q", got.EventType, logging.EventNetworkPassed)
	}
	if want := "method=tls host=partial.example:443 rule=allowlisted"; got.Detail != want {
		t.Errorf("completed row Detail = %q, want %q", got.Detail, want)
	}
}

// TestDecisionLogScannerSkipsMalformed confirms the reader never logs a
// well-terminated but malformed line (wrong field count or unknown verdict),
// and still logs the valid records around it.
func TestDecisionLogScannerSkipsMalformed(t *testing.T) {
	sink := &fakeDecisionSink{}
	scanner := newDecisionLogScanner(sink, "s")

	scanner.Feed([]byte(
		"allow\ttls\tok.example\t443\tallowlisted\n" + // valid
			"garbage-with-no-tabs\n" + // wrong field count
			"maybe\ttls\tx.example\t443\treason\n" + // unknown verdict
			"deny\thttp\tno.example\t80\tdisallowed_host\n", // valid
	))

	if len(sink.events) != 2 {
		t.Fatalf("expected 2 valid events (malformed lines skipped), got %d: %+v", len(sink.events), sink.events)
	}
	if sink.events[0].EventType != logging.EventNetworkPassed || sink.events[1].EventType != logging.EventNetworkBlocked {
		t.Errorf("unexpected event ordering/types: %+v", sink.events)
	}
}

// TestEgressChildDenyPaths confirms the fenced child's deny list always includes
// the audit DB path and, on the netns egress path, the whole egress decision-log
// directory — closing the forgeable-receipt hole (the child shares wrap's uid).
// With no decision-log dir (non-netns), only the audit path is denied.
func TestEgressChildDenyPaths(t *testing.T) {
	projectRoot := t.TempDir()
	// Audit dir distinct from the project root so auditDenyPath returns the dir.
	dbPath := filepath.Join(projectRoot, ".nock", "events.db")

	// netns path: decision-log dir present -> must be denied alongside the audit path.
	decisionDir := t.TempDir()
	got := egressChildDenyPaths(dbPath, projectRoot, decisionDir)
	if !containsPath(got, decisionDir) {
		t.Errorf("netns deny list %v does not include the decision-log dir %q", got, decisionDir)
	}
	if !containsPath(got, filepath.Dir(dbPath)) {
		t.Errorf("netns deny list %v does not include the audit dir %q", got, filepath.Dir(dbPath))
	}

	// non-netns path: no decision-log dir -> only the audit path is denied.
	got = egressChildDenyPaths(dbPath, projectRoot, "")
	if len(got) != 1 {
		t.Fatalf("non-netns deny list should hold exactly the audit path, got %v", got)
	}
	if containsPath(got, decisionDir) {
		t.Errorf("non-netns deny list %v must not include a decision-log dir", got)
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
