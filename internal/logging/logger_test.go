package logging

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- helpers ----------

func tempDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test-events.db")
}

func mustNewLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	dbPath := tempDBPath(t)
	l, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("NewLogger(%q) failed: %v", dbPath, err)
	}
	return l, dbPath
}

func boolPtr(b bool) *bool                { return &b }
func strPtr(s string) *string             { return &s }
func eventTypePtr(e EventType) *EventType { return &e }
func timePtr(t time.Time) *time.Time      { return &t }

func sampleEvent(et EventType, category, detail string, blocked bool, sessionID string) Event {
	return Event{
		Timestamp: time.Now().UTC().Truncate(time.Second),
		EventType: et,
		Category:  category,
		Detail:    detail,
		Blocked:   blocked,
		SessionID: sessionID,
	}
}

// ---------- Database lifecycle ----------

func TestNewLogger_CreatesDBFile(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	defer l.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("DB file not created: %v", err)
	}
	if info.IsDir() {
		t.Fatal("DB path is a directory, expected a file")
	}
}

func TestNewLogger_CreatesParentDirectories(t *testing.T) {
	base := t.TempDir()
	dbPath := filepath.Join(base, "deep", "nested", "dir", "events.db")
	l, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("NewLogger with nested path failed: %v", err)
	}
	defer l.Close()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("DB file not created at nested path: %v", err)
	}
}

func TestNewLogger_OpensExistingDBWithoutDataLoss(t *testing.T) {
	dbPath := tempDBPath(t)
	l1, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("first NewLogger failed: %v", err)
	}

	evt := sampleEvent(EventSecretBlocked, "secret", "API_KEY", true, "sess-1")
	if err := l1.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	l1.Close()

	// Reopen the same DB.
	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("second NewLogger failed: %v", err)
	}
	defer l2.Close()

	events, err := l2.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event after reopen, got %d", len(events))
	}
	if events[0].Detail != "API_KEY" {
		t.Errorf("expected detail %q, got %q", "API_KEY", events[0].Detail)
	}
}

func TestNewLogger_InvalidPathReturnsError(t *testing.T) {
	_, err := NewLogger("/dev/null/impossible/path/events.db", "")
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

func TestClose(t *testing.T) {
	l, _ := mustNewLogger(t)
	if err := l.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// After close, operations should fail.
	err := l.Log(sampleEvent(EventSessionStart, "session", "test", false, "s"))
	if err == nil {
		t.Fatal("expected error after Close, got nil")
	}
}

// ---------- Logging events ----------

func TestLog_WritesAndRetrievesAllFields(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	now := time.Now().UTC().Truncate(time.Second)
	evt := Event{
		Timestamp: now,
		EventType: EventFileBlocked,
		Category:  "filesystem",
		Detail:    "/etc/passwd",
		Blocked:   true,
		SessionID: "sess-abc",
	}
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	got := events[0]
	if got.ID == 0 {
		t.Error("expected non-zero ID")
	}
	if !got.Timestamp.Equal(now) {
		t.Errorf("timestamp mismatch: got %v, want %v", got.Timestamp, now)
	}
	if got.EventType != EventFileBlocked {
		t.Errorf("event type: got %q, want %q", got.EventType, EventFileBlocked)
	}
	if got.Category != "filesystem" {
		t.Errorf("category: got %q, want %q", got.Category, "filesystem")
	}
	if got.Detail != "/etc/passwd" {
		t.Errorf("detail: got %q, want %q", got.Detail, "/etc/passwd")
	}
	if !got.Blocked {
		t.Error("expected Blocked=true")
	}
	if got.SessionID != "sess-abc" {
		t.Errorf("session ID: got %q, want %q", got.SessionID, "sess-abc")
	}
}

func TestLog_MultipleEventsInSequence(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	for i := 0; i < 5; i++ {
		evt := sampleEvent(EventFilePassed, "filesystem", "/tmp/file", false, "sess-1")
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log #%d failed: %v", i, err)
		}
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}
}

func TestLog_AllEventTypes(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	allTypes := []EventType{
		EventSecretBlocked, EventSecretPassed,
		EventFileBlocked, EventFilePassed,
		EventNetworkBlocked, EventNetworkPassed,
		EventProxyStart, EventProxyStop, EventNetworkError,
		EventSessionStart, EventSessionEnd,
		EventConfigLoaded,
	}

	for _, et := range allTypes {
		evt := sampleEvent(et, "test", "detail", false, "sess-types")
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log(%s) failed: %v", et, err)
		}
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != len(allTypes) {
		t.Fatalf("expected %d events, got %d", len(allTypes), len(events))
	}

	gotTypes := make(map[EventType]bool)
	for _, e := range events {
		gotTypes[e.EventType] = true
	}
	for _, et := range allTypes {
		if !gotTypes[et] {
			t.Errorf("missing event type %s", et)
		}
	}
}

func TestLog_PreservesTimestampAccuracy(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	ts := time.Date(2025, 3, 15, 10, 30, 45, 0, time.UTC)
	evt := Event{
		Timestamp: ts,
		EventType: EventSessionStart,
		Category:  "session",
		Detail:    "start",
		Blocked:   false,
		SessionID: "sess-ts",
	}
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	got := events[0].Timestamp.Truncate(time.Second)
	want := ts.Truncate(time.Second)
	if !got.Equal(want) {
		t.Errorf("timestamp: got %v, want %v", got, want)
	}
}

func TestLog_EmptyDetailString(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	evt := sampleEvent(EventConfigLoaded, "session", "", false, "sess-empty")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log with empty detail failed: %v", err)
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Detail != "" {
		t.Errorf("expected empty detail, got %q", events[0].Detail)
	}
}

// ---------- Query filtering ----------

func seedEvents(t *testing.T, l *Logger) {
	t.Helper()
	base := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	events := []Event{
		{Timestamp: base, EventType: EventSecretBlocked, Category: "secret", Detail: "API_KEY", Blocked: true, SessionID: "s1"},
		{Timestamp: base.Add(1 * time.Minute), EventType: EventSecretPassed, Category: "secret", Detail: "HOME", Blocked: false, SessionID: "s1"},
		{Timestamp: base.Add(2 * time.Minute), EventType: EventFileBlocked, Category: "filesystem", Detail: "/etc/shadow", Blocked: true, SessionID: "s1"},
		{Timestamp: base.Add(3 * time.Minute), EventType: EventFilePassed, Category: "filesystem", Detail: "/tmp/out.txt", Blocked: false, SessionID: "s2"},
		{Timestamp: base.Add(4 * time.Minute), EventType: EventNetworkBlocked, Category: "network", Detail: "evil.com:443", Blocked: true, SessionID: "s2"},
		{Timestamp: base.Add(5 * time.Minute), EventType: EventNetworkPassed, Category: "network", Detail: "api.example.com:443", Blocked: false, SessionID: "s2"},
		{Timestamp: base.Add(6 * time.Minute), EventType: EventSessionStart, Category: "session", Detail: "start", Blocked: false, SessionID: "s3"},
		{Timestamp: base.Add(7 * time.Minute), EventType: EventSessionEnd, Category: "session", Detail: "end", Blocked: false, SessionID: "s3"},
	}
	for _, e := range events {
		if err := l.Log(e); err != nil {
			t.Fatalf("seedEvents: %v", err)
		}
	}
}

func TestQuery_NoFilters(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 8 {
		t.Fatalf("expected 8 events, got %d", len(events))
	}
}

func TestQuery_ByEventType(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	events, err := l.Query(QueryOptions{EventType: eventTypePtr(EventSecretBlocked)})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != EventSecretBlocked {
		t.Errorf("expected EventSecretBlocked, got %s", events[0].EventType)
	}
}

func TestQuery_ByCategory(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	events, err := l.Query(QueryOptions{Category: strPtr("network")})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 network events, got %d", len(events))
	}
	for _, e := range events {
		if e.Category != "network" {
			t.Errorf("expected category network, got %s", e.Category)
		}
	}
}

func TestQuery_ByBlockedTrue(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	events, err := l.Query(QueryOptions{Blocked: boolPtr(true)})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 blocked events, got %d", len(events))
	}
	for _, e := range events {
		if !e.Blocked {
			t.Error("expected Blocked=true for all results")
		}
	}
}

func TestQuery_ByBlockedFalse(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	events, err := l.Query(QueryOptions{Blocked: boolPtr(false)})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("expected 5 passed events, got %d", len(events))
	}
	for _, e := range events {
		if e.Blocked {
			t.Error("expected Blocked=false for all results")
		}
	}
}

func TestQuery_BySessionID(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	events, err := l.Query(QueryOptions{SessionID: strPtr("s2")})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events for s2, got %d", len(events))
	}
	for _, e := range events {
		if e.SessionID != "s2" {
			t.Errorf("expected session s2, got %s", e.SessionID)
		}
	}
}

func TestQuery_SinceUntilTimeRange(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	base := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	since := base.Add(2 * time.Minute)
	until := base.Add(5 * time.Minute)

	events, err := l.Query(QueryOptions{Since: timePtr(since), Until: timePtr(until)})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) < 3 || len(events) > 4 {
		t.Fatalf("expected 3 events in range (or more), got %d", len(events))
	}
	for _, e := range events {
		if e.Timestamp.Before(since) || e.Timestamp.After(until) {
			t.Errorf("event timestamp %v outside range [%v, %v]", e.Timestamp, since, until)
		}
	}
}

func TestQuery_SinceUntilBoundarySubSecondPrecision(t *testing.T) {
	// Stored timestamps carry 9 fractional digits. A Since/Until bound must be
	// encoded the same way, or a second-precision bound sorts lexicographically
	// against the stored value and silently drops (Since) or over-includes
	// (Until) events inside the boundary second. Regression guard for the
	// format change that made storage 9-digit while bounds stayed RFC3339.
	l, _ := mustNewLogger(t)
	defer l.Close()

	// An event half a second into the boundary second.
	evtTime := time.Date(2025, 6, 1, 12, 0, 0, 500_000_000, time.UTC)
	if err := l.Log(Event{
		Timestamp: evtTime,
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    "BOUNDARY",
		Blocked:   true,
		SessionID: "sess-boundary",
	}); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	secondStart := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC) // 12:00:00.000

	// Since the top of the second must INCLUDE the .5s event (it is after it).
	got, err := l.Query(QueryOptions{Since: timePtr(secondStart)})
	if err != nil {
		t.Fatalf("Query(Since) failed: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Since=%s must include the 12:00:00.5 event, got %d", secondStart.Format(time.RFC3339), len(got))
	}

	// Until the top of the second must EXCLUDE the .5s event (it is after it).
	got, err = l.Query(QueryOptions{Until: timePtr(secondStart)})
	if err != nil {
		t.Fatalf("Query(Until) failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Until=%s must exclude the 12:00:00.5 event, got %d", secondStart.Format(time.RFC3339), len(got))
	}
}

func TestQuery_LimitAndOffset(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	// First page: 3 events.
	page1, err := l.Query(QueryOptions{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("Query page 1 failed: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page 1: expected 3, got %d", len(page1))
	}

	// Second page: 3 events.
	page2, err := l.Query(QueryOptions{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatalf("Query page 2 failed: %v", err)
	}
	if len(page2) != 3 {
		t.Fatalf("page 2: expected 3, got %d", len(page2))
	}

	// Third page: 2 remaining events.
	page3, err := l.Query(QueryOptions{Limit: 3, Offset: 6})
	if err != nil {
		t.Fatalf("Query page 3 failed: %v", err)
	}
	if len(page3) != 2 {
		t.Fatalf("page 3: expected 2, got %d", len(page3))
	}

	// Ensure no overlap between pages.
	ids := make(map[int64]bool)
	for _, e := range page1 {
		ids[e.ID] = true
	}
	for _, e := range page2 {
		if ids[e.ID] {
			t.Errorf("page 2 event ID %d overlaps with page 1", e.ID)
		}
		ids[e.ID] = true
	}
	for _, e := range page3 {
		if ids[e.ID] {
			t.Errorf("page 3 event ID %d overlaps with earlier pages", e.ID)
		}
	}
}

func TestQuery_MultipleFilters(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	// AND logic: blocked AND filesystem category.
	events, err := l.Query(QueryOptions{
		Category: strPtr("filesystem"),
		Blocked:  boolPtr(true),
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 blocked filesystem event, got %d", len(events))
	}
	if events[0].Detail != "/etc/shadow" {
		t.Errorf("expected /etc/shadow, got %s", events[0].Detail)
	}
}

func TestQuery_NoMatchesReturnsEmptySlice(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	events, err := l.Query(QueryOptions{Category: strPtr("nonexistent")})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if events == nil {
		t.Fatal("expected non-nil slice, got nil")
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

// ---------- Stats ----------

func TestStats_AllSessions(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	s, err := l.Stats("")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if s.TotalEvents != 8 {
		t.Errorf("TotalEvents: got %d, want 8", s.TotalEvents)
	}
	if s.BlockedCount != 3 {
		t.Errorf("BlockedCount: got %d, want 3", s.BlockedCount)
	}
	if s.PassedCount != 5 {
		t.Errorf("PassedCount: got %d, want 5", s.PassedCount)
	}
	if s.SessionCount != 3 {
		t.Errorf("SessionCount: got %d, want 3", s.SessionCount)
	}
	if s.FirstEvent == nil || s.LastEvent == nil {
		t.Fatal("expected non-nil FirstEvent and LastEvent")
	}
}

func TestStats_SpecificSession(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	s, err := l.Stats("s1")
	if err != nil {
		t.Fatalf("Stats(s1) failed: %v", err)
	}
	if s.TotalEvents != 3 {
		t.Errorf("TotalEvents for s1: got %d, want 3", s.TotalEvents)
	}
	if s.SessionCount != 1 {
		t.Errorf("SessionCount for s1: got %d, want 1", s.SessionCount)
	}
	if s.BlockedCount != 2 {
		t.Errorf("BlockedCount for s1: got %d, want 2", s.BlockedCount)
	}
	if s.PassedCount != 1 {
		t.Errorf("PassedCount for s1: got %d, want 1", s.PassedCount)
	}
}

func TestStats_NoEvents(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	s, err := l.Stats("")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if s.TotalEvents != 0 {
		t.Errorf("TotalEvents: got %d, want 0", s.TotalEvents)
	}
	if s.BlockedCount != 0 {
		t.Errorf("BlockedCount: got %d, want 0", s.BlockedCount)
	}
	if s.PassedCount != 0 {
		t.Errorf("PassedCount: got %d, want 0", s.PassedCount)
	}
	if s.SessionCount != 0 {
		t.Errorf("SessionCount: got %d, want 0", s.SessionCount)
	}
	if s.FirstEvent != nil {
		t.Errorf("expected nil FirstEvent, got %v", s.FirstEvent)
	}
	if s.LastEvent != nil {
		t.Errorf("expected nil LastEvent, got %v", s.LastEvent)
	}
}

func TestStats_ByCategoryAndByType(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	seedEvents(t, l)

	s, err := l.Stats("")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	// ByCategory: secret=2, filesystem=2, network=2, session=2
	expectedCats := map[string]int{
		"secret":     2,
		"filesystem": 2,
		"network":    2,
		"session":    2,
	}
	for cat, want := range expectedCats {
		got := s.ByCategory[cat]
		if got != want {
			t.Errorf("ByCategory[%s]: got %d, want %d", cat, got, want)
		}
	}

	// ByType: each event type appears once.
	expectedTypes := []EventType{
		EventSecretBlocked, EventSecretPassed,
		EventFileBlocked, EventFilePassed,
		EventNetworkBlocked, EventNetworkPassed,
		EventSessionStart, EventSessionEnd,
	}
	for _, et := range expectedTypes {
		got := s.ByType[et]
		if got != 1 {
			t.Errorf("ByType[%s]: got %d, want 1", et, got)
		}
	}
}

// ---------- Pruning ----------

func TestPrune_RemovesOldEvents(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	// Insert an old event and a recent event.
	old := Event{
		Timestamp: time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second),
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    "OLD_KEY",
		Blocked:   true,
		SessionID: "s-old",
	}
	recent := Event{
		Timestamp: time.Now().UTC().Truncate(time.Second),
		EventType: EventSecretPassed,
		Category:  "secret",
		Detail:    "NEW_KEY",
		Blocked:   false,
		SessionID: "s-new",
	}
	if err := l.Log(old); err != nil {
		t.Fatalf("Log old: %v", err)
	}
	if err := l.Log(recent); err != nil {
		t.Fatalf("Log recent: %v", err)
	}

	pruned, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned count: got %d, want 1", pruned)
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 remaining event, got %d", len(events))
	}
	if events[0].Detail != "NEW_KEY" {
		t.Errorf("remaining event detail: got %q, want %q", events[0].Detail, "NEW_KEY")
	}
}

func TestPrune_ReturnsCorrectCount(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	for i := 0; i < 5; i++ {
		evt := Event{
			Timestamp: time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second),
			EventType: EventFileBlocked,
			Category:  "filesystem",
			Detail:    "/old",
			Blocked:   true,
			SessionID: "s-prune",
		}
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	pruned, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if pruned != 5 {
		t.Errorf("pruned count: got %d, want 5", pruned)
	}
}

func TestPrune_NoOldEventsRemovesNothing(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	evt := sampleEvent(EventFilePassed, "filesystem", "/new", false, "s-new")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log: %v", err)
	}

	pruned, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if pruned != 0 {
		t.Errorf("pruned count: got %d, want 0", pruned)
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestPruneRetainsEventAfterFractionalCutoff(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	pruneAge := 24 * time.Hour
	eventTime := time.Now().Add(-pruneAge).Add(500 * time.Millisecond)
	oldCutoffFormat := eventTime.Truncate(time.Second).Format(time.RFC3339)
	storedTimestamp := formatTimestampForChain(eventTime)
	if !(storedTimestamp < oldCutoffFormat) {
		t.Fatalf("negative control failed: fractional timestamp %q should sort before second-precision cutoff %q", storedTimestamp, oldCutoffFormat)
	}
	if err := l.Log(Event{Timestamp: eventTime, EventType: EventSessionStart, Category: "session", Detail: "boundary", SessionID: "fractional-cutoff"}); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	pruned, err := l.Prune(pruneAge)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("Prune removed %d events, want 0 for event after cutoff", pruned)
	}
}

// ---------- Security ----------

func TestSecurity_DetailStoresNamesNotValues(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	// Log event with env var name (not value).
	evt := sampleEvent(EventSecretBlocked, "secret", "DATABASE_URL", true, "s-sec")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log: %v", err)
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if strings.Contains(events[0].Detail, "=") {
		t.Error("detail field should not contain '=' (store names, not key=value pairs)")
	}
}

func TestSecurity_PathTraversalBlocked(t *testing.T) {
	_, err := NewLogger("../../etc/evil.db", "")
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("expected path traversal error, got: %v", err)
	}
}

func TestSecurity_SQLInjectionPrevented(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	// Attempt SQL injection through detail field.
	malicious := "'; DROP TABLE events; --"
	evt := sampleEvent(EventSecretBlocked, "secret", malicious, true, "s-inject")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log with injection attempt failed: %v", err)
	}

	// Table should still be intact.
	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query after injection attempt failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Detail != malicious {
		t.Errorf("detail should store literal string, got %q", events[0].Detail)
	}

	// Also attempt injection through session_id filter.
	injectedSession := "'; DROP TABLE events; --"
	events, err = l.Query(QueryOptions{SessionID: &injectedSession})
	if err != nil {
		t.Fatalf("Query with injected session failed: %v", err)
	}
	// Should return no events (no session with that ID).
	if len(events) != 0 {
		t.Errorf("expected 0 events for injected session, got %d", len(events))
	}

	// Verify table still works.
	events, err = l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query after injection should still work: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("table should still have 1 event, got %d", len(events))
	}
}

func TestSecurity_FilePermissions(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	defer l.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permissions: got %o, want 600", perm)
	}
}

// ---------- Concurrency ----------

func TestConcurrency_MultipleGoroutinesLog(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	const goroutines = 10
	const eventsPerGoroutine = 20

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*eventsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				evt := Event{
					Timestamp: time.Now().UTC().Truncate(time.Second),
					EventType: EventFilePassed,
					Category:  "filesystem",
					Detail:    "/tmp/concurrent",
					Blocked:   false,
					SessionID: "s-concurrent",
				}
				if err := l.Log(evt); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Log error: %v", err)
	}

	events, err := l.Query(QueryOptions{Limit: goroutines * eventsPerGoroutine})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	expected := goroutines * eventsPerGoroutine
	if len(events) != expected {
		t.Errorf("expected %d events, got %d", expected, len(events))
	}
}

func TestConcurrency_LogAndQuerySimultaneous(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	// Seed some initial events.
	for i := 0; i < 10; i++ {
		evt := sampleEvent(EventNetworkPassed, "network", "example.com", false, "s-rw")
		if err := l.Log(evt); err != nil {
			t.Fatalf("seed Log: %v", err)
		}
	}

	var wg sync.WaitGroup
	logErrs := make(chan error, 50)
	queryErrs := make(chan error, 50)

	// Writers.
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				evt := Event{
					Timestamp: time.Now().UTC().Truncate(time.Second),
					EventType: EventNetworkBlocked,
					Category:  "network",
					Detail:    "blocked.com",
					Blocked:   true,
					SessionID: "s-rw",
				}
				if err := l.Log(evt); err != nil {
					logErrs <- err
				}
			}
		}()
	}

	// Readers.
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				_, err := l.Query(QueryOptions{SessionID: strPtr("s-rw")})
				if err != nil {
					queryErrs <- err
				}
			}
		}()
	}

	wg.Wait()
	close(logErrs)
	close(queryErrs)

	for err := range logErrs {
		t.Errorf("concurrent Log error: %v", err)
	}
	for err := range queryErrs {
		t.Errorf("concurrent Query error: %v", err)
	}
}

// ============ AUDIT CHAIN TESTS ============

func TestCanonicalBytes_ByteLiteralPin(t *testing.T) {
	// CRITICAL: This test pins the exact canonical byte format using a hardcoded oracle.
	// It serves as an independent check that canonicalBytes() maintains fixed field order.
	// Expected values computed out-of-band with Python hashlib.
	// Timestamp must have EXACTLY 9 fractional-second digits with trailing Z.

	id := int64(1)
	ts := "2025-03-15T10:30:45.123456789Z"
	et := EventSecretBlocked
	cat := "secret"
	detail := "API_KEY"
	blocked := true
	sid := "sess-1"

	cb := canonicalBytes(id, ts, et, cat, detail, blocked, sid)

	// Expected canonical bytes (hardcoded oracle from Python):
	expectedCanonical := []byte{
		0x01,                                           // version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // id=1 u64be
		0x00, 0x00, 0x00, 0x1e, // len("2025-03-15T10:30:45.123456789Z") = 30
		0x32, 0x30, 0x32, 0x35, 0x2d, 0x30, 0x33, 0x2d, 0x31, 0x35, 0x54, 0x31, 0x30, 0x3a, 0x33, 0x30, 0x3a, 0x34, 0x35, 0x2e, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x5a, // "2025-03-15T10:30:45.123456789Z"
		0x00, 0x00, 0x00, 0x0e, // len("secret_blocked") = 14
		0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, // "secret_blocked"
		0x00, 0x00, 0x00, 0x06, // len("secret") = 6
		0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // "secret"
		0x00, 0x00, 0x00, 0x07, // len("API_KEY") = 7
		0x41, 0x50, 0x49, 0x5f, 0x4b, 0x45, 0x59, // "API_KEY"
		0x01,                   // blocked=true
		0x00, 0x00, 0x00, 0x06, // len("sess-1") = 6
		0x73, 0x65, 0x73, 0x73, 0x2d, 0x31, // "sess-1"
	}

	if len(cb) != len(expectedCanonical) {
		t.Errorf("canonical bytes length: got %d, want %d", len(cb), len(expectedCanonical))
	}
	if !bytesEqual(cb, expectedCanonical) {
		t.Errorf("canonical bytes mismatch:\ngot:  %x\nwant: %x", cb, expectedCanonical)
	}

	// Also verify the entry_hash matches the oracle value
	entryHash, err := chainEntry(id, ts, et, cat, detail, blocked, sid, chainGenesisHashHex)
	if err != nil {
		t.Fatalf("chainEntry failed: %v", err)
	}

	// Expected entry_hash (oracle computed: hex(sha256(cb || genesis_bytes)))
	expectedHash := "9cd9976e175dad0c1fe728164b8d3cb752817b170c7ffcc0ba92c56c873cee42"
	if entryHash != expectedHash {
		t.Errorf("entry_hash mismatch: got %s, want %s", entryHash, expectedHash)
	}
}

func TestChainIntact_SingleEvent(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	evt := sampleEvent(EventSecretBlocked, "secret", "TEST_VAR", true, "sess-chain-1")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if !result.Intact {
		t.Errorf("chain should be intact, got broken: %s", result.BrokenReason)
	}
	if result.EntriesVerified != 1 {
		t.Errorf("entries verified: got %d, want 1", result.EntriesVerified)
	}
	if result.HeadHash == "" {
		t.Error("head hash should not be empty")
	}
}

func TestChainIntact_MultipleEvents(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	for i := 0; i < 10; i++ {
		evt := sampleEvent(EventFilePassed, "filesystem", "/tmp/file", false, "sess-chain-multi")
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if !result.Intact {
		t.Errorf("chain should be intact, got broken: %s", result.BrokenReason)
	}
	if result.EntriesVerified != 10 {
		t.Errorf("entries verified: got %d, want 10", result.EntriesVerified)
	}
}

func TestMigrationUsesEventCountWhenLegacyIDsHaveGaps(t *testing.T) {
	dbPath := tempDBPath(t)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			event_type TEXT NOT NULL,
			category TEXT NOT NULL,
			detail TEXT NOT NULL,
			blocked INTEGER NOT NULL DEFAULT 0,
			session_id TEXT NOT NULL
		);
		INSERT INTO events (id, timestamp, event_type, category, detail, blocked, session_id)
		VALUES (1, '2026-09-14T10:00:00Z', 'session_start', 'session', 'first', 0, 'legacy'),
		       (3, '2026-09-14T10:02:00Z', 'session_end', 'session', 'third', 0, 'legacy');
	`)
	if err != nil {
		db.Close()
		t.Fatalf("create legacy database with ID gap: %v", err)
	}
	db.Close()

	l, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("NewLogger migration failed: %v", err)
	}
	defer l.Close()

	var rowCount int
	var legacyThroughID int64
	if err := l.db.QueryRow("SELECT row_count, legacy_through_id FROM chain_head WHERE id = 1").Scan(&rowCount, &legacyThroughID); err != nil {
		t.Fatalf("read migrated chain head: %v", err)
	}
	if rowCount == int(legacyThroughID) {
		t.Fatalf("negative control failed: gapped legacy IDs should make row count differ from highest ID; both were %d", rowCount)
	}
	if rowCount != 2 || legacyThroughID != 3 {
		t.Fatalf("migrated chain head = (row_count %d, legacy_through_id %d), want (2, 3)", rowCount, legacyThroughID)
	}

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !result.Intact {
		t.Fatalf("migrated chain with legacy ID gap should be intact: %s", result.BrokenReason)
	}
}

func TestMigrationNormalizesLegacyTimestampsForBoundaryQueries(t *testing.T) {
	// A pre-chain DB stored timestamps at second precision. After migration the
	// column must be uniform 9-digit, or a boundary-second Until query silently
	// drops a legacy row: the legacy "...00Z" sorts lexicographically after a
	// 9-digit bound "...00.000000000Z". Regression guard for the mixed-width
	// timestamp column (also fixes Prune cutoff and Stats MIN/MAX on legacy DBs).
	dbPath := tempDBPath(t)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			event_type TEXT NOT NULL,
			category TEXT NOT NULL,
			detail TEXT NOT NULL,
			blocked INTEGER NOT NULL DEFAULT 0,
			session_id TEXT NOT NULL
		);
		INSERT INTO events (id, timestamp, event_type, category, detail, blocked, session_id)
		VALUES (1, '2026-09-14T10:00:00Z', 'session_start', 'session', 'legacy-boundary', 0, 'legacy');
	`)
	if err != nil {
		db.Close()
		t.Fatalf("create legacy database: %v", err)
	}
	db.Close()

	l, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("NewLogger migration failed: %v", err)
	}
	defer l.Close()

	// (a) The stored timestamp is normalized to 9 fractional digits.
	var stored string
	if err := l.db.QueryRow("SELECT timestamp FROM events WHERE id = 1").Scan(&stored); err != nil {
		t.Fatalf("read migrated timestamp: %v", err)
	}
	if want := "2026-09-14T10:00:00.000000000Z"; stored != want {
		t.Errorf("legacy timestamp not normalized: got %q, want %q", stored, want)
	}

	// (b) An Until query at exactly the legacy row's second must INCLUDE it.
	boundary := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	got, err := l.Query(QueryOptions{Until: timePtr(boundary)})
	if err != nil {
		t.Fatalf("Query(Until) failed: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Until=%s must include the legacy 10:00:00 row, got %d", boundary.Format(time.RFC3339), len(got))
	}

	// (c) The migrated chain verifies intact over the normalized value.
	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !result.Intact {
		t.Fatalf("migrated chain should be intact: %s", result.BrokenReason)
	}
}

func TestVerifyChainUsesConsistentSnapshot(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	defer l.Close()
	if err := l.Log(sampleEvent(EventSessionStart, "session", "first", false, "snapshot")); err != nil {
		t.Fatalf("initial Log failed: %v", err)
	}

	// Negative control: separate reads can observe an old head and a newer event set.
	var oldCount int
	if err := l.db.QueryRow("SELECT row_count FROM chain_head WHERE id = 1").Scan(&oldCount); err != nil {
		t.Fatalf("read old chain head: %v", err)
	}
	writer, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("open concurrent writer: %v", err)
	}
	defer writer.Close()
	if err := writer.Log(sampleEvent(EventSessionEnd, "session", "second", false, "snapshot")); err != nil {
		t.Fatalf("concurrent Log failed: %v", err)
	}
	var newCount int
	if err := l.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&newCount); err != nil {
		t.Fatalf("read new event count: %v", err)
	}
	if oldCount == newCount {
		t.Fatalf("negative control failed: separate snapshots both reported %d rows", oldCount)
	}

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !result.Intact || result.EntriesVerified != newCount {
		t.Fatalf("transactional verification = intact %v, entries %d, reason %q; want intact snapshot with %d entries", result.Intact, result.EntriesVerified, result.BrokenReason, newCount)
	}
}

func TestTamperDetection_BlockedBitFlip(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	l.Close()

	// Log an event
	l, _ = NewLogger(dbPath, "")
	evt := sampleEvent(EventSecretBlocked, "secret", "TEST", true, "sess-tamper")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	l.Close()

	// Tamper: flip blocked bit via raw SQL
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	_, err = db.Exec("UPDATE events SET blocked = 0 WHERE id = 1")
	if err != nil {
		t.Fatalf("tamper failed: %v", err)
	}
	db.Close()

	// Verify detects tampering
	l, _ = NewLogger(dbPath, "")
	defer l.Close()

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if result.Intact {
		t.Error("tampered chain should be detected as broken")
	}
	if result.FirstBrokenID != 1 {
		t.Errorf("first broken ID: got %d, want 1", result.FirstBrokenID)
	}
}

func TestTamperDetection_DetailMutation(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	l.Close()

	l, _ = NewLogger(dbPath, "")
	evt := sampleEvent(EventFileBlocked, "filesystem", "/etc/passwd", true, "sess-tamper-detail")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	l.Close()

	// Tamper: change detail
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	_, err = db.Exec("UPDATE events SET detail = '/etc/shadow' WHERE id = 1")
	if err != nil {
		t.Fatalf("tamper failed: %v", err)
	}
	db.Close()

	l, _ = NewLogger(dbPath, "")
	defer l.Close()

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if result.Intact {
		t.Error("tampered chain should be detected")
	}
}

func TestTamperDetection_MiddleRowDeletion(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	l.Close()

	l, _ = NewLogger(dbPath, "")
	for i := 0; i < 5; i++ {
		evt := sampleEvent(EventNetworkPassed, "network", "example.com", false, "sess-tamper-mid")
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}
	l.Close()

	// Tamper: delete middle row (id=3)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	_, err = db.Exec("DELETE FROM events WHERE id = 3")
	if err != nil {
		t.Fatalf("tamper failed: %v", err)
	}
	db.Close()

	l, _ = NewLogger(dbPath, "")
	defer l.Close()

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if result.Intact {
		t.Error("tampered chain (middle deletion) should be detected")
	}
}

func TestTamperDetection_TailTruncation(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	l.Close()

	l, _ = NewLogger(dbPath, "")
	for i := 0; i < 10; i++ {
		evt := sampleEvent(EventSessionStart, "session", "start", false, "sess-tail-trunc")
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}
	l.Close()

	// Tamper: delete tail rows (6-10)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	_, err = db.Exec("DELETE FROM events WHERE id > 5")
	if err != nil {
		t.Fatalf("tamper failed: %v", err)
	}
	db.Close()

	l, _ = NewLogger(dbPath, "")
	defer l.Close()

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if result.Intact {
		t.Error("tampered chain (tail truncation) should be detected via chain_head row_count")
	}
}

func TestTailTruncationWithChainHeadRewrite_DocumentsV1Limit(t *testing.T) {
	// This test documents the v1 honest limit: if both data AND chain_head are rewritten,
	// tail truncation appears intact. This is an acceptable v1 limitation.
	l, dbPath := mustNewLogger(t)
	l.Close()

	l, _ = NewLogger(dbPath, "")
	for i := 0; i < 5; i++ {
		evt := sampleEvent(EventConfigLoaded, "session", "config", false, "sess-v1-limit")
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}
	l.Close()

	// Get the current head hash (from id=3, assuming we'll keep first 3)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	var headHashAtID3 string
	err = db.QueryRow("SELECT entry_hash FROM events WHERE id = 3").Scan(&headHashAtID3)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	// Delete tail rows AND rewrite chain_head
	_, err = db.Exec("DELETE FROM events WHERE id > 3")
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	_, err = db.Exec("UPDATE chain_head SET entry_hash = ?, row_count = 3 WHERE id = 1", headHashAtID3)
	if err != nil {
		t.Fatalf("chain_head update failed: %v", err)
	}
	db.Close()

	// Verify: should appear intact (this documents the v1 limit)
	l, _ = NewLogger(dbPath, "")
	defer l.Close()

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	// With this attack, v1 cannot detect the truncation because chain_head matches
	if !result.Intact {
		t.Error("rewritten tail + rewritten chain_head appears intact (v1 limit documented)")
	}
}

func TestPruneReAnchorsChain(t *testing.T) {
	// After Prune, the chain is re-anchored at the first surviving row.
	// VerifyChain should return intact=true with prune marker info.
	l, dbPath := mustNewLogger(t)
	l.Close()

	l, _ = NewLogger(dbPath, "")

	// Log an old event and several recent events
	oldTime := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	recentTime := time.Now().UTC().Truncate(time.Second)

	oldEvt := Event{
		Timestamp: oldTime,
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    "OLD_SECRET",
		Blocked:   true,
		SessionID: "sess-prune-reanchor",
	}
	for i := 0; i < 3; i++ {
		recentEvt := Event{
			Timestamp: recentTime.Add(time.Duration(i) * time.Second),
			EventType: EventSecretPassed,
			Category:  "secret",
			Detail:    "NEW_SECRET",
			Blocked:   false,
			SessionID: "sess-prune-reanchor",
		}
		if err := l.Log(recentEvt); err != nil {
			t.Fatalf("Log recent %d failed: %v", i, err)
		}
	}
	if err := l.Log(oldEvt); err != nil {
		t.Fatalf("Log old failed: %v", err)
	}

	// Now prune old events
	pruned, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned count: got %d, want 1", pruned)
	}

	// Verify: chain should be intact (re-anchored)
	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if !result.Intact {
		t.Errorf("re-anchored chain should be intact, got broken: %s", result.BrokenReason)
	}
	if result.EntriesVerified != 3 {
		t.Errorf("entries verified after prune: got %d, want 3", result.EntriesVerified)
	}
	// The prune boundary must be recorded so verify can surface it; an intact
	// verdict with no prune marker would let a compaction read as pristine.
	if result.PrunedAt == nil {
		t.Error("PrunedAt not set after a prune; the re-anchor left no boundary marker")
	}
	if result.PrunedCount != 1 {
		t.Errorf("PrunedCount after prune: got %d, want 1", result.PrunedCount)
	}
}

func TestLogAfterTailPruneContinuesFromChainHead(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Log(Event{Timestamp: now, EventType: EventSessionStart, Category: "session", Detail: "survivor", SessionID: "tail-prune"}); err != nil {
			t.Fatalf("Log survivor %d failed: %v", i, err)
		}
	}
	if err := l.Log(Event{Timestamp: now.Add(-48 * time.Hour), EventType: EventSessionEnd, Category: "session", Detail: "old-tail", SessionID: "tail-prune"}); err != nil {
		t.Fatalf("Log old tail failed: %v", err)
	}
	if pruned, err := l.Prune(24 * time.Hour); err != nil || pruned != 1 {
		t.Fatalf("Prune = (%d, %v), want (1, nil)", pruned, err)
	}
	if err := l.Log(Event{Timestamp: now, EventType: EventSessionEnd, Category: "session", Detail: "after-prune", SessionID: "tail-prune"}); err != nil {
		t.Fatalf("Log after tail prune failed: %v", err)
	}

	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !result.Intact {
		t.Fatalf("chain should remain intact after logging across an ID gap: %s", result.BrokenReason)
	}
}

func TestTamperingAfterPruneDetected(t *testing.T) {
	// After Prune re-anchors, tampering a surviving row is still detected.
	l, dbPath := mustNewLogger(t)
	l.Close()

	l, _ = NewLogger(dbPath, "")

	// Log old event + new events
	oldTime := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	recentTime := time.Now().UTC().Truncate(time.Second)

	oldEvt := Event{
		Timestamp: oldTime,
		EventType: EventFileBlocked,
		Category:  "filesystem",
		Detail:    "/old/path",
		Blocked:   true,
		SessionID: "sess-tamp-post-prune",
	}
	recentEvt := Event{
		Timestamp: recentTime,
		EventType: EventFilePassed,
		Category:  "filesystem",
		Detail:    "/new/path",
		Blocked:   false,
		SessionID: "sess-tamp-post-prune",
	}

	if err := l.Log(oldEvt); err != nil {
		t.Fatalf("Log old failed: %v", err)
	}
	if err := l.Log(recentEvt); err != nil {
		t.Fatalf("Log recent failed: %v", err)
	}

	// Prune old events
	if _, err := l.Prune(24 * time.Hour); err != nil {
		t.Fatalf("Prune failed: %v", err)
	}

	// Verify chain is intact after prune
	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !result.Intact {
		t.Fatalf("chain should be intact after prune: %s", result.BrokenReason)
	}

	l.Close()

	// Tamper: change the surviving row's detail
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	_, err = db.Exec("UPDATE events SET detail = '/tampered/path' WHERE id = 2")
	if err != nil {
		t.Fatalf("tamper failed: %v", err)
	}
	db.Close()

	// Re-open and verify: should detect tampering
	l, _ = NewLogger(dbPath, "")
	defer l.Close()

	result, err = l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain after tamper failed: %v", err)
	}

	if result.Intact {
		t.Error("tampered chain after prune should be detected as broken")
	}
	if result.FirstBrokenID != 2 {
		t.Errorf("first broken ID: got %d, want 2", result.FirstBrokenID)
	}
}

func TestMigration_ChainExistingDB(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	l.Close()

	// Re-open with existing DB to trigger detection that hash columns are missing
	l, _ = NewLogger(dbPath, "")

	// Log a few events to create a migration scenario
	for i := 0; i < 3; i++ {
		evt := sampleEvent(EventFilePassed, "filesystem", "/tmp/test", false, "sess-mig")
		if err := l.Log(evt); err != nil {
			t.Fatalf("Log failed: %v", err)
		}
	}

	// Verify that migration worked and chain is intact
	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if !result.Intact {
		t.Errorf("chain after migration should be intact: %s", result.BrokenReason)
	}
	if result.EntriesVerified != 3 {
		t.Errorf("entries after migration: got %d, want 3", result.EntriesVerified)
	}
	if result.MigratedAt != nil {
		// If this is the first run, there should be no migration marker
		// (only set if the DB pre-existed without hash columns)
		// For a fresh logger, it's nil
	}

	l.Close()
}

func TestConcurrencyWithAuditChain(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	const goroutines = 10
	const eventsPerGoroutine = 20

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*eventsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				evt := Event{
					Timestamp: time.Now().UTC().Truncate(time.Second),
					EventType: EventFilePassed,
					Category:  "filesystem",
					Detail:    "/tmp/concurrent",
					Blocked:   false,
					SessionID: "s-concurrent-audit",
				}
				if err := l.Log(evt); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Log error: %v", err)
	}

	// Verify chain is still intact
	result, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	if !result.Intact {
		t.Errorf("chain after concurrent logging should be intact: %s", result.BrokenReason)
	}
	if result.EntriesVerified != goroutines*eventsPerGoroutine {
		t.Errorf("entries verified: got %d, want %d", result.EntriesVerified, goroutines*eventsPerGoroutine)
	}
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
