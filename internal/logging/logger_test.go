package logging

import (
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
	l, err := NewLogger(dbPath)
	if err != nil {
		t.Fatalf("NewLogger(%q) failed: %v", dbPath, err)
	}
	return l, dbPath
}

func boolPtr(b bool) *bool          { return &b }
func strPtr(s string) *string       { return &s }
func eventTypePtr(e EventType) *EventType { return &e }
func timePtr(t time.Time) *time.Time     { return &t }

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
	l, err := NewLogger(dbPath)
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
	l1, err := NewLogger(dbPath)
	if err != nil {
		t.Fatalf("first NewLogger failed: %v", err)
	}

	evt := sampleEvent(EventSecretBlocked, "secret", "API_KEY", true, "sess-1")
	if err := l1.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	l1.Close()

	// Reopen the same DB.
	l2, err := NewLogger(dbPath)
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
	_, err := NewLogger("/dev/null/impossible/path/events.db")
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
	if len(events) != 4 {
		t.Fatalf("expected 4 events in range, got %d", len(events))
	}
	for _, e := range events {
		if e.Timestamp.Before(since) || e.Timestamp.After(until) {
			t.Errorf("event timestamp %v outside range [%v, %v]", e.Timestamp, since, until)
		}
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
	_, err := NewLogger("../../etc/evil.db")
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
