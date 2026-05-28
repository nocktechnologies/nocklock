# SQLite Event Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SQLite-backed event logging so every fence action (blocked/passed env vars, future file/network events) is recorded for audit, debugging, and the `nocklock log` command.

**Architecture:** A `logging` package wraps `modernc.org/sqlite` (pure Go, no CGO) behind a `Logger` struct with `Log`, `Query`, `Stats`, and `Prune` methods. The `wrap` command generates a UUID session ID, logs fence events as they happen, and the `log` command reads them back. Path traversal protection and 0600 file permissions harden the DB file. WAL mode enables concurrent reads during a live session.

**Tech Stack:** Go 1.22+, `modernc.org/sqlite`, `github.com/google/uuid`, cobra, existing `internal/config` and `internal/fence/secrets` packages.

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `internal/logging/logger.go` | Types, NewLogger, Log, Query, Stats, Prune, Close |
| Create | `internal/logging/logger_test.go` | Full test suite for logging package |
| Modify | `internal/cli/wrap.go` | Generate session UUID, open logger, log fence events |
| Modify | `internal/cli/log.go` | Replace placeholder with real log viewer + flags |
| Modify | `internal/cli/status.go` | Add event log summary line |
| Modify | `go.mod` / `go.sum` | Add `modernc.org/sqlite` and `github.com/google/uuid` |

---

### Task 1: Add Dependencies

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Create feature branch**

```bash
cd /Users/kevin/Dev/nocklock
git checkout main
git pull origin main
git checkout -b feature/sqlite-logging
```

- [ ] **Step 2: Add dependencies**

```bash
cd /Users/kevin/Dev/nocklock
go get modernc.org/sqlite
go get github.com/google/uuid
```

- [ ] **Step 3: Verify dependencies resolve**

```bash
cd /Users/kevin/Dev/nocklock
go mod tidy
go build ./cmd/nocklock
```

Expected: clean build, no errors.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add modernc.org/sqlite and google/uuid dependencies"
```

---

### Task 2: Logger Core — Types, NewLogger, Log, Close

**Files:**
- Create: `internal/logging/logger.go`
- Create: `internal/logging/logger_test.go`

- [ ] **Step 1: Write the failing tests for NewLogger, Log, and Close**

Create `internal/logging/logger_test.go`:

```go
package logging

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

func TestNewLoggerCreatesDBAndTable(t *testing.T) {
	dbPath := tempDBPath(t)
	l, err := NewLogger(dbPath)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer l.Close()

	// DB file should exist
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("DB file not created: %v", err)
	}
	// Check file permissions are 0600
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("DB file permissions = %o, want 0600", perm)
	}
}

func TestNewLoggerCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sub", "deep", "events.db")
	l, err := NewLogger(dbPath)
	if err != nil {
		t.Fatalf("NewLogger with nested dirs failed: %v", err)
	}
	defer l.Close()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("DB file not created in nested dir: %v", err)
	}
}

func TestNewLoggerInvalidPath(t *testing.T) {
	// /dev/null/impossible is not a valid path on any OS
	_, err := NewLogger("/dev/null/impossible/events.db")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestNewLoggerPathTraversal(t *testing.T) {
	_, err := NewLogger("../../../etc/events.db")
	if err == nil {
		t.Error("expected error for path traversal")
	}

	_, err = NewLogger("/tmp/foo/../../../etc/events.db")
	if err == nil {
		t.Error("expected error for path traversal with absolute path")
	}
}

func TestNewLoggerOpensExistingDB(t *testing.T) {
	dbPath := tempDBPath(t)

	// Create and write an event
	l1, err := NewLogger(dbPath)
	if err != nil {
		t.Fatalf("first NewLogger failed: %v", err)
	}
	err = l1.Log(Event{
		Timestamp: time.Now(),
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    "AWS_ACCESS_KEY_ID",
		Blocked:   true,
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	l1.Close()

	// Reopen — data should still be there
	l2, err := NewLogger(dbPath)
	if err != nil {
		t.Fatalf("second NewLogger failed: %v", err)
	}
	defer l2.Close()

	events, err := l2.Query(QueryOptions{Limit: 10})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event after reopen, got %d", len(events))
	}
}

func TestCloseIsClean(t *testing.T) {
	l, _ := mustNewLogger(t)
	err := l.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestLogWriteAndRetrieve(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	now := time.Now().Truncate(time.Second)
	event := Event{
		Timestamp: now,
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    "AWS_ACCESS_KEY_ID",
		Blocked:   true,
		SessionID: "test-session-1",
	}
	if err := l.Log(event); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	events, err := l.Query(QueryOptions{Limit: 10})
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
	if got.EventType != EventSecretBlocked {
		t.Errorf("EventType = %q, want %q", got.EventType, EventSecretBlocked)
	}
	if got.Category != "secret" {
		t.Errorf("Category = %q, want %q", got.Category, "secret")
	}
	if got.Detail != "AWS_ACCESS_KEY_ID" {
		t.Errorf("Detail = %q, want %q", got.Detail, "AWS_ACCESS_KEY_ID")
	}
	if !got.Blocked {
		t.Error("Blocked = false, want true")
	}
	if got.SessionID != "test-session-1" {
		t.Errorf("SessionID = %q, want %q", got.SessionID, "test-session-1")
	}
	if got.Timestamp.Truncate(time.Second) != now {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, now)
	}
}

func TestLogMultipleEvents(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	for i := 0; i < 5; i++ {
		err := l.Log(Event{
			Timestamp: time.Now(),
			EventType: EventSecretBlocked,
			Category:  "secret",
			Detail:    "VAR_" + string(rune('A'+i)),
			Blocked:   true,
			SessionID: "session-1",
		})
		if err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}

	events, err := l.Query(QueryOptions{Limit: 100})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestLogAllEventTypes(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	types := []EventType{
		EventSecretBlocked, EventSecretPassed,
		EventFileBlocked, EventFilePassed,
		EventNetworkBlocked, EventNetworkPassed,
		EventSessionStart, EventSessionEnd,
		EventConfigLoaded,
	}

	for _, et := range types {
		err := l.Log(Event{
			Timestamp: time.Now(),
			EventType: et,
			Category:  "test",
			Detail:    string(et),
			SessionID: "session-1",
		})
		if err != nil {
			t.Errorf("Log(%q) failed: %v", et, err)
		}
	}

	events, err := l.Query(QueryOptions{Limit: 100})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != len(types) {
		t.Errorf("expected %d events, got %d", len(types), len(events))
	}
}

func TestLogEmptyDetail(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	err := l.Log(Event{
		Timestamp: time.Now(),
		EventType: EventSessionStart,
		Category:  "session",
		Detail:    "",
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("Log with empty detail failed: %v", err)
	}

	events, err := l.Query(QueryOptions{Limit: 10})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Detail != "" {
		t.Errorf("Detail = %q, want empty", events[0].Detail)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/kevin/Dev/nocklock
go test ./internal/logging/ -v -count=1
```

Expected: compilation error — `logging` package doesn't exist yet.

- [ ] **Step 3: Write minimal implementation — types, NewLogger, Log, Close**

Create `internal/logging/logger.go`:

```go
// Package logging provides SQLite-backed event storage for NockLock fence events.
package logging

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// EventType categorizes what kind of fence event occurred.
type EventType string

const (
	EventSecretBlocked  EventType = "secret_blocked"
	EventSecretPassed   EventType = "secret_passed"
	EventFileBlocked    EventType = "file_blocked"
	EventFilePassed     EventType = "file_passed"
	EventNetworkBlocked EventType = "network_blocked"
	EventNetworkPassed  EventType = "network_passed"
	EventSessionStart   EventType = "session_start"
	EventSessionEnd     EventType = "session_end"
	EventConfigLoaded   EventType = "config_loaded"
)

// Event represents a single fence event.
type Event struct {
	ID        int64
	Timestamp time.Time
	EventType EventType
	Category  string // "secret", "filesystem", "network", "session"
	Detail    string // what was blocked/passed (env var NAME only, never values)
	Blocked   bool
	SessionID string
}

// QueryOptions filters event queries. All fields are optional.
type QueryOptions struct {
	EventType *EventType
	Category  *string
	Blocked   *bool
	SessionID *string
	Since     *time.Time
	Until     *time.Time
	Limit     int // 0 = default (100)
	Offset    int
}

// Stats holds aggregate counts for events.
type Stats struct {
	TotalEvents  int
	BlockedCount int
	PassedCount  int
	SessionCount int
	FirstEvent   *time.Time
	LastEvent    *time.Time
	ByCategory   map[string]int
	ByType       map[EventType]int
}

// Logger handles SQLite event storage.
type Logger struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	event_type TEXT NOT NULL,
	category TEXT NOT NULL,
	detail TEXT NOT NULL,
	blocked INTEGER NOT NULL DEFAULT 0,
	session_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_blocked ON events(blocked);
`

// validatePath rejects paths containing traversal sequences.
func validatePath(dbPath string) error {
	cleaned := filepath.Clean(dbPath)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected in DB path: %q", dbPath)
	}
	return nil
}

// NewLogger opens or creates the SQLite database at dbPath.
// Creates parent directories and the events table if they don't exist.
// Sets WAL mode and 0600 file permissions.
func NewLogger(dbPath string) (*Logger, error) {
	if err := validatePath(dbPath); err != nil {
		return nil, err
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open event log at %s: %w", dbPath, err)
	}

	// Enable WAL mode for concurrent read/write.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create events table: %w", err)
	}

	// Set file permissions to 0600 (owner read/write only).
	if err := os.Chmod(dbPath, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set DB file permissions: %w", err)
	}

	return &Logger{db: db}, nil
}

// Log records a single event. Thread-safe (SQLite WAL handles locking).
func (l *Logger) Log(event Event) error {
	ts := event.Timestamp.UTC().Format(time.RFC3339)
	blocked := 0
	if event.Blocked {
		blocked = 1
	}
	_, err := l.db.Exec(
		`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ts, string(event.EventType), event.Category, event.Detail, blocked, event.SessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to log event: %w", err)
	}
	return nil
}

// Query returns events matching the given filters.
// All filters are optional — nil/empty means "no filter".
func (l *Logger) Query(opts QueryOptions) ([]Event, error) {
	query := "SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events WHERE 1=1"
	var args []any

	if opts.EventType != nil {
		query += " AND event_type = ?"
		args = append(args, string(*opts.EventType))
	}
	if opts.Category != nil {
		query += " AND category = ?"
		args = append(args, *opts.Category)
	}
	if opts.Blocked != nil {
		blocked := 0
		if *opts.Blocked {
			blocked = 1
		}
		query += " AND blocked = ?"
		args = append(args, blocked)
	}
	if opts.SessionID != nil {
		query += " AND session_id = ?"
		args = append(args, *opts.SessionID)
	}
	if opts.Since != nil {
		query += " AND timestamp >= ?"
		args = append(args, opts.Since.UTC().Format(time.RFC3339))
	}
	if opts.Until != nil {
		query += " AND timestamp <= ?"
		args = append(args, opts.Until.UTC().Format(time.RFC3339))
	}

	query += " ORDER BY timestamp ASC"

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, limit, opts.Offset)

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var ts string
		var blocked int
		var eventType string
		if err := rows.Scan(&e.ID, &ts, &eventType, &e.Category, &e.Detail, &blocked, &e.SessionID); err != nil {
			return nil, fmt.Errorf("failed to scan event row: %w", err)
		}
		e.EventType = EventType(eventType)
		e.Blocked = blocked != 0
		e.Timestamp, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("failed to parse event timestamp %q: %w", ts, err)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating event rows: %w", err)
	}

	// Always return non-nil slice.
	if events == nil {
		events = []Event{}
	}
	return events, nil
}

// Stats returns aggregate counts. If sessionID is empty, stats cover all sessions.
func (l *Logger) Stats(sessionID string) (*Stats, error) {
	where := ""
	var args []any
	if sessionID != "" {
		where = " WHERE session_id = ?"
		args = append(args, sessionID)
	}

	s := &Stats{
		ByCategory: make(map[string]int),
		ByType:     make(map[EventType]int),
	}

	// Total, blocked, passed counts.
	row := l.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(blocked), 0), COALESCE(SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END), 0) FROM events"+where, args...)
	if err := row.Scan(&s.TotalEvents, &s.BlockedCount, &s.PassedCount); err != nil {
		return nil, fmt.Errorf("failed to query event stats: %w", err)
	}

	// Session count.
	row = l.db.QueryRow("SELECT COUNT(DISTINCT session_id) FROM events"+where, args...)
	if err := row.Scan(&s.SessionCount); err != nil {
		return nil, fmt.Errorf("failed to query session count: %w", err)
	}

	// First and last event timestamps.
	var firstStr, lastStr sql.NullString
	row = l.db.QueryRow("SELECT MIN(timestamp), MAX(timestamp) FROM events"+where, args...)
	if err := row.Scan(&firstStr, &lastStr); err != nil {
		return nil, fmt.Errorf("failed to query event time range: %w", err)
	}
	if firstStr.Valid {
		t, err := time.Parse(time.RFC3339, firstStr.String)
		if err == nil {
			s.FirstEvent = &t
		}
	}
	if lastStr.Valid {
		t, err := time.Parse(time.RFC3339, lastStr.String)
		if err == nil {
			s.LastEvent = &t
		}
	}

	// Counts by category.
	catRows, err := l.db.Query("SELECT category, COUNT(*) FROM events"+where+" GROUP BY category", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query category counts: %w", err)
	}
	defer catRows.Close()
	for catRows.Next() {
		var cat string
		var count int
		if err := catRows.Scan(&cat, &count); err != nil {
			return nil, fmt.Errorf("failed to scan category count: %w", err)
		}
		s.ByCategory[cat] = count
	}
	if err := catRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating category rows: %w", err)
	}

	// Counts by event type.
	typeRows, err := l.db.Query("SELECT event_type, COUNT(*) FROM events"+where+" GROUP BY event_type", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query type counts: %w", err)
	}
	defer typeRows.Close()
	for typeRows.Next() {
		var et string
		var count int
		if err := typeRows.Scan(&et, &count); err != nil {
			return nil, fmt.Errorf("failed to scan type count: %w", err)
		}
		s.ByType[EventType(et)] = count
	}
	if err := typeRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating type rows: %w", err)
	}

	return s, nil
}

// Prune removes events older than the given duration.
// Returns the number of events removed.
func (l *Logger) Prune(olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan).UTC().Format(time.RFC3339)
	result, err := l.db.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to prune events: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get prune count: %w", err)
	}
	return int(n), nil
}

// Close closes the database connection.
func (l *Logger) Close() error {
	return l.db.Close()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/kevin/Dev/nocklock
go test ./internal/logging/ -v -count=1
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/logging/logger.go internal/logging/logger_test.go
git commit -m "feat: add SQLite event logging engine with core tests"
```

---

### Task 3: Query Filter Tests

**Files:**
- Modify: `internal/logging/logger_test.go`

- [ ] **Step 1: Write query filter tests**

Append to `internal/logging/logger_test.go`:

```go
func ptr[T any](v T) *T { return &v }

func TestQueryNoFiltersReturnsAll(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	for i := 0; i < 3; i++ {
		l.Log(Event{
			Timestamp: time.Now(),
			EventType: EventSecretBlocked,
			Category:  "secret",
			Detail:    fmt.Sprintf("VAR_%d", i),
			Blocked:   true,
			SessionID: "s1",
		})
	}

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
}

func TestQueryByEventType(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretPassed, Category: "secret", Detail: "B", SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSessionStart, Category: "session", Detail: "", SessionID: "s1"})

	et := EventSecretBlocked
	events, err := l.Query(QueryOptions{EventType: &et})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 || events[0].Detail != "A" {
		t.Errorf("expected 1 secret_blocked event, got %d", len(events))
	}
}

func TestQueryByCategory(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSessionStart, Category: "session", Detail: "", SessionID: "s1"})

	cat := "secret"
	events, err := l.Query(QueryOptions{Category: &cat})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 secret event, got %d", len(events))
	}
}

func TestQueryByBlocked(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretPassed, Category: "secret", Detail: "B", Blocked: false, SessionID: "s1"})

	blocked := true
	events, err := l.Query(QueryOptions{Blocked: &blocked})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 || events[0].Detail != "A" {
		t.Errorf("expected 1 blocked event, got %v", events)
	}
}

func TestQueryBySessionID(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "B", Blocked: true, SessionID: "s2"})

	sid := "s1"
	events, err := l.Query(QueryOptions{SessionID: &sid})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 || events[0].Detail != "A" {
		t.Errorf("expected 1 event for s1, got %d", len(events))
	}
}

func TestQueryByTimeRange(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)

	l.Log(Event{Timestamp: old, EventType: EventSecretBlocked, Category: "secret", Detail: "OLD", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: recent, EventType: EventSecretBlocked, Category: "secret", Detail: "NEW", Blocked: true, SessionID: "s1"})

	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	events, err := l.Query(QueryOptions{Since: &since})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 || events[0].Detail != "NEW" {
		t.Errorf("expected 1 recent event, got %d", len(events))
	}
}

func TestQueryLimitAndOffset(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	for i := 0; i < 10; i++ {
		l.Log(Event{
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			EventType: EventSecretBlocked,
			Category:  "secret",
			Detail:    fmt.Sprintf("VAR_%d", i),
			Blocked:   true,
			SessionID: "s1",
		})
	}

	// Page 1: first 3
	events, err := l.Query(QueryOptions{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("page 1: expected 3 events, got %d", len(events))
	}

	// Page 2: next 3
	events, err = l.Query(QueryOptions{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("page 2: expected 3 events, got %d", len(events))
	}
}

func TestQueryMultipleFilters(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretPassed, Category: "secret", Detail: "B", Blocked: false, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "C", Blocked: true, SessionID: "s2"})

	et := EventSecretBlocked
	sid := "s1"
	events, err := l.Query(QueryOptions{EventType: &et, SessionID: &sid})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 || events[0].Detail != "A" {
		t.Errorf("expected 1 event matching both filters, got %d", len(events))
	}
}

func TestQueryEmptyResult(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	events, err := l.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if events == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}
```

- [ ] **Step 2: Run tests**

```bash
cd /Users/kevin/Dev/nocklock
go test ./internal/logging/ -v -count=1
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/logging/logger_test.go
git commit -m "test: add query filter tests for event logging"
```

---

### Task 4: Stats and Prune Tests

**Files:**
- Modify: `internal/logging/logger_test.go`

- [ ] **Step 1: Write stats and prune tests**

Append to `internal/logging/logger_test.go`:

```go
func TestStatsForSession(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretPassed, Category: "secret", Detail: "B", Blocked: false, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSessionStart, Category: "session", Detail: "", SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "C", Blocked: true, SessionID: "s2"})

	s, err := l.Stats("s1")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if s.TotalEvents != 3 {
		t.Errorf("TotalEvents = %d, want 3", s.TotalEvents)
	}
	if s.BlockedCount != 1 {
		t.Errorf("BlockedCount = %d, want 1", s.BlockedCount)
	}
	if s.PassedCount != 2 {
		t.Errorf("PassedCount = %d, want 2", s.PassedCount)
	}
	if s.SessionCount != 1 {
		t.Errorf("SessionCount = %d, want 1", s.SessionCount)
	}
}

func TestStatsAllSessions(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretPassed, Category: "secret", Detail: "B", Blocked: false, SessionID: "s2"})

	s, err := l.Stats("")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if s.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", s.TotalEvents)
	}
	if s.SessionCount != 2 {
		t.Errorf("SessionCount = %d, want 2", s.SessionCount)
	}
}

func TestStatsNoEvents(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	s, err := l.Stats("")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if s.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d, want 0", s.TotalEvents)
	}
	if s.FirstEvent != nil {
		t.Error("expected nil FirstEvent for empty DB")
	}
	if s.LastEvent != nil {
		t.Error("expected nil LastEvent for empty DB")
	}
}

func TestStatsByCategoryAndType(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "B", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: time.Now(), EventType: EventSessionStart, Category: "session", Detail: "", SessionID: "s1"})

	s, err := l.Stats("")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if s.ByCategory["secret"] != 2 {
		t.Errorf("ByCategory[secret] = %d, want 2", s.ByCategory["secret"])
	}
	if s.ByCategory["session"] != 1 {
		t.Errorf("ByCategory[session] = %d, want 1", s.ByCategory["session"])
	}
	if s.ByType[EventSecretBlocked] != 2 {
		t.Errorf("ByType[secret_blocked] = %d, want 2", s.ByType[EventSecretBlocked])
	}
	if s.ByType[EventSessionStart] != 1 {
		t.Errorf("ByType[session_start] = %d, want 1", s.ByType[EventSessionStart])
	}
}

func TestPruneRemovesOldEvents(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now()

	l.Log(Event{Timestamp: old, EventType: EventSecretBlocked, Category: "secret", Detail: "OLD", Blocked: true, SessionID: "s1"})
	l.Log(Event{Timestamp: recent, EventType: EventSecretBlocked, Category: "secret", Detail: "NEW", Blocked: true, SessionID: "s1"})

	removed, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if removed != 1 {
		t.Errorf("Prune removed %d, want 1", removed)
	}

	events, err := l.Query(QueryOptions{Limit: 100})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != 1 || events[0].Detail != "NEW" {
		t.Errorf("expected only NEW event remaining, got %v", events)
	}
}

func TestPruneNoOldEvents(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "A", Blocked: true, SessionID: "s1"})

	removed, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if removed != 0 {
		t.Errorf("Prune removed %d, want 0", removed)
	}
}

func TestPruneReturnsCorrectCount(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	old := time.Now().Add(-72 * time.Hour)
	for i := 0; i < 5; i++ {
		l.Log(Event{Timestamp: old, EventType: EventSecretBlocked, Category: "secret", Detail: fmt.Sprintf("OLD_%d", i), Blocked: true, SessionID: "s1"})
	}
	l.Log(Event{Timestamp: time.Now(), EventType: EventSecretBlocked, Category: "secret", Detail: "NEW", Blocked: true, SessionID: "s1"})

	removed, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if removed != 5 {
		t.Errorf("Prune removed %d, want 5", removed)
	}
}
```

- [ ] **Step 2: Run tests**

```bash
cd /Users/kevin/Dev/nocklock
go test ./internal/logging/ -v -count=1
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/logging/logger_test.go
git commit -m "test: add stats and prune tests for event logging"
```

---

### Task 5: Security and Concurrency Tests

**Files:**
- Modify: `internal/logging/logger_test.go`

- [ ] **Step 1: Write security and concurrency tests**

Append to `internal/logging/logger_test.go`:

```go
func TestDetailNeverContainsValues(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	// Simulate what wrap.go does: log the NAME, never the VALUE
	l.Log(Event{
		Timestamp: time.Now(),
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    "AWS_SECRET_ACCESS_KEY", // name only
		Blocked:   true,
		SessionID: "s1",
	})

	events, err := l.Query(QueryOptions{Limit: 10})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	for _, e := range events {
		if strings.Contains(e.Detail, "=") {
			t.Errorf("Detail %q contains '=' — possible value leak", e.Detail)
		}
	}
}

func TestSQLInjectionInDetail(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	malicious := "'; DROP TABLE events; --"
	err := l.Log(Event{
		Timestamp: time.Now(),
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    malicious,
		Blocked:   true,
		SessionID: "s1",
	})
	if err != nil {
		t.Fatalf("Log with SQL injection string failed: %v", err)
	}

	// Table should still exist and event should be stored literally
	events, err := l.Query(QueryOptions{Limit: 10})
	if err != nil {
		t.Fatalf("Query after injection attempt failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Detail != malicious {
		t.Errorf("Detail = %q, want %q (stored literally)", events[0].Detail, malicious)
	}
}

func TestDBFilePermissions(t *testing.T) {
	l, dbPath := mustNewLogger(t)
	defer l.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("DB file permissions = %o, want 0600", perm)
	}
}

func TestConcurrentLog(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	const goroutines = 10
	const eventsPerGoroutine = 20
	errs := make(chan error, goroutines*eventsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			for i := 0; i < eventsPerGoroutine; i++ {
				err := l.Log(Event{
					Timestamp: time.Now(),
					EventType: EventSecretBlocked,
					Category:  "secret",
					Detail:    fmt.Sprintf("G%d_VAR_%d", id, i),
					Blocked:   true,
					SessionID: fmt.Sprintf("session-%d", id),
				})
				errs <- err
			}
		}(g)
	}

	for i := 0; i < goroutines*eventsPerGoroutine; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Log failed: %v", err)
		}
	}

	events, err := l.Query(QueryOptions{Limit: goroutines * eventsPerGoroutine})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(events) != goroutines*eventsPerGoroutine {
		t.Errorf("expected %d events, got %d", goroutines*eventsPerGoroutine, len(events))
	}
}

func TestConcurrentLogAndQuery(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()

	done := make(chan struct{})

	// Writer goroutine
	go func() {
		for i := 0; i < 50; i++ {
			l.Log(Event{
				Timestamp: time.Now(),
				EventType: EventSecretBlocked,
				Category:  "secret",
				Detail:    fmt.Sprintf("VAR_%d", i),
				Blocked:   true,
				SessionID: "s1",
			})
		}
		close(done)
	}()

	// Reader goroutine — should never error
	var queryErr error
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				_, err := l.Query(QueryOptions{Limit: 10})
				if err != nil {
					queryErr = err
					return
				}
			}
		}
	}()

	<-done
	if queryErr != nil {
		t.Errorf("concurrent Query failed: %v", queryErr)
	}
}
```

- [ ] **Step 2: Run tests**

```bash
cd /Users/kevin/Dev/nocklock
go test ./internal/logging/ -v -count=1 -race
```

Expected: all tests PASS, no race conditions detected.

- [ ] **Step 3: Commit**

```bash
git add internal/logging/logger_test.go
git commit -m "test: add security and concurrency tests for event logging"
```

---

### Task 6: Integrate Logging into wrap Command

**Files:**
- Modify: `internal/cli/wrap.go`

- [ ] **Step 1: Update wrap.go to generate session UUID and log fence events**

Replace the full `internal/cli/wrap.go` with:

```go
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

var wrapCmd = &cobra.Command{
	Use:   "wrap -- <command> [args...]",
	Short: "Wrap a command with NockLock fences",
	Long:  "Wraps an AI agent command with filesystem, network, and secret isolation.",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return fmt.Errorf("no command specified. Usage: nocklock wrap -- <command> [args...]")
		}

		// Find and load config.
		configPath, err := config.FindConfig()
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("no NockLock config found. Run 'nocklock init' first")
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to load config at %s: %w", configPath, err)
		}

		// Generate session UUID.
		sessionID := uuid.New().String()

		// Open logger — warn but don't fail if logging is unavailable.
		dbPath := cfg.Logging.DB
		if !filepath.IsAbs(dbPath) {
			// Resolve relative to the config file's directory's parent (project root).
			dbPath = filepath.Join(filepath.Dir(filepath.Dir(configPath)), dbPath)
		}
		logger, logErr := logging.NewLogger(dbPath)
		if logErr != nil {
			fmt.Fprintf(os.Stderr, "NockLock: warning — could not open event log: %v\n", logErr)
		}
		if logger != nil {
			defer logger.Close()
		}

		// Helper to log without crashing if logger is nil.
		logEvent := func(e logging.Event) {
			if logger == nil {
				return
			}
			e.SessionID = sessionID
			e.Timestamp = time.Now()
			logger.Log(e)
		}

		// Log session start.
		logEvent(logging.Event{
			EventType: logging.EventSessionStart,
			Category:  "session",
			Detail:    strings.Join(args, " "),
		})

		// Log config loaded.
		logEvent(logging.Event{
			EventType: logging.EventConfigLoaded,
			Category:  "session",
			Detail:    cfg.Project.Name,
		})

		// Apply secret fence.
		fence, fenceErr := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block)
		if fenceErr != nil {
			return fmt.Errorf("invalid secret fence config: %w", fenceErr)
		}
		childEnv, blockedNames := fence.Filter(os.Environ())

		// Log each blocked env var.
		for _, name := range blockedNames {
			logEvent(logging.Event{
				EventType: logging.EventSecretBlocked,
				Category:  "secret",
				Detail:    name,
				Blocked:   true,
			})
		}

		// Log passed env var names (as a batch — one event listing all names).
		passedNames := make([]string, 0)
		for _, entry := range childEnv {
			if name, _, ok := strings.Cut(entry, "="); ok && name != "" {
				passedNames = append(passedNames, name)
			}
		}
		if len(passedNames) > 0 {
			logEvent(logging.Event{
				EventType: logging.EventSecretPassed,
				Category:  "secret",
				Detail:    strings.Join(passedNames, ", "),
				Blocked:   false,
			})
		}

		if len(blockedNames) > 0 {
			fmt.Fprintf(os.Stderr, "NockLock: secret fence active — blocked %d environment variable(s)\n", len(blockedNames))
			if cfg.Logging.Level == "debug" {
				fmt.Fprintf(os.Stderr, "  blocked: %s\n", strings.Join(blockedNames, ", "))
			}
		} else {
			fmt.Fprintf(os.Stderr, "NockLock: secret fence active — no variables blocked\n")
		}

		// Spawn child process.
		child := exec.Command(args[0], args[1:]...)
		child.Env = childEnv
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		childErr := child.Run()

		// Log session end.
		exitCode := 0
		if childErr != nil {
			if exitErr, ok := childErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
				if exitCode < 0 {
					exitCode = 1
				}
			} else {
				exitCode = 1
			}
		}

		logEvent(logging.Event{
			EventType: logging.EventSessionEnd,
			Category:  "session",
			Detail:    fmt.Sprintf("exit_code=%d", exitCode),
		})

		if childErr != nil {
			if _, ok := childErr.(*exec.ExitError); ok {
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				return &exitCodeError{code: exitCode}
			}
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to run %q: %w", args[0], childErr)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}
```

- [ ] **Step 2: Build and run existing tests**

```bash
cd /Users/kevin/Dev/nocklock
go build ./cmd/nocklock
go test ./... -v -count=1
```

Expected: clean build, all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/wrap.go
git commit -m "feat: integrate event logging into wrap command"
```

---

### Task 7: Implement `nocklock log` Command

**Files:**
- Modify: `internal/cli/log.go`

- [ ] **Step 1: Replace placeholder log.go with full implementation**

Replace the full `internal/cli/log.go` with:

```go
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

var (
	logSession string
	logBlocked bool
	logSince   string
	logJSON    bool
	logStats   bool
	logPrune   string
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View fence event log",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.FindConfig()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "No config found. Run 'nocklock init' first.")
				return nil
			}
			return fmt.Errorf("failed to locate config: %w", err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		dbPath := cfg.Logging.DB
		if !filepath.IsAbs(dbPath) {
			dbPath = filepath.Join(filepath.Dir(filepath.Dir(configPath)), dbPath)
		}

		logger, err := logging.NewLogger(dbPath)
		if err != nil {
			return fmt.Errorf("could not open event log: %w", err)
		}
		defer logger.Close()

		// Handle --prune first (destructive operation, then exit).
		if logPrune != "" {
			dur, err := parseDuration(logPrune)
			if err != nil {
				return fmt.Errorf("invalid prune duration %q: %w", logPrune, err)
			}
			removed, err := logger.Prune(dur)
			if err != nil {
				return fmt.Errorf("prune failed: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Pruned %d event(s) older than %s\n", removed, logPrune)
			return nil
		}

		// Handle --stats.
		if logStats {
			s, err := logger.Stats(logSession)
			if err != nil {
				return fmt.Errorf("stats failed: %w", err)
			}
			if logJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			fmt.Printf("Total events: %d\n", s.TotalEvents)
			fmt.Printf("Blocked: %d\n", s.BlockedCount)
			fmt.Printf("Passed: %d\n", s.PassedCount)
			fmt.Printf("Sessions: %d\n", s.SessionCount)
			if s.FirstEvent != nil {
				fmt.Printf("First event: %s\n", s.FirstEvent.Local().Format("2006-01-02 15:04:05"))
			}
			if s.LastEvent != nil {
				fmt.Printf("Last event: %s\n", s.LastEvent.Local().Format("2006-01-02 15:04:05"))
			}
			for cat, count := range s.ByCategory {
				fmt.Printf("  %s: %d\n", cat, count)
			}
			return nil
		}

		// Build query options.
		opts := logging.QueryOptions{Limit: 1000}
		if logSession != "" {
			opts.SessionID = &logSession
		}
		if logBlocked {
			b := true
			opts.Blocked = &b
		}
		if logSince != "" {
			dur, err := parseDuration(logSince)
			if err != nil {
				return fmt.Errorf("invalid --since duration %q: %w", logSince, err)
			}
			since := time.Now().Add(-dur)
			opts.Since = &since
		}

		events, err := logger.Query(opts)
		if err != nil {
			return fmt.Errorf("query failed: %w", err)
		}

		if len(events) == 0 {
			fmt.Println("No fence events recorded.")
			return nil
		}

		if logJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(events)
		}

		// Group events by session and display.
		printEventsBySession(events)
		return nil
	},
}

// printEventsBySession groups events by session ID and formats output.
func printEventsBySession(events []logging.Event) {
	type sessionGroup struct {
		id     string
		events []logging.Event
	}

	// Preserve order; group by session.
	var groups []sessionGroup
	seen := map[string]int{}
	for _, e := range events {
		idx, ok := seen[e.SessionID]
		if !ok {
			idx = len(groups)
			seen[e.SessionID] = idx
			groups = append(groups, sessionGroup{id: e.SessionID})
		}
		groups[idx].events = append(groups[idx].events, e)
	}

	// Print most recent session first.
	totalBlocked := 0
	totalPassed := 0
	for i := len(groups) - 1; i >= 0; i-- {
		g := groups[i]
		var start, end time.Time
		blocked := []string{}
		passed := []string{}

		for _, e := range g.events {
			switch e.EventType {
			case logging.EventSessionStart:
				start = e.Timestamp
			case logging.EventSessionEnd:
				end = e.Timestamp
			case logging.EventSecretBlocked:
				blocked = append(blocked, e.Detail)
			case logging.EventSecretPassed:
				passed = append(passed, e.Detail)
			}
		}

		// Print session header.
		shortID := g.id
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		if !start.IsZero() && !end.IsZero() {
			fmt.Printf("\nSession: %s (%s — %s)\n",
				shortID,
				start.Local().Format("2006-01-02 15:04:05"),
				end.Local().Format("2006-01-02 15:04:05"))
		} else if !start.IsZero() {
			fmt.Printf("\nSession: %s (%s — in progress)\n",
				shortID,
				start.Local().Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("\nSession: %s\n", shortID)
		}

		for _, name := range blocked {
			fmt.Printf("  secret_blocked: %s\n", name)
		}
		if len(passed) > 0 {
			fmt.Printf("  secret_passed: %s\n", strings.Join(passed, ", "))
		}
		if !start.IsZero() && !end.IsZero() {
			dur := end.Sub(start)
			fmt.Printf("  Duration: %s\n", formatDuration(dur))
		}

		totalBlocked += len(blocked)
		totalPassed += len(passed)
	}

	fmt.Printf("\nTotal: %d session(s), %d blocked, %d passed\n",
		len(groups), totalBlocked, totalPassed)
}

// formatDuration produces human-readable "Xh Ym Zs" strings.
func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// parseDuration parses "24h", "30d", "7d", etc.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(s, "%d", &days); err != nil {
			return 0, fmt.Errorf("invalid day duration: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func init() {
	logCmd.Flags().StringVar(&logSession, "session", "", "Show events for specific session ID")
	logCmd.Flags().BoolVar(&logBlocked, "blocked", false, "Show only blocked events")
	logCmd.Flags().StringVar(&logSince, "since", "", "Show events since duration (e.g., 24h, 7d)")
	logCmd.Flags().BoolVar(&logJSON, "json", false, "Output as JSON")
	logCmd.Flags().BoolVar(&logStats, "stats", false, "Show aggregate statistics only")
	logCmd.Flags().StringVar(&logPrune, "prune", "", "Delete events older than duration (e.g., 30d)")
	rootCmd.AddCommand(logCmd)
}
```

- [ ] **Step 2: Build and test**

```bash
cd /Users/kevin/Dev/nocklock
go build ./cmd/nocklock
go vet ./...
```

Expected: clean build, no vet warnings.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/log.go
git commit -m "feat: implement nocklock log command with filters"
```

---

### Task 8: Update `nocklock status` with Event Log Info

**Files:**
- Modify: `internal/cli/status.go`

- [ ] **Step 1: Update status.go to show event log summary**

Replace `internal/cli/status.go` with:

```go
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active fenced sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.FindConfig()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "No config found. Run 'nocklock init' first.")
				return nil
			}
			return fmt.Errorf("failed to locate config: %w", err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		fmt.Println(version.BuildInfo())

		// Secret fence status.
		passCount := len(cfg.Secrets.Pass)
		blockCount := len(cfg.Secrets.Block)
		if passCount > 0 || blockCount > 0 {
			fmt.Printf("Secret fence: active (blocking %d patterns)\n", blockCount)
		} else {
			fmt.Println("Secret fence: not configured")
		}

		fmt.Println("Filesystem fence: not active")
		fmt.Println("Network fence: not active")

		// Event log summary.
		dbPath := cfg.Logging.DB
		if !filepath.IsAbs(dbPath) {
			dbPath = filepath.Join(filepath.Dir(filepath.Dir(configPath)), dbPath)
		}
		logger, logErr := logging.NewLogger(dbPath)
		if logErr != nil {
			fmt.Printf("Event log: unavailable (%v)\n", logErr)
			return nil
		}
		defer logger.Close()

		stats, err := logger.Stats("")
		if err != nil {
			fmt.Printf("Event log: error (%v)\n", err)
			return nil
		}

		fmt.Printf("Event log: %s (%d events, %d sessions)\n", cfg.Logging.DB, stats.TotalEvents, stats.SessionCount)

		if stats.LastEvent != nil {
			fmt.Printf("Last event: %s\n", stats.LastEvent.Local().Format("2006-01-02 15:04:05"))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
```

- [ ] **Step 2: Build and run all tests**

```bash
cd /Users/kevin/Dev/nocklock
go build ./cmd/nocklock
go test ./... -v -count=1
go vet ./...
go fmt ./...
```

Expected: clean build, all tests PASS, no warnings, formatted.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/status.go
git commit -m "feat: update nocklock status with event log info"
```

---

### Task 9: Final Verification

- [ ] **Step 1: Run full test suite with race detector**

```bash
cd /Users/kevin/Dev/nocklock
go test ./... -v -count=1 -race
```

Expected: all tests PASS, no race conditions.

- [ ] **Step 2: Run vet and format**

```bash
cd /Users/kevin/Dev/nocklock
go vet ./...
go fmt ./...
```

Expected: no warnings, no formatting changes.

- [ ] **Step 3: Review git log**

```bash
git log --oneline feature/sqlite-logging ^main
```

Expected commits (newest first):
```
feat: update nocklock status with event log info
feat: implement nocklock log command with filters
feat: integrate event logging into wrap command
test: add security and concurrency tests for event logging
test: add stats and prune tests for event logging
test: add query filter tests for event logging
feat: add SQLite event logging engine with core tests
chore: add modernc.org/sqlite and google/uuid dependencies
```
