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

// validatePath rejects paths containing traversal sequences and paths outside the project root.
func validatePath(dbPath, projectRoot string) error {
	cleaned := filepath.Clean(dbPath)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected in DB path: %q", dbPath)
	}
	if projectRoot != "" {
		root := filepath.Clean(projectRoot) + string(filepath.Separator)
		if !strings.HasPrefix(cleaned, root) && cleaned != filepath.Clean(projectRoot) {
			return fmt.Errorf("DB path %q is outside project root %q", dbPath, projectRoot)
		}
	}
	return nil
}

// NewLogger opens or creates the SQLite database at dbPath.
// Creates parent directories and the events table if they don't exist.
// Sets WAL mode and 0600 file permissions.
// If projectRoot is non-empty, dbPath must reside under it.
func NewLogger(dbPath string, projectRoot string) (*Logger, error) {
	if err := validatePath(dbPath, projectRoot); err != nil {
		return nil, err
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	// Pre-create file with correct permissions to avoid TOCTOU window.
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create event log at %s: %w", dbPath, err)
	}
	f.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open event log at %s: %w", dbPath, err)
	}

	// Serialize writes through a single connection to avoid SQLITE_BUSY under
	// concurrent access. Reads still benefit from WAL concurrency.
	db.SetMaxOpenConns(1)

	// Enable WAL mode for concurrent read/write.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Set a busy timeout so concurrent operations wait rather than fail.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set busy timeout: %w", err)
	}

	// Zero freed pages so pruned event data is not forensically recoverable.
	if _, err := db.Exec("PRAGMA secure_delete=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable secure delete: %w", err)
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

// LogBatch records multiple events in a single transaction for efficiency.
// Thread-safe. Use this when logging multiple events at once (e.g., blocked vars).
func (l *Logger) LogBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return fmt.Errorf("failed to prepare batch insert: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		ts := event.Timestamp.UTC().Format(time.RFC3339)
		blocked := 0
		if event.Blocked {
			blocked = 1
		}
		if _, err := stmt.Exec(ts, string(event.EventType), event.Category, event.Detail, blocked, event.SessionID); err != nil {
			return fmt.Errorf("failed to insert event in batch: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch: %w", err)
	}
	return nil
}

// Query returns events matching the given filters.
// All filters are optional — nil/empty means "no filter".
// Always returns a non-nil slice.
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
	if limit > 10000 {
		limit = 10000
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, limit, opts.Offset)

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0, limit)
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
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating event rows: %w", err)
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

	// Single query for all scalar aggregates.
	row := l.db.QueryRow(
		"SELECT COUNT(*), COALESCE(SUM(blocked), 0), COALESCE(SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END), 0), COUNT(DISTINCT session_id), MIN(timestamp), MAX(timestamp) FROM events"+where,
		args...,
	)
	var firstStr, lastStr sql.NullString
	if err := row.Scan(&s.TotalEvents, &s.BlockedCount, &s.PassedCount, &s.SessionCount, &firstStr, &lastStr); err != nil {
		return nil, fmt.Errorf("failed to query event stats: %w", err)
	}
	if firstStr.Valid {
		if t, err := time.Parse(time.RFC3339, firstStr.String); err == nil {
			s.FirstEvent = &t
		}
	}
	if lastStr.Valid {
		if t, err := time.Parse(time.RFC3339, lastStr.String); err == nil {
			s.LastEvent = &t
		}
	}

	// Single query for both category and type breakdowns using UNION ALL.
	breakdownRows, err := l.db.Query(
		"SELECT 'cat', category, COUNT(*) FROM events"+where+" GROUP BY category UNION ALL SELECT 'typ', event_type, COUNT(*) FROM events"+where+" GROUP BY event_type",
		append(args, args...)...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query event breakdowns: %w", err)
	}
	defer breakdownRows.Close()
	for breakdownRows.Next() {
		var kind, key string
		var count int
		if err := breakdownRows.Scan(&kind, &key, &count); err != nil {
			return nil, fmt.Errorf("failed to scan breakdown row: %w", err)
		}
		if kind == "cat" {
			s.ByCategory[key] = count
		} else {
			s.ByType[EventType(key)] = count
		}
	}
	if err := breakdownRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating breakdown rows: %w", err)
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
