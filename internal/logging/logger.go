// Package logging provides SQLite-backed event storage for NockLock fence events.
package logging

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
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
	EventProxyStart     EventType = "proxy_start"
	EventProxyStop      EventType = "proxy_stop"
	EventNetworkError   EventType = "network_error"
	EventSessionStart   EventType = "session_start"
	EventSessionEnd     EventType = "session_end"
	EventConfigLoaded   EventType = "config_loaded"
)

// formatTimestampForChain formats a time.Time as UTC RFC3339 with exactly 9 fractional second digits and trailing Z.
// This is the critical canonical format for the audit chain hash.
func formatTimestampForChain(t time.Time) string {
	utc := t.UTC()
	// Format as: 2026-09-14T15:30:45.123456789Z
	return utc.Format("2006-01-02T15:04:05.000000000") + "Z"
}

// Event represents a single fence event.
type Event struct {
	ID        int64
	Timestamp time.Time
	EventType EventType
	Category  string // "secret", "filesystem", "network", "session"
	Detail    string // context: env var name (secrets), command name (session), exit code (session end)
	Blocked   bool
	SessionID string
}

// QueryOptions filters event queries. All fields are optional.
type QueryOptions struct {
	EventType  *EventType
	Category   *string
	Blocked    *bool
	SessionID  *string
	Since      *time.Time
	Until      *time.Time
	Limit      int // 0 = default (100)
	Offset     int
	Descending bool // if true, order by timestamp DESC
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

// ChainVerifyResult holds the outcome of a chain verification.
type ChainVerifyResult struct {
	Intact          bool       // true if chain is unbroken from genesis to current head
	EntriesVerified int        // number of entries checked
	FirstBrokenID   int64      // id of first broken entry (0 if intact)
	BrokenReason    string     // explanation of what broke (if not intact)
	HeadHash        string     // current chain head hash (hex)
	MigratedAt      *time.Time // when chain was created on existing DB (if applicable)
	LegacyThroughID int64      // highest id of pre-migration rows (if applicable)
	PrunedAt        *time.Time // when chain was re-anchored due to prune (if applicable)
	PrunedCount     int        // number of events removed in the last prune (if applicable)
}

// chainGenesisHashHex is the entry_hash for genesis (SHA-256 of the empty input).
const chainGenesisHashHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	event_type TEXT NOT NULL,
	category TEXT NOT NULL,
	detail TEXT NOT NULL,
	blocked INTEGER NOT NULL DEFAULT 0,
	session_id TEXT NOT NULL,
	prev_hash TEXT NOT NULL DEFAULT '',
	entry_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_blocked ON events(blocked);
CREATE TABLE IF NOT EXISTS chain_head (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	entry_hash TEXT NOT NULL,
	row_count INTEGER NOT NULL,
	migrated_at TEXT,
	legacy_through_id INTEGER,
	pruned_at TEXT,
	pruned_count INTEGER
);
`

// validatePath rejects paths containing traversal sequences and paths outside the project root.
func validatePath(dbPath, projectRoot string) error {
	cleaned := filepath.Clean(dbPath)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected in DB path: %q", dbPath)
	}
	if projectRoot != "" {
		// Resolve symlinks to prevent symlink-based escapes.
		resolvedPath, err := filepath.EvalSymlinks(filepath.Dir(cleaned))
		if err == nil {
			resolvedPath = filepath.Join(resolvedPath, filepath.Base(cleaned))
		} else {
			// Directory doesn't exist yet — use the cleaned path.
			resolvedPath = cleaned
		}
		resolvedRoot, err := filepath.EvalSymlinks(projectRoot)
		if err != nil {
			resolvedRoot = filepath.Clean(projectRoot)
		}
		rel, err := filepath.Rel(resolvedRoot, resolvedPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("DB path %q resolves outside project root %q", dbPath, projectRoot)
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

	// Reject a symlink at the final DB path before touching it. A repository
	// could commit .nock/events.db as a symlink pointing outside the project;
	// following it would chmod and let SQLite write to (corrupt) the target.
	// This early lstat gives a clear error; O_NOFOLLOW below is the authoritative
	// guard that also closes the lstat->open TOCTOU window.
	if fi, err := os.Lstat(dbPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to open event log at %s: path is a symlink", dbPath)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat event log path %s: %w", dbPath, err)
	}

	// Pre-create file with correct permissions to avoid a TOCTOU window, and
	// with O_NOFOLLOW so the open fails (ELOOP) rather than following a symlink
	// swapped in after the lstat above.
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR|oNoFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create event log at %s: %w", dbPath, err)
	}

	// Re-validate the opened file: confirm it is a regular file and that the
	// path entry still resolves to the same inode we hold open (defends against
	// a symlink swap racing the open on platforms lacking O_NOFOLLOW).
	openedInfo, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to stat opened event log at %s: %w", dbPath, err)
	}
	if !openedInfo.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("refusing to open event log at %s: not a regular file", dbPath)
	}
	if pathInfo, err := os.Lstat(dbPath); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to re-stat event log path %s: %w", dbPath, err)
	} else if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		f.Close()
		return nil, fmt.Errorf("refusing to open event log at %s: path changed after open", dbPath)
	}

	// Fix permissions through the file descriptor so we never chmod a symlink
	// target by path.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to set DB file permissions: %w", err)
	}
	f.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open event log at %s: %w", dbPath, err)
	}

	// Serialize all operations through a single connection to avoid SQLITE_BUSY.
	// WAL mode allows external processes to read concurrently.
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

	// Migrate existing DBs to add hash columns and initialize chain
	if err := migrateToChain(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate audit chain: %w", err)
	}

	return &Logger{db: db}, nil
}

// Log records a single event with hash chain. Thread-safe (SQLite WAL handles locking).
func (l *Logger) Log(event Event) error {
	ts := formatTimestampForChain(event.Timestamp)
	blocked := 0
	if event.Blocked {
		blocked = 1
	}

	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin log transaction: %w", err)
	}
	defer tx.Rollback()
	if err := initChainHeadIfNeeded(tx); err != nil {
		return fmt.Errorf("failed to initialize chain_head: %w", err)
	}

	var prevHashHex string
	if err := tx.QueryRow("SELECT entry_hash FROM chain_head WHERE id = 1").Scan(&prevHashHex); err != nil {
		return fmt.Errorf("failed to read chain head: %w", err)
	}

	// Insert without hash values first
	result, err := tx.Exec(
		`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash)
		 VALUES (?, ?, ?, ?, ?, ?, '', '')`,
		ts, string(event.EventType), event.Category, event.Detail, blocked, event.SessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}

	eventID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get event ID: %w", err)
	}

	// Compute hash chain
	entryHash, err := chainEntry(eventID, ts, event.EventType, event.Category, event.Detail, event.Blocked, event.SessionID, prevHashHex)
	if err != nil {
		return fmt.Errorf("failed to compute chain: %w", err)
	}

	// Update with computed hashes
	_, err = tx.Exec(
		"UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = ?",
		prevHashHex, entryHash, eventID,
	)
	if err != nil {
		return fmt.Errorf("failed to update event hashes: %w", err)
	}

	_, err = tx.Exec(
		"UPDATE chain_head SET entry_hash = ?, row_count = (SELECT COUNT(*) FROM events) WHERE id = 1",
		entryHash,
	)
	if err != nil {
		return fmt.Errorf("failed to update chain_head: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit log transaction: %w", err)
	}
	return nil
}

// LogBatch records multiple events in a single transaction for efficiency, with chain.
// Thread-safe. Use this when logging multiple events at once (e.g., blocked vars).
func (l *Logger) LogBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin batch transaction: %w", err)
	}
	defer tx.Rollback()

	// Initialize chain_head if needed
	if err := initChainHeadIfNeeded(tx); err != nil {
		return fmt.Errorf("failed to initialize chain_head: %w", err)
	}

	// Get current head
	var currentHeadHash string
	err = tx.QueryRow("SELECT entry_hash FROM chain_head WHERE id = 1").Scan(&currentHeadHash)
	if err != nil {
		currentHeadHash = chainGenesisHashHex
	}

	prevHashHex := currentHeadHash

	// Insert all events with chaining
	for _, event := range events {
		ts := formatTimestampForChain(event.Timestamp)
		blocked := 0
		if event.Blocked {
			blocked = 1
		}

		result, err := tx.Exec(
			`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ts, string(event.EventType), event.Category, event.Detail, blocked, event.SessionID, prevHashHex, "",
		)
		if err != nil {
			return fmt.Errorf("failed to insert event in batch: %w", err)
		}

		eventID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get event ID: %w", err)
		}

		// Compute hash
		entryHash, err := chainEntry(eventID, ts, event.EventType, event.Category, event.Detail, event.Blocked, event.SessionID, prevHashHex)
		if err != nil {
			return fmt.Errorf("failed to compute chain for event %d: %w", eventID, err)
		}

		// Update with computed hash
		_, err = tx.Exec(
			"UPDATE events SET entry_hash = ? WHERE id = ?",
			entryHash, eventID,
		)
		if err != nil {
			return fmt.Errorf("failed to update event hash: %w", err)
		}

		prevHashHex = entryHash
	}

	// Update chain_head with final state
	count, err := countEvents(tx)
	if err != nil {
		return fmt.Errorf("failed to count events: %w", err)
	}

	_, err = tx.Exec(
		"UPDATE chain_head SET entry_hash = ?, row_count = ? WHERE id = 1",
		prevHashHex, count,
	)
	if err != nil {
		return fmt.Errorf("failed to update chain_head: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
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
		// Bounds must use the same 9-fractional-digit encoding as stored
		// timestamps (formatTimestampForChain); a second-precision RFC3339
		// bound sorts lexicographically before an in-second stored value
		// (".500...Z" < "Z"), silently dropping boundary-second events.
		query += " AND timestamp >= ?"
		args = append(args, formatTimestampForChain(*opts.Since))
	}
	if opts.Until != nil {
		query += " AND timestamp <= ?"
		args = append(args, formatTimestampForChain(*opts.Until))
	}

	if opts.Descending {
		query += " ORDER BY timestamp DESC"
	} else {
		query += " ORDER BY timestamp ASC"
	}

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

// Prune removes events older than the given duration and re-anchors the chain.
// Re-anchoring sets the first surviving row's prev_hash to genesis and recomputes
// the forward chain, recording a prune-boundary marker in chain_head.
// Returns the number of events removed.
func (l *Logger) Prune(olderThan time.Duration) (int, error) {
	cutoff := formatTimestampForChain(time.Now().Add(-olderThan))

	tx, err := l.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin prune transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete old events
	result, err := tx.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old events: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get prune count: %w", err)
	}
	pruneCount := int(n)

	if pruneCount == 0 {
		// No events pruned, commit and return
		return pruneCount, tx.Commit()
	}

	// Get the first surviving row
	var firstID int64
	var firstTS, firstET, firstCat, firstDetail, firstSID string
	var firstBlocked int
	err = tx.QueryRow("SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events ORDER BY id ASC LIMIT 1").
		Scan(&firstID, &firstTS, &firstET, &firstCat, &firstDetail, &firstBlocked, &firstSID)
	if err == sql.ErrNoRows {
		// All events were pruned
		_, err = tx.Exec("UPDATE chain_head SET entry_hash = ?, row_count = 0, pruned_at = ?, pruned_count = ? WHERE id = 1",
			chainGenesisHashHex, time.Now().UTC().Format(time.RFC3339), pruneCount)
		if err != nil {
			return 0, fmt.Errorf("failed to update chain_head after full prune: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("failed to commit prune: %w", err)
		}
		return pruneCount, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get first surviving row: %w", err)
	}

	// Re-anchor the first surviving row to genesis
	firstEntryHash, err := chainEntry(firstID, firstTS, EventType(firstET), firstCat, firstDetail, firstBlocked != 0, firstSID, chainGenesisHashHex)
	if err != nil {
		return 0, fmt.Errorf("failed to compute re-anchored hash for first row: %w", err)
	}

	_, err = tx.Exec("UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = ?",
		chainGenesisHashHex, firstEntryHash, firstID)
	if err != nil {
		return 0, fmt.Errorf("failed to update first row with re-anchor: %w", err)
	}

	// Re-chain all subsequent rows
	rows, err := tx.Query("SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events WHERE id > ? ORDER BY id ASC", firstID)
	if err != nil {
		return 0, fmt.Errorf("failed to query subsequent rows: %w", err)
	}
	defer rows.Close()

	prevHashHex := firstEntryHash
	for rows.Next() {
		var id int64
		var ts, et, cat, detail, sid string
		var blocked int
		if err := rows.Scan(&id, &ts, &et, &cat, &detail, &blocked, &sid); err != nil {
			return 0, fmt.Errorf("failed to scan row: %w", err)
		}

		entryHash, err := chainEntry(id, ts, EventType(et), cat, detail, blocked != 0, sid, prevHashHex)
		if err != nil {
			return 0, fmt.Errorf("failed to compute entry hash for row %d: %w", id, err)
		}

		_, err = tx.Exec("UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = ?",
			prevHashHex, entryHash, id)
		if err != nil {
			return 0, fmt.Errorf("failed to update row %d: %w", id, err)
		}

		prevHashHex = entryHash
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating rows during re-chain: %w", err)
	}

	// Update chain_head with re-anchoring marker
	count, err := countEvents(tx)
	if err != nil {
		return 0, fmt.Errorf("failed to count events after prune: %w", err)
	}

	_, err = tx.Exec("UPDATE chain_head SET entry_hash = ?, row_count = ?, pruned_at = ?, pruned_count = ? WHERE id = 1",
		prevHashHex, count, time.Now().UTC().Format(time.RFC3339), pruneCount)
	if err != nil {
		return 0, fmt.Errorf("failed to update chain_head after re-anchor: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit prune: %w", err)
	}
	return pruneCount, nil
}

// Close closes the database connection.
func (l *Logger) Close() error {
	return l.db.Close()
}

// ============ AUDIT CHAIN HELPERS ============

// canonicalBytes returns the deterministic byte encoding of an Event for hashing.
// Format: version || u64be(id) || lp(timestamp) || lp(event_type) || lp(category) || lp(detail) || blocked || lp(session_id)
// where lp = uint32be length + UTF-8 bytes, blocked = 0x00/0x01, version = 0x01
func canonicalBytes(id int64, ts string, et EventType, cat, detail string, blocked bool, sid string) []byte {
	var buf []byte

	// Version byte
	buf = append(buf, 0x01)

	// id as uint64 big-endian
	idBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(idBuf, uint64(id))
	buf = append(buf, idBuf...)

	// Helper to length-prefix a string
	appendLP := func(s string) {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(s)))
		buf = append(buf, lenBuf...)
		buf = append(buf, []byte(s)...)
	}

	// timestamp, event_type, category, detail (all length-prefixed strings)
	appendLP(ts)
	appendLP(string(et))
	appendLP(cat)
	appendLP(detail)

	// blocked as single byte
	if blocked {
		buf = append(buf, 0x01)
	} else {
		buf = append(buf, 0x00)
	}

	// session_id (length-prefixed)
	appendLP(sid)

	return buf
}

// chainEntry computes the entry_hash for a row given the previous hash.
// prevHashHex is the hex-encoded previous entry_hash (or 64 zeros for genesis).
// Returns (entry_hash hex string, error).
func chainEntry(id int64, ts string, et EventType, cat, detail string, blocked bool, sid, prevHashHex string) (string, error) {
	// Decode previous hash from hex to bytes
	prevHashBytes, err := hex.DecodeString(prevHashHex)
	if err != nil {
		return "", fmt.Errorf("invalid prev_hash hex: %w", err)
	}
	if len(prevHashBytes) != 32 {
		return "", fmt.Errorf("prev_hash must be 32 bytes, got %d", len(prevHashBytes))
	}

	// Compute canonical bytes for this row
	cb := canonicalBytes(id, ts, et, cat, detail, blocked, sid)

	// Concatenate canonical bytes with previous hash bytes
	toHash := append(cb, prevHashBytes...)

	// SHA256
	h := sha256.Sum256(toHash)

	return hex.EncodeToString(h[:]), nil
}

// detectMissingHashColumns checks if prev_hash and entry_hash columns exist.
func detectMissingHashColumns(db *sql.DB) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(events)")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	hasColumns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notnull int
		var dfltValue *string
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return false, err
		}
		hasColumns[name] = true
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	missing := !hasColumns["prev_hash"] || !hasColumns["entry_hash"]
	return missing, nil
}

// initChainHeadIfNeeded creates the chain_head table if it doesn't exist.
// Called within a transaction.
func initChainHeadIfNeeded(tx *sql.Tx) error {
	// Table already created in schema, just ensure it has a seed row
	var count int
	err := tx.QueryRow("SELECT COUNT(*) FROM chain_head").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to count chain_head: %w", err)
	}

	if count == 0 {
		// Seed with genesis state
		_, err := tx.Exec(
			"INSERT INTO chain_head (id, entry_hash, row_count) VALUES (1, ?, 0)",
			chainGenesisHashHex,
		)
		if err != nil {
			return fmt.Errorf("failed to seed chain_head: %w", err)
		}
	}

	return nil
}

// countEvents returns the total number of events in the database (within a transaction).
func countEvents(tx *sql.Tx) (int, error) {
	var count int
	err := tx.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	return count, err
}

// migrateToChain adds hash columns to existing DBs and chains existing rows.
// Called within NewLogger before the first Log.
func migrateToChain(db *sql.DB) error {
	missing, err := detectMissingHashColumns(db)
	if err != nil {
		return err
	}
	if !missing {
		// Already migrated, just ensure chain_head is initialized
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := initChainHeadIfNeeded(tx); err != nil {
			return err
		}
		return tx.Commit()
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin migration transaction: %w", err)
	}
	defer tx.Rollback()

	// Add columns
	if _, err := tx.Exec("ALTER TABLE events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("failed to add prev_hash column: %w", err)
	}
	if _, err := tx.Exec("ALTER TABLE events ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("failed to add entry_hash column: %w", err)
	}

	// Initialize chain_head
	if err := initChainHeadIfNeeded(tx); err != nil {
		return err
	}

	// Walk existing rows in id order and chain them
	rows, err := tx.Query("SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events ORDER BY id ASC")
	if err != nil {
		return fmt.Errorf("failed to query existing events: %w", err)
	}
	defer rows.Close()

	prevHashHex := chainGenesisHashHex
	highestID := int64(0)
	rowCount := 0
	for rows.Next() {
		var id int64
		var ts, et, cat, detail, sid string
		var blocked int
		if err := rows.Scan(&id, &ts, &et, &cat, &detail, &blocked, &sid); err != nil {
			return fmt.Errorf("failed to scan event row: %w", err)
		}

		entryHash, err := chainEntry(id, ts, EventType(et), cat, detail, blocked != 0, sid, prevHashHex)
		if err != nil {
			return fmt.Errorf("failed to chain event %d: %w", id, err)
		}

		_, err = tx.Exec(
			"UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = ?",
			prevHashHex, entryHash, id,
		)
		if err != nil {
			return fmt.Errorf("failed to update event %d with chain: %w", id, err)
		}

		prevHashHex = entryHash
		highestID = id
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating events during migration: %w", err)
	}

	// Update chain_head with migration info
	_, err = tx.Exec(
		"UPDATE chain_head SET entry_hash = ?, row_count = ?, migrated_at = ?, legacy_through_id = ? WHERE id = 1",
		prevHashHex, rowCount, time.Now().UTC().Format(time.RFC3339), highestID,
	)
	if err != nil {
		return fmt.Errorf("failed to update chain_head after migration: %w", err)
	}

	return tx.Commit()
}

// VerifyChain walks the hash chain from genesis and returns the verification result.
func (l *Logger) VerifyChain() (*ChainVerifyResult, error) {
	result := &ChainVerifyResult{}
	tx, err := l.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin chain verification transaction: %w", err)
	}
	defer tx.Rollback()

	// Get chain_head state
	var headHash string
	var rowCount int
	var migratedAtStr *string
	var legacyID *int64
	var prunedAtStr *string
	var prunedCountVal *int
	err = tx.QueryRow(
		"SELECT entry_hash, row_count, migrated_at, legacy_through_id, pruned_at, pruned_count FROM chain_head WHERE id = 1",
	).Scan(&headHash, &rowCount, &migratedAtStr, &legacyID, &prunedAtStr, &prunedCountVal)
	if err == sql.ErrNoRows {
		// Empty log
		result.HeadHash = chainGenesisHashHex
		result.Intact = true
		return result, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read chain_head: %w", err)
	}

	result.HeadHash = headHash

	if migratedAtStr != nil {
		t, err := time.Parse(time.RFC3339, *migratedAtStr)
		if err == nil {
			result.MigratedAt = &t
		}
	}
	if legacyID != nil {
		result.LegacyThroughID = *legacyID
	}
	if prunedAtStr != nil {
		t, err := time.Parse(time.RFC3339, *prunedAtStr)
		if err == nil {
			result.PrunedAt = &t
		}
	}
	if prunedCountVal != nil {
		result.PrunedCount = *prunedCountVal
	}

	// Get all events in order
	rows, err := tx.Query(
		"SELECT id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash FROM events ORDER BY id ASC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query events for verification: %w", err)
	}
	defer rows.Close()

	prevHashHex := chainGenesisHashHex
	for rows.Next() {
		var id int64
		var ts, et, cat, detail, sid, storedPrevHash, storedEntryHash string
		var blocked int
		if err := rows.Scan(&id, &ts, &et, &cat, &detail, &blocked, &sid, &storedPrevHash, &storedEntryHash); err != nil {
			return nil, fmt.Errorf("failed to scan event row: %w", err)
		}

		// Check for non-genesis prev_hash on first row (indicates pruning)
		if result.EntriesVerified == 0 && storedPrevHash != chainGenesisHashHex {
			result.Intact = false
			result.FirstBrokenID = id
			result.BrokenReason = fmt.Sprintf("first row id=%d has non-genesis prev_hash; earlier rows removed", id)
			return result, nil
		}

		// Check prev_hash link
		if storedPrevHash != prevHashHex {
			result.Intact = false
			result.FirstBrokenID = id
			result.BrokenReason = fmt.Sprintf("entry %d: prev_hash mismatch (expected %s, got %s)", id, prevHashHex, storedPrevHash)
			return result, nil
		}

		// Recompute entry_hash
		expectedHash, err := chainEntry(id, ts, EventType(et), cat, detail, blocked != 0, sid, prevHashHex)
		if err != nil {
			result.Intact = false
			result.FirstBrokenID = id
			result.BrokenReason = fmt.Sprintf("entry %d: failed to compute hash: %v", id, err)
			return result, nil
		}

		if storedEntryHash != expectedHash {
			result.Intact = false
			result.FirstBrokenID = id
			result.BrokenReason = fmt.Sprintf("entry %d: entry_hash mismatch (expected %s, got %s)", id, expectedHash, storedEntryHash)
			return result, nil
		}

		prevHashHex = storedEntryHash
		result.EntriesVerified++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating events during verification: %w", err)
	}

	// Check chain_head consistency
	actualRowCount := result.EntriesVerified
	if rowCount != actualRowCount {
		result.Intact = false
		result.BrokenReason = fmt.Sprintf("chain_head row_count (%d) does not match actual events (%d)", rowCount, actualRowCount)
		return result, nil
	}

	if headHash != prevHashHex {
		result.Intact = false
		result.BrokenReason = fmt.Sprintf("chain_head entry_hash mismatch (expected %s, got %s)", prevHashHex, headHash)
		return result, nil
	}

	result.Intact = true
	return result, nil
}
