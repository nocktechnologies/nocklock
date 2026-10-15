// Package logging provides SQLite-backed event storage for NockLock fence events.
package logging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// EventType categorizes what kind of fence event occurred.
type EventType string

const (
	EventSecretBlocked        EventType = "secret_blocked"
	EventSecretPassed         EventType = "secret_passed"
	EventFileBlocked          EventType = "file_blocked"
	EventFilePassed           EventType = "file_passed"
	EventFilesystemFenceState EventType = "filesystem_fence_state"
	EventNetworkBlocked       EventType = "network_blocked"
	EventNetworkPassed        EventType = "network_passed"
	EventProxyStart           EventType = "proxy_start"
	EventProxyStop            EventType = "proxy_stop"
	EventNetworkError         EventType = "network_error"
	EventSessionStart         EventType = "session_start"
	EventSessionEnd           EventType = "session_end"
	EventConfigLoaded         EventType = "config_loaded"
	EventConfigDigest         EventType = "config.digest"
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
	ID          int64
	Timestamp   time.Time
	EventType   EventType
	Category    string // "secret", "filesystem", "network", "session"
	Detail      string // context: env var name (secrets), command name (session), exit code (session end)
	EgressLevel string `json:"egress_level,omitempty"`
	Blocked     bool
	SessionID   string
}

const signedEventDetailSchema = "nocklock-event-detail/v1"

type signedEventDetail struct {
	Schema      string `json:"schema"`
	Detail      string `json:"detail"`
	EgressLevel string `json:"egress_level"`
}

// encodeEventDetail preserves the existing detail string when no additional
// signed event fields are present. New fields use a versioned JSON envelope in
// the already-signed detail column, so existing audit databases need no schema
// migration and their historical hashes remain unchanged.
func encodeEventDetail(eventType EventType, detail, egressLevel string) string {
	if eventType != EventSessionStart || egressLevel == "" {
		return detail
	}
	data, _ := json.Marshal(signedEventDetail{
		Schema:      signedEventDetailSchema,
		Detail:      detail,
		EgressLevel: egressLevel,
	})
	return string(data)
}

func decodeEventDetail(eventType EventType, stored string) (detail, egressLevel string) {
	if eventType != EventSessionStart {
		return stored, ""
	}
	var envelope signedEventDetail
	if err := json.Unmarshal([]byte(stored), &envelope); err != nil ||
		envelope.Schema != signedEventDetailSchema || envelope.EgressLevel == "" {
		return stored, ""
	}
	return envelope.Detail, envelope.EgressLevel
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
	ByID       bool // if true, order by insertion ID instead of timestamp
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
	db               *sql.DB
	writeDSN         string  // file:...?mode=rw for the throwaway verify_receipt write connection
	signer           *signer // nil when Ed25519 signing is off
	onCommit         func(Event, string)
	projectRoot      string               // canonical project root for the external trusted identity
	identitySync     func(*os.File) error // per-instance record durability fault injection for tests
	identityRootSync func(*os.File) error // per-instance root-establishment fault injection
}

// eventTransaction is the common database/sql operation set shared by a
// regular transaction and a connection held in an explicit SQLite transaction.
type eventTransaction interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Option configures a Logger at construction.
type Option func(*loggerConfig)

type loggerConfig struct {
	signingEnabled      bool
	existingSigningOnly bool
	signingKeyPath      string
	onCommit            func(Event, string)
	afterValidate       func() // test seam, see withAfterValidate
}

// WithEventCommitted observes an event and its audit-chain entry hash only
// after the event transaction commits. The callback must return promptly.
func WithEventCommitted(fn func(Event, string)) Option {
	return func(c *loggerConfig) { c.onCommit = fn }
}

// WithSigning enables Ed25519 signing of each row and the chain_head, using the
// NockLock-managed key at keyPath (generated 0600 on first use if absent). Only
// the event-writing path (wrap, and log --prune) needs this; read-only opens do
// not, and an adopted log opened without a key fails closed on any write.
func WithSigning(keyPath string) Option {
	return func(c *loggerConfig) {
		c.signingEnabled = true
		c.signingKeyPath = keyPath
	}
}

// WithExistingSigning opens an existing adopted database with its matching key,
// without creating a database, adopting signing, or re-signing its head. Anchor operations use this
// option so a database stripped between preflight and open cannot be blessed
// as a newly adopted chain. Callers must still verify the signed chain before
// emitting or registering any anchor.
func WithExistingSigning(keyPath string) Option {
	return func(c *loggerConfig) {
		c.signingEnabled = true
		c.existingSigningOnly = true
		c.signingKeyPath = keyPath
	}
}

// withAfterValidate lets a test act as a racing writer between validatePath and
// the path-based open (N10717). Unexported: never set in production.
func withAfterValidate(fn func()) Option {
	return func(c *loggerConfig) { c.afterValidate = fn }
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

	// Signature verdict (v1.1 Ed25519). SigState is one of:
	//   ""          hash-only verification was requested (no signature awareness)
	//   "unsigned"  no signatures present, or a public key confirms none adopted
	//   "unverified" signatures are present but no public key was supplied
	//   "authentic" every post-adoption row and the chain_head verified against the key
	//   "forged"    a signature is missing where required or does not verify
	//   "suspect"   signing was explicitly required but the log carries no
	//               signatures and no adoption markers (whether or not any
	//               events remain) — possibly fully stripped or wholly deleted;
	//               never a clean pass (see classifySigState)
	// These states are never conflated: a pass on an unsigned chain is CONSISTENT,
	// not AUTHENTIC.
	SigState          string
	SignedEntries     int        // rows carrying a signature
	UnsignedEntries   int        // rows with no signature
	SigVerified       int        // rows whose signature verified against the key in this run
	SigAttested       int        // rows whose signature a valid verify_receipt attests (prefix skipped this run, re-proven byte-identical; never verified in this run)
	SigBrokenID       int64      // id of the first row whose signature failed (0 = none)
	SigBrokenReason   string     // explanation of the signature failure
	SignedGenesisAt   *time.Time // when signing was adopted (if applicable)
	UnsignedThroughID int64      // highest id predating signing adoption
	HeadSigned        bool       // chain_head carries a signature
	PubKeyProvided    bool       // a public key was available for verification
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
	entry_hash TEXT NOT NULL DEFAULT '',
	entry_sig TEXT NOT NULL DEFAULT ''
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
	pruned_count INTEGER,
	head_sig TEXT NOT NULL DEFAULT '',
	signed_genesis_at TEXT,
	unsigned_through_id INTEGER,
	signing_pubkey_fingerprint TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS verify_receipt (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	version INTEGER NOT NULL,
	key_fingerprint TEXT NOT NULL,
	signed_genesis_at TEXT,
	unsigned_through_id INTEGER,
	through_id INTEGER NOT NULL,
	through_count INTEGER NOT NULL,
	through_head_hash TEXT NOT NULL,
	digest TEXT NOT NULL,
	sig TEXT NOT NULL
);
`

// validatePath rejects paths containing traversal sequences and paths outside
// the two directories an event log may legitimately occupy: the project itself,
// and the project's audit state directory.
//
// The guard's purpose is to stop a repository-supplied .nock/config.toml from
// aiming logging.db at an arbitrary file (NockLock would create and write a
// SQLite database over it). The audit state directory is admitted because that
// is where NockLock now keeps the log by default — outside the project, so the
// fenced agent cannot reach it (config.AuditStateDir). It is derived from the
// project root here rather than trusted from the caller, so a hostile config
// cannot nominate some other directory as "the state directory".
func validatePath(dbPath, projectRoot string) error {
	cleaned := filepath.Clean(dbPath)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected in DB path: %q", dbPath)
	}
	if projectRoot != "" {
		// Canonicalize both sides into the same symlink frame before the
		// containment check: resolve the DB directory and the project root so an
		// in-root path is not falsely rejected on macOS (where /tmp and
		// /var/folders are /private/* symlinks). The final DB component is left
		// unresolved so a symlink AT the DB path is still caught by the
		// Lstat/O_NOFOLLOW guard below rather than followed here.
		resolvedDir, err := resolveDeepestExisting(filepath.Dir(cleaned))
		if err != nil {
			return fmt.Errorf("cannot canonicalize DB path %q under project root %q: %w", dbPath, projectRoot, err)
		}
		resolvedPath := filepath.Join(resolvedDir, filepath.Base(cleaned))
		resolvedRoot, err := filepath.EvalSymlinks(projectRoot)
		if err != nil {
			resolvedRoot = filepath.Clean(projectRoot)
		}
		if !pathContains(resolvedRoot, resolvedPath) && !inAuditStateDir(projectRoot, resolvedPath) {
			return fmt.Errorf("DB path %q resolves outside both project root %q and its audit state directory", dbPath, projectRoot)
		}
	}
	return nil
}

// pathContains reports whether path is root itself or lies beneath it. The
// comparison is at component boundaries: rel is ".." or "../…" only when path
// is genuinely outside root, whereas a bare strings.HasPrefix(rel, "..") would
// also reject an in-root child literally named "..evil".
func pathContains(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// inAuditStateDir reports whether path lies in the audit state directory that
// belongs to projectRoot. The directory is computed, never created, so a
// validation call has no side effects.
func inAuditStateDir(projectRoot, path string) bool {
	stateDir, err := config.AuditStateDir(projectRoot)
	if err != nil {
		return false
	}
	resolved, err := resolveDeepestExisting(stateDir)
	if err != nil {
		resolved = filepath.Clean(stateDir)
	}
	return pathContains(resolved, path)
}

// resolveDeepestExisting canonicalizes dir by resolving symlinks in its deepest
// existing ancestor and rejoining the components that do not exist yet, so
// validatePath's containment check compares both sides in the same symlink
// frame even when the audit directory has not been created.
//
// The walk steps over a component ONLY when that component is genuinely absent
// (its own Lstat reports "does not exist"); it then treats the raw name as a
// not-yet-created child and continues upward. Any other state fails closed
// rather than degrading to the raw frame — the raw frame is exactly where a
// symlinked ancestor could escape the project root undetected. That includes:
//   - an EvalSymlinks failure that is not "does not exist" (a symlink loop, a
//     permission-blocked or non-directory ancestor); and
//   - a DANGLING symlink: EvalSymlinks reports the missing target as "does not
//     exist", but the symlink entry itself is present, so Lstat succeeds. Left
//     unchecked this would carry the symlink's raw name up the walk as if it
//     were a plain new directory and admit an out-of-root target.
func resolveDeepestExisting(dir string) (string, error) {
	dir = filepath.Clean(dir)
	tail := ""
	for {
		resolved, err := filepath.EvalSymlinks(dir)
		if err == nil {
			return filepath.Join(resolved, tail), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		// EvalSymlinks reported a missing path. Lstat (which does not follow the
		// final component) tells us whether THIS component is truly absent or is
		// a present-but-unresolvable entry such as a dangling symlink.
		if _, lerr := os.Lstat(dir); lerr == nil {
			return "", fmt.Errorf("ancestor %q exists but cannot be resolved: %w", dir, err)
		} else if !errors.Is(lerr, os.ErrNotExist) {
			return "", lerr
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// No existing ancestor (e.g. reached the filesystem root); fall back
			// to the cleaned path so containment is still checked, not skipped.
			return filepath.Join(dir, tail), nil
		}
		tail = filepath.Join(filepath.Base(dir), tail)
		dir = parent
	}
}

// NewLogger opens or creates the SQLite database at dbPath.
// Creates parent directories and the events table if they don't exist.
// Sets WAL mode and 0600 file permissions.
// If projectRoot is non-empty, dbPath must reside under it.
func NewLogger(dbPath string, projectRoot string, opts ...Option) (*Logger, error) {
	var lc loggerConfig
	for _, opt := range opts {
		opt(&lc)
	}

	if err := validatePath(dbPath, projectRoot); err != nil {
		return nil, err
	}

	if lc.afterValidate != nil {
		lc.afterValidate()
	}
	dir := filepath.Dir(dbPath)
	if !lc.existingSigningOnly {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
		}
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
	flags := os.O_RDWR | oNoFollow
	if !lc.existingSigningOnly {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(dbPath, flags, 0o600)
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
	if !lc.existingSigningOnly {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, fmt.Errorf("failed to set DB file permissions: %w", err)
		}
	}
	f.Close()

	canonicalRoot := ""
	if projectRoot != "" {
		canonicalRoot, err = filepath.Abs(projectRoot)
		if err == nil {
			canonicalRoot, err = resolveDeepestExisting(canonicalRoot)
		}
		if err != nil {
			return nil, fmt.Errorf("cannot resolve project root for chain identity: %w", err)
		}
	}
	absolute, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, err
	}
	// mode=rw cannot create a missing DB and observes committed WAL pages.
	// immutable=1 would incorrectly ignore a live WAL and is not safe here. This
	// is also the DSN the best-effort verify_receipt write opens on its own
	// throwaway connection (writeVerifyReceipt), so its short busy timeout never
	// touches this Logger's shared, pooled connection.
	writeDSN := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: "mode=rw"}).String()
	dsn := dbPath
	if lc.existingSigningOnly {
		dsn = writeDSN
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open event log at %s: %w", dbPath, err)
	}

	// Serialize all operations through a single connection to avoid SQLITE_BUSY.
	// WAL mode allows external processes to read concurrently.
	db.SetMaxOpenConns(1)

	// Set the busy timeout before enabling WAL so concurrent first opens wait
	// rather than failing while changing the journal mode.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set busy timeout: %w", err)
	}

	if lc.existingSigningOnly {
		l, err := openExistingSignedLogger(db, canonicalRoot, lc)
		if err != nil {
			db.Close()
			return l, err
		}
		l.writeDSN = writeDSN
		return l, nil
	}

	// Enable WAL mode for concurrent read/write.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
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

	// Migrate existing DBs to add hash columns and initialize chain
	if err := migrateToChain(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate audit chain: %w", err)
	}

	// Add the v1.1 signature columns to any DB missing them. This runs on every
	// open — signed or not — so a read-only open of an old DB does not leave it
	// half-migrated for a later signing write.
	if err := migrateSigColumns(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate signature columns: %w", err)
	}

	if _, err := db.Exec(chainIdentitySchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize chain identity metadata: %w", err)
	}
	l := &Logger{db: db, writeDSN: writeDSN, onCommit: lc.onCommit, projectRoot: canonicalRoot}

	if lc.signingEnabled {
		adopted, err := signingAlreadyAdopted(db)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to check signing adoption state: %w", err)
		}
		var s *signer
		if adopted {
			// An adopted log must already have its original key. Do not create a
			// replacement key that could silently sever the signature history.
			s, err = loadSigner(lc.signingKeyPath)
		} else {
			s, err = loadOrCreateSigner(lc.signingKeyPath)
		}
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to load signing key: %w", err)
		}
		l.signer = s
		// Adopt signing on first signed open: record the genesis marker and sign
		// the current head. Existing rows stay unsigned; verify treats them as
		// UNSIGNED-but-consistent, not forged.
		if err := adoptSigningIfNeeded(db, s); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to adopt signing: %w", err)
		}
	}

	return l, nil
}

const chainIdentitySchema = `CREATE TABLE IF NOT EXISTS chain_identity (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	version INTEGER NOT NULL,
	agent_id TEXT NOT NULL,
	chain_id TEXT NOT NULL,
	legacy_anchor_digest TEXT NOT NULL
)`

// openExistingSignedLogger validates the current SQLite snapshot before any
// schema or signing mutation. The same transaction protects validation and the
// optional v2 mirror-table addition for a valid older signed log. A concurrent
// WAL writer makes an unsafe read-to-write promotion fail rather than blessing
// another snapshot. SQLite may manage its WAL/SHM files; no immutable read is used.
func openExistingSignedLogger(db *sql.DB, projectRoot string, lc loggerConfig) (*Logger, error) {
	s, err := loadSigner(lc.signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var genesis *string
	var fingerprint string
	if err := tx.QueryRow("SELECT signed_genesis_at, signing_pubkey_fingerprint FROM chain_head WHERE id = 1").Scan(&genesis, &fingerprint); err != nil {
		return nil, fmt.Errorf("anchor operations require existing signing adoption: %w", err)
	}
	if genesis == nil {
		return nil, errors.New("anchor operations require existing signing adoption; refusing to adopt or re-sign this database")
	}
	if err := validateAdoptedSigningHead(tx, s, fingerprint); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(chainIdentitySchema); err != nil {
		return nil, fmt.Errorf("failed to initialize chain identity metadata: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Logger{db: db, signer: s, onCommit: lc.onCommit, projectRoot: projectRoot}, nil
}

func validateAdoptedSigningHead(tx *sql.Tx, s *signer, fingerprint string) error {
	if fingerprint == "" {
		return fmt.Errorf("audit log signing metadata has no public key fingerprint; refusing to write")
	}
	if fingerprint != publicKeyFingerprint(s.pub) {
		return fmt.Errorf("audit log signing key does not match the adopted public key fingerprint; refusing to write")
	}
	var headHash, headSig string
	var rowCount int
	if err := tx.QueryRow("SELECT entry_hash, row_count, head_sig FROM chain_head WHERE id = 1").Scan(&headHash, &rowCount, &headSig); err != nil {
		return fmt.Errorf("failed to read chain head for signing key validation: %w", err)
	}
	headMeta, err := readHeadSignatureMetadata(tx)
	if err != nil {
		return fmt.Errorf("failed to read chain head signing metadata for key validation: %w", err)
	}
	if headSig == "" || !verifyHeadSig(s.pub, headHash, rowCount, headMeta, headSig) {
		return fmt.Errorf("audit log signing key does not verify the adopted chain head; refusing to write")
	}
	return nil
}

// Log records a single event with hash chain. Thread-safe (SQLite WAL handles locking).
func (l *Logger) Log(event Event) error {
	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin log transaction: %w", err)
	}
	defer tx.Rollback()
	var hash string
	if err := l.logInTransaction(tx, &event, &hash); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit log transaction: %w", err)
	}
	if l.onCommit != nil {
		l.onCommit(event, hash)
	}
	return nil
}

// LogAfterLatest records an event built from the latest event of eventType and
// returns that committed predecessor. The lookup and append share one SQLite
// BEGIN IMMEDIATE transaction, so concurrent writers cannot observe the same
// predecessor.
func (l *Logger) LogAfterLatest(eventType EventType, build func(*Event) (Event, error)) (*Event, error) {
	if build == nil {
		return nil, errors.New("log event builder is required")
	}

	ctx := context.Background()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to reserve log connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, fmt.Errorf("failed to begin immediate log transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	previous, err := latestEvent(ctx, conn, eventType)
	if err != nil {
		return nil, err
	}
	event, err := build(previous)
	if err != nil {
		return nil, err
	}
	var hash string
	if err := l.logInTransaction(conn, &event, &hash); err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, fmt.Errorf("failed to commit immediate log transaction: %w", err)
	}
	committed = true
	if l.onCommit != nil {
		l.onCommit(event, hash)
	}
	return previous, nil
}

// LogImmediate records an event like Log, but opens a BEGIN IMMEDIATE
// transaction, so busy_timeout applies when another process holds the write
// lock. Log's deferred transaction reads before it writes and fails at once
// with SQLITE_BUSY in that case.
func (l *Logger) LogImmediate(event Event) error {
	_, err := l.LogAfterLatest(event.EventType, func(*Event) (Event, error) { return event, nil })
	return err
}

// LatestBlockedEvent returns the newest blocked=1 row of eventType in
// sessionID, or nil when there is none. Newest means highest row id, not
// latest timestamp, so a skewed clock cannot reorder history. The returned
// Event carries only ID and Timestamp.
func (l *Logger) LatestBlockedEvent(sessionID string, eventType EventType) (*Event, error) {
	var id int64
	var timestamp string
	err := l.db.QueryRow(
		"SELECT id, timestamp FROM events WHERE session_id = ? AND event_type = ? AND blocked = 1 ORDER BY id DESC LIMIT 1",
		sessionID, string(eventType),
	).Scan(&id, &timestamp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read latest blocked %s event: %w", eventType, err)
	}
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event %d timestamp %q: %w", id, timestamp, err)
	}
	return &Event{ID: id, Timestamp: ts}, nil
}

func latestEvent(ctx context.Context, tx eventTransaction, eventType EventType) (*Event, error) {
	var event Event
	var timestamp string
	var blocked int
	var storedType string
	var storedDetail string
	err := tx.QueryRowContext(ctx,
		"SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events WHERE event_type = ? ORDER BY id DESC LIMIT 1",
		string(eventType),
	).Scan(&event.ID, &timestamp, &storedType, &event.Category, &storedDetail, &blocked, &event.SessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read previous event: %w", err)
	}
	event.EventType = EventType(storedType)
	event.Detail, event.EgressLevel = decodeEventDetail(event.EventType, storedDetail)
	event.Blocked = blocked != 0
	event.Timestamp, err = time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous event timestamp %q: %w", timestamp, err)
	}
	return &event, nil
}

func (l *Logger) logInTransaction(tx eventTransaction, event *Event, hash *string) error {
	ts := formatTimestampForChain(event.Timestamp)
	storedDetail := encodeEventDetail(event.EventType, event.Detail, event.EgressLevel)
	blocked := 0
	if event.Blocked {
		blocked = 1
	}
	if err := initChainHeadIfNeeded(tx); err != nil {
		return fmt.Errorf("failed to initialize chain_head: %w", err)
	}
	if err := l.ensureWritableSignerState(tx); err != nil {
		return err
	}

	var prevHashHex string
	if err := tx.QueryRowContext(context.Background(), "SELECT entry_hash FROM chain_head WHERE id = 1").Scan(&prevHashHex); err != nil {
		return fmt.Errorf("failed to read chain head: %w", err)
	}

	// Insert without hash values first
	result, err := tx.ExecContext(context.Background(),
		`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash)
		 VALUES (?, ?, ?, ?, ?, ?, '', '')`,
		ts, string(event.EventType), event.Category, storedDetail, blocked, event.SessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}

	eventID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get event ID: %w", err)
	}

	// Compute hash chain
	cb := canonicalBytes(eventID, ts, event.EventType, event.Category, storedDetail, event.Blocked, event.SessionID)
	entryHash, err := chainEntryFromCanonical(cb, prevHashHex)
	if err != nil {
		return fmt.Errorf("failed to compute chain: %w", err)
	}

	// Sign over the SAME canonical bytes the hash covers (v1.1). Empty when
	// signing is off.
	entrySig := ""
	if l.signer != nil {
		entrySig = l.signer.signRow(cb)
	}

	// Update with computed hashes and signature
	_, err = tx.ExecContext(context.Background(),
		"UPDATE events SET prev_hash = ?, entry_hash = ?, entry_sig = ? WHERE id = ?",
		prevHashHex, entryHash, entrySig, eventID,
	)
	if err != nil {
		return fmt.Errorf("failed to update event hashes: %w", err)
	}

	count, err := countEvents(tx)
	if err != nil {
		return fmt.Errorf("failed to count events: %w", err)
	}
	headMeta, err := readHeadSignatureMetadata(tx)
	if err != nil {
		return fmt.Errorf("failed to read chain head signing metadata: %w", err)
	}
	headSig, err := signHead(l.signer, entryHash, count, headMeta)
	if err != nil {
		return fmt.Errorf("failed to sign chain head: %w", err)
	}
	_, err = tx.ExecContext(context.Background(),
		"UPDATE chain_head SET entry_hash = ?, row_count = ?, head_sig = ? WHERE id = 1",
		entryHash, count, headSig,
	)
	if err != nil {
		return fmt.Errorf("failed to update chain_head: %w", err)
	}
	event.ID = eventID
	*hash = entryHash

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
	if err := l.ensureWritableSignerState(tx); err != nil {
		return err
	}

	// Get current head
	var currentHeadHash string
	err = tx.QueryRow("SELECT entry_hash FROM chain_head WHERE id = 1").Scan(&currentHeadHash)
	if err != nil {
		currentHeadHash = chainGenesisHashHex
	}

	prevHashHex := currentHeadHash
	hashes := make([]string, 0, len(events))
	committedEvents := make([]Event, 0, len(events))

	// Insert all events with chaining
	for i := range events {
		event := events[i]
		ts := formatTimestampForChain(event.Timestamp)
		storedDetail := encodeEventDetail(event.EventType, event.Detail, event.EgressLevel)
		blocked := 0
		if event.Blocked {
			blocked = 1
		}

		result, err := tx.Exec(
			`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ts, string(event.EventType), event.Category, storedDetail, blocked, event.SessionID, prevHashHex, "",
		)
		if err != nil {
			return fmt.Errorf("failed to insert event in batch: %w", err)
		}

		eventID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get event ID: %w", err)
		}

		// Compute hash and sign the same canonical bytes.
		cb := canonicalBytes(eventID, ts, event.EventType, event.Category, storedDetail, event.Blocked, event.SessionID)
		entryHash, err := chainEntryFromCanonical(cb, prevHashHex)
		if err != nil {
			return fmt.Errorf("failed to compute chain for event %d: %w", eventID, err)
		}
		entrySig := ""
		if l.signer != nil {
			entrySig = l.signer.signRow(cb)
		}

		// Update with computed hash and signature
		_, err = tx.Exec(
			"UPDATE events SET entry_hash = ?, entry_sig = ? WHERE id = ?",
			entryHash, entrySig, eventID,
		)
		if err != nil {
			return fmt.Errorf("failed to update event hash: %w", err)
		}

		prevHashHex = entryHash
		event.ID = eventID
		committedEvents = append(committedEvents, event)
		hashes = append(hashes, entryHash)
	}

	// Update chain_head with final state
	count, err := countEvents(tx)
	if err != nil {
		return fmt.Errorf("failed to count events: %w", err)
	}

	headMeta, err := readHeadSignatureMetadata(tx)
	if err != nil {
		return fmt.Errorf("failed to read chain head signing metadata: %w", err)
	}
	headSig, err := signHead(l.signer, prevHashHex, count, headMeta)
	if err != nil {
		return fmt.Errorf("failed to sign chain head: %w", err)
	}
	_, err = tx.Exec(
		"UPDATE chain_head SET entry_hash = ?, row_count = ?, head_sig = ? WHERE id = 1",
		prevHashHex, count, headSig,
	)
	if err != nil {
		return fmt.Errorf("failed to update chain_head: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}
	if l.onCommit != nil {
		for i, event := range committedEvents {
			l.onCommit(event, hashes[i])
		}
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

	orderBy := "timestamp"
	if opts.ByID {
		orderBy = "id"
	}
	if opts.Descending {
		query += " ORDER BY " + orderBy + " DESC"
	} else {
		query += " ORDER BY " + orderBy + " ASC"
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
		var storedDetail string
		if err := rows.Scan(&e.ID, &ts, &eventType, &e.Category, &storedDetail, &blocked, &e.SessionID); err != nil {
			return nil, fmt.Errorf("failed to scan event row: %w", err)
		}
		e.EventType = EventType(eventType)
		e.Detail, e.EgressLevel = decodeEventDetail(e.EventType, storedDetail)
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
// Requires explicit project context, even for a legacy chain: a rolled-back DB
// cannot prove that no external remote pin exists. The shared identity-lock wait
// is bounded to five seconds. Returns the number of events removed.
func (l *Logger) Prune(olderThan time.Duration) (int, error) {
	unlock, err := l.lockPruneIdentity()
	if err != nil {
		return 0, err
	}
	defer unlock()
	cutoff := formatTimestampForChain(time.Now().Add(-olderThan))

	tx, err := l.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin prune transaction: %w", err)
	}
	defer tx.Rollback()

	if err := initChainHeadIfNeeded(tx); err != nil {
		return 0, err
	}
	if err := l.ensureWritableSignerState(tx); err != nil {
		return 0, err
	}

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

	// A prune re-chains every surviving row, so any verify_receipt now attests a
	// prefix that no longer exists byte-for-byte. It would be ignored on the next
	// verify (digest mismatch, full walk), but dropping it here avoids that wasted
	// rescan. The table is created at open, so this is a no-op on a fresh chain.
	if _, err := tx.Exec("DELETE FROM verify_receipt"); err != nil {
		return 0, fmt.Errorf("failed to clear verify receipt during prune: %w", err)
	}

	// Get the first surviving row
	var firstID int64
	var firstTS, firstET, firstCat, firstDetail, firstSID string
	var firstBlocked int
	err = tx.QueryRow("SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events ORDER BY id ASC LIMIT 1").
		Scan(&firstID, &firstTS, &firstET, &firstCat, &firstDetail, &firstBlocked, &firstSID)
	if err == sql.ErrNoRows {
		// All events were pruned. The head returns to genesis; re-sign it so an
		// adopted log keeps an authentic head.
		prunedAt := time.Now().UTC().Format(time.RFC3339)
		headMeta, metaErr := readHeadSignatureMetadata(tx)
		if metaErr != nil {
			return 0, fmt.Errorf("failed to read chain head signing metadata after full prune: %w", metaErr)
		}
		headMeta.prunedAt = &prunedAt
		headMeta.prunedCount = &pruneCount
		headSig, signErr := signHead(l.signer, chainGenesisHashHex, 0, headMeta)
		if signErr != nil {
			return 0, fmt.Errorf("failed to sign chain head after full prune: %w", signErr)
		}
		_, err = tx.Exec("UPDATE chain_head SET entry_hash = ?, row_count = 0, pruned_at = ?, pruned_count = ?, head_sig = ? WHERE id = 1",
			chainGenesisHashHex, prunedAt, pruneCount, headSig)
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

	prunedAt := time.Now().UTC().Format(time.RFC3339)
	headMeta, err := readHeadSignatureMetadata(tx)
	if err != nil {
		return 0, fmt.Errorf("failed to read chain head signing metadata after re-anchor: %w", err)
	}
	headMeta.prunedAt = &prunedAt
	headMeta.prunedCount = &pruneCount
	headSig, err := signHead(l.signer, prevHashHex, count, headMeta)
	if err != nil {
		return 0, fmt.Errorf("failed to sign chain head after re-anchor: %w", err)
	}
	_, err = tx.Exec("UPDATE chain_head SET entry_hash = ?, row_count = ?, pruned_at = ?, pruned_count = ?, head_sig = ? WHERE id = 1",
		prevHashHex, count, prunedAt, pruneCount, headSig)
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
	cb := canonicalBytes(id, ts, et, cat, detail, blocked, sid)
	return chainEntryFromCanonical(cb, prevHashHex)
}

// chainEntryFromCanonical computes the entry_hash from already-encoded canonical
// bytes and the previous hash. Split out so the signing path can hash and sign
// the exact same canonical byte string without encoding it twice.
func chainEntryFromCanonical(cb []byte, prevHashHex string) (string, error) {
	prevHashBytes, err := hex.DecodeString(prevHashHex)
	if err != nil {
		return "", fmt.Errorf("invalid prev_hash hex: %w", err)
	}
	if len(prevHashBytes) != 32 {
		return "", fmt.Errorf("prev_hash must be 32 bytes, got %d", len(prevHashBytes))
	}

	// Concatenate canonical bytes with previous hash bytes, then SHA-256.
	// A fresh slice avoids aliasing the caller's cb (append could grow in place).
	toHash := make([]byte, 0, len(cb)+len(prevHashBytes))
	toHash = append(toHash, cb...)
	toHash = append(toHash, prevHashBytes...)
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
func initChainHeadIfNeeded(tx eventTransaction) error {
	// Table already created in schema, just ensure it has a seed row
	var count int
	err := tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM chain_head").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to count chain_head: %w", err)
	}

	if count == 0 {
		// Seed with genesis state
		_, err := tx.ExecContext(context.Background(),
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
func countEvents(tx eventTransaction) (int, error) {
	var count int
	err := tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM events").Scan(&count)
	return count, err
}

// columnSet returns the set of column names on a table.
func columnSet(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt *string
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

// migrateSigColumns adds the v1.1 signature columns to an existing DB that
// predates signing (a v1 hash-chain DB has the hash columns but not these).
// Idempotent: it only ALTERs columns that are missing.
func migrateSigColumns(db *sql.DB) error {
	eventCols, err := columnSet(db, "events")
	if err != nil {
		return err
	}
	headCols, err := columnSet(db, "chain_head")
	if err != nil {
		return err
	}

	var alters []string
	if !eventCols["entry_sig"] {
		alters = append(alters, "ALTER TABLE events ADD COLUMN entry_sig TEXT NOT NULL DEFAULT ''")
	}
	if !headCols["head_sig"] {
		alters = append(alters, "ALTER TABLE chain_head ADD COLUMN head_sig TEXT NOT NULL DEFAULT ''")
	}
	if !headCols["signed_genesis_at"] {
		alters = append(alters, "ALTER TABLE chain_head ADD COLUMN signed_genesis_at TEXT")
	}
	if !headCols["unsigned_through_id"] {
		alters = append(alters, "ALTER TABLE chain_head ADD COLUMN unsigned_through_id INTEGER")
	}
	if !headCols["signing_pubkey_fingerprint"] {
		alters = append(alters, "ALTER TABLE chain_head ADD COLUMN signing_pubkey_fingerprint TEXT NOT NULL DEFAULT ''")
	}
	if len(alters) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range alters {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("failed to add signature column (%s): %w", stmt, err)
		}
	}
	return tx.Commit()
}

// signingAlreadyAdopted reports whether this log has a signing-adoption marker.
// It is checked before loading a key so an adopted log never creates a silent
// replacement key when its original managed key is missing.
func signingAlreadyAdopted(db *sql.DB) (bool, error) {
	var genesis *string
	err := db.QueryRow("SELECT signed_genesis_at FROM chain_head WHERE id = 1").Scan(&genesis)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return genesis != nil, nil
}

// readHeadSignatureMetadata loads all chain_head fields authenticated by the
// versioned head signature.
func readHeadSignatureMetadata(tx eventTransaction) (headSignatureMetadata, error) {
	var meta headSignatureMetadata
	var fingerprint string
	if err := tx.QueryRowContext(context.Background(),
		"SELECT pruned_at, pruned_count, signed_genesis_at, unsigned_through_id, signing_pubkey_fingerprint FROM chain_head WHERE id = 1",
	).Scan(&meta.prunedAt, &meta.prunedCount, &meta.signedGenesisAt, &meta.unsignedThroughID, &fingerprint); err != nil {
		return headSignatureMetadata{}, err
	}
	meta.publicKeyFingerprintHex = fingerprint
	return meta, nil
}

// adoptSigningIfNeeded records the signing genesis marker on the first signed
// open of a log: it stamps signed_genesis_at and unsigned_through_id (the
// highest id predating signing) and signs the current head. Rows written before
// this point stay unsigned; everything after is signed forward.
func adoptSigningIfNeeded(db *sql.DB, s *signer) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := initChainHeadIfNeeded(tx); err != nil {
		return err
	}

	var genesis *string
	var fingerprint string
	if err := tx.QueryRow("SELECT signed_genesis_at, signing_pubkey_fingerprint FROM chain_head WHERE id = 1").Scan(&genesis, &fingerprint); err != nil {
		return fmt.Errorf("failed to read signing genesis: %w", err)
	}
	if genesis != nil {
		if err := validateAdoptedSigningHead(tx, s, fingerprint); err != nil {
			return err
		}
		// Already adopted with the same key.
		return tx.Commit()
	}

	var maxID int64
	if err := tx.QueryRow("SELECT COALESCE(MAX(id), 0) FROM events").Scan(&maxID); err != nil {
		return fmt.Errorf("failed to read max event id: %w", err)
	}

	var headHash string
	var rowCount int
	if err := tx.QueryRow("SELECT entry_hash, row_count FROM chain_head WHERE id = 1").Scan(&headHash, &rowCount); err != nil {
		return fmt.Errorf("failed to read chain head for adoption: %w", err)
	}
	signedGenesisAt := time.Now().UTC().Format(time.RFC3339)
	_, err = tx.Exec(
		"UPDATE chain_head SET signed_genesis_at = ?, unsigned_through_id = ?, signing_pubkey_fingerprint = ? WHERE id = 1",
		signedGenesisAt, maxID, publicKeyFingerprint(s.pub),
	)
	if err != nil {
		return fmt.Errorf("failed to write signing genesis marker: %w", err)
	}
	headMeta, err := readHeadSignatureMetadata(tx)
	if err != nil {
		return fmt.Errorf("failed to read chain head signing metadata at adoption: %w", err)
	}
	headSig, err := signHead(s, headHash, rowCount, headMeta)
	if err != nil {
		return fmt.Errorf("failed to sign chain head at adoption: %w", err)
	}
	if _, err = tx.Exec("UPDATE chain_head SET head_sig = ? WHERE id = 1", headSig); err != nil {
		return fmt.Errorf("failed to sign chain head at adoption: %w", err)
	}
	return tx.Commit()
}

// ensureWritableSignerState fails closed: if signing has been adopted for this
// log but this Logger holds no key, no write may proceed. This makes an
// unsigned write (or a prune) after adoption impossible, not merely detectable.
func (l *Logger) ensureWritableSignerState(tx eventTransaction) error {
	if l.signer != nil {
		return nil
	}
	var genesis *string
	err := tx.QueryRowContext(context.Background(), "SELECT signed_genesis_at FROM chain_head WHERE id = 1").Scan(&genesis)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to check signing state: %w", err)
	}
	if genesis != nil {
		return fmt.Errorf("audit log has adopted Ed25519 signing but no signing key is loaded; refusing to write unsigned (open with WithSigning)")
	}
	return nil
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

		// Normalize legacy timestamps to the canonical 9-fractional-digit form
		// (spec §2). A pre-chain DB was written with second-precision RFC3339,
		// and a mixed-width timestamp column breaks every lexicographic compare
		// against it — Query's Since/Until bounds, Prune's cutoff, and Stats'
		// MIN/MAX. The instant is unchanged; only the stored string encoding is.
		// The hash below covers the normalized value, so the chain stays
		// self-consistent, and this is idempotent (the column-presence guard
		// runs the walk once, and re-encoding an already-9-digit value is a
		// no-op).
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return fmt.Errorf("failed to parse legacy timestamp %q for event %d: %w", ts, id, err)
		}
		ts = formatTimestampForChain(parsed)

		entryHash, err := chainEntry(id, ts, EventType(et), cat, detail, blocked != 0, sid, prevHashHex)
		if err != nil {
			return fmt.Errorf("failed to chain event %d: %w", id, err)
		}

		_, err = tx.Exec(
			"UPDATE events SET timestamp = ?, prev_hash = ?, entry_hash = ? WHERE id = ?",
			ts, prevHashHex, entryHash, id,
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

// VerifyChain walks the hash chain from genesis and returns the verification
// result. It performs hash-only (CONSISTENCY) verification: it counts any
// signatures present but does not check them. Use VerifyChainSigned to verify
// authenticity against a public key.
func (l *Logger) VerifyChain() (*ChainVerifyResult, error) {
	return l.verifyChain(context.Background(), nil, false)
}

// VerifyChainSigned walks the hash chain and, using the supplied Ed25519 public
// key, verifies every post-adoption row signature and the chain_head signature.
// A nil key falls back to hash-only verification (equivalent to VerifyChain).
// When requireSigned is true, a missing signing-adoption record is FORGED rather
// than an unsigned fallback. Use it only when the caller has an external
// expectation that this log was signed, such as an explicitly supplied key.
// The three states — AUTHENTIC, CONSISTENT/UNSIGNED, FORGED/TAMPERED — are kept
// distinct in the result and never conflated.
func (l *Logger) VerifyChainSigned(pub ed25519.PublicKey, requireSigned bool) (*ChainVerifyResult, error) {
	return l.verifyChain(context.Background(), pub, requireSigned)
}

// VerifyChainSignedContext is VerifyChainSigned bounded by ctx. When ctx ends
// before the walk completes it returns ErrVerifyInterrupted and no result: a
// partial walk is never reported as authentic or as tampering.
func (l *Logger) VerifyChainSignedContext(ctx context.Context, pub ed25519.PublicKey, requireSigned bool) (*ChainVerifyResult, error) {
	return l.verifyChain(ctx, pub, requireSigned)
}

// ErrVerifyInterrupted reports that a chain walk stopped (context cancelled or
// deadline reached) before it finished. It is distinct from Intact=false and
// from every signature state: the chain was neither authenticated nor shown to
// be tampered with, so callers must emit no anchor and claim no verdict.
var ErrVerifyInterrupted = errors.New("chain verification interrupted before completion; the chain was not judged (the walk deadline or context ended first, so retry with a longer one)")

// verifyCtxCheckInterval is how many rows the walk verifies between context
// checks.
const verifyCtxCheckInterval = 1024

// verifyRowHook, when set by a test, runs before each row with the number of
// rows already verified. It lets tests cancel at an exact row, not a wall clock.
var verifyRowHook func(rowsVerified int)

// verifyInterrupted maps an error raised while ctx is done to
// ErrVerifyInterrupted, keeping the context cause matchable.
func verifyInterrupted(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil {
		if err != nil {
			// Keep a real failure that coincided with the deadline visible.
			return fmt.Errorf("%w: %w (underlying error: %v)", ErrVerifyInterrupted, cause, err)
		}
		return fmt.Errorf("%w: %w", ErrVerifyInterrupted, cause)
	}
	return err
}

// walkInterrupted returns ErrVerifyInterrupted once ctx has ended, else nil.
func walkInterrupted(ctx context.Context) error {
	return verifyInterrupted(ctx, nil)
}

// chainHeadRecord is the stored chain_head row: the tail anchor (hash and row
// count), its signature, and the metadata the signature covers.
type chainHeadRecord struct {
	hash            string
	rowCount        int
	migratedAt      *string
	legacyThroughID *int64
	sig             string
	meta            headSignatureMetadata
}

// readChainHeadRecord reads the chain_head row. It returns sql.ErrNoRows when
// the table holds no head. It is the single reader of the head for both
// verifyChain (nocklock verify) and the public receipt verifier.
func readChainHeadRecord(tx *sql.Tx) (chainHeadRecord, error) {
	var h chainHeadRecord
	err := tx.QueryRow(
		"SELECT entry_hash, row_count, migrated_at, legacy_through_id, pruned_at, pruned_count, head_sig, signed_genesis_at, unsigned_through_id, signing_pubkey_fingerprint FROM chain_head WHERE id = 1",
	).Scan(&h.hash, &h.rowCount, &h.migratedAt, &h.legacyThroughID, &h.meta.prunedAt, &h.meta.prunedCount, &h.sig, &h.meta.signedGenesisAt, &h.meta.unsignedThroughID, &h.meta.publicKeyFingerprintHex)
	if err != nil {
		return chainHeadRecord{}, err
	}
	return h, nil
}

func (l *Logger) verifyChain(ctx context.Context, pub ed25519.PublicKey, requireSigned bool) (*ChainVerifyResult, error) {
	tx, err := l.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin chain verification transaction: %w", err)
	}
	result, prog, skipWrite, verr := verifyChainInTransaction(ctx, tx, pub, requireSigned)
	// End the read snapshot before any receipt write: the write runs in its own
	// short transaction (writeVerifyReceipt), never while this snapshot is open.
	_ = tx.Rollback()

	// A key holder records the verified prefix so later runs skip its signatures.
	// prog is frozen at the last fully-verified row: for an authentic chain that is
	// the head; for one that fails at row j it is at most j-1; for an interrupted
	// walk it is the last row proved before the deadline. Recording that bounded
	// prefix — even on a tampered or forged chain — keeps a stale wider receipt
	// from lingering and never covers past the last good row (fail-closed: the
	// receipt is always re-proven on use). skipWrite avoids re-writing an identical
	// receipt on a steady-state chain. Only a real DB/transaction error, which
	// yields no trustworthy prefix, writes nothing. The write is best-effort.
	if prog != nil && !skipWrite && (verr == nil || errors.Is(verr, ErrVerifyInterrupted)) {
		l.writeVerifyReceipt(pub, prog)
	}
	return result, verr
}

// verifyChainInTransaction lets anchor preflight authenticate the head and its
// prefix in the same SQLite snapshot without weakening ordinary verification. It
// returns the verdict, the verified prefix a key holder may record as a receipt
// (verifyProgress, returned even on ErrVerifyInterrupted so an interrupted walk
// still records what it proved), and an error. The walk checks ctx every
// verifyCtxCheckInterval rows and once more after the last row, and returns
// ErrVerifyInterrupted (and no verdict) when ctx ends.
//
// When a valid signed verify_receipt is present (Step 2 of
// docs/design/anchor-verification-profile.md), the first attempt re-proves the
// receipt's prefix is byte-identical (linkage, hash recompute and the rolling
// digest) and skips only its Ed25519 signature checks, verifying signatures for
// the suffix and always re-checking the head. If the prefix does not reproduce
// the receipt, the second attempt re-runs the full walk with no receipt on a
// fresh query in the SAME snapshot, so the verdict and diagnostics are identical
// to verification without a receipt.
// The returned skipWrite is true when a valid receipt was used and the verified
// prefix did not extend past it, so re-writing the identical receipt would be
// wasted I/O; the caller then skips the write.
func verifyChainInTransaction(ctx context.Context, tx *sql.Tx, pub ed25519.PublicKey, requireSigned bool) (result *ChainVerifyResult, prog *verifyProgress, skipWrite bool, err error) {
	// Get chain_head state
	head, err := readChainHeadRecord(tx)
	if err == sql.ErrNoRows {
		result := &ChainVerifyResult{PubKeyProvided: pub != nil}
		var actualRowCount int
		if countErr := tx.QueryRow("SELECT COUNT(*) FROM events").Scan(&actualRowCount); countErr != nil {
			return nil, nil, false, fmt.Errorf("failed to count events without chain_head: %w", countErr)
		}

		result.HeadHash = chainGenesisHashHex
		if actualRowCount > 0 {
			result.Intact = false
			result.BrokenReason = fmt.Sprintf("chain_head missing while events table contains %d row(s)", actualRowCount)
			return result, emptyVerifyProgress(head), false, nil
		}

		// No chain_head row and no events: there is nothing to walk, so the
		// empty chain is intact. It is NOT automatically a clean signed pass: a signed
		// check that was explicitly required still has no adoption marker here,
		// which is "suspect" exactly as for a populated log. Otherwise a writer
		// could delete every row and reset the head to downgrade a required
		// check to an unsigned pass.
		result.Intact = true
		result.SigState = classifySigState(pub, false, false, 0, requireSigned)
		if result.SigState == "suspect" {
			result.SigBrokenReason = suspectSigReason
		}
		return result, emptyVerifyProgress(head), false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to read chain_head: %w", err)
	}

	// Load and authenticate a receipt once; walkEvents uses it to skip the prefix.
	// A nil pub (hash-only verification) never qualifies, so hash-only verification
	// is byte-for-byte unchanged.
	var receipt *verifyReceipt
	if pub != nil && !verifyReceiptDisableRead {
		if r, _ := loadVerifyReceipt(tx); validVerifyReceiptFor(r, pub, head) {
			receipt = r
		}
	}

	result, prog, mismatch, err := walkEvents(ctx, tx, pub, requireSigned, head, receipt)
	if err != nil {
		return nil, prog, false, err
	}
	if mismatch {
		// The prefix did not reproduce the receipt: discard it and run the full
		// walk on a fresh query in the same snapshot, so the verdict and its
		// diagnostics (first broken id, reason) match verification without a
		// receipt exactly.
		result, prog, _, err = walkEvents(ctx, tx, pub, requireSigned, head, nil)
		if err != nil {
			return nil, prog, false, err
		}
		return result, prog, false, nil
	}
	// A valid receipt that was not extended attests the identical prefix already on
	// disk, so re-writing it would be a wasted (fsync-bearing) transaction.
	skipWrite = receipt != nil && prog.throughID == receipt.ThroughID
	return result, prog, skipWrite, nil
}

// emptyVerifyProgress is the zero-row prefix (nothing to attest). Its metadata
// still binds the current head so a caller inspecting it sees the adoption state.
func emptyVerifyProgress(head chainHeadRecord) *verifyProgress {
	return &verifyProgress{
		throughHeadHash:   chainGenesisHashHex,
		digest:            verifyReceiptDigestSeed(),
		signedGenesisAt:   head.meta.signedGenesisAt,
		unsignedThroughID: head.meta.unsignedThroughID,
	}
}

// walkEvents performs one verification pass over the events in tx's snapshot.
// With receipt == nil it is the full walk, byte-for-byte as before. With a
// receipt it re-proves the receipt's prefix byte-identical and skips only that
// prefix's signature verification. It returns the verdict, the attestable
// verified prefix, and receiptMismatch=true when a non-nil receipt's prefix did
// not reproduce (the caller then re-walks with receipt == nil).
func walkEvents(ctx context.Context, tx *sql.Tx, pub ed25519.PublicKey, requireSigned bool, head chainHeadRecord, receipt *verifyReceipt) (result *ChainVerifyResult, prog *verifyProgress, receiptMismatch bool, err error) {
	result = &ChainVerifyResult{PubKeyProvided: pub != nil}

	headHash, rowCount, headSig := head.hash, head.rowCount, head.sig
	migratedAtStr, legacyID := head.migratedAt, head.legacyThroughID
	prunedAtStr, prunedCountVal := head.meta.prunedAt, head.meta.prunedCount
	signedGenesisStr, unsignedThroughID := head.meta.signedGenesisAt, head.meta.unsignedThroughID
	publicKeyFingerprintHex := head.meta.publicKeyFingerprintHex
	headMeta := head.meta

	result.HeadHash = headHash
	result.HeadSigned = headSig != ""

	if migratedAtStr != nil {
		if t, err := time.Parse(time.RFC3339, *migratedAtStr); err == nil {
			result.MigratedAt = &t
		}
	}
	if legacyID != nil {
		result.LegacyThroughID = *legacyID
	}
	if prunedAtStr != nil {
		if t, err := time.Parse(time.RFC3339, *prunedAtStr); err == nil {
			result.PrunedAt = &t
		}
	}
	if prunedCountVal != nil {
		result.PrunedCount = *prunedCountVal
	}
	adopted := signedGenesisStr != nil
	if adopted {
		if t, err := time.Parse(time.RFC3339, *signedGenesisStr); err == nil {
			result.SignedGenesisAt = &t
		}
	}
	if unsignedThroughID != nil {
		result.UnsignedThroughID = *unsignedThroughID
	}

	// prog tracks the attestable verified prefix: rows actually verified under the
	// key this run, plus — once the receipt boundary is confirmed — the receipt's
	// re-proven prefix. It never includes rows merely scanned.
	prog = emptyVerifyProgress(head)

	// Get all events in order
	rows, err := tx.QueryContext(ctx,
		"SELECT id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash, entry_sig FROM events ORDER BY id ASC",
	)
	if err != nil {
		return nil, prog, false, verifyInterrupted(ctx, fmt.Errorf("failed to query events for verification: %w", err))
	}
	defer rows.Close()

	sigForged := false
	if pub != nil && adopted {
		switch {
		case publicKeyFingerprintHex == "":
			sigForged = true
			result.SigBrokenReason = "chain_head signing public key fingerprint missing after signing adoption"
		case publicKeyFingerprintHex != publicKeyFingerprint(pub):
			sigForged = true
			result.SigBrokenReason = "chain_head signing public key fingerprint does not match the supplied key"
		}
	}

	prevHashHex := chainGenesisHashHex
	digest := verifyReceiptDigestSeed()
	usingReceipt := receipt != nil
	boundaryResolved := false

	for rows.Next() {
		if verifyRowHook != nil {
			verifyRowHook(result.EntriesVerified)
		}
		if result.EntriesVerified%verifyCtxCheckInterval == 0 {
			if err := walkInterrupted(ctx); err != nil {
				return nil, prog, false, err
			}
		}
		var id int64
		var ts, et, cat, detail, sid, storedPrevHash, storedEntryHash, storedSig string
		var blocked int
		if err := rows.Scan(&id, &ts, &et, &cat, &detail, &blocked, &sid, &storedPrevHash, &storedEntryHash, &storedSig); err != nil {
			return nil, prog, false, verifyInterrupted(ctx, fmt.Errorf("failed to scan event row: %w", err))
		}

		// A row is in the (tentative) attested prefix when a receipt is active, the
		// boundary is not yet resolved, and its id is within the receipt's prefix.
		inPrefix := usingReceipt && !boundaryResolved && id <= receipt.ThroughID
		// trustBlindly is the negative-control-19 mutation only: skip the prefix's
		// integrity re-verification (per-row hash recompute and the rolling-digest
		// comparison) that makes receipt-skipping safe. Never true in production.
		trustBlindly := inPrefix && verifyReceiptSkipDigestCheck

		// Check for non-genesis prev_hash on first row (indicates pruning)
		if result.EntriesVerified == 0 && storedPrevHash != chainGenesisHashHex {
			// A link break inside the attested prefix discards the receipt and re-runs
			// the full, receipt-free walk (mismatch=true), so the verdict AND its
			// diagnostics (FirstBrokenID, SigBrokenID, reasons, counts) are identical
			// to verification without a receipt. Returning here would keep the verdict
			// but skip the prefix's per-row signature accounting, diverging the counts.
			if inPrefix {
				return nil, prog, true, nil
			}
			result.Intact = false
			result.FirstBrokenID = id
			result.BrokenReason = fmt.Sprintf("first row id=%d has non-genesis prev_hash; earlier rows removed", id)
			return result, prog, false, nil
		}

		// Check prev_hash link
		if storedPrevHash != prevHashHex {
			if inPrefix { // see the first-row branch: re-walk for identical diagnostics.
				return nil, prog, true, nil
			}
			result.Intact = false
			result.FirstBrokenID = id
			result.BrokenReason = fmt.Sprintf("entry %d: prev_hash mismatch (expected %s, got %s)", id, prevHashHex, storedPrevHash)
			return result, prog, false, nil
		}

		// Recompute entry_hash over the canonical bytes (reused for the signature
		// check). This runs for every row, prefix included, so a prefix content edit
		// is caught here exactly as in the full walk. The mutation seam alone skips
		// it for an attested-prefix row.
		var cb []byte
		if !trustBlindly {
			cb = canonicalBytes(id, ts, EventType(et), cat, detail, blocked != 0, sid)
			expectedHash, hErr := chainEntryFromCanonical(cb, prevHashHex)
			if hErr != nil {
				if inPrefix { // see the first-row branch: re-walk for identical diagnostics.
					return nil, prog, true, nil
				}
				result.Intact = false
				result.FirstBrokenID = id
				result.BrokenReason = fmt.Sprintf("entry %d: failed to compute hash: %v", id, hErr)
				return result, prog, false, nil
			}
			if storedEntryHash != expectedHash {
				if inPrefix { // see the first-row branch: re-walk for identical diagnostics.
					return nil, prog, true, nil
				}
				result.Intact = false
				result.FirstBrokenID = id
				result.BrokenReason = fmt.Sprintf("entry %d: entry_hash mismatch (expected %s, got %s)", id, expectedHash, storedEntryHash)
				return result, prog, false, nil
			}
		}

		// Signature accounting. An attested-prefix row's signature is re-proven by
		// the rolling digest, not re-verified here, so it counts as SigAttested;
		// every other row is verified against the key. SigAttested mirrors the
		// SigVerified guard (pub present, not already forged) so the two counters
		// reconcile exactly even when a pre-loop head-fingerprint mismatch set
		// sigForged.
		if storedSig != "" {
			result.SignedEntries++
			switch {
			case inPrefix:
				if pub != nil && !sigForged {
					result.SigAttested++
				}
			case pub != nil && !sigForged:
				if verifyRowSig(pub, cb, storedSig) {
					result.SigVerified++
				} else {
					sigForged = true
					result.SigBrokenID = id
					result.SigBrokenReason = fmt.Sprintf("entry %d: signature does not verify against the key", id)
				}
			}
		} else {
			result.UnsignedEntries++
			// A post-adoption row with no signature is a stripped signature — a
			// forgery signal, not a benign pre-adoption row. In the attested prefix
			// a strip changes the digest instead, falling back to the full walk.
			if !inPrefix && pub != nil && !sigForged && adopted && id > result.UnsignedThroughID {
				sigForged = true
				result.SigBrokenID = id
				result.SigBrokenReason = fmt.Sprintf("entry %d: signature missing after signing adoption (stripped)", id)
			}
		}

		// Fold the rolling digest over the STORED bytes. It binds entry_sig, which
		// the hash chain does not cover, so a signature edit or strip on an
		// otherwise-consistent prefix changes the digest and forces a full walk. It
		// is load-bearing only for a keyed walk (the boundary check and the receipt),
		// so a hash-only walk and the mutation seam skip it.
		if pub != nil && !trustBlindly {
			digest = verifyRollingDigest(digest, storedEntryHash, storedSig)
		}

		prevHashHex = storedEntryHash
		result.EntriesVerified++

		// Resolve the receipt boundary when we reach (or pass) its last prefix row.
		if usingReceipt && !boundaryResolved && id >= receipt.ThroughID {
			boundaryResolved = true
			if !trustBlindly {
				if id != receipt.ThroughID ||
					int64(result.EntriesVerified) != receipt.ThroughCount ||
					prevHashHex != receipt.ThroughHeadHash ||
					!bytes.Equal(digest, receipt.Digest) {
					// The prefix does not reproduce the receipt (a row was deleted at
					// the boundary, the count differs, or a hash/signature byte
					// changed): fall back to the full walk for identical diagnostics.
					return nil, prog, true, nil
				}
			}
			// Confirmed (or blindly trusted under the mutation): the whole prefix is
			// attested, so advance the attestable progress to the boundary.
			prog.advanceTo(id, int64(result.EntriesVerified), prevHashHex, digest)
			continue
		}

		// Suffix rows (and every row when no receipt is used) advance the attestable
		// prefix until a forgery is seen, which freezes it at the last good row so a
		// receipt never attests past the break.
		if !inPrefix && !sigForged {
			prog.advanceTo(id, int64(result.EntriesVerified), prevHashHex, digest)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, prog, false, verifyInterrupted(ctx, fmt.Errorf("error iterating events during verification: %w", err))
	}
	// A receipt whose prefix extends past the last row never reproduced (the
	// boundary row is missing): fall back to the full walk.
	if usingReceipt && !boundaryResolved {
		return nil, prog, true, nil
	}
	// A deadline that lands after the last periodic check must not let the walk
	// report a verdict it did not finish under.
	if err := walkInterrupted(ctx); err != nil {
		return nil, prog, false, err
	}
	if pub != nil && !adopted && (headSig != "" || publicKeyFingerprintHex != "" || result.SignedEntries > 0) {
		// Signing artifacts remain but the adoption marker is gone — a genuine
		// inconsistency (a partial strip), so report it forged rather than a
		// downgraded unsigned pass. A COMPLETE strip leaves no artifacts here;
		// when the caller explicitly required signing that surfaces as the
		// distinct "suspect" state below (classifySigState), so a fully stripped
		// log is never a clean pass either.
		sigForged = true
		result.SigBrokenReason = "signing artifacts are present but the signing adoption marker is missing"
	}

	// Check chain_head consistency (hash layer)
	actualRowCount := result.EntriesVerified
	if rowCount != actualRowCount {
		result.Intact = false
		result.BrokenReason = fmt.Sprintf("chain_head row_count (%d) does not match actual events (%d)", rowCount, actualRowCount)
		return result, prog, false, nil
	}

	if headHash != prevHashHex {
		result.Intact = false
		result.BrokenReason = fmt.Sprintf("chain_head entry_hash mismatch (expected %s, got %s)", prevHashHex, headHash)
		return result, prog, false, nil
	}

	result.Intact = true

	// Verify the chain_head signature. Signing the head is what upgrades
	// tail-truncation resistance: an attacker rewriting the head in lockstep
	// still needs the key. The receipt never covers the head: it is always
	// re-checked here.
	if pub != nil && !sigForged && adopted {
		if headSig == "" {
			sigForged = true
			result.SigBrokenReason = "chain_head signature missing after signing adoption (stripped)"
		} else if !verifyHeadSig(pub, headHash, rowCount, headMeta, headSig) {
			sigForged = true
			result.SigBrokenReason = "chain_head signature does not verify against the key"
		}
	}

	result.SigState = classifySigState(pub, adopted, sigForged, result.SignedEntries, requireSigned)
	if result.SigState == "suspect" {
		result.SigBrokenReason = suspectSigReason
	}
	return result, prog, false, nil
}

// suspectSigReason explains the "suspect" state. It applies whether or not the
// log still has events: a log with zero rows and no adoption marker is exactly
// what a complete deletion leaves behind.
const suspectSigReason = "signed verification was required (an Ed25519 public key was explicitly supplied) but the log carries no signatures and no adoption markers; if this log was expected to be signed, its signatures may have been fully stripped or every row deleted. Distinguishing a never-signed log from a fully stripped one requires an external head anchor (scoped follow-on)."

// classifySigState maps the walk outcome to one of the distinct signature
// states, never conflating them.
//
// The "suspect" state closes a No-Silent-Success gap: a writer who clears EVERY
// signing artifact (all entry_sig, head_sig, signed_genesis_at,
// unsigned_through_id, signing_pubkey_fingerprint) makes an adopted, tampered
// log look never-adopted — on disk it is indistinguishable from a log that was
// legitimately never signed. When the caller EXPLICITLY required signing
// (requireSigned, i.e. an --ed25519-pub was supplied) and the log carries no
// signatures and no adoption markers, that is reported "suspect", never a
// clean pass. This holds regardless of how many events remain: deleting every
// row and resetting chain_head to genesis is a truncation to zero, and the
// signed head exists precisely so truncation cannot pass a required check. A
// merely derived key (from the local key file) is not an assertion about this
// particular log, so a genuinely unsigned log stays "unsigned". Telling a
// never-signed log apart from a fully stripped one cryptographically needs an
// external head anchor (scoped follow-on).
func classifySigState(pub ed25519.PublicKey, adopted, sigForged bool, signedEntries int, requireSigned bool) string {
	if sigForged {
		return "forged"
	}
	if pub == nil {
		if signedEntries > 0 {
			// Signatures exist but we cannot check them without the key —
			// never report this as authentic.
			return "unverified"
		}
		return "unsigned"
	}
	if !adopted {
		// A key is available but the log has no adoption marker (partial
		// artifacts are already "forged" above). If the caller explicitly
		// required signing, a full strip — or a complete deletion — is
		// indistinguishable from never-signed on disk, so report the honest,
		// non-clean "suspect" rather than passing.
		if requireSigned {
			return "suspect"
		}
		return "unsigned"
	}
	return "authentic"
}
