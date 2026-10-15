package logging

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// runCloseRootDomain seeds a run's rolling close root. It is a distinct domain
// label from the row and head signatures so a run commitment can never be
// confused with a chain hash. See docs/design/run-lifecycle-contract.md ("Root").
const runCloseRootDomain = "nocklock-run-close-v1"

// ErrRunNotTracked is returned by CloseRun when the logger holds no accumulator
// for the session. That happens when the run never committed a row, when the
// process restarted (the in-memory accumulator is lost and nothing rescans the
// database to rebuild it), or when the run was already closed. In every case the
// run reads unclosed; the writer must not fabricate a close.
var ErrRunNotTracked = errors.New("run not tracked by this logger (never started, already closed, or lost to a restart)")

// runAccumulator is the per-session_id rolling commitment advanced under the
// logger mutex as each of the run's rows commits. It is bounded to a counter and
// a 32-byte root, never raw row bytes, so a long-lived run cannot grow it.
//
// Invariant (docs/design/run-lifecycle-contract.md, "Who writes a run's rows"):
// every row carrying a run's session_id is appended through the one Logger that
// also calls CloseRun. A run's session_id is a UUID minted once per wrap process
// and shared in-process with every producer (the network proxy and its look-back
// rules, the egress decision-log scanner, the macOS denial tailer, the
// config-digest recorder, the secret preflight) — each constructed with that
// same *Logger. No re-exec'd helper (__netns-*, __landlock-exec) and no other
// nocklock subcommand opens a second Logger that writes under an in-flight run's
// id; the hidden helpers hold no Logger at all. Because the accumulator is
// instance-local, this is the property that lets the close sign exactly the rows
// an id-ordered recompute later sees. A future out-of-process producer would
// have to receive the session_id in-process and join teardown before the close,
// or the run would read close_mismatch — so new producers must route through
// this Logger, not a fresh one.
type runAccumulator struct {
	firstID int64    // id of the run's first committed row
	lastID  int64    // id of the run's most recent committed row (close excluded)
	count   int      // number of the run's rows folded so far (close excluded)
	root    [32]byte // rolling digest over those rows' canonical bytes
}

// seedRunRoot computes R_0 = SHA-256(runCloseRootDomain || 0x00 || session_id).
func seedRunRoot(sessionID string) [32]byte {
	h := sha256.New()
	h.Write([]byte(runCloseRootDomain))
	h.Write([]byte{0x00})
	h.Write([]byte(sessionID))
	var root [32]byte
	copy(root[:], h.Sum(nil))
	return root
}

// advanceRunRoot computes R_i = SHA-256(R_{i-1} || SHA-256(canonical_bytes_i)).
func advanceRunRoot(prev [32]byte, canonical []byte) [32]byte {
	return advanceRunRootHashed(prev, sha256.Sum256(canonical))
}

// advanceRunRootHashed folds a row whose canonical-bytes hash is already known,
// so the verifier can keep one 32-byte digest per row instead of the full
// canonical bytes.
func advanceRunRootHashed(prev, rowHash [32]byte) [32]byte {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(rowHash[:])
	var next [32]byte
	copy(next[:], h.Sum(nil))
	return next
}

// foldRun advances the accumulator for sessionID with one committed row. The
// caller must hold l.mu. Rows with no session_id are not part of any run, and a
// session_close row is excluded from its own run's commitment (the close signs
// first_id..last_id, close excluded), so both are skipped.
func (l *Logger) foldRun(sessionID string, eventType EventType, id int64, canonical []byte) {
	if sessionID == "" || eventType == EventSessionClose {
		return
	}
	acc := l.accumulators[sessionID]
	if acc == nil {
		acc = &runAccumulator{firstID: id, root: seedRunRoot(sessionID)}
		l.accumulators[sessionID] = acc
	}
	acc.root = advanceRunRoot(acc.root, canonical)
	acc.count++
	acc.lastID = id
}

// CloseRun writes the signed session_close row binding the run's extent
// (first_id, last_id, rows, root) as accumulated during the run's appends. end is
// the writer's own reason the run ended (clean, child_exit, refused,
// audit_failed) and is informational. The accumulator read and the close append
// share one critical section under l.mu, so the close can never sign a fold that
// is still in progress.
//
// It returns the number of the run's rows the writer had covered (the close
// excluded) so a failed close can be reported with that coverage. The close is
// written exactly once: on success the accumulator entry is dropped, so a second
// call returns ErrRunNotTracked and writes nothing.
func (l *Logger) CloseRun(sessionID, end string) (coveredRows int, err error) {
	l.mu.Lock()
	acc := l.accumulators[sessionID]
	if acc == nil {
		l.mu.Unlock()
		return 0, ErrRunNotTracked
	}
	coveredRows = acc.count
	event := Event{
		Timestamp: time.Now(),
		EventType: EventSessionClose,
		Category:  "session",
		Detail:    formatCloseDetail(sessionID, acc, end),
		SessionID: sessionID,
	}
	hash, appendErr := l.appendLocked(&event)
	if appendErr != nil {
		l.mu.Unlock()
		return coveredRows, appendErr
	}
	delete(l.accumulators, sessionID)
	l.mu.Unlock()
	if l.onCommit != nil {
		l.onCommit(event, hash)
	}
	return coveredRows, nil
}

// formatCloseDetail renders the session_close detail as whitespace-free key=value
// fields. All values (a UUID session id, decimal counts, a hex root, and a bare
// end token) contain no spaces, so the verifier parses them by splitting on
// whitespace.
func formatCloseDetail(sessionID string, acc *runAccumulator, end string) string {
	return fmt.Sprintf("close=1 session=%s first_id=%d last_id=%d rows=%d root=%x end=%s",
		sessionID, acc.firstID, acc.lastID, acc.count, acc.root[:], end)
}

// closeBinding holds the signed values parsed from a session_close row's detail.
type closeBinding struct {
	firstID int64
	lastID  int64
	rows    int
	root    string // 64-hex
	end     string
}

// parseCloseDetail parses a session_close detail string. A malformed detail is an
// error; the caller treats that run as close_mismatch (a close row the verifier
// cannot read is not a clean close).
func parseCloseDetail(detail string) (closeBinding, error) {
	var b closeBinding
	fields := map[string]string{}
	for _, tok := range strings.Fields(detail) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		fields[k] = v
	}
	if fields["close"] != "1" {
		return b, fmt.Errorf("session_close detail missing close=1")
	}
	var err error
	if b.firstID, err = strconv.ParseInt(fields["first_id"], 10, 64); err != nil {
		return b, fmt.Errorf("session_close first_id: %w", err)
	}
	if b.lastID, err = strconv.ParseInt(fields["last_id"], 10, 64); err != nil {
		return b, fmt.Errorf("session_close last_id: %w", err)
	}
	if b.rows, err = strconv.Atoi(fields["rows"]); err != nil {
		return b, fmt.Errorf("session_close rows: %w", err)
	}
	b.root = fields["root"]
	if len(b.root) != 64 {
		return b, fmt.Errorf("session_close root must be 64 hex chars, got %d", len(b.root))
	}
	b.end = fields["end"]
	return b, nil
}

// sessionStartOwesClose reports whether a decoded session_start detail carries
// the lifecycle=1 marker, meaning the run owes a session_close. The leading
// command= value is Go-quoted, so it is skipped before scanning the trailing
// key=value fields: a lifecycle=1 substring inside the quoted command must never
// be mistaken for the real field (the same forgery the quoting defends against in
// sessionStartDetail).
func sessionStartOwesClose(innerDetail string) bool {
	rest := innerDetail
	const prefix = "command="
	if strings.HasPrefix(rest, prefix) {
		after := rest[len(prefix):]
		if len(after) > 0 && after[0] == '"' {
			if quoted, err := strconv.QuotedPrefix(after); err == nil {
				rest = after[len(quoted):]
			}
		}
	}
	for _, field := range strings.Fields(rest) {
		if field == "lifecycle=1" {
			return true
		}
	}
	return false
}

// RunLifecycleStatus is the verifier's verdict for one run's lifecycle.
type RunLifecycleStatus string

const (
	// RunClosed: a single session_close whose recomputed values match the signed
	// ones, with no later row carrying the run's session_id.
	RunClosed RunLifecycleStatus = "closed"
	// RunUnclosed: a run whose signed session_start says it owes a close, but none
	// is present. Neutral: a crash, a kill, or a failed close all look identical.
	RunUnclosed RunLifecycleStatus = "unclosed"
	// RunPruned: a recomputed value differs from the signed one, pruned_at is set,
	// and the two post-prune checks pass — a legitimate prune, neutral.
	RunPruned RunLifecycleStatus = "pruned"
	// RunCloseMismatch: a recomputed value differs with no prune to explain it (or
	// a post-prune check fails). A failure regardless of --require-closed.
	RunCloseMismatch RunLifecycleStatus = "close_mismatch"
	// RunRowsAfterClose: a row carrying the run's session_id after its close, or a
	// second close. A failure regardless of --require-closed.
	RunRowsAfterClose RunLifecycleStatus = "rows_after_close"
	// RunLegacy: a run with a session_start lacking lifecycle=1 and no close,
	// written before this contract. Never a failure.
	RunLegacy RunLifecycleStatus = "legacy"
)

// Failure reports whether a status is a tamper verdict that fails verification
// regardless of --require-closed.
func (s RunLifecycleStatus) Failure() bool {
	return s == RunCloseMismatch || s == RunRowsAfterClose
}

// RunStatus is the lifecycle verdict for a single run.
type RunStatus struct {
	SessionID string
	Status    RunLifecycleStatus
	Reason    string // human-readable explanation, for operator output
}

// rawRunRow is a surviving row of a run, carrying the hash of its canonical bytes
// (bounded to 32 bytes, not the full row) needed to recompute the run's root from
// stored data, plus the raw detail for session_start/session_close inspection.
type rawRunRow struct {
	id        int64
	eventType EventType
	detail    string   // raw stored detail column
	rowHash   [32]byte // SHA-256 of the row's canonical bytes
}

// verifyRunsCtxInterval bounds how often VerifyRuns checks its context, matching
// the chain walk's 1,024-row cadence.
const verifyRunsCtxInterval = 1024

// VerifyRuns enumerates every run in the chain and reports its lifecycle status.
// A run is found by a session_start row (whose signed detail is inspected for
// lifecycle=1) or by a session_close row whose session has no surviving start.
// Statuses are returned in each run's first-seen id order. The scan reads the raw
// detail column (never the decoded envelope) so the per-run root matches what the
// writer folded at append time. ctx bounds the whole pass — the scan, the
// per-run classification and the root recomputation — the same way --walk-timeout
// bounds the chain walk; when it ends the pass returns ErrVerifyInterrupted and
// no statuses, never a verdict.
//
// The prune boundary and the event scan are read on one reserved connection
// inside a single deferred read transaction, so a concurrent prune cannot land
// between the two reads and make an honest run look like close_mismatch.
func (l *Logger) VerifyRuns(ctx context.Context) ([]RunStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, verifyInterrupted(ctx, fmt.Errorf("failed to open run-verification snapshot: %w", err))
	}
	defer tx.Rollback() // read-only: nothing to commit

	pruned, err := chainPruned(ctx, tx)
	if err != nil {
		// A deadline that expires during the prune-boundary read is a neutral
		// interrupt, not a hard failure — same convention as the scan and BeginTx.
		return nil, verifyInterrupted(ctx, err)
	}
	order, runs, err := scanRuns(ctx, tx)
	if err != nil {
		return nil, err
	}
	// lastIDOwner resolves a single id's session on the same snapshot, used only
	// for the post-prune last_id ownership check. A point lookup replaces an
	// every-row id→session map, so verify does not retain a session-id string per
	// row. A genuinely missing row (pruned away) returns ok=false so the check is
	// skipped; any other error — a dead context or a transient read failure — is
	// returned, never swallowed, so a tamper check that cannot complete is not
	// silently downgraded to a neutral pass.
	lastIDOwner := func(id int64) (string, bool, error) {
		var sid string
		err := tx.QueryRowContext(ctx, "SELECT session_id FROM events WHERE id = ?", id).Scan(&sid)
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		return sid, true, nil
	}
	return classifyRuns(ctx, order, runs, pruned, lastIDOwner)
}

// scanRuns streams the chain once in id order, grouping surviving rows by
// session_id. Each row keeps only the 32-byte hash of its canonical bytes;
// the raw detail column is retained only for session_start and session_close
// rows, the only types whose detail the verifier parses, so a large store does
// not hold every row's full detail text in memory. ctx is checked on the same
// cadence as the chain walk.
func scanRuns(ctx context.Context, tx *sql.Tx) (order []string, runs map[string][]rawRunRow, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events ORDER BY id ASC")
	if err != nil {
		return nil, nil, verifyInterrupted(ctx, fmt.Errorf("failed to read events for run verification: %w", err))
	}
	defer rows.Close()

	runs = map[string][]rawRunRow{}
	seen := map[string]bool{}
	scanned := 0
	for rows.Next() {
		if scanned%verifyRunsCtxInterval == 0 {
			if err := walkInterrupted(ctx); err != nil {
				return nil, nil, err
			}
		}
		scanned++
		var id int64
		var ts, etStr, cat, detail, sid string
		var blocked int
		if err := rows.Scan(&id, &ts, &etStr, &cat, &detail, &blocked, &sid); err != nil {
			return nil, nil, fmt.Errorf("failed to scan event for run verification: %w", err)
		}
		if sid == "" {
			continue
		}
		et := EventType(etStr)
		cb := canonicalBytes(id, ts, et, cat, detail, blocked != 0, sid)
		keptDetail := ""
		if et == EventSessionStart || et == EventSessionClose {
			keptDetail = detail
		}
		runs[sid] = append(runs[sid], rawRunRow{id: id, eventType: et, detail: keptDetail, rowHash: sha256.Sum256(cb)})
		if !seen[sid] {
			seen[sid] = true
			order = append(order, sid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, verifyInterrupted(ctx, fmt.Errorf("error iterating events for run verification: %w", err))
	}
	return order, runs, nil
}

// classifyRuns classifies every enumerated run in first-seen id order, checking
// ctx before each run and once more before returning so --walk-timeout bounds
// this phase too (the SQL scan already bounded its own phase). Runs are far fewer
// than rows, so the per-run check is cheap and need not be throttled. It returns
// ErrVerifyInterrupted with no statuses when the context ends at any point —
// including mid-classification, which the final check catches — so a deadline
// never yields a partial or post-deadline verdict. A classification error that
// coincides with a dead context is reported as the neutral interrupt; a genuine
// read error with a live context stays a hard failure (a tamper check that cannot
// complete is never treated as a pass).
func classifyRuns(ctx context.Context, order []string, runs map[string][]rawRunRow, pruned bool, lastIDOwner func(int64) (string, bool, error)) ([]RunStatus, error) {
	statuses := make([]RunStatus, 0, len(order))
	for _, sid := range order {
		if err := walkInterrupted(ctx); err != nil {
			return nil, err
		}
		st, ok, err := classifyRun(ctx, sid, runs[sid], pruned, lastIDOwner)
		if err != nil {
			return nil, verifyInterrupted(ctx, err)
		}
		if ok {
			statuses = append(statuses, st)
		}
	}
	if err := walkInterrupted(ctx); err != nil {
		return nil, err
	}
	return statuses, nil
}

// chainPruned reports whether chain_head records a prune boundary (pruned_at set),
// read on the caller's snapshot transaction.
func chainPruned(ctx context.Context, tx *sql.Tx) (bool, error) {
	var prunedAt sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT pruned_at FROM chain_head WHERE id = 1").Scan(&prunedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read chain prune boundary: %w", err)
	}
	return prunedAt.Valid, nil
}

// classifyRun computes one run's lifecycle status. ok is false when the session
// is not an enumerable run (rows carrying a session_id but neither a
// session_start nor a session_close — not a run, so no status describes it). It
// returns ErrVerifyInterrupted if ctx ends while recomputing a large run's root.
func classifyRun(ctx context.Context, sid string, rrs []rawRunRow, pruned bool, lastIDOwner func(int64) (string, bool, error)) (RunStatus, bool, error) {
	var closeRows []rawRunRow
	var nonClose []rawRunRow
	sawStart := false
	startHasLifecycle := false
	for _, r := range rrs {
		switch r.eventType {
		case EventSessionClose:
			closeRows = append(closeRows, r)
		case EventSessionStart:
			sawStart = true
			inner, _ := decodeEventDetail(EventSessionStart, r.detail)
			// OR across starts: if any session_start of this run owes a close,
			// the run owes one — a later start that lacked lifecycle=1 must not
			// clear the obligation an earlier one recorded.
			startHasLifecycle = startHasLifecycle || sessionStartOwesClose(inner)
			nonClose = append(nonClose, r)
		default:
			nonClose = append(nonClose, r)
		}
	}

	// rows_after_close outranks every other verdict: a second close, or any
	// ordinary row after the close, regardless of what the rest would read.
	if len(closeRows) >= 2 {
		return RunStatus{sid, RunRowsAfterClose, "more than one session_close row"}, true, nil
	}
	if len(closeRows) == 1 {
		closeID := closeRows[0].id
		for _, r := range nonClose {
			if r.id > closeID {
				return RunStatus{sid, RunRowsAfterClose, fmt.Sprintf("row %d carries the run's session_id after its close (row %d)", r.id, closeID)}, true, nil
			}
		}
		st, err := classifyClosedRun(ctx, sid, closeRows[0], nonClose, sawStart, startHasLifecycle, pruned, lastIDOwner)
		if err != nil {
			return RunStatus{}, false, err
		}
		return st, true, nil
	}

	// No close row.
	if !sawStart {
		// Rows carrying a session_id but no start and no close are not an
		// enumerable run (e.g. a config-digest row left by a process that exited
		// before session_start). No lifecycle status describes them.
		return RunStatus{}, false, nil
	}
	if startHasLifecycle {
		return RunStatus{sid, RunUnclosed, "session_start owes a close (lifecycle=1) but none was written"}, true, nil
	}
	return RunStatus{sid, RunLegacy, "session_start predates the close contract (no lifecycle=1)"}, true, nil
}

// classifyClosedRun handles a run with exactly one session_close and no row after
// it. It recomputes the run's commitment from the surviving non-close rows and
// compares it to the signed binding. It returns ErrVerifyInterrupted if ctx ends
// during the recomputation.
func classifyClosedRun(ctx context.Context, sid string, closeRow rawRunRow, nonClose []rawRunRow, sawStart, startHasLifecycle, pruned bool, lastIDOwner func(int64) (string, bool, error)) (RunStatus, error) {
	binding, err := parseCloseDetail(closeRow.detail)
	if err != nil {
		return RunStatus{sid, RunCloseMismatch, "unparseable session_close detail: " + err.Error()}, nil
	}
	// A close row is itself the writer's statement that the run owed a close, so a
	// surviving start that says it did not (no lifecycle=1) is a contradiction:
	// close_mismatch, not legacy.
	if sawStart && !startHasLifecycle {
		return RunStatus{sid, RunCloseMismatch, "session_close present on a run whose session_start lacks lifecycle=1"}, nil
	}

	recRoot, recFirst, recLast, err := recomputeRun(ctx, sid, nonClose)
	if err != nil {
		return RunStatus{}, err
	}
	if len(nonClose) == binding.rows && recRoot == binding.root && recFirst == binding.firstID && recLast == binding.lastID {
		return RunStatus{sid, RunClosed, "recomputed rows and root equal the signed binding"}, nil
	}

	if pruned {
		consistent, err := postPruneConsistent(sid, binding, len(nonClose), lastIDOwner)
		if err != nil {
			return RunStatus{}, err
		}
		if consistent {
			return RunStatus{sid, RunPruned, "recomputed values differ under a recorded prune; post-prune checks pass"}, nil
		}
	}
	return RunStatus{sid, RunCloseMismatch, "recomputed rows or root differ from the signed binding with no prune to explain it"}, nil
}

// recomputeRun folds the surviving non-close rows of a run in id order, returning
// the recomputed root, first id and last id (the row count is just len(nonClose),
// which the caller already has). The input is already in ascending id order
// (scanRuns reads ORDER BY id ASC). ctx is checked on the same cadence as the
// chain walk so a single very large run cannot outrun --walk-timeout.
func recomputeRun(ctx context.Context, sid string, nonClose []rawRunRow) (root string, firstID, lastID int64, err error) {
	acc := seedRunRoot(sid)
	for i, r := range nonClose {
		if i%verifyRunsCtxInterval == 0 {
			if err := walkInterrupted(ctx); err != nil {
				return "", 0, 0, err
			}
		}
		acc = advanceRunRootHashed(acc, r.rowHash)
		if i == 0 {
			firstID = r.id
		}
		lastID = r.id
	}
	return fmt.Sprintf("%x", acc[:]), firstID, lastID, nil
}

// postPruneConsistent runs the two narrower checks that a legitimate prune cannot
// fail, used only when a recomputed value already differs and pruned_at is set.
// See docs/design/run-lifecycle-contract.md ("Limits").
func postPruneConsistent(sessionID string, binding closeBinding, survivingCount int, lastIDOwner func(int64) (string, bool, error)) (bool, error) {
	// Row-count check (always applies): a prune only ever removes rows, so the
	// surviving non-close count cannot exceed the signed rows.
	if survivingCount > binding.rows {
		return false, nil
	}
	// If the count is unchanged while a recomputed value still differs, a prune
	// cannot explain it (a prune would have lowered the count) — this catches an
	// edited, re-signed row that would otherwise read as a legitimate prune.
	if survivingCount == binding.rows {
		return false, nil
	}
	// last_id check (conditional): if the row at the signed last_id still exists,
	// it must still carry this run's session_id. If that row was itself pruned
	// away, the check is skipped and the verdict rests on the row-count check. A
	// lookup error is propagated, never read as a skip, so the check fails closed.
	owner, ok, err := lastIDOwner(binding.lastID)
	if err != nil {
		return false, err
	}
	if ok && owner != sessionID {
		return false, nil
	}
	return true, nil
}
