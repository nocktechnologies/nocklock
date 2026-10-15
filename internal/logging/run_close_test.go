package logging

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- helpers ----------
// dbPathOf lives in anchor_test.go.

// lifecycleStart builds a session_start that owes a close (carries lifecycle=1 in
// its signed detail, inside the egress-level envelope wrap uses).
func lifecycleStart(sid string) Event {
	e := sampleEvent(EventSessionStart, "session", `command="agent --flag" lifecycle=1`, false, sid)
	e.EgressLevel = "OFF"
	return e
}

func logOrFatal(t *testing.T, l *Logger, e Event) {
	t.Helper()
	if err := l.Log(e); err != nil {
		t.Fatalf("Log(%s): %v", e.EventType, err)
	}
}

// appendClosedRun writes a lifecycle run (start, two ordinary rows, end) under sid
// and returns before the close so the caller can close it.
func appendOpenRun(t *testing.T, l *Logger, sid string) {
	t.Helper()
	logOrFatal(t, l, lifecycleStart(sid))
	logOrFatal(t, l, sampleEvent(EventNetworkPassed, "network", "egress level=OFF", false, sid))
	logOrFatal(t, l, sampleEvent(EventFilePassed, "filesystem", "root=.", false, sid))
	logOrFatal(t, l, sampleEvent(EventSessionEnd, "session", "exit_code=0", false, sid))
}

// runStatusFor returns the lifecycle verdict for one session, failing if absent.
func runStatusFor(t *testing.T, l *Logger, sid string) RunStatus {
	t.Helper()
	runs, err := l.VerifyRuns(context.Background())
	if err != nil {
		t.Fatalf("VerifyRuns: %v", err)
	}
	for _, r := range runs {
		if r.SessionID == sid {
			return r
		}
	}
	t.Fatalf("run %s not enumerated; got %+v", sid, runs)
	return RunStatus{}
}

func wantStatus(t *testing.T, l *Logger, sid string, want RunLifecycleStatus) {
	t.Helper()
	got := runStatusFor(t, l, sid)
	if got.Status != want {
		t.Fatalf("run %s status = %q (%s), want %q", sid, got.Status, got.Reason, want)
	}
}

// independentRunRoot recomputes a run's rows/root over its surviving non-close
// rows with plain SHA-256, independent of the accumulator and verifier helpers,
// so it can cross-check the signed close binding.
func independentRunRoot(t *testing.T, dbPath, sid string) (root string, count int, firstID, lastID int64) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT id, timestamp, event_type, category, detail, blocked, session_id FROM events WHERE session_id = ? ORDER BY id ASC", sid)
	if err != nil {
		t.Fatalf("query run rows: %v", err)
	}
	defer rows.Close()

	seed := sha256.New()
	seed.Write([]byte("nocklock-run-close-v1"))
	seed.Write([]byte{0x00})
	seed.Write([]byte(sid))
	acc := seed.Sum(nil)

	for rows.Next() {
		var id int64
		var ts, et, cat, detail, s string
		var blocked int
		if err := rows.Scan(&id, &ts, &et, &cat, &detail, &blocked, &s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if EventType(et) == EventSessionClose {
			continue
		}
		cb := canonicalBytes(id, ts, EventType(et), cat, detail, blocked != 0, s)
		rowHash := sha256.Sum256(cb)
		h := sha256.New()
		h.Write(acc)
		h.Write(rowHash[:])
		acc = h.Sum(nil)
		if count == 0 {
			firstID = id
		}
		lastID = id
		count++
	}
	return hex.EncodeToString(acc), count, firstID, lastID
}

// closeDetailOf returns the parsed binding from a run's single session_close row.
func closeDetailOf(t *testing.T, dbPath, sid string) closeBinding {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var detail string
	if err := db.QueryRow("SELECT detail FROM events WHERE session_id = ? AND event_type = ? ORDER BY id DESC LIMIT 1", sid, string(EventSessionClose)).Scan(&detail); err != nil {
		t.Fatalf("read close detail: %v", err)
	}
	b, err := parseCloseDetail(detail)
	if err != nil {
		t.Fatalf("parse close detail %q: %v", detail, err)
	}
	return b
}

func deleteRowAndRechain(t *testing.T, dbPath string, id int64) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("DELETE FROM events WHERE id = ?", id); err != nil {
		t.Fatalf("delete row %d: %v", id, err)
	}
	rechainAll(t, db)
}

func rowID(t *testing.T, dbPath, sid string, et EventType) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var id int64
	if err := db.QueryRow("SELECT id FROM events WHERE session_id = ? AND event_type = ? ORDER BY id ASC LIMIT 1", sid, string(et)).Scan(&id); err != nil {
		t.Fatalf("find %s row for %s: %v", et, sid, err)
	}
	return id
}

// ---------- control 1: clean close ----------

func TestRunClose_CleanCloseVerifiesClosed(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)

	sid := "run-clean"
	appendOpenRun(t, l, sid)
	covered, err := l.CloseRun(sid, "clean")
	if err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	if covered != 4 {
		t.Fatalf("covered rows = %d, want 4 (start + 2 + end)", covered)
	}

	wantStatus(t, l, sid, RunClosed)

	// The signed binding must equal an independent recomputation (control 1).
	binding := closeDetailOf(t, dbPath, sid)
	root, count, first, last := independentRunRoot(t, dbPath, sid)
	if binding.rows != count || binding.root != root || binding.firstID != first || binding.lastID != last {
		t.Fatalf("signed binding {rows:%d root:%s first:%d last:%d} != independent {rows:%d root:%s first:%d last:%d}",
			binding.rows, binding.root, binding.firstID, binding.lastID, count, root, first, last)
	}
	if binding.end != "clean" {
		t.Fatalf("close end = %q, want clean", binding.end)
	}
}

// ---------- control 5: two interleaved runs ----------

func TestRunClose_TwoInterleavedRunsBothClosed(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)

	a, b := "run-a", "run-b"
	logOrFatal(t, l, lifecycleStart(a))
	logOrFatal(t, l, lifecycleStart(b))
	logOrFatal(t, l, sampleEvent(EventNetworkPassed, "network", "a1", false, a))
	logOrFatal(t, l, sampleEvent(EventNetworkPassed, "network", "b1", false, b))
	logOrFatal(t, l, sampleEvent(EventSessionEnd, "session", "exit_code=0", false, a))
	logOrFatal(t, l, sampleEvent(EventSessionEnd, "session", "exit_code=0", false, b))
	if _, err := l.CloseRun(a, "clean"); err != nil {
		t.Fatalf("CloseRun a: %v", err)
	}
	if _, err := l.CloseRun(b, "clean"); err != nil {
		t.Fatalf("CloseRun b: %v", err)
	}

	wantStatus(t, l, a, RunClosed)
	wantStatus(t, l, b, RunClosed)

	// Each root must cover only its own run's rows.
	ba := closeDetailOf(t, dbPath, a)
	bb := closeDetailOf(t, dbPath, b)
	if ba.root == bb.root {
		t.Fatal("interleaved runs share a root; each must cover only its own rows")
	}
}

// ---------- control 4 / 22: rows after close ----------

func TestRunClose_RowAfterCloseIsRowsAfterClose(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-extra"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	// A late row under the same session id lands after the close.
	logOrFatal(t, l, sampleEvent(EventNetworkPassed, "network", "late", false, sid))
	wantStatus(t, l, sid, RunRowsAfterClose)
}

func TestRunClose_TwoClosesIsRowsAfterClose(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-double"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	// A second close row written directly (the accumulator is already gone, so
	// CloseRun would refuse; this models a duplicate close reaching the chain).
	logOrFatal(t, l, Event{Timestamp: time.Now(), EventType: EventSessionClose, Category: "session", Detail: "close=1 session=run-double first_id=1 last_id=4 rows=4 root=" + fmt.Sprintf("%064x", 0) + " end=clean", SessionID: sid})
	wantStatus(t, l, sid, RunRowsAfterClose)
}

// ---------- control 2 / 3 / 17 / 18: close_mismatch without a prune ----------

func TestRunClose_EditedRowNoPruneIsCloseMismatch(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)
	sid := "run-edit"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	target := rowID(t, dbPath, sid, EventFilePassed)
	tamperRowAndRechain(t, dbPath, target, "root=/tampered")
	wantStatus(t, l, sid, RunCloseMismatch)
}

func TestRunClose_RemovedRowNoPruneIsCloseMismatch(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)
	sid := "run-remove"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	deleteRowAndRechain(t, dbPath, rowID(t, dbPath, sid, EventFilePassed))
	wantStatus(t, l, sid, RunCloseMismatch)
}

func TestRunClose_StartRemovedNoPruneIsCloseMismatch(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)
	sid := "run-nostart"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	// Remove only the session_start, re-sign; the close survives with no start and
	// no prune to explain the difference.
	deleteRowAndRechain(t, dbPath, rowID(t, dbPath, sid, EventSessionStart))
	wantStatus(t, l, sid, RunCloseMismatch)
}

func TestRunClose_PreStartRowDeletedNoPruneIsCloseMismatch(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)
	sid := "run-predigest"
	// A pre-start config-digest row makes first_id precede the start row.
	logOrFatal(t, l, sampleEvent(EventConfigDigest, "session", "digest=abc", false, sid))
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	wantStatus(t, l, sid, RunClosed) // verifies closed before the deletion
	deleteRowAndRechain(t, dbPath, rowID(t, dbPath, sid, EventConfigDigest))
	wantStatus(t, l, sid, RunCloseMismatch) // pruned_at unset distinguishes this from a prune
}

// ---------- control 11 / 19 / 20 / 21 / 23: prune interactions ----------

func TestRunClose_PrunedStartSurvivesIsPruned(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)
	sid := "run-prune-prestart"
	// Pre-start config-digest row is old; the start and the rest are recent.
	digest := sampleEvent(EventConfigDigest, "session", "digest=old", false, sid)
	digest.Timestamp = time.Now().Add(-48 * time.Hour)
	logOrFatal(t, l, digest)
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	if n, err := l.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("Prune removed %d (err %v), want 1 (the old digest)", n, err)
	}
	// The run is found via its surviving start row; recomputed values differ under
	// a recorded prune — pruned, not close_mismatch.
	wantStatus(t, l, sid, RunPruned)
	_ = dbPath
}

func TestRunClose_PrunedCloseOnlySurvivesIsPruned(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-prune-closeonly"
	// Every pre-close row is old; the close (written now) postdates the cutoff.
	start := lifecycleStart(sid)
	start.Timestamp = time.Now().Add(-48 * time.Hour)
	logOrFatal(t, l, start)
	mid := sampleEvent(EventNetworkPassed, "network", "old", false, sid)
	mid.Timestamp = time.Now().Add(-48 * time.Hour)
	logOrFatal(t, l, mid)
	end := sampleEvent(EventSessionEnd, "session", "exit_code=0", false, sid)
	end.Timestamp = time.Now().Add(-48 * time.Hour)
	logOrFatal(t, l, end)
	// A recent unrelated row keeps the chain non-empty after the prune.
	logOrFatal(t, l, sampleEvent(EventConfigLoaded, "session", "keep", false, "other"))
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	if n, err := l.Prune(24 * time.Hour); err != nil || n != 3 {
		t.Fatalf("Prune removed %d (err %v), want 3 (the run's pre-close rows)", n, err)
	}
	// Found by its close alone, every non-close row gone: pruned.
	wantStatus(t, l, sid, RunPruned)
}

func TestRunClose_PrunedMiddleRowIsPruned(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-prune-middle"
	// Out-of-order timestamps: a middle row is older than first and last.
	start := lifecycleStart(sid)
	start.Timestamp = time.Now().Add(-1 * time.Hour)
	logOrFatal(t, l, start)
	mid := sampleEvent(EventFilePassed, "filesystem", "middle", false, sid)
	mid.Timestamp = time.Now().Add(-48 * time.Hour)
	logOrFatal(t, l, mid)
	end := sampleEvent(EventSessionEnd, "session", "exit_code=0", false, sid)
	end.Timestamp = time.Now()
	logOrFatal(t, l, end)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	if n, err := l.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("Prune removed %d (err %v), want 1 (the middle row)", n, err)
	}
	wantStatus(t, l, sid, RunPruned)
}

func TestRunClose_PruneWhileOpenIsPruned(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-prune-open"
	digest := sampleEvent(EventConfigDigest, "session", "digest=old", false, sid)
	digest.Timestamp = time.Now().Add(-48 * time.Hour)
	logOrFatal(t, l, digest)
	appendOpenRun(t, l, sid)
	// Prune the old pre-start row while the run is still open (before the close).
	if n, err := l.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("Prune removed %d (err %v), want 1", n, err)
	}
	// The accumulator still covers the pruned row, so the close signs rows/root
	// that include it; recompute over survivors differs — pruned, never closed.
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	wantStatus(t, l, sid, RunPruned)
}

func TestRunClose_EditEqualCountUnderPruneIsCloseMismatch(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)
	sid := "run-prune-edit"
	// An old throwaway row the prune removes (to set pruned_at), plus a fully
	// recent run that survives intact.
	old := sampleEvent(EventConfigLoaded, "session", "old", false, "other")
	old.Timestamp = time.Now().Add(-48 * time.Hour)
	logOrFatal(t, l, old)
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	if n, err := l.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("Prune removed %d (err %v), want 1", n, err)
	}
	// Edit a surviving run row without removing any: count stays equal to the
	// signed rows while the root differs — a prune cannot explain that.
	tamperRowAndRechain(t, dbPath, rowID(t, dbPath, sid, EventFilePassed), "root=/tampered")
	wantStatus(t, l, sid, RunCloseMismatch)
}

// ---------- control 6 / 8: unclosed ----------

func TestRunClose_KilledWriterIsUnclosed(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	sid := "run-killed"
	appendOpenRun(t, l, sid) // writer dies before CloseRun
	wantStatus(t, l, sid, RunUnclosed)
	// The chain itself stays intact.
	res, err := l.VerifyChainSigned(pub, false)
	if err != nil || !res.Intact {
		t.Fatalf("chain should stay intact for an unclosed run: intact=%v err=%v", res.Intact, err)
	}
}

func TestRunClose_TruncatedTailIsUnclosed(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	dbPath := dbPathOf(t, l)
	sid := "run-truncated"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	wantStatus(t, l, sid, RunClosed)
	// Truncate the close (the tail) and re-chain: the run reads unclosed again,
	// chain intact.
	deleteRowAndRechain(t, dbPath, rowID(t, dbPath, sid, EventSessionClose))
	wantStatus(t, l, sid, RunUnclosed)
}

// ---------- control 9: legacy ----------

func TestRunClose_LegacyRunNoLifecycle(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-legacy"
	// A session_start without lifecycle=1 and no close: a pre-contract run.
	logOrFatal(t, l, sampleEvent(EventSessionStart, "session", `command="old"`, false, sid))
	logOrFatal(t, l, sampleEvent(EventSessionEnd, "session", "exit_code=0", false, sid))
	wantStatus(t, l, sid, RunLegacy)
}

func TestRunClose_StartWithoutLifecycleButCloseIsCloseMismatch(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-nolifecycle-close"
	logOrFatal(t, l, sampleEvent(EventSessionStart, "session", `command="old"`, false, sid))
	logOrFatal(t, l, sampleEvent(EventSessionEnd, "session", "exit_code=0", false, sid))
	// The accumulator exists (rows were folded), so a close can be written even
	// though the start lacked lifecycle=1 — a contradiction the verifier flags.
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	wantStatus(t, l, sid, RunCloseMismatch)
}

// ---------- control 24: an old verifier accepts close rows ----------

func TestRunClose_OldVerifierAcceptsCloseRows(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	sid := "run-compat"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	// A chain-only verifier (unaware of close semantics) must still see the chain
	// as intact and authentic — session_close is an ordinary signed row.
	res, err := l.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !res.Intact || res.SigState != "authentic" {
		t.Fatalf("chain with close rows: intact=%v sig=%q, want intact authentic", res.Intact, res.SigState)
	}
}

// ---------- control 7: a failed close is loud and leaves the run unclosed ----------

func TestRunClose_FailedCloseIsUnclosedAndReportsCoverage(t *testing.T) {
	l, keyPath, _ := newSigningLogger(t)
	dbPath := dbPathOf(t, l)
	sid := "run-failclose"
	appendOpenRun(t, l, sid)

	// Force the close append to fail by closing the database first; the writer
	// must surface the error (so wrap can warn) and still report how much of the
	// run it had covered.
	if err := l.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	covered, err := l.CloseRun(sid, "clean")
	if err == nil {
		t.Fatal("CloseRun on a closed database should fail, got nil")
	}
	if covered != 4 {
		t.Fatalf("covered rows reported = %d, want 4", covered)
	}

	// Reopened, the run has no close row and reads unclosed.
	l2, err := NewLogger(dbPath, "", WithSigning(keyPath))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	wantStatus(t, l2, sid, RunUnclosed)
}

func TestRunClose_CloseRunOnceThenNotTracked(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-once"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("first CloseRun: %v", err)
	}
	// The accumulator entry is dropped on success: a second close finds no run and
	// writes nothing (no retry).
	if _, err := l.CloseRun(sid, "clean"); !errors.Is(err, ErrRunNotTracked) {
		t.Fatalf("second CloseRun err = %v, want ErrRunNotTracked", err)
	}
	// A session the logger never saw is also not tracked.
	if _, err := l.CloseRun("never", "clean"); !errors.Is(err, ErrRunNotTracked) {
		t.Fatalf("unknown-run CloseRun err = %v, want ErrRunNotTracked", err)
	}
}

// ---------- VerifyRuns honours its context ----------

func TestRunClose_VerifyRunsHonoursContext(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	sid := "run-ctx"
	appendOpenRun(t, l, sid)
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.VerifyRuns(ctx); !errors.Is(err, ErrVerifyInterrupted) {
		t.Fatalf("VerifyRuns on a cancelled context err = %v, want ErrVerifyInterrupted", err)
	}
}

// ---------- control 26: two producers serialize through one critical section ----------

func TestRunClose_ConcurrentProducersReadClosed(t *testing.T) {
	// Build a logger with the commit→fold seam instrumented: the hook runs under
	// the logger mutex, so no two appends may be inside it at once.
	var inCritical atomic.Int32
	var raced atomic.Bool
	hookDir := t.TempDir()
	key := hookDir + "/audit.key"
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	l, err := NewLogger(hookDir+"/events.db", hookDir, WithSigning(key), withAfterCommit(func() {
		if inCritical.Add(1) != 1 {
			raced.Store(true)
		}
		time.Sleep(time.Millisecond)
		inCritical.Add(-1)
	}))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	sid := "run-concurrent"
	logOrFatal(t, l, lifecycleStart(sid))

	const producers = 8
	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if err := l.Log(sampleEvent(EventNetworkPassed, "network", fmt.Sprintf("p%d", n), false, sid)); err != nil {
				t.Errorf("concurrent Log: %v", err)
			}
		}(i)
	}
	wg.Wait()
	logOrFatal(t, l, sampleEvent(EventSessionEnd, "session", "exit_code=0", false, sid))
	if _, err := l.CloseRun(sid, "clean"); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	if raced.Load() {
		t.Fatal("two appends entered the commit→fold critical section at once; the mutex did not serialize them")
	}
	wantStatus(t, l, sid, RunClosed)

	dbPath := dbPathOf(t, l)
	binding := closeDetailOf(t, dbPath, sid)
	root, count, _, _ := independentRunRoot(t, dbPath, sid)
	if binding.rows != count || binding.root != root {
		t.Fatalf("concurrent appends corrupted the accumulator: signed {rows:%d root:%s} != recomputed {rows:%d root:%s}",
			binding.rows, binding.root, count, root)
	}
}
