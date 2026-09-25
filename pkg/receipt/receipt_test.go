package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

const (
	sessA = "session-a"
	sessB = "session-b"

	// testKeyFile names the throwaway signing key each test generates.
	testKeyFile = "audit.key"
)

// buildSignedDB writes an interleaved two-session log through the real signing
// Logger and returns the DB path and the public key. Row ids: 1=A, 2=B, 3=A,
// 4=A, 5=B. The hash link runs across both sessions.
func buildSignedDB(t *testing.T, dir string) (string, ed25519.PublicKey) {
	t.Helper()
	dbPath := filepath.Join(dir, "events.db")
	keyPath := filepath.Join(dir, "keys", testKeyFile)
	writeSessions(t, dbPath, keyPath, time.Now())
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatalf("load public key: %v", err)
	}
	return dbPath, pub
}

func writeSessions(t *testing.T, dbPath, keyPath string, base time.Time) {
	t.Helper()
	var opts []logging.Option
	if keyPath != "" {
		opts = append(opts, logging.WithSigning(keyPath))
	}
	l, err := logging.NewLogger(dbPath, "", opts...)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	seq := []struct {
		sid string
		et  logging.EventType
		det string
	}{
		{sessA, logging.EventSessionStart, "claude"},
		{sessB, logging.EventSessionStart, "codex"},
		{sessA, logging.EventFileBlocked, "/etc/shadow"},
		{sessA, logging.EventSessionEnd, "0"},
		{sessB, logging.EventSessionEnd, "0"},
	}
	for i, e := range seq {
		err := l.Log(logging.Event{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			EventType: e.et,
			Category:  "session",
			Detail:    e.det,
			Blocked:   e.et == logging.EventFileBlocked,
			SessionID: e.sid,
		})
		if err != nil {
			t.Fatalf("Log row %d: %v", i+1, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// rawExec mutates the DB behind the verifier's back, as a file-level attacker.
func rawExec(t *testing.T, dbPath, stmt string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	res, err := db.Exec(stmt, args...)
	if err != nil {
		t.Fatalf("raw exec %q: %v", stmt, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("raw exec %q affected %d rows, want 1", stmt, n)
	}
}

func rowFor(t *testing.T, r Result, id int64) RowResult {
	t.Helper()
	for _, row := range r.Rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("no RowResult for id %d in %+v", id, r.Rows)
	return RowResult{}
}

func TestVerifySession_IntactSignedSession(t *testing.T) {
	dbPath, pub := buildSignedDB(t, t.TempDir())
	r, err := VerifySession(dbPath, pub, sessA)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if r.Verdict != VerdictIntact {
		t.Fatalf("verdict = %s (%s), want INTACT", r.Verdict, r.Reason)
	}
	if r.RowsChecked != 3 || len(r.Rows) != 3 {
		t.Fatalf("RowsChecked=%d len(Rows)=%d, want 3 session-a rows", r.RowsChecked, len(r.Rows))
	}
	for i, want := range []int64{1, 3, 4} {
		row := r.Rows[i]
		if row.ID != want || !row.LinkOK || !row.HashOK || !row.Signed || !row.SigOK {
			t.Fatalf("row %d = %+v, want id %d fully verified", i, row, want)
		}
	}
	sum := sha256.Sum256(pub)
	if r.KeyID != hex.EncodeToString(sum[:]) {
		t.Fatalf("KeyID = %q, want hex(sha256(pub))", r.KeyID)
	}
	if r.FirstBadRow != 0 || r.SessionID != sessA {
		t.Fatalf("FirstBadRow=%d SessionID=%q, want 0 and %q", r.FirstBadRow, r.SessionID, sessA)
	}
	if !r.TailVerified || r.TailReason != "" {
		t.Fatalf("TailVerified=%v TailReason=%q, want a verified tail on an intact signed log", r.TailVerified, r.TailReason)
	}
}

// rawExecN is rawExec for statements that must touch exactly want rows.
func rawExecN(t *testing.T, dbPath string, want int64, stmt string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	res, err := db.Exec(stmt, args...)
	if err != nil {
		t.Fatalf("raw exec %q: %v", stmt, err)
	}
	if n, _ := res.RowsAffected(); n != want {
		t.Fatalf("raw exec %q affected %d rows, want %d", stmt, n, want)
	}
}

func TestVerifySession_IntactRequiresHead(t *testing.T) {
	dbPath, pub := buildSignedDB(t, t.TempDir())
	r, err := VerifySession(dbPath, pub, sessA)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if r.Verdict != VerdictIntact || !r.TailVerified || r.TailReason != "" {
		t.Fatalf("with signed head: verdict=%s TailVerified=%v TailReason=%q (%s), want INTACT with a verified tail", r.Verdict, r.TailVerified, r.TailReason, r.Reason)
	}

	// The same rows, head removed: every row check still passes, and the
	// verdict must no longer be INTACT.
	rawExec(t, dbPath, "DELETE FROM chain_head WHERE id = 1")
	r, err = VerifySession(dbPath, pub, sessA)
	if err != nil {
		t.Fatalf("VerifySession without head: %v", err)
	}
	if r.Verdict == VerdictIntact || r.TailVerified {
		t.Fatalf("without head: verdict=%s TailVerified=%v, want not INTACT and no tail evidence", r.Verdict, r.TailVerified)
	}
}

func TestVerifySession_TailTruncationIsTampered(t *testing.T) {
	for _, tc := range []struct {
		name      string
		deleteSQL string
		deleted   int64
		wantFirst int64
		wantFound string
	}{
		// Row 5 is session-b: session-a's own rows are untouched and still
		// link, hash, and verify. Only the signed head can see the loss.
		{"other session's tail row", "DELETE FROM events WHERE id = 5", 1, 5, "holds 4"},
		// Rows 4 (session-a's end) and 5: the tail of the requested session.
		{"requested session's tail rows", "DELETE FROM events WHERE id >= 4", 2, 4, "holds 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, pub := buildSignedDB(t, t.TempDir())
			rawExecN(t, dbPath, tc.deleted, tc.deleteSQL)
			r, err := VerifySession(dbPath, pub, sessA)
			if err != nil {
				t.Fatalf("VerifySession: %v", err)
			}
			if r.Verdict != VerdictTampered || r.FirstBadRow != tc.wantFirst {
				t.Fatalf("verdict=%s FirstBadRow=%d (%s), want TAMPERED at row %d after tail truncation", r.Verdict, r.FirstBadRow, r.Reason, tc.wantFirst)
			}
			if r.TailVerified {
				t.Fatal("TailVerified after tail truncation")
			}
			if !strings.Contains(r.Reason, "anchors 5 rows") || !strings.Contains(r.Reason, tc.wantFound) {
				t.Fatalf("reason %q must name the anchored count (5) and the found count (%s)", r.Reason, tc.wantFound)
			}
			for _, row := range r.Rows {
				if !row.LinkOK || !row.HashOK || !row.SigOK {
					t.Fatalf("row %+v: surviving rows must still verify; the verdict comes from the head", row)
				}
			}
		})
	}
}

func TestVerifySession_StaleHeadIsTampered(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "events.db")
	keyPath := filepath.Join(dir, "keys", testKeyFile)
	logN := func(n int) {
		t.Helper()
		l, err := logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		for i := 0; i < n; i++ {
			if err := l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventFilePassed, Category: "filesystem", Detail: "f", SessionID: sessA}); err != nil {
				t.Fatalf("Log: %v", err)
			}
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
	logN(3)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var oldHash, oldSig string
	var oldCount int
	if err := db.QueryRow("SELECT entry_hash, row_count, head_sig FROM chain_head WHERE id = 1").Scan(&oldHash, &oldCount, &oldSig); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if oldCount != 3 || oldSig == "" {
		t.Fatalf("precondition: head count=%d signed=%v, want a signed head over 3 rows", oldCount, oldSig != "")
	}
	logN(2)
	// Roll the head back to its genuine, validly signed 3-row state.
	rawExec(t, dbPath, "UPDATE chain_head SET entry_hash = ?, row_count = ?, head_sig = ? WHERE id = 1", oldHash, oldCount, oldSig)

	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifySession(dbPath, pub, sessA)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if r.Verdict != VerdictTampered || r.FirstBadRow != 4 || r.TailVerified {
		t.Fatalf("verdict=%s FirstBadRow=%d TailVerified=%v (%s), want TAMPERED at row 4 (first row beyond the head)", r.Verdict, r.FirstBadRow, r.TailVerified, r.Reason)
	}
	if !strings.Contains(r.Reason, "anchors 3 rows") || !strings.Contains(r.Reason, "holds 5") {
		t.Fatalf("reason %q must name the anchored count (3) and the found count (5)", r.Reason)
	}
}

func TestVerifySession_MissingHeadIsUnanchored(t *testing.T) {
	for _, tc := range []struct {
		name string
		stmt string
	}{
		{"head row deleted", "DELETE FROM chain_head WHERE id = 1"},
		{"head table dropped", "DROP TABLE chain_head"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, pub := buildSignedDB(t, t.TempDir())
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tc.stmt); err != nil {
				t.Fatalf("%s: %v", tc.stmt, err)
			}
			db.Close()
			r, err := VerifySession(dbPath, pub, sessA)
			if err != nil {
				t.Fatalf("VerifySession: %v", err)
			}
			if r.Verdict != VerdictUnanchored || r.TailVerified {
				t.Fatalf("verdict=%s TailVerified=%v (%s), want UNANCHORED with no tail evidence", r.Verdict, r.TailVerified, r.Reason)
			}
			if r.TailReason == "" || r.Reason == "" {
				t.Fatalf("TailReason=%q Reason=%q, want both to explain the missing head", r.TailReason, r.Reason)
			}
		})
	}
}

func TestVerifySession_HeadBadSignatureIsTampered(t *testing.T) {
	dbPath, pub := buildSignedDB(t, t.TempDir())
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign the stored head, unchanged, with a different key: hash, count,
	// and metadata still match the chain, only the signer is wrong.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	head, found, err := logging.ReadChainHead(tx)
	tx.Rollback()
	db.Close()
	if err != nil || !found {
		t.Fatalf("ReadChainHead: found=%v err=%v", found, err)
	}
	hb, err := head.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	foreign := base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, hb))
	rawExec(t, dbPath, "UPDATE chain_head SET head_sig = ? WHERE id = 1", foreign)

	r, err := VerifySession(dbPath, pub, sessA)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if r.Verdict != VerdictTampered || r.TailVerified {
		t.Fatalf("verdict=%s TailVerified=%v (%s), want TAMPERED for a head signed by another key", r.Verdict, r.TailVerified, r.Reason)
	}
	if !strings.Contains(r.Reason, "chain_head signature") {
		t.Fatalf("reason %q must name the chain_head signature", r.Reason)
	}
}

func TestVerifySession_SingleRowMutationFlips(t *testing.T) {
	t.Run("in session", func(t *testing.T) {
		dbPath, pub := buildSignedDB(t, t.TempDir())
		rawExec(t, dbPath, "UPDATE events SET detail = ? WHERE id = 3", "/etc/hosts")
		r, _ := VerifySession(dbPath, pub, sessA)
		if r.Verdict != VerdictTampered || r.FirstBadRow != 3 {
			t.Fatalf("verdict=%s FirstBadRow=%d (%s), want TAMPERED at row 3", r.Verdict, r.FirstBadRow, r.Reason)
		}
		if row := rowFor(t, r, 3); row.HashOK {
			t.Fatalf("row 3 HashOK after mutation: %+v", row)
		}
	})
	t.Run("other session breaks the shared link", func(t *testing.T) {
		dbPath, pub := buildSignedDB(t, t.TempDir())
		rawExec(t, dbPath, "UPDATE events SET blocked = 1 WHERE id = 2")
		r, _ := VerifySession(dbPath, pub, sessA)
		if r.Verdict != VerdictTampered || r.FirstBadRow != 2 {
			t.Fatalf("verdict=%s FirstBadRow=%d (%s), want TAMPERED at row 2 (session-b)", r.Verdict, r.FirstBadRow, r.Reason)
		}
	})
}

func TestVerifySession_ForgedPrevHashValidSigFails(t *testing.T) {
	dbPath, pub := buildSignedDB(t, t.TempDir())

	// Forge row 3's prev_hash and recompute its entry_hash over the forged link,
	// so the row is self-consistent and its signature (over canon only) is still
	// valid. Only the link check can catch this.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var ts, et, cat, det, sid string
	var blocked int
	if err := db.QueryRow("SELECT timestamp, event_type, category, detail, blocked, session_id FROM events WHERE id = 3").
		Scan(&ts, &et, &cat, &det, &blocked, &sid); err != nil {
		t.Fatal(err)
	}
	db.Close()
	forged := sha256.Sum256([]byte("forged predecessor"))
	forgedHex := hex.EncodeToString(forged[:])
	cb := logging.CanonicalBytes(3, ts, et, cat, det, blocked != 0, sid)
	entry, err := logging.ChainEntryFromCanonical(cb, forgedHex)
	if err != nil {
		t.Fatal(err)
	}
	rawExec(t, dbPath, "UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = 3", forgedHex, entry)

	r, _ := VerifySession(dbPath, pub, sessA)
	if r.Verdict != VerdictTampered || r.FirstBadRow != 3 {
		t.Fatalf("verdict=%s FirstBadRow=%d (%s), want TAMPERED at row 3", r.Verdict, r.FirstBadRow, r.Reason)
	}
	row := rowFor(t, r, 3)
	if row.LinkOK || !row.HashOK || !row.SigOK {
		t.Fatalf("row 3 = %+v, want LinkOK=false with HashOK and SigOK true (forged link, valid sig)", row)
	}
}

func TestVerifySession_UnknownSessionIsNoRows(t *testing.T) {
	dbPath, pub := buildSignedDB(t, t.TempDir())
	r, err := VerifySession(dbPath, pub, "no-such-session")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if r.Verdict != VerdictNoRows || r.RowsChecked != 0 {
		t.Fatalf("verdict=%s RowsChecked=%d, want NO_ROWS and 0", r.Verdict, r.RowsChecked)
	}
}

func TestVerifySession_UnsignedRowFails(t *testing.T) {
	t.Run("stripped signature", func(t *testing.T) {
		dbPath, pub := buildSignedDB(t, t.TempDir())
		rawExec(t, dbPath, "UPDATE events SET entry_sig = '' WHERE id = 3")
		r, _ := VerifySession(dbPath, pub, sessA)
		if r.Verdict != VerdictUnsigned || r.FirstBadRow != 3 {
			t.Fatalf("verdict=%s FirstBadRow=%d (%s), want UNSIGNED at row 3", r.Verdict, r.FirstBadRow, r.Reason)
		}
	})
	t.Run("never-signed log", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "events.db")
		writeSessions(t, dbPath, "", time.Now())
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := VerifySession(dbPath, pub, sessA)
		if r.Verdict != VerdictUnsigned || r.FirstBadRow != 1 {
			t.Fatalf("verdict=%s FirstBadRow=%d (%s), want UNSIGNED at row 1", r.Verdict, r.FirstBadRow, r.Reason)
		}
	})
}

func TestVerifySession_WrongKeyFails(t *testing.T) {
	dbPath, _ := buildSignedDB(t, t.TempDir())
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := VerifySession(dbPath, other, sessA)
	// The head signature fails under the foreign key too, and a bad head
	// outranks a bad row signature, so the head is named as the reason.
	if r.Verdict != VerdictTampered || r.TailVerified || !strings.Contains(r.Reason, "chain_head signature") {
		t.Fatalf("verdict=%s TailVerified=%v (%s), want TAMPERED naming the chain_head signature under a foreign key", r.Verdict, r.TailVerified, r.Reason)
	}
	if row := rowFor(t, r, 1); row.SigOK {
		t.Fatalf("row 1 SigOK under a foreign key: %+v", row)
	}
}

func TestVerifySession_MissingDBIsUnverifiable(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "absent.db")
	r, err := VerifySession(dbPath, pub, sessA)
	if err == nil || r.Verdict != VerdictUnverifiable {
		t.Fatalf("verdict=%s err=%v, want UNVERIFIABLE and an error", r.Verdict, err)
	}
	if _, statErr := os.Stat(dbPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("VerifySession created %s (stat err %v); it must never create the DB", dbPath, statErr)
	}
}

func TestVerifySession_BadKeyIsError(t *testing.T) {
	dbPath, pub := buildSignedDB(t, t.TempDir())
	for name, key := range map[string]ed25519.PublicKey{"nil": nil, "short": pub[:31]} {
		r, err := VerifySession(dbPath, key, sessA)
		if err == nil || r.Verdict != VerdictUnverifiable {
			t.Fatalf("%s key: verdict=%s err=%v, want UNVERIFIABLE and an error", name, r.Verdict, err)
		}
	}
}

func TestVerifySession_DBIsNotModified(t *testing.T) {
	dir := t.TempDir()
	dbPath, pub := buildSignedDB(t, dir)
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{sessA, sessB, "no-such-session"} {
		if _, err := VerifySession(dbPath, pub, sid); err != nil {
			t.Fatalf("VerifySession(%s): %v", sid, err)
		}
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		b, a := sha256.Sum256(before), sha256.Sum256(after)
		t.Fatalf("DB bytes changed: before %x after %x", b, a)
	}
	// SQLite may create the -shm index and an empty -wal for a read-only
	// WAL-mode open; neither holds rows. A -wal with content or a rollback
	// -journal would mean something was written.
	if wi, err := os.Stat(dbPath + "-wal"); err == nil && wi.Size() != 0 {
		t.Fatalf("VerifySession left a non-empty -wal (%d bytes)", wi.Size())
	}
	if _, err := os.Stat(dbPath + "-journal"); err == nil {
		t.Fatal("VerifySession left a rollback -journal next to the DB")
	}
}

func TestCheckSameFile(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.db")
	b := filepath.Join(dir, "b.db")
	link := filepath.Join(dir, "link.db")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	lstat := func(p string) os.FileInfo {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi
	}
	pre := lstat(a)
	if err := checkSameFile(a, pre, lstat(a)); err != nil {
		t.Fatalf("same file: %v, want nil", err)
	}
	if err := checkSameFile(a, pre, lstat(b)); err == nil {
		t.Fatal("different inode: got nil, want an identity error")
	}
	if err := checkSameFile(a, pre, lstat(link)); err == nil {
		t.Fatal("symlink after read: got nil, want an error")
	}
}

// A writer that died without checkpointing leaves a non-empty -wal and no live
// connection. VerifySession must read it; neither the main file nor the
// -wal may change (SQLite may create the -shm index, which holds no rows).
func TestVerifySession_DBIsNotModified_UncheckpointedWALNoWriter(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "events.db")
	keyPath := filepath.Join(dir, "keys", testKeyFile)
	l, err := logging.NewLogger(srcPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventFilePassed, Category: "filesystem", Detail: "f", SessionID: sessA}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	// Snapshot main file + -wal while the writer is still open: this is what a
	// crash leaves on disk.
	crashDir := t.TempDir()
	dbPath := filepath.Join(crashDir, "events.db")
	for _, s := range []string{"", "-wal"} {
		b, err := os.ReadFile(srcPath + s)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dbPath+s, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	read := func() (main, wal []byte) {
		main, err := os.ReadFile(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		wal, err = os.ReadFile(dbPath + "-wal")
		if err != nil {
			t.Fatal(err)
		}
		return main, wal
	}
	mainBefore, walBefore := read()
	if len(walBefore) == 0 {
		t.Fatal("precondition: want a non-empty -wal")
	}
	r, err := VerifySession(dbPath, pub, sessA)
	if err != nil || r.Verdict != VerdictIntact || r.RowsChecked != 3 {
		t.Fatalf("verdict=%s rows=%d err=%v (%s), want INTACT over 3 rows", r.Verdict, r.RowsChecked, err, r.Reason)
	}
	mainAfter, walAfter := read()
	if !bytes.Equal(mainBefore, mainAfter) {
		t.Fatal("main DB bytes changed: VerifySession checkpointed or wrote the log")
	}
	if !bytes.Equal(walBefore, walAfter) {
		t.Fatal("-wal bytes changed: VerifySession wrote the log")
	}
}

func TestVerifySession_ReadsUncheckpointedWAL(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "events.db")
	keyPath := filepath.Join(dir, "keys", testKeyFile)
	l, err := logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()
	for i := 0; i < 3; i++ {
		if err := l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventFilePassed, Category: "filesystem", Detail: "f", SessionID: sessA}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if wi, err := os.Stat(dbPath + "-wal"); err != nil || wi.Size() == 0 {
		t.Fatalf("precondition: want a non-empty -wal while the writer is open (err %v)", err)
	}
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifySession(dbPath, pub, sessA)
	if err != nil || r.Verdict != VerdictIntact || r.RowsChecked != 3 {
		t.Fatalf("verdict=%s rows=%d err=%v (%s), want INTACT over the 3 rows still in the WAL", r.Verdict, r.RowsChecked, err, r.Reason)
	}
}

func TestVerifySession_PathSwapIsUnverifiable(t *testing.T) {
	for _, tc := range []struct {
		name string
		swap func(t *testing.T, dbPath, replacement string)
	}{
		{
			name: "regular file",
			swap: func(t *testing.T, dbPath, replacement string) {
				t.Helper()
				if err := os.Rename(replacement, dbPath); err != nil {
					t.Fatalf("replace DB: %v", err)
				}
			},
		},
		{
			name: "symlink",
			swap: func(t *testing.T, dbPath, replacement string) {
				t.Helper()
				if err := os.Remove(dbPath); err != nil {
					t.Fatalf("remove DB: %v", err)
				}
				if err := os.Symlink(replacement, dbPath); err != nil {
					t.Fatalf("symlink DB: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath, pub := buildSignedDB(t, dir)
			replacement, _ := buildSignedDB(t, t.TempDir())
			beforeSQLiteOpen = func() { tc.swap(t, dbPath, replacement) }
			t.Cleanup(func() { beforeSQLiteOpen = func() {} })

			r, err := VerifySession(dbPath, pub, sessA)
			if err == nil || r.Verdict != VerdictUnverifiable {
				t.Fatalf("verdict=%s err=%v, want UNVERIFIABLE after path swap", r.Verdict, err)
			}
		})
	}
}

func TestVerifySession_WALCreatedDuringOpenIsRead(t *testing.T) {
	dir := t.TempDir()
	dbPath, pub := buildSignedDB(t, dir)
	keyPath := filepath.Join(dir, "keys", testKeyFile)
	var writer *logging.Logger
	beforeSQLiteOpen = func() {
		var err error
		writer, err = logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
		if err != nil {
			t.Fatalf("open concurrent writer: %v", err)
		}
		if err := writer.Log(logging.Event{
			Timestamp: time.Now(), EventType: logging.EventFilePassed,
			Category: "filesystem", Detail: "new-tail", SessionID: sessA,
		}); err != nil {
			t.Fatalf("append concurrent WAL row: %v", err)
		}
	}
	t.Cleanup(func() {
		beforeSQLiteOpen = func() {}
		if writer != nil {
			_ = writer.Close()
		}
	})

	r, err := VerifySession(dbPath, pub, sessA)
	if err != nil || r.Verdict != VerdictIntact || r.RowsChecked != 4 {
		t.Fatalf("verdict=%s rows=%d err=%v (%s), want INTACT including the WAL tail", r.Verdict, r.RowsChecked, err, r.Reason)
	}
}

// TestWriteExternalFixture regenerates testdata for the external-module test.
// It runs only with NOCKLOCK_RECEIPT_WRITE_FIXTURE=1.
func TestWriteExternalFixture(t *testing.T) {
	if os.Getenv("NOCKLOCK_RECEIPT_WRITE_FIXTURE") != "1" {
		t.Skip("set NOCKLOCK_RECEIPT_WRITE_FIXTURE=1 to regenerate testdata")
	}
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "events.db")
	keyPath := filepath.Join(tmp, "keys", testKeyFile)
	writeSessions(t, dbPath, keyPath, time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "signed.db"), db, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "signed.pub"), []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
