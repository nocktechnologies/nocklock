package logging

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"
)

// TestProfileAnchorVerification measures where full-chain authentication time
// goes during anchor emission (N11775). It is a profiling recipe, not a
// regression test: it skips unless NOCKLOCK_PROFILE_ROWS is set, e.g.
//
//	NOCKLOCK_PROFILE_ROWS=100000 go test ./internal/logging -run TestProfileAnchorVerification -count=1 -v -timeout 30m
//
// See docs/design/anchor-verification-profile.md for how to read the output.
func TestProfileAnchorVerification(t *testing.T) {
	raw := os.Getenv("NOCKLOCK_PROFILE_ROWS")
	if raw == "" {
		t.Skip("set NOCKLOCK_PROFILE_ROWS (e.g. 100000) to run the anchor verification profile")
	}
	rows, err := strconv.Atoi(raw)
	if err != nil || rows < 1 {
		t.Fatalf("NOCKLOCK_PROFILE_ROWS=%q: want a positive integer", raw)
	}
	reps := 3

	l, keyPath, pub := newSigningLogger(t)
	defer l.Close()
	dbPath := profileDBPath(t, l)

	// Genuinely signed rows through the normal append path (row + head signature each).
	start := time.Now()
	const batch = 1000
	for done := 0; done < rows; done += batch {
		n := min(batch, rows-done)
		evs := make([]Event, n)
		for i := range evs {
			evs[i] = Event{Timestamp: time.Now(), EventType: EventType("profile"), Category: "bench",
				Detail: fmt.Sprintf("row %d synthetic audit detail payload", done+i), SessionID: "profile"}
		}
		if err := l.LogBatch(evs); err != nil {
			t.Fatalf("LogBatch: %v", err)
		}
	}
	populate := time.Since(start)

	type phase struct {
		name string
		fn   func() error
	}
	var rowsData []profileRow
	if err := l.db.QueryRow("SELECT COUNT(*) FROM events").Scan(new(int)); err != nil {
		t.Fatal(err)
	}
	rowsData = loadProfileRows(t, l.db)

	phases := []phase{
		{"sqlite scan only (SELECT + Scan, no crypto)", func() error { _ = loadProfileRows(t, l.db); return nil }},
		{"hash recompute only (in-memory rows, no sig, no SQLite)", func() error {
			prev := chainGenesisHashHex
			for _, r := range rowsData {
				cb := canonicalBytes(r.id, r.ts, EventType(r.et), r.cat, r.detail, r.blocked != 0, r.sid)
				h, err := chainEntryFromCanonical(cb, prev)
				if err != nil {
					return err
				}
				prev = h
			}
			return nil
		}},
		{"ed25519 row-sig verify only (in-memory rows)", func() error {
			for _, r := range rowsData {
				cb := canonicalBytes(r.id, r.ts, EventType(r.et), r.cat, r.detail, r.blocked != 0, r.sid)
				if !verifyRowSig(pub, cb, r.sig) {
					return fmt.Errorf("row %d signature did not verify", r.id)
				}
			}
			return nil
		}},
		{"prefix rescan: SQLite scan + hash chain + sig-inclusive SHA-256 digest, no sig verify (design option C)", func() error {
			rs, err := l.db.Query("SELECT id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash, entry_sig FROM events ORDER BY id ASC")
			if err != nil {
				return err
			}
			defer rs.Close()
			prev, digest := chainGenesisHashHex, [sha256.Size]byte{}
			for rs.Next() {
				var r profileRow
				if err := rs.Scan(&r.id, &r.ts, &r.et, &r.cat, &r.detail, &r.blocked, &r.sid, &r.prev, &r.hash, &r.sig); err != nil {
					return err
				}
				cb := canonicalBytes(r.id, r.ts, EventType(r.et), r.cat, r.detail, r.blocked != 0, r.sid)
				h, err := chainEntryFromCanonical(cb, prev)
				if err != nil || h != r.hash || r.prev != prev {
					return fmt.Errorf("row %d: chain mismatch (%v)", r.id, err)
				}
				digest = sha256.Sum256(append(append(digest[:], r.hash...), r.sig...))
				prev = h
			}
			return rs.Err()
		}},
		{"VerifyChain (hash only, key nil)", func() error {
			res, err := l.VerifyChain()
			if err == nil && !res.Intact {
				err = fmt.Errorf("not intact: %s", res.BrokenReason)
			}
			return err
		}},
		{"VerifyChainSigned (full authentication)", func() error {
			res, err := l.VerifyChainSigned(pub, true)
			if err == nil && (!res.Intact || res.SigState != "authentic") {
				err = fmt.Errorf("not authentic: %s %s", res.BrokenReason, res.SigBrokenReason)
			}
			return err
		}},
		{"EmitAnchor (VerifyChainSigned + sign head)", func() error { _, err := l.EmitAnchor(); return err }},
	}

	// Anchor sign and file write in isolation, on a precomputed anchor.
	anchor, err := l.EmitAnchor()
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := anchorCanonicalBytes(anchor)
	_, priv, _ := ed25519.GenerateKey(nil)
	anchorPath := filepath.Join(t.TempDir(), "chain-anchor.json")
	phases = append(phases,
		phase{"ed25519.Sign of one anchor (isolated)", func() error { _ = ed25519.Sign(priv, cb); return nil }},
		phase{"WriteAnchor temp file + rename (isolated)", func() error { return WriteAnchor(anchorPath, anchor) }},
	)

	t.Logf("host: %s/%s, %d CPU, %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	t.Logf("rows: %d, genuinely signed via LogBatch (populate %s), key %s", rows, populate.Round(time.Millisecond), keyPath)
	t.Logf("remote: disabled (no network in any phase)")
	t.Logf("| phase | warm run 1 | run 2 | run 3 | median |")
	for _, p := range phases {
		d := make([]time.Duration, reps)
		for i := range d {
			s := time.Now()
			if err := p.fn(); err != nil {
				t.Fatalf("%s: %v", p.name, err)
			}
			d[i] = time.Since(s)
		}
		sorted := append([]time.Duration(nil), d...)
		sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
		t.Logf("| %s | %s | %s | %s | %s |", p.name, d[0], d[1], d[2], sorted[reps/2])
	}

	// Cold-open: fresh connection pool and prepared state, OS page cache still
	// warm (dropping it needs root, which this recipe never uses).
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := NewLogger(dbPath, filepath.Dir(dbPath), WithSigning(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	s := time.Now()
	if _, err := l2.EmitAnchor(); err != nil {
		t.Fatal(err)
	}
	t.Logf("cold-open (new process-equivalent connection, warm OS page cache) EmitAnchor: %s", time.Since(s))
	t.Logf("db size: %d bytes", fileSize(dbPath))
}

type profileRow struct {
	id                   int64
	ts, et, cat, detail  string
	sid, prev, hash, sig string
	blocked              int
}

func loadProfileRows(t *testing.T, db *sql.DB) []profileRow {
	t.Helper()
	rs, err := db.Query("SELECT id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash, entry_sig FROM events ORDER BY id ASC")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []profileRow
	for rs.Next() {
		var r profileRow
		if err := rs.Scan(&r.id, &r.ts, &r.et, &r.cat, &r.detail, &r.blocked, &r.sid, &r.prev, &r.hash, &r.sig); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func profileDBPath(t *testing.T, l *Logger) string {
	t.Helper()
	var seq int
	var name, file string
	if err := l.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return st.Size()
}
