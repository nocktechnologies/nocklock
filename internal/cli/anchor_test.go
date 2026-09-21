package cli

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"

	_ "modernc.org/sqlite"
)

// ---------- verdict rendering (unit) ----------

func TestWriteAnchorVerifyResult_OK(t *testing.T) {
	var buf bytes.Buffer
	err := writeAnchorVerifyResult(&buf, &logging.AnchorVerifyResult{
		OK:             true,
		Classification: "ok",
		Reason:         "local chain reproduces the anchored head at 5 rows",
		AnchorRowCount: 5,
		LocalRowCount:  5,
		AnchorHeadHash: "abc",
	})
	if err != nil {
		t.Fatalf("ok result must not error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ANCHOR: OK") || !strings.Contains(out, "Anchor head: abc") {
		t.Errorf("missing OK verdict / head line:\n%s", out)
	}
}

func TestWriteAnchorVerifyResult_TruncationExitsNonZero(t *testing.T) {
	var buf bytes.Buffer
	err := writeAnchorVerifyResult(&buf, &logging.AnchorVerifyResult{
		Classification: "truncation",
		Reason:         "truncation detected: anchor attests 5 rows, local has 3",
	})
	var ece *exitCodeError
	if !asExitCodeError(err, &ece) || ece.code != 1 {
		t.Fatalf("truncation must exit 1, got %v", err)
	}
	if !strings.Contains(buf.String(), "ANCHOR: TRUNCATION") {
		t.Errorf("missing TRUNCATION verdict:\n%s", buf.String())
	}
}

func TestWriteAnchorVerifyResult_TruncationAfterPruneCarriesNote(t *testing.T) {
	var buf bytes.Buffer
	_ = writeAnchorVerifyResult(&buf, &logging.AnchorVerifyResult{
		Classification:    "truncation",
		Reason:            "truncation detected: anchor attests 5 rows, local has 3",
		PrunedAfterAnchor: true,
	})
	if !strings.Contains(buf.String(), "NOTE:") || !strings.Contains(buf.String(), "prune") {
		t.Errorf("a prune after the anchor should carry a NOTE:\n%s", buf.String())
	}
}

func TestWriteAnchorVerifyResult_TamperedExitsNonZero(t *testing.T) {
	var buf bytes.Buffer
	err := writeAnchorVerifyResult(&buf, &logging.AnchorVerifyResult{
		Classification: "tampered",
		Reason:         "tamper detected: local chain does not reproduce the anchored head hash at 4 rows",
	})
	var ece *exitCodeError
	if !asExitCodeError(err, &ece) || ece.code != 1 {
		t.Fatalf("tampered must exit 1, got %v", err)
	}
	if !strings.Contains(buf.String(), "ANCHOR: TAMPERED") {
		t.Errorf("missing TAMPERED verdict:\n%s", buf.String())
	}
}

func TestWriteAnchorVerifyResult_ForgedAndIdentityAreForgedVerdict(t *testing.T) {
	for _, class := range []string{"forged", "identity_mismatch"} {
		var buf bytes.Buffer
		err := writeAnchorVerifyResult(&buf, &logging.AnchorVerifyResult{
			Classification: class,
			Reason:         "anchor signature does not verify against the supplied key",
		})
		var ece *exitCodeError
		if !asExitCodeError(err, &ece) || ece.code != 1 {
			t.Fatalf("%s must exit 1, got %v", class, err)
		}
		if !strings.Contains(buf.String(), "ANCHOR: FORGED") {
			t.Errorf("%s should render ANCHOR: FORGED:\n%s", class, buf.String())
		}
	}
}

func TestWriteAnchorVerifyResult_NoKeyFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	err := writeAnchorVerifyResult(&buf, &logging.AnchorVerifyResult{
		Classification: "no_key",
		Reason:         "no public key available to authenticate the anchor",
	})
	var ece *exitCodeError
	if !asExitCodeError(err, &ece) || ece.code != 1 {
		t.Fatalf("no_key must exit 1 (never a hash-only pass), got %v", err)
	}
	if !strings.Contains(buf.String(), "ANCHOR: FAILED") {
		t.Errorf("missing FAILED verdict:\n%s", buf.String())
	}
}

// ---------- end-to-end: emit -> verify -> truncation, through the CLI wiring ----------

// setupAnchorProject writes a NockLock config, chdirs into it, isolates the
// signing key under XDG_CONFIG_HOME, and returns the absolute event DB path.
func setupAnchorProject(t *testing.T) (dbPath, keyPath string) {
	t.Helper()
	project := t.TempDir()
	nockDir := filepath.Join(project, config.Dir)
	if err := os.MkdirAll(nockDir, 0o700); err != nil {
		t.Fatalf("mkdir .nock: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Logging.DB = filepath.Join(config.Dir, "events.db")
	if err := writeConfigTOML(filepath.Join(nockDir, config.File), &cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(project)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg"))
	kp, err := logging.DefaultSigningKeyPath()
	if err != nil {
		t.Fatalf("resolve key path: %v", err)
	}
	return filepath.Join(project, config.Dir, "events.db"), kp
}

func TestAnchorEmitVerify_EndToEnd(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)

	// Seed a signed 5-row chain with the same managed key the CLI resolves.
	l, err := logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("seed logger: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Log(logging.Event{EventType: logging.EventFileBlocked, Category: "filesystem", Detail: "/etc/shadow", Blocked: true, SessionID: "s"}); err != nil {
			t.Fatalf("seed Log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	// Emit the anchor through the CLI handler.
	anchorPath := filepath.Join(t.TempDir(), "chain-anchor.json")
	var emitOut bytes.Buffer
	if err := runAnchorEmit(&emitOut, anchorPath); err != nil {
		t.Fatalf("runAnchorEmit: %v", err)
	}
	anchor, err := logging.ReadAnchor(anchorPath)
	if err != nil {
		t.Fatalf("read emitted anchor: %v", err)
	}
	if anchor.RowCount != 5 {
		t.Fatalf("emitted anchor row_count = %d, want 5", anchor.RowCount)
	}

	// Intact chain verifies OK through the CLI handler.
	var okOut bytes.Buffer
	if err := runVerifyAgainstAnchor(&okOut, anchorPath, ""); err != nil {
		t.Fatalf("runVerifyAgainstAnchor(intact) should pass, got: %v", err)
	}
	if !strings.Contains(okOut.String(), "ANCHOR: OK") {
		t.Errorf("intact chain: missing ANCHOR: OK:\n%s", okOut.String())
	}

	// Attacker truncates the tail and rewrites chain_head in lockstep.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	var hashAt3 string
	if err := db.QueryRow("SELECT entry_hash FROM events WHERE id = 3").Scan(&hashAt3); err != nil {
		t.Fatalf("read hash@3: %v", err)
	}
	if _, err := db.Exec("DELETE FROM events WHERE id > 3"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET entry_hash = ?, row_count = 3 WHERE id = 1", hashAt3); err != nil {
		t.Fatalf("rewrite head: %v", err)
	}
	db.Close()

	// The CLI now reports TRUNCATION and exits non-zero.
	var badOut bytes.Buffer
	err = runVerifyAgainstAnchor(&badOut, anchorPath, "")
	var ece *exitCodeError
	if !asExitCodeError(err, &ece) || ece.code != 1 {
		t.Fatalf("truncated chain must exit 1, got %v", err)
	}
	if !strings.Contains(badOut.String(), "ANCHOR: TRUNCATION") {
		t.Errorf("truncated chain: missing ANCHOR: TRUNCATION:\n%s", badOut.String())
	}
}
