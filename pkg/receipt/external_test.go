package receipt_test

// This file imports only the public package, the way another module (for
// example nockguard) would. Its fixture was written through the real signing
// Logger by TestWriteExternalFixture.

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/pkg/receipt"
)

func loadFixture(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	db, err := os.ReadFile(filepath.Join("testdata", "signed.db"))
	if err != nil {
		t.Fatalf("read fixture db: %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "events.db")
	if err := os.WriteFile(dbPath, db, 0o600); err != nil {
		t.Fatal(err)
	}
	pubHex, err := os.ReadFile(filepath.Join("testdata", "signed.pub"))
	if err != nil {
		t.Fatalf("read fixture pub: %v", err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("fixture pub: len=%d err=%v", len(pub), err)
	}
	return dbPath, ed25519.PublicKey(pub)
}

func TestExternal_VerifySessionFromPublicAPI(t *testing.T) {
	dbPath, pub := loadFixture(t)

	r, err := receipt.VerifySession(dbPath, pub, "session-a")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if r.Verdict != receipt.VerdictIntact || r.RowsChecked != 3 {
		t.Fatalf("session-a: verdict=%s rows=%d (%s), want INTACT over 3 rows", r.Verdict, r.RowsChecked, r.Reason)
	}

	r, _ = receipt.VerifySession(dbPath, pub, "no-such-session")
	if r.Verdict != receipt.VerdictNoRows {
		t.Fatalf("unknown session: verdict=%s, want NO_ROWS", r.Verdict)
	}

	r, err = receipt.VerifySession(filepath.Join(t.TempDir(), "absent.db"), pub, "session-a")
	if err == nil || r.Verdict != receipt.VerdictUnverifiable {
		t.Fatalf("missing db: verdict=%s err=%v, want UNVERIFIABLE with error", r.Verdict, err)
	}
}
