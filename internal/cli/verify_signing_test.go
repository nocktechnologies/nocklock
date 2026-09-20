package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

func TestWriteAuditVerifyResult_Authentic(t *testing.T) {
	var buf bytes.Buffer
	err := writeAuditVerifyResult(&buf, &logging.ChainVerifyResult{
		Intact:          true,
		EntriesVerified: 5,
		SigState:        "authentic",
		SigVerified:     5,
		HeadSigned:      true,
		HeadHash:        "abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "AUDIT: AUTHENTIC") {
		t.Errorf("missing AUTHENTIC verdict:\n%s", out)
	}
	if strings.Contains(out, "CONSISTENT") {
		t.Errorf("authentic result must not also say CONSISTENT:\n%s", out)
	}
}

func TestWriteAuditVerifyResult_AuthenticWithUnsignedPrefix(t *testing.T) {
	var buf bytes.Buffer
	genesis := time.Now()
	_ = writeAuditVerifyResult(&buf, &logging.ChainVerifyResult{
		Intact:            true,
		EntriesVerified:   5,
		SigState:          "authentic",
		SigVerified:       2,
		UnsignedEntries:   3,
		UnsignedThroughID: 3,
		SignedGenesisAt:   &genesis,
		HeadSigned:        true,
	})
	out := buf.String()
	if !strings.Contains(out, "AUDIT: AUTHENTIC") {
		t.Errorf("missing AUTHENTIC verdict:\n%s", out)
	}
	if !strings.Contains(out, "predate signing adoption") {
		t.Errorf("missing pre-adoption note:\n%s", out)
	}
}

func TestWriteAuditVerifyResult_ForgedRowExitsNonZero(t *testing.T) {
	var buf bytes.Buffer
	err := writeAuditVerifyResult(&buf, &logging.ChainVerifyResult{
		Intact:          true,
		EntriesVerified: 3,
		SigState:        "forged",
		SigBrokenID:     2,
		SigBrokenReason: "entry 2: signature does not verify against the key",
	})
	if err == nil {
		t.Fatal("forged result must return a non-nil (non-zero exit) error")
	}
	var ece *exitCodeError
	if !asExitCodeError(err, &ece) || ece.code != 1 {
		t.Errorf("forged result must exit 1, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "AUDIT: FORGED") || !strings.Contains(out, "entry 2") {
		t.Errorf("missing FORGED verdict at entry 2:\n%s", out)
	}
}

func TestWriteAuditVerifyResult_ForgedHeadNamesChainHead(t *testing.T) {
	var buf bytes.Buffer
	err := writeAuditVerifyResult(&buf, &logging.ChainVerifyResult{
		Intact:          true,
		EntriesVerified: 3,
		SigState:        "forged",
		SigBrokenID:     0, // head failure
		SigBrokenReason: "chain_head signature does not verify against the key",
	})
	if err == nil {
		t.Fatal("forged head must return a non-zero exit error")
	}
	out := buf.String()
	if !strings.Contains(out, "AUDIT: FORGED") || !strings.Contains(out, "chain_head") {
		t.Errorf("forged head verdict should name chain_head:\n%s", out)
	}
}

func TestWriteAuditVerifyResult_SuspectIsDistinctAndExitsNonZero(t *testing.T) {
	var buf bytes.Buffer
	err := writeAuditVerifyResult(&buf, &logging.ChainVerifyResult{
		Intact:          true,
		EntriesVerified: 3,
		SigState:        "suspect",
		SigBrokenReason: "signed verification was required but the log carries no signatures and no adoption markers",
	})
	if err == nil {
		t.Fatal("suspect result must return a non-zero exit error (never a clean pass)")
	}
	var ece *exitCodeError
	if !asExitCodeError(err, &ece) || ece.code != 1 {
		t.Errorf("suspect result must exit 1, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "AUDIT: SUSPECT") {
		t.Errorf("missing SUSPECT verdict:\n%s", out)
	}
	if strings.Contains(out, "CONSISTENT") || strings.Contains(out, "AUTHENTIC") {
		t.Errorf("suspect must not read CONSISTENT or AUTHENTIC:\n%s", out)
	}
}

// TestWriteAuditVerifyResult_MigrationNoteSaysNotAuthenticated pins the honest
// wording for pre-migration rows (spec §5): under both the CONSISTENT and the
// AUTHENTIC verdicts, rows that predate the chain are reported as structurally
// chained but NOT authenticated. A verify output must never claim pre-migration
// history is proven.
func TestWriteAuditVerifyResult_MigrationNoteSaysNotAuthenticated(t *testing.T) {
	migrated := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	const wantNote = "NOTE: entries 1..3 predate the chain (migrated 2026-09-14T12:00:00Z); structurally chained, not authenticated."
	for _, state := range []string{"unsigned", "authentic"} {
		var buf bytes.Buffer
		res := &logging.ChainVerifyResult{
			Intact:          true,
			EntriesVerified: 5,
			SigState:        state,
			MigratedAt:      &migrated,
			LegacyThroughID: 3,
			HeadHash:        "abc",
		}
		if state == "authentic" {
			genesis := migrated
			res.SignedGenesisAt = &genesis
			res.SigVerified, res.SignedEntries, res.UnsignedEntries, res.UnsignedThroughID, res.HeadSigned = 2, 2, 3, 3, true
		}
		if err := writeAuditVerifyResult(&buf, res); err != nil {
			t.Fatalf("state %q: unexpected error: %v", state, err)
		}
		out := buf.String()
		if !strings.Contains(out, wantNote) {
			t.Errorf("state %q: missing the honest migration note %q in:\n%s", state, wantNote, out)
		}
	}
}

func TestWriteAuditVerifyResult_UnverifiedIsConsistentNotAuthentic(t *testing.T) {
	var buf bytes.Buffer
	err := writeAuditVerifyResult(&buf, &logging.ChainVerifyResult{
		Intact:          true,
		EntriesVerified: 3,
		SigState:        "unverified",
		SignedEntries:   3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "AUDIT: CONSISTENT") {
		t.Errorf("unverified must read CONSISTENT:\n%s", out)
	}
	if strings.Contains(out, "AUTHENTIC") {
		t.Errorf("signatures present but unchecked must NOT read authentic:\n%s", out)
	}
	if !strings.Contains(out, "authenticity NOT checked") {
		t.Errorf("missing the No-Silent-Success note about unchecked signatures:\n%s", out)
	}
}

// TestRunExportPubkey prints a stable base64 key derived from the managed key
// file, using an isolated XDG_CONFIG_HOME so the real ~/.config is untouched.
func TestRunExportPubkey(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var buf bytes.Buffer
	if err := runExportPubkey(&buf); err != nil {
		t.Fatalf("runExportPubkey: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(out, "ed25519 ") {
		t.Fatalf("export output not prefixed with 'ed25519 ': %q", out)
	}
	// The printed key must parse back to a valid Ed25519 public key.
	b64 := strings.TrimPrefix(out, "ed25519 ")
	pub, err := logging.ParsePublicKey(b64)
	if err != nil {
		t.Fatalf("exported key does not parse: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("exported key size %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// A second export is stable (same key file).
	var buf2 bytes.Buffer
	if err := runExportPubkey(&buf2); err != nil {
		t.Fatalf("second export: %v", err)
	}
	if buf.String() != buf2.String() {
		t.Error("exported public key changed between calls")
	}
}

func TestResolveVerifyPublicKey_FlagOverrides(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	got, err := resolveVerifyPublicKey(logging.EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("resolveVerifyPublicKey: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("flag-supplied public key did not round-trip")
	}
}

func TestResolveVerifyPublicKey_MissingKeyIsNil(t *testing.T) {
	// Isolated empty config dir: no key file exists yet, so verification falls
	// back to hash-only (nil key), not an error.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "empty"))
	got, err := resolveVerifyPublicKey("")
	if err != nil {
		t.Fatalf("missing key must not error: %v", err)
	}
	if got != nil {
		t.Error("expected nil public key when no key file exists")
	}
}

func TestResolveVerifyPublicKey_BadFlag(t *testing.T) {
	if _, err := resolveVerifyPublicKey("not-a-valid-key"); err == nil {
		t.Fatal("expected an error for an invalid --ed25519-pub value")
	}
}

// asExitCodeError reports whether err is an *exitCodeError and binds it.
func asExitCodeError(err error, target **exitCodeError) bool {
	e, ok := err.(*exitCodeError)
	if ok {
		*target = e
	}
	return ok
}
