package logging

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ---------- helpers ----------

// newSigningLogger opens a signing Logger with a fresh key under t.TempDir().
func newSigningLogger(t *testing.T) (*Logger, string, ed25519.PublicKey) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "events.db")
	keyPath := filepath.Join(t.TempDir(), "keys", "audit.key")
	l, err := NewLogger(dbPath, "", WithSigning(keyPath))
	if err != nil {
		t.Fatalf("NewLogger(WithSigning) failed: %v", err)
	}
	pub, err := LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPublicKeyFile failed: %v", err)
	}
	return l, keyPath, pub
}

// ---------- key custody ----------

func TestSigningKey_GeneratedOnFirstUse0600(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "sub", "audit.key")
	s, err := loadOrCreateSigner(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateSigner failed: %v", err)
	}
	if len(s.priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key size %d, want %d", len(s.priv), ed25519.PrivateKeySize)
	}

	fi, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatalf("lstat key: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("key file is a symlink")
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perms: got %o, want 600", fi.Mode().Perm())
	}
	// Stored content is the 32-byte seed only.
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(data) != ed25519.SeedSize {
		t.Fatalf("key file holds %d bytes, want %d (raw seed)", len(data), ed25519.SeedSize)
	}

	// Reload derives the identical keypair.
	s2, err := loadOrCreateSigner(keyPath)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !s.pub.Equal(s2.pub) {
		t.Error("reloaded public key differs from generated one")
	}
}

func TestSigningKey_RejectsWorldReadable(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "audit.key")
	if _, err := loadOrCreateSigner(keyPath); err != nil {
		t.Fatalf("initial create failed: %v", err)
	}
	// Loosen to 0644 (group/world readable) — must fail closed.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := loadOrCreateSigner(keyPath); err == nil {
		t.Fatal("expected loadOrCreateSigner to reject 0644 key, got nil error")
	} else if !containsAny(err.Error(), "group/world", "accessible") {
		t.Errorf("expected a permission error, got: %v", err)
	}
}

func TestSigningKey_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	realKey := filepath.Join(dir, "keys", "real.key")
	if _, err := loadOrCreateSigner(realKey); err != nil {
		t.Fatalf("create real key: %v", err)
	}
	linkPath := filepath.Join(dir, "keys", "audit.key")
	if err := os.Symlink(realKey, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := loadOrCreateSigner(linkPath); err == nil {
		t.Fatal("expected loadOrCreateSigner to reject a symlinked key, got nil error")
	} else if !containsAny(err.Error(), "symlink") {
		t.Errorf("expected a symlink error, got: %v", err)
	}
}

// errReader always fails, to drive the key-generation path into its error branch.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errFakeEntropy }

var errFakeEntropy = os.ErrClosed // any non-nil error works as a stand-in

// TestSigningKey_CreateFailureLeavesNoPartialKey proves the cleanup contract:
// when the create/write path fails, no key file is left on disk. A discarded
// Close (or a failed Write) must never persist a corrupt/truncated signing key.
func TestSigningKey_CreateFailureLeavesNoPartialKey(t *testing.T) {
	// Force key generation to fail after the file has already been created.
	orig := signingRand
	signingRand = errReader{}
	t.Cleanup(func() { signingRand = orig })

	keyPath := filepath.Join(t.TempDir(), "keys", "audit.key")
	if _, err := loadOrCreateSigner(keyPath); err == nil {
		t.Fatal("expected loadOrCreateSigner to fail when entropy is unavailable")
	}

	// The partial key file must have been removed — nothing left behind.
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("expected no key file after a failed create, but Lstat gave: %v", err)
	}

	// Recovery: with entropy restored, a fresh create still succeeds (the failed
	// attempt did not poison the path).
	signingRand = orig
	if _, err := loadOrCreateSigner(keyPath); err != nil {
		t.Fatalf("create after recovery failed: %v", err)
	}
	if fi, err := os.Lstat(keyPath); err != nil {
		t.Fatalf("expected a key file after recovery: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("recovered key perms: got %o, want 600", fi.Mode().Perm())
	}
}

// TestSigningKey_AcceptsUserOwnedSymlinkedDirectory pins the [MAJOR] fix: a key
// directory reached through a benign, user-owned symlink must be ACCEPTED on
// every platform. macOS temp dirs resolve /var -> /private/var and many users
// keep a symlinked ~/.config; rejecting those broke key creation outright. The
// security property is the resolved target's ownership and permissions, not the
// mere presence of a symlink in the path. Create AND load must both succeed.
func TestSigningKey_AcceptsUserOwnedSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	targetDir := filepath.Join(root, "real")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	linkDir := filepath.Join(root, "nocklock")
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Fatalf("symlink key directory: %v", err)
	}
	keyPath := filepath.Join(linkDir, "audit.key")

	if _, err := loadOrCreateSigner(keyPath); err != nil {
		t.Fatalf("user-owned symlinked key directory must be accepted for create, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "audit.key")); err != nil {
		t.Errorf("key was not created in the resolved target directory: %v", err)
	}
	if _, err := loadSigner(keyPath); err != nil {
		t.Fatalf("user-owned symlinked key directory must be accepted for load, got: %v", err)
	}
}

// TestSigningKey_RejectsSymlinkToNonPrivateDirectory keeps the malicious-target
// guard: a symlink whose RESOLVED target is group/world accessible must still be
// rejected, so a benign-looking symlink cannot smuggle in a non-private key
// directory. (A target owned by another uid is likewise rejected by the
// euid-ownership check, but that cannot be constructed unprivileged on this
// host.)
func TestSigningKey_RejectsSymlinkToNonPrivateDirectory(t *testing.T) {
	root := t.TempDir()
	targetDir := filepath.Join(root, "world")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.Chmod(targetDir, 0o755); err != nil {
		t.Fatalf("chmod target group/world accessible: %v", err)
	}
	linkDir := filepath.Join(root, "nocklock")
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Fatalf("symlink key directory: %v", err)
	}
	if _, err := loadOrCreateSigner(filepath.Join(linkDir, "audit.key")); err == nil {
		t.Fatal("expected a symlink to a group/world-accessible directory to be rejected")
	} else if !containsAny(err.Error(), "0700", "group/world") {
		t.Errorf("expected a permission error on the resolved target, got: %v", err)
	}
}

func TestSigningKey_RejectsNonPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nocklock")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir key directory: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod key directory: %v", err)
	}
	if _, err := loadOrCreateSigner(filepath.Join(dir, "audit.key")); err == nil {
		t.Fatal("expected non-private signing directory to be rejected")
	} else if !containsAny(err.Error(), "0700") {
		t.Errorf("expected 0700 permission error, got: %v", err)
	}
}

// ---------- canonical-bytes reuse (sign over the SAME bytes v1 hashes) ----------

func TestSigning_SignsSameCanonicalBytesAsHash(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	evt := sampleEvent(EventSecretBlocked, "secret", "API_KEY", true, "sess-1")
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	// Read the stored row back and recompute the canonical bytes independently.
	var id int64
	var ts, et, cat, detail, sid, prevHash, entryHash, entrySig string
	var blocked int
	err := l.db.QueryRow("SELECT id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash, entry_sig FROM events ORDER BY id ASC LIMIT 1").
		Scan(&id, &ts, &et, &cat, &detail, &blocked, &sid, &prevHash, &entryHash, &entrySig)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}

	cb := canonicalBytes(id, ts, EventType(et), cat, detail, blocked != 0, sid)

	// (a) The hash covers exactly these canonical bytes.
	wantHash, err := chainEntryFromCanonical(cb, prevHash)
	if err != nil {
		t.Fatalf("chainEntryFromCanonical: %v", err)
	}
	if wantHash != entryHash {
		t.Errorf("entry_hash is not over canonicalBytes: got %s, want %s", entryHash, wantHash)
	}

	// (b) The signature verifies over the SAME canonical bytes — proof the row
	// is signed over exactly the bytes v1 hashes.
	sig, err := base64.StdEncoding.DecodeString(entrySig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, cb, sig) {
		t.Error("stored signature does not verify over the row's canonical bytes")
	}
	// It must NOT verify over anything else (flip one byte of detail).
	cbTampered := canonicalBytes(id, ts, EventType(et), cat, "API_KE!", blocked != 0, sid)
	if ed25519.Verify(pub, cbTampered, sig) {
		t.Error("signature verified over tampered canonical bytes — signing scope is wrong")
	}
}

// TestSigning_RowSignatureVerifiesOverByteLiteral pins the SIGNING contract
// independently of the encoder — the NCC #1902 lesson applied to signing. The
// test above proves the signature covers whatever canonicalBytes returns; this
// one proves what those bytes ARE, by verifying the stored entry_sig of a known
// row against a hardcoded byte string that never passes through canonicalBytes.
// It also pins the scope negatively: the row signature is over the canonical
// bytes ONLY, not over the hash-chain input (canonical || prev_hash). That
// exclusion is deliberate — it is what lets a prune re-anchor the chain while
// every surviving row signature stays valid (see Prune and the prune tests).
func TestSigning_RowSignatureVerifiesOverByteLiteral(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	// The same known row TestCanonicalBytes_ByteLiteralPin (logger_test.go)
	// pins for the hash; a fresh DB assigns it id=1.
	evt := Event{
		Timestamp: time.Date(2025, 3, 15, 10, 30, 45, 123456789, time.UTC),
		EventType: EventSecretBlocked,
		Category:  "secret",
		Detail:    "API_KEY",
		Blocked:   true,
		SessionID: "sess-1",
	}
	if err := l.Log(evt); err != nil {
		t.Fatalf("Log: %v", err)
	}

	var id int64
	var entrySig string
	if err := l.db.QueryRow("SELECT id, entry_sig FROM events ORDER BY id ASC LIMIT 1").Scan(&id, &entrySig); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if id != 1 {
		t.Fatalf("known row should be id=1 in a fresh log, got %d", id)
	}
	sig, err := base64.StdEncoding.DecodeString(entrySig)
	if err != nil {
		t.Fatalf("decode entry_sig: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("entry_sig is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	// Hardcoded oracle (spec §2 layout), deliberately duplicated rather than
	// shared with the hash test so the two pins are independent:
	// version || u64be(id) || lp(timestamp) || lp(event_type) || lp(category)
	// || lp(detail) || blocked || lp(session_id), lp = u32be length + bytes.
	literal := []byte{
		0x01,                                           // version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // id=1 u64be
		0x00, 0x00, 0x00, 0x1e, // len("2025-03-15T10:30:45.123456789Z") = 30
		0x32, 0x30, 0x32, 0x35, 0x2d, 0x30, 0x33, 0x2d, 0x31, 0x35, 0x54, 0x31, 0x30, 0x3a, 0x33, 0x30, 0x3a, 0x34, 0x35, 0x2e, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x5a, // "2025-03-15T10:30:45.123456789Z"
		0x00, 0x00, 0x00, 0x0e, // len("secret_blocked") = 14
		0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, // "secret_blocked"
		0x00, 0x00, 0x00, 0x06, // len("secret") = 6
		0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // "secret"
		0x00, 0x00, 0x00, 0x07, // len("API_KEY") = 7
		0x41, 0x50, 0x49, 0x5f, 0x4b, 0x45, 0x59, // "API_KEY"
		0x01,                   // blocked=true
		0x00, 0x00, 0x00, 0x06, // len("sess-1") = 6
		0x73, 0x65, 0x73, 0x73, 0x2d, 0x31, // "sess-1"
	}

	if !ed25519.Verify(pub, literal, sig) {
		t.Fatalf("stored entry_sig does not verify over the hardcoded canonical byte literal: the bytes signed drifted from the pinned layout")
	}

	// Negative pin (a): NOT over the hash-chain input canonical || prev_hash.
	// prev_hash for id=1 is the genesis hash.
	chainInput := append(append([]byte{}, literal...), mustHex(t, chainGenesisHashHex)...)
	if ed25519.Verify(pub, chainInput, sig) {
		t.Error("signature verified over canonical||prev_hash: the row signature must cover canonical bytes only")
	}

	// Negative pin (b): NOT over the same row with the blocked byte flipped.
	// The blocked byte sits immediately before lp(session_id).
	flipped := append([]byte{}, literal...)
	blockedOff := len(literal) - (4 + len("sess-1")) - 1
	if flipped[blockedOff] != 0x01 {
		t.Fatalf("pinned blocked-byte offset %d holds %#x, want 0x01", blockedOff, flipped[blockedOff])
	}
	flipped[blockedOff] = 0x00
	if ed25519.Verify(pub, flipped, sig) {
		t.Error("signature verified with the blocked bit flipped: the blocked byte is not covered")
	}
}

// TestHeadCanonicalBytes_ByteLiteralPin pins the versioned head layout so a row
// signature can never be replayed as a head signature and metadata cannot be
// silently omitted from its authentication scope.
func TestHeadCanonicalBytes_ByteLiteralPin(t *testing.T) {
	headHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	prunedAt := "2026-09-17T15:00:00Z"
	prunedCount := 4
	signedGenesisAt := "2026-09-17T14:00:00Z"
	unsignedThroughID := int64(3)
	fingerprint := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cb, err := headCanonicalBytes(headHash, 5, headSignatureMetadata{
		prunedAt:                &prunedAt,
		prunedCount:             &prunedCount,
		signedGenesisAt:         &signedGenesisAt,
		unsignedThroughID:       &unsignedThroughID,
		publicKeyFingerprintHex: fingerprint,
	})
	if err != nil {
		t.Fatalf("headCanonicalBytes: %v", err)
	}
	want := []byte{0x03} // domain tag distinct from the 0x01 row version
	want = append(want, mustHex(t, headHash)...)
	var cnt [8]byte
	binary.BigEndian.PutUint64(cnt[:], 5)
	want = append(want, cnt[:]...)
	want = append(want, 1, 0, 0, 0, byte(len(prunedAt)))
	want = append(want, prunedAt...)
	want = append(want, 1, 0, 0, 0, 0, 0, 0, 0, 4)
	want = append(want, 1, 0, 0, 0, byte(len(signedGenesisAt)))
	want = append(want, signedGenesisAt...)
	want = append(want, 1, 0, 0, 0, 0, 0, 0, 0, 3)
	want = append(want, mustHex(t, fingerprint)...)
	if !bytesEqual(cb, want) {
		t.Errorf("head canonical bytes mismatch:\ngot:  %x\nwant: %x", cb, want)
	}
	if len(cb) != len(want) {
		t.Errorf("head canonical length %d, want %d", len(cb), len(want))
	}
}

// ---------- sign -> verify happy path ----------

func TestSigning_VerifyAuthentic(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	for i := 0; i < 5; i++ {
		if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/tmp/x", false, "s")); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	res, err := l.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !res.Intact {
		t.Fatalf("chain should be intact: %s", res.BrokenReason)
	}
	if res.SigState != "authentic" {
		t.Errorf("SigState = %q, want authentic (%s)", res.SigState, res.SigBrokenReason)
	}
	if res.SigVerified != 5 || res.SignedEntries != 5 || res.UnsignedEntries != 0 {
		t.Errorf("counts: verified=%d signed=%d unsigned=%d, want 5/5/0", res.SigVerified, res.SignedEntries, res.UnsignedEntries)
	}
	if !res.HeadSigned {
		t.Error("head should be signed")
	}
}

func TestSigning_LogBatchAuthentic(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	batch := []Event{
		sampleEvent(EventSecretBlocked, "secret", "A", true, "s"),
		sampleEvent(EventSecretBlocked, "secret", "B", true, "s"),
		sampleEvent(EventSecretBlocked, "secret", "C", true, "s"),
	}
	if err := l.LogBatch(batch); err != nil {
		t.Fatalf("LogBatch: %v", err)
	}
	res, err := l.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !res.Intact || res.SigState != "authentic" || res.SigVerified != 3 {
		t.Errorf("batch not authentic: intact=%v state=%q verified=%d (%s)", res.Intact, res.SigState, res.SigVerified, res.SigBrokenReason)
	}
}

// ---------- tamper -> FORGED ----------

func TestSigning_TamperedRowIsForged(t *testing.T) {
	l, keyPath, pub := newSigningLogger(t)
	dbPath := ""
	// Recover db path for reopening.
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(sampleEvent(EventNetworkPassed, "network", "example.com", false, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	l.Close()

	// Tamper directly: rewrite the hash chain consistently (an active writer can
	// do this — that is exactly what the unkeyed chain cannot resist) but the
	// attacker lacks the key, so the signature will not match the new content.
	tamperRowAndRechain(t, dbPath, 2, "evil.example.com")

	// Reopen WITHOUT signing (read-only verify path) and check with the pubkey.
	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	res, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if res.SigState != "forged" {
		t.Errorf("tampered signed row: SigState = %q, want forged", res.SigState)
	}
	if res.SigBrokenID != 2 {
		t.Errorf("SigBrokenID = %d, want 2", res.SigBrokenID)
	}
	_ = keyPath
}

// ---------- chain_head signature verify: the truncation upgrade ----------

// TestSigning_HeadSignatureCatchesLockstepTruncation is the marquee test: it is
// the v1 "rewritten tail + rewritten chain_head appears intact" attack, now
// caught by the head signature. The hash layer still reads CONSISTENT (v1's
// documented limit), but VerifyChainSigned reports FORGED.
func TestSigning_HeadSignatureCatchesLockstepTruncation(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Log(sampleEvent(EventFileBlocked, "filesystem", "/etc/shadow", true, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	l.Close()

	// Attacker with file access truncates to 3 rows and rewrites chain_head's
	// hash + count in lockstep (defeats every v1 check) but cannot forge the
	// head signature without the key.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	var hashAt3 string
	if err := db.QueryRow("SELECT entry_hash FROM events WHERE id = 3").Scan(&hashAt3); err != nil {
		t.Fatalf("read hash@3: %v", err)
	}
	if _, err := db.Exec("DELETE FROM events WHERE id > 3"); err != nil {
		t.Fatalf("delete tail: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET entry_hash = ?, row_count = 3 WHERE id = 1", hashAt3); err != nil {
		t.Fatalf("rewrite head: %v", err)
	}
	db.Close()

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	// Hash-only verify is fooled (documents the v1 limit).
	hashOnly, err := l2.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !hashOnly.Intact {
		t.Fatalf("hash-only verify should still read intact (v1 limit): %s", hashOnly.BrokenReason)
	}

	// Signed verify catches it via the head signature.
	signed, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if signed.SigState != "forged" {
		t.Errorf("lockstep truncation: SigState = %q, want forged", signed.SigState)
	}
	if !containsAny(signed.SigBrokenReason, "chain_head") {
		t.Errorf("expected a chain_head signature failure, got: %q", signed.SigBrokenReason)
	}
}

func TestSigning_StrippedRowSignatureIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/tmp/x", false, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	l.Close()

	// Strip a post-adoption row's signature (attacker removes the sig column).
	db, _ := sql.Open("sqlite", dbPath)
	if _, err := db.Exec("UPDATE events SET entry_sig = '' WHERE id = 2"); err != nil {
		t.Fatalf("strip sig: %v", err)
	}
	db.Close()

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	res, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if res.SigState != "forged" {
		t.Errorf("stripped sig: SigState = %q, want forged (%s)", res.SigState, res.SigBrokenReason)
	}
	if res.SigBrokenID != 2 {
		t.Errorf("SigBrokenID = %d, want 2", res.SigBrokenID)
	}
}

func TestSigning_StrippedSignatureCannotBeHiddenByRewritingAdoptionBoundary(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/x", false, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	// An attacker strips a row signature, then raises the unsigned prefix
	// boundary to recast it as pre-adoption. The authenticated head metadata
	// must make this report FORGED rather than AUTHENTIC.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE events SET entry_sig = '' WHERE id = 2"); err != nil {
		t.Fatalf("strip signature: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET unsigned_through_id = 2 WHERE id = 1"); err != nil {
		t.Fatalf("rewrite adoption boundary: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	res, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if res.SigState != "forged" || !containsAny(res.SigBrokenReason, "chain_head") {
		t.Errorf("rewritten adoption boundary: state=%q reason=%q, want forged chain_head failure", res.SigState, res.SigBrokenReason)
	}
}

func TestSigning_RemovedAdoptionMarkerWithSigningArtifactsIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/x", false, "s")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET signed_genesis_at = NULL, unsigned_through_id = NULL, signing_pubkey_fingerprint = '' WHERE id = 1"); err != nil {
		t.Fatalf("remove adoption marker: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	res, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if res.SigState != "forged" || !containsAny(res.SigBrokenReason, "adoption marker") {
		t.Errorf("removed adoption marker: state=%q reason=%q, want forged missing-marker failure", res.SigState, res.SigBrokenReason)
	}
}

func TestSigning_ExplicitKeyRejectsCompleteSignatureStripping(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/x", false, "s")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE events SET entry_sig = ''"); err != nil {
		t.Fatalf("remove row signatures: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET head_sig = '', signed_genesis_at = NULL, unsigned_through_id = NULL, signing_pubkey_fingerprint = '' WHERE id = 1"); err != nil {
		t.Fatalf("remove signing metadata: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	// Without an external signing expectation, a completely erased record is
	// indistinguishable from a valid legacy unsigned log.
	fallback, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("fallback VerifyChainSigned: %v", err)
	}
	if fallback.SigState != "unsigned" {
		t.Fatalf("fallback state = %q, want unsigned", fallback.SigState)
	}

	// With an explicit external signing expectation, a completely erased record
	// must never read as a clean pass: it surfaces as the distinct SUSPECT state
	// (a full strip is indistinguishable from never-signed on disk, so it is not
	// FORGED — that requires a detectable inconsistency or a real mismatch).
	required, err := l2.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("required VerifyChainSigned: %v", err)
	}
	if required.SigState != "suspect" {
		t.Errorf("complete signature stripping with required signing: state=%q reason=%q, want suspect", required.SigState, required.SigBrokenReason)
	}
	if !containsAny(required.SigBrokenReason, "required", "stripped") {
		t.Errorf("suspect reason should explain the required-but-missing signatures, got: %q", required.SigBrokenReason)
	}
}

// TestSigning_CompleteDeletionWithRequiredSigningIsSuspect covers the
// truncation-to-zero case: a writer deletes EVERY event, strips every signing
// artifact, and resets chain_head to the unsigned genesis state. Without an
// external expectation that reads as a legitimately empty unsigned log; with an
// explicitly supplied key it must be SUSPECT (non-zero), never a clean pass —
// otherwise the signed head's truncation protection would have a hole at zero
// rows. Both the "chain_head reset" and the "chain_head row removed" shapes are
// exercised.
func TestSigning_CompleteDeletionWithRequiredSigningIsSuspect(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := l.Log(sampleEvent(EventSecretBlocked, "secret", "TOKEN", true, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("DELETE FROM events"); err != nil {
		t.Fatalf("delete every event: %v", err)
	}
	if _, err := db.Exec(
		"UPDATE chain_head SET entry_hash = ?, row_count = 0, head_sig = '', signed_genesis_at = NULL, unsigned_through_id = NULL, signing_pubkey_fingerprint = '' WHERE id = 1",
		chainGenesisHashHex,
	); err != nil {
		t.Fatalf("reset chain_head to unsigned genesis: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	required, err := l2.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("required VerifyChainSigned: %v", err)
	}
	if !required.Intact || required.EntriesVerified != 0 {
		t.Fatalf("hash layer of an emptied log: intact=%v entries=%d, want intact/0", required.Intact, required.EntriesVerified)
	}
	if required.SigState != "suspect" {
		t.Errorf("complete deletion with required signing: state=%q reason=%q, want suspect", required.SigState, required.SigBrokenReason)
	}
	if !containsAny(required.SigBrokenReason, "required") {
		t.Errorf("suspect reason should say signing was required, got: %q", required.SigBrokenReason)
	}

	// No external expectation: an empty unsigned log is just that.
	fallback, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("fallback VerifyChainSigned: %v", err)
	}
	if fallback.SigState != "unsigned" {
		t.Errorf("complete deletion without required signing: state=%q, want unsigned", fallback.SigState)
	}

	// The other shape: no chain_head row at all (removed underneath an open
	// logger, since opening re-initialises it). Still suspect when required.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw again: %v", err)
	}
	if _, err := raw.Exec("DELETE FROM chain_head"); err != nil {
		t.Fatalf("delete chain_head: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}
	noHead, err := l2.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("no-chain_head VerifyChainSigned: %v", err)
	}
	if !noHead.Intact || noHead.SigState != "suspect" {
		t.Errorf("missing chain_head with required signing: intact=%v state=%q reason=%q, want intact/suspect", noHead.Intact, noHead.SigState, noHead.SigBrokenReason)
	}
	noHeadFallback, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("no-chain_head fallback VerifyChainSigned: %v", err)
	}
	if noHeadFallback.SigState != "unsigned" {
		t.Errorf("missing chain_head without required signing: state=%q, want unsigned", noHeadFallback.SigState)
	}
}

// ---------- wrong public key -> FORGED ----------

// TestSigning_WrongPublicKeyIsForged: a signed, untouched log checked against a
// key that is not the signer's must FAIL, in both the derived-key and the
// required-key modes. The first line of defence is the authenticated fingerprint;
// if the attacker rewrites that to match the wrong key, the row and head
// signatures themselves still do not verify.
func TestSigning_WrongPublicKeyIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(sampleEvent(EventFileBlocked, "filesystem", "/etc/shadow", true, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unrelated key: %v", err)
	}
	if wrongPub.Equal(pub) {
		t.Fatal("unrelated key collided with the signing key")
	}

	for _, require := range []bool{false, true} {
		res, err := l.VerifyChainSigned(wrongPub, require)
		if err != nil {
			t.Fatalf("VerifyChainSigned(wrong key, require=%v): %v", require, err)
		}
		if !res.Intact {
			t.Fatalf("hash layer must be intact (the log is untouched): %s", res.BrokenReason)
		}
		if res.SigState != "forged" || !containsAny(res.SigBrokenReason, "fingerprint") {
			t.Errorf("wrong key (require=%v): state=%q reason=%q, want forged with a fingerprint mismatch", require, res.SigState, res.SigBrokenReason)
		}
	}

	// The right key still reads authentic: the failure above is the key, not the log.
	right, err := l.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned(right key): %v", err)
	}
	if right.SigState != "authentic" {
		t.Errorf("right key: state=%q reason=%q, want authentic", right.SigState, right.SigBrokenReason)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	// Attacker rewrites the stored fingerprint to the wrong key's. The rows were
	// signed by the real key, so the very first row signature fails against it.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET signing_pubkey_fingerprint = ? WHERE id = 1", publicKeyFingerprint(wrongPub)); err != nil {
		t.Fatalf("rewrite fingerprint: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}
	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	res, err := l2.VerifyChainSigned(wrongPub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned(wrong key, rewritten fingerprint): %v", err)
	}
	if res.SigState != "forged" || res.SigBrokenID != 1 {
		t.Errorf("wrong key with rewritten fingerprint: state=%q brokenID=%d reason=%q, want forged at entry 1", res.SigState, res.SigBrokenID, res.SigBrokenReason)
	}
}

// ---------- tamper classes with a lockstep re-chain: hash-only is fooled, signing is not ----------

// TestSigning_BlockedBitFlipWithRechainIsForged: an active writer flips a row's
// blocked bit (the "make an exfiltration attempt read as passed" edit) and
// recomputes the hash chain forward, which defeats every v1 check. The row's
// signature covers the blocked byte and the attacker cannot re-sign, so signed
// verification reports FORGED at that row.
func TestSigning_BlockedBitFlipWithRechainIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(sampleEvent(EventSecretBlocked, "secret", "API_KEY", true, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE events SET blocked = 0 WHERE id = 2"); err != nil {
		t.Fatalf("flip blocked bit: %v", err)
	}
	rechainAll(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	hashOnly, err := l2.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !hashOnly.Intact {
		t.Fatalf("hash-only verify should be fooled by a lockstep re-chain (v1 limit): %s", hashOnly.BrokenReason)
	}
	signed, err := l2.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if signed.SigState != "forged" || signed.SigBrokenID != 2 {
		t.Errorf("flipped blocked bit: state=%q brokenID=%d reason=%q, want forged at entry 2", signed.SigState, signed.SigBrokenID, signed.SigBrokenReason)
	}
}

// TestSigning_MiddleRowDeletionWithRechainIsForged: deleting a middle row and
// re-chaining leaves every SURVIVING row signature valid (each covers its own
// canonical bytes, whose ids are unchanged), so the row layer alone would pass.
// The chain_head signature — over the head hash and row count — is what catches
// it: the attacker cannot re-sign the new head. This is the head signature's
// justification in one test.
func TestSigning_MiddleRowDeletionWithRechainIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	for i := 0; i < 4; i++ {
		if err := l.Log(sampleEvent(EventNetworkBlocked, "network", "exfil.example", true, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("DELETE FROM events WHERE id = 2"); err != nil {
		t.Fatalf("delete middle row: %v", err)
	}
	rechainAll(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	hashOnly, err := l2.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !hashOnly.Intact || hashOnly.EntriesVerified != 3 {
		t.Fatalf("hash-only verify should be fooled by a lockstep re-chain (v1 limit): intact=%v entries=%d (%s)", hashOnly.Intact, hashOnly.EntriesVerified, hashOnly.BrokenReason)
	}
	signed, err := l2.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if signed.SigVerified != 3 {
		t.Errorf("surviving row signatures should still verify: SigVerified=%d, want 3", signed.SigVerified)
	}
	if signed.SigState != "forged" || signed.SigBrokenID != 0 || !containsAny(signed.SigBrokenReason, "chain_head") {
		t.Errorf("deleted middle row: state=%q brokenID=%d reason=%q, want forged via chain_head", signed.SigState, signed.SigBrokenID, signed.SigBrokenReason)
	}
}

// ---------- no key, but signatures present -> unverified (No-Silent-Success) ----------

func TestSigning_NoKeyWithSignaturesIsUnverifiedNotAuthentic(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	for i := 0; i < 3; i++ {
		if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/tmp/x", false, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	// Hash-only verify (no pubkey): signatures are present but unchecked.
	res, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Intact {
		t.Fatalf("should be intact: %s", res.BrokenReason)
	}
	if res.SigState != "unverified" {
		t.Errorf("SigState = %q, want unverified (never authentic without a key)", res.SigState)
	}
	if res.SignedEntries != 3 {
		t.Errorf("SignedEntries = %d, want 3", res.SignedEntries)
	}
}

// ---------- migration boundary: pre-genesis unsigned+consistent, post-genesis signed ----------

func TestSigning_MigrationBoundary(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "events.db")
	keyPath := filepath.Join(t.TempDir(), "keys", "audit.key")

	// Phase 1: a pre-adoption (v1 hash-chain) log with 3 unsigned rows.
	l1, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("phase1 open: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l1.Log(sampleEvent(EventFilePassed, "filesystem", "/pre", false, "s")); err != nil {
			t.Fatalf("phase1 Log: %v", err)
		}
	}
	l1.Close()

	// Phase 2: adopt signing and add 2 signed rows.
	l2, err := NewLogger(dbPath, "", WithSigning(keyPath))
	if err != nil {
		t.Fatalf("phase2 open: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := l2.Log(sampleEvent(EventSecretBlocked, "secret", "post", true, "s")); err != nil {
			t.Fatalf("phase2 Log: %v", err)
		}
	}
	pub, err := LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatalf("load pub: %v", err)
	}
	res, err := l2.VerifyChainSigned(pub, false)
	l2.Close()
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !res.Intact {
		t.Fatalf("mixed chain should be intact: %s", res.BrokenReason)
	}
	// The pre-adoption unsigned rows must be treated as UNSIGNED-but-consistent,
	// NOT forged; the whole log is authentic for what was signed.
	if res.SigState != "authentic" {
		t.Errorf("SigState = %q, want authentic (%s)", res.SigState, res.SigBrokenReason)
	}
	if res.UnsignedEntries != 3 {
		t.Errorf("UnsignedEntries = %d, want 3 (pre-adoption)", res.UnsignedEntries)
	}
	if res.SignedEntries != 2 || res.SigVerified != 2 {
		t.Errorf("signed=%d verified=%d, want 2/2", res.SignedEntries, res.SigVerified)
	}
	if res.UnsignedThroughID != 3 {
		t.Errorf("UnsignedThroughID = %d, want 3", res.UnsignedThroughID)
	}
	if res.SignedGenesisAt == nil {
		t.Error("SignedGenesisAt should be set after adoption")
	}
}

// ---------- fail-closed: adopted log opened without a key refuses to write ----------

func TestSigning_AdoptedLogWithoutKeyFailsClosed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "events.db")
	keyPath := filepath.Join(t.TempDir(), "keys", "audit.key")

	l1, err := NewLogger(dbPath, "", WithSigning(keyPath))
	if err != nil {
		t.Fatalf("signing open: %v", err)
	}
	if err := l1.Log(sampleEvent(EventFilePassed, "filesystem", "/x", false, "s")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	l1.Close()

	// Reopen without the key and try to write — must be refused, not silently
	// written unsigned.
	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	if err := l2.Log(sampleEvent(EventFilePassed, "filesystem", "/y", false, "s")); err == nil {
		t.Fatal("expected an unsigned write to an adopted log to fail closed, got nil error")
	}
	if err := l2.LogBatch([]Event{sampleEvent(EventFilePassed, "filesystem", "/z", false, "s")}); err == nil {
		t.Fatal("expected LogBatch to fail closed on an adopted log without a key")
	}
	if _, err := l2.Prune(time.Nanosecond); err == nil {
		t.Fatal("expected Prune to fail closed on an adopted log without a key")
	}
}

// ---------- prune keeps row signatures valid and re-signs the head ----------

func TestSigning_PrunePreservesRowSignaturesAndResignsHead(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	old := sampleEvent(EventFilePassed, "filesystem", "/old", false, "s")
	old.Timestamp = time.Now().Add(-48 * time.Hour)
	if err := l.Log(old); err != nil {
		t.Fatalf("Log old: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/new", false, "s")); err != nil {
			t.Fatalf("Log new: %v", err)
		}
	}
	n, err := l.Prune(24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	res, err := l.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !res.Intact {
		t.Fatalf("post-prune chain should be intact: %s", res.BrokenReason)
	}
	if res.SigState != "authentic" {
		t.Errorf("post-prune SigState = %q, want authentic (%s) — row sigs must survive a prune and the head must be re-signed", res.SigState, res.SigBrokenReason)
	}
	if res.SigVerified != 3 {
		t.Errorf("SigVerified = %d, want 3", res.SigVerified)
	}
}

func TestSigning_RewrittenPruneMetadataIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	old := sampleEvent(EventFilePassed, "filesystem", "/old", false, "s")
	old.Timestamp = time.Now().Add(-48 * time.Hour)
	if err := l.Log(old); err != nil {
		t.Fatalf("Log old: %v", err)
	}
	if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/new", false, "s")); err != nil {
		t.Fatalf("Log new: %v", err)
	}
	if _, err := l.Prune(24 * time.Hour); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET pruned_count = pruned_count + 1 WHERE id = 1"); err != nil {
		t.Fatalf("rewrite prune count: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	res, err := l2.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if res.SigState != "forged" || !containsAny(res.SigBrokenReason, "chain_head") {
		t.Errorf("rewritten prune metadata: state=%q reason=%q, want forged chain_head failure", res.SigState, res.SigBrokenReason)
	}
}

func TestSigning_AdoptedLogRejectsMissingOrReplacementKey(t *testing.T) {
	l, keyPath, _ := newSigningLogger(t)
	var dbPath string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&dbPath); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/x", false, "s")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove original key: %v", err)
	}
	if _, err := NewLogger(dbPath, "", WithSigning(keyPath)); err == nil {
		t.Fatal("expected adopted log to reject a missing signing key")
	}
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Errorf("adopted log created a replacement key: %v", err)
	}

	replacementPath := filepath.Join(t.TempDir(), "keys", "replacement.key")
	replacement, err := loadOrCreateSigner(replacementPath)
	if err != nil {
		t.Fatalf("create replacement key: %v", err)
	}
	replacementSeed, err := os.ReadFile(replacementPath)
	if err != nil {
		t.Fatalf("read replacement key: %v", err)
	}
	if err := os.WriteFile(keyPath, replacementSeed, 0o600); err != nil {
		t.Fatalf("replace managed key: %v", err)
	}
	if _, err := NewLogger(dbPath, "", WithSigning(keyPath)); err == nil {
		t.Fatal("expected adopted log to reject a replacement signing key")
	} else if !containsAny(err.Error(), "does not match", "fingerprint") {
		t.Errorf("expected key fingerprint mismatch, got: %v", err)
	}

	// Rewriting the database fingerprint to match the replacement key is still
	// not enough: the existing authenticated head must verify before a signer
	// can append and replace it.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET signing_pubkey_fingerprint = ? WHERE id = 1", publicKeyFingerprint(replacement.pub)); err != nil {
		t.Fatalf("rewrite signing fingerprint: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}
	if _, err := NewLogger(dbPath, "", WithSigning(keyPath)); err == nil {
		t.Fatal("expected adopted log to reject a replacement key with a rewritten fingerprint")
	} else if !containsAny(err.Error(), "does not verify", "chain head") {
		t.Errorf("expected chain-head key validation error, got: %v", err)
	}
}

// ---------- concurrency (WAL, concurrent signed append) ----------

func TestSigning_ConcurrentSignedAppend(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	const goroutines = 8
	const each = 15
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*each)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/c", false, "s")); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent signed Log error: %v", err)
	}

	res, err := l.VerifyChainSigned(pub, false)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !res.Intact || res.SigState != "authentic" {
		t.Fatalf("concurrent signed log not authentic: intact=%v state=%q (%s)", res.Intact, res.SigState, res.SigBrokenReason)
	}
	if res.SigVerified != goroutines*each {
		t.Errorf("SigVerified = %d, want %d", res.SigVerified, goroutines*each)
	}
}

// ---------- v1 DB with no signing stays hash-only consistent after sig migration ----------

func TestSigning_UnsignedLogRemainsConsistent(t *testing.T) {
	l, _ := mustNewLogger(t)
	defer l.Close()
	for i := 0; i < 3; i++ {
		if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/x", false, "s")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	// No key ever adopted: hash-only verify is CONSISTENT/UNSIGNED.
	res, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Intact || res.SigState != "unsigned" {
		t.Errorf("unsigned log: intact=%v state=%q, want intact/unsigned", res.Intact, res.SigState)
	}
	if res.SignedEntries != 0 {
		t.Errorf("SignedEntries = %d, want 0", res.SignedEntries)
	}
}

// ---------- test-local helpers ----------

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	b := make([]byte, len(h)/2)
	for i := 0; i < len(b); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := h[i*2+j]
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			default:
				t.Fatalf("bad hex %q", h)
			}
		}
		b[i] = v
	}
	return b
}

// tamperRowAndRechain rewrites a row's detail and recomputes the hash chain
// forward from it — the exact move an unkeyed active writer makes. The signature
// column is left as the original (the attacker cannot re-sign without the key).
func tamperRowAndRechain(t *testing.T, dbPath string, targetID int64, newDetail string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("UPDATE events SET detail = ? WHERE id = ?", newDetail, targetID); err != nil {
		t.Fatalf("rewrite detail: %v", err)
	}
	rechainAll(t, db)
}

// rechainAll recomputes prev_hash/entry_hash for every remaining row in id
// order and rewrites chain_head's hash and count to match — the lockstep
// re-chain an unkeyed active writer performs after any edit or deletion.
// Signature columns are left untouched (the attacker has no key).
func rechainAll(t *testing.T, db *sql.DB) {
	t.Helper()

	rows, err := db.Query("SELECT id, timestamp, event_type, category, detail, blocked, session_id, prev_hash FROM events ORDER BY id ASC")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	type row struct {
		id                       int64
		ts, et, cat, detail, sid string
		blocked                  int
		prev                     string
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ts, &r.et, &r.cat, &r.detail, &r.blocked, &r.sid, &r.prev); err != nil {
			t.Fatalf("scan: %v", err)
		}
		all = append(all, r)
	}
	rows.Close()

	prev := chainGenesisHashHex
	var head string
	for _, r := range all {
		h, err := chainEntry(r.id, r.ts, EventType(r.et), r.cat, r.detail, r.blocked != 0, r.sid, prev)
		if err != nil {
			t.Fatalf("rechain: %v", err)
		}
		if _, err := db.Exec("UPDATE events SET prev_hash = ?, entry_hash = ? WHERE id = ?", prev, h, r.id); err != nil {
			t.Fatalf("update: %v", err)
		}
		prev = h
		head = h
	}
	if _, err := db.Exec("UPDATE chain_head SET entry_hash = ?, row_count = ? WHERE id = 1", head, len(all)); err != nil {
		t.Fatalf("update head: %v", err)
	}
}
