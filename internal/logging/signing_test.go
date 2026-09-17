package logging

import (
	"crypto/ed25519"
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
	keyPath := filepath.Join(t.TempDir(), "signing-ed25519.key")
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
	keyPath := filepath.Join(t.TempDir(), "sub", "signing-ed25519.key")
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
	keyPath := filepath.Join(t.TempDir(), "signing-ed25519.key")
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
	realKey := filepath.Join(dir, "real.key")
	if _, err := loadOrCreateSigner(realKey); err != nil {
		t.Fatalf("create real key: %v", err)
	}
	linkPath := filepath.Join(dir, "signing-ed25519.key")
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

	keyPath := filepath.Join(t.TempDir(), "signing-ed25519.key")
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

// TestHeadCanonicalBytes_ByteLiteralPin pins the domain-separated head layout so
// a row signature can never be replayed as a head signature.
func TestHeadCanonicalBytes_ByteLiteralPin(t *testing.T) {
	headHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	cb, err := headCanonicalBytes(headHash, 5)
	if err != nil {
		t.Fatalf("headCanonicalBytes: %v", err)
	}
	want := []byte{0x02} // domain tag distinct from the 0x01 row version
	want = append(want, mustHex(t, headHash)...)
	var cnt [8]byte
	binary.BigEndian.PutUint64(cnt[:], 5)
	want = append(want, cnt[:]...)
	if !bytesEqual(cb, want) {
		t.Errorf("head canonical bytes mismatch:\ngot:  %x\nwant: %x", cb, want)
	}
	if len(cb) != 1+32+8 {
		t.Errorf("head canonical length %d, want %d", len(cb), 1+32+8)
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
	res, err := l.VerifyChainSigned(pub)
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
	res, err := l.VerifyChainSigned(pub)
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

	res, err := l2.VerifyChainSigned(pub)
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
	signed, err := l2.VerifyChainSigned(pub)
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
	res, err := l2.VerifyChainSigned(pub)
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
	keyPath := filepath.Join(t.TempDir(), "signing-ed25519.key")

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
	res, err := l2.VerifyChainSigned(pub)
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
	keyPath := filepath.Join(t.TempDir(), "signing-ed25519.key")

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
	res, err := l.VerifyChainSigned(pub)
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

	res, err := l.VerifyChainSigned(pub)
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
