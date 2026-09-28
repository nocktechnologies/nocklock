package logging

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// dbPathOf reads the on-disk path of an open logger's SQLite database.
func dbPathOf(t *testing.T, l *Logger) string {
	t.Helper()
	var p string
	if err := l.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&p); err != nil {
		t.Fatalf("read db path: %v", err)
	}
	return p
}

// emitN logs n events on a signing logger and returns the emitted anchor.
func emitN(t *testing.T, l *Logger, n int) *Anchor {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Log(sampleEvent(EventFileBlocked, "filesystem", "/etc/shadow", true, "s")); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	a, err := l.EmitAnchor()
	if err != nil {
		t.Fatalf("EmitAnchor: %v", err)
	}
	return a
}

// ---------- pinned canonical bytes (the #1902 lesson applied to anchors) ----------

// TestAnchorCanonicalBytes_ByteLiteralPin pins the EXACT bytes signed for a
// known anchor against a hand-typed literal, independent of the encoder, so a
// future refactor cannot silently change the signed format and invalidate every
// previously emitted anchor. It signs with a real key via anchorCanonicalBytes
// and then verifies that signature against the hand-built literal: if the two
// agree, the encoder produced exactly the pinned layout. The version byte,
// length prefixes, field order, and the u64be row_count are all hand-typed; only
// the field CONTENT bytes come from []byte()/mustHex (not the encoder under
// test), matching TestSigning_RowSignatureVerifiesOverByteLiteral.
func TestAnchorCanonicalBytes_ByteLiteralPin(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	const (
		agentID   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 chars
		headHash  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // 32 bytes hex
		createdAt = "2025-03-15T10:30:45.123456789Z"                                   // 30 chars
	)
	a := &Anchor{
		Version:   AnchorVersion,
		AgentID:   agentID,
		HeadHash:  headHash,
		RowCount:  5,
		CreatedAt: createdAt,
	}
	cb, err := anchorCanonicalBytes(a)
	if err != nil {
		t.Fatalf("anchorCanonicalBytes: %v", err)
	}
	sig := ed25519.Sign(priv, cb)

	// Hand-built oracle (layout in anchor.go):
	// 0x05 || u32be(len agent_id) || agent_id || head_hash(32) || u64be(row_count) || u32be(len created_at) || created_at
	var want []byte
	want = append(want, 0x05)                   // anchorSigVersion (= AnchorVersion 1)
	want = append(want, 0x00, 0x00, 0x00, 0x40) // len(agent_id) = 64
	want = append(want, []byte(agentID)...)
	want = append(want, mustHex(t, headHash)...)                        // 32 raw bytes
	want = append(want, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05) // row_count = 5 u64be
	want = append(want, 0x00, 0x00, 0x00, 0x1e)                         // len(created_at) = 30
	want = append(want, []byte(createdAt)...)

	if !bytesEqual(cb, want) {
		t.Fatalf("anchor canonical bytes mismatch:\ngot:  %x\nwant: %x", cb, want)
	}
	if len(cb) != len(want) {
		t.Fatalf("anchor canonical length %d, want %d", len(cb), len(want))
	}
	// The signature over the encoder's bytes must verify over the hand-typed
	// literal — proof the two are byte-identical.
	if !ed25519.Verify(pub, want, sig) {
		t.Fatal("signature does not verify over the hand-typed anchor literal: the signed layout drifted")
	}

	// Domain separation: the anchor's leading byte must not collide with the row
	// (0x01) or head (0x03) version bytes.
	if cb[0] != 0x05 {
		t.Errorf("anchor domain byte = %#x, want 0x05 (distinct from row 0x01 and head 0x03)", cb[0])
	}
}

// ---------- emit -> verify happy paths ----------

func TestAnchor_EmitVerifyIntactChainPasses(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 4)
	if a.Version != AnchorVersion {
		t.Errorf("anchor version = %d, want %d", a.Version, AnchorVersion)
	}
	if a.RowCount != 4 {
		t.Errorf("anchor row_count = %d, want 4", a.RowCount)
	}
	if a.AgentID != publicKeyFingerprint(pub) {
		t.Errorf("anchor agent_id = %s, want the signing pubkey fingerprint %s", a.AgentID, publicKeyFingerprint(pub))
	}

	res, err := l.VerifyAgainstAnchor(a, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if !res.OK || res.Classification != "ok" {
		t.Errorf("intact chain: OK=%v class=%q reason=%q, want ok", res.OK, res.Classification, res.Reason)
	}
}

// TestAnchor_ChainGrownPastAnchorPasses: an anchor is a point-in-time pin; a
// chain that keeps growing after it still verifies, because the anchored head is
// reproduced at the anchored count.
func TestAnchor_ChainGrownPastAnchorPasses(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 3)
	for i := 0; i < 4; i++ {
		if err := l.Log(sampleEvent(EventNetworkPassed, "network", "example.com", false, "s")); err != nil {
			t.Fatalf("Log post-anchor: %v", err)
		}
	}
	res, err := l.VerifyAgainstAnchor(a, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if !res.OK || res.Classification != "ok" {
		t.Errorf("grown chain: OK=%v class=%q reason=%q, want ok", res.OK, res.Classification, res.Reason)
	}
	if res.LocalRowCount != 7 || res.AnchorRowCount != 3 {
		t.Errorf("counts: local=%d anchor=%d, want 7/3", res.LocalRowCount, res.AnchorRowCount)
	}
}

// ---------- the truncation teeth (RED / GREEN) ----------

// TestAnchor_TruncationDetectedWhereHashChainIsFooled is the marquee test on the
// keyless / hash-only verification path (e.g. NockCC pulled events.db and the
// anchor but not the private key). An attacker truncates the tail and rewrites
// chain_head in lockstep:
//   - RED: the hash-only VerifyChain() still reads INTACT — this is exactly the
//     documented v1 limit, so the plain (keyless) `verify --audit` PASSES.
//   - GREEN: VerifyAgainstAnchor reports TRUNCATION — the anchor pins a row
//     count the shortened local chain cannot satisfy.
func TestAnchor_TruncationDetectedWhereHashChainIsFooled(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	dbPath := dbPathOf(t, l)

	a := emitN(t, l, 5) // anchor attests 5 rows
	if a.RowCount != 5 {
		t.Fatalf("anchor row_count = %d, want 5", a.RowCount)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	// Attacker: drop the last 2 rows and rewrite chain_head to match (the v1
	// tail-truncation attack the unkeyed chain cannot resist).
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	var hashAt3 string
	if err := db.QueryRow("SELECT entry_hash FROM events WHERE id = 3").Scan(&hashAt3); err != nil {
		t.Fatalf("read hash@3: %v", err)
	}
	if _, err := db.Exec("DELETE FROM events WHERE id > 3"); err != nil {
		t.Fatalf("truncate tail: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET entry_hash = ?, row_count = 3 WHERE id = 1", hashAt3); err != nil {
		t.Fatalf("rewrite chain_head: %v", err)
	}
	db.Close()

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	// RED: the hash-only chain check is fooled — the shortened chain is
	// internally consistent, so a keyless `verify --audit` passes.
	hashOnly, err := l2.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !hashOnly.Intact {
		t.Fatalf("RED failed: hash-only VerifyChain should read intact after lockstep truncation (v1 limit), got broken: %s", hashOnly.BrokenReason)
	}

	// GREEN: the anchor catches the truncation.
	res, err := l2.VerifyAgainstAnchor(a, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if res.OK || res.Classification != "truncation" {
		t.Fatalf("GREEN failed: want truncation, got OK=%v class=%q reason=%q", res.OK, res.Classification, res.Reason)
	}
	if !containsAny(res.Reason, "anchor attests 5", "local has 3") {
		t.Errorf("truncation reason should name the counts, got: %q", res.Reason)
	}
}

// TestAnchor_RollbackToEarlierSignedSnapshotDetected is the strongest teeth: a
// rollback to an earlier, LEGITIMATELY-signed whole-database snapshot. The
// restored snapshot's head signature was valid at the time, so even the SIGNED
// verify (VerifyChainSigned) reads AUTHENTIC — signing provably cannot catch
// this (the README names rollback as the residual gap). The anchor, which pinned
// the later, larger row count, catches it as TRUNCATION.
func TestAnchor_RollbackToEarlierSignedSnapshotDetected(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "events.db")
	keyPath := filepath.Join(t.TempDir(), "keys", "audit.key")

	// Phase 1: signed log with 3 rows; snapshot the whole DB here.
	l1, err := NewLogger(dbPath, "", WithSigning(keyPath))
	if err != nil {
		t.Fatalf("phase1 open: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l1.Log(sampleEvent(EventSecretBlocked, "secret", "TOKEN", true, "s")); err != nil {
			t.Fatalf("phase1 Log: %v", err)
		}
	}
	if err := l1.Close(); err != nil {
		t.Fatalf("phase1 close: %v", err)
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot.db")
	copyFile(t, dbPath, snapshot)

	// Phase 2: append 2 more rows (N=5) and emit the anchor at 5.
	l2, err := NewLogger(dbPath, "", WithSigning(keyPath))
	if err != nil {
		t.Fatalf("phase2 open: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := l2.Log(sampleEvent(EventSecretBlocked, "secret", "TOKEN", true, "s")); err != nil {
			t.Fatalf("phase2 Log: %v", err)
		}
	}
	anchor, err := l2.EmitAnchor()
	if err != nil {
		t.Fatalf("EmitAnchor: %v", err)
	}
	if err := l2.Close(); err != nil {
		t.Fatalf("phase2 close: %v", err)
	}
	if anchor.RowCount != 5 {
		t.Fatalf("anchor row_count = %d, want 5", anchor.RowCount)
	}

	pub, err := LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatalf("load pub: %v", err)
	}

	// Attacker: roll the whole database back to the earlier signed snapshot
	// (N=3). Remove any WAL/SHM sidecars so the rolled-back main file is read.
	copyFile(t, snapshot, dbPath)
	for _, side := range []string{dbPath + "-wal", dbPath + "-shm"} {
		_ = os.Remove(side)
	}

	l3, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen rolled-back: %v", err)
	}
	defer l3.Close()

	// Signing is FOOLED: the snapshot's head was validly signed at N=3.
	signed, err := l3.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !signed.Intact || signed.SigState != "authentic" {
		t.Fatalf("rollback should read AUTHENTIC to the signed verify (its head was validly signed): intact=%v state=%q reason=%q", signed.Intact, signed.SigState, signed.SigBrokenReason)
	}

	// The anchor catches the rollback as truncation (attests 5, local has 3).
	res, err := l3.VerifyAgainstAnchor(anchor, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if res.OK || res.Classification != "truncation" {
		t.Fatalf("rollback not caught: OK=%v class=%q reason=%q, want truncation", res.OK, res.Classification, res.Reason)
	}
	if res.LocalRowCount != 3 || res.AnchorRowCount != 5 {
		t.Errorf("counts: local=%d anchor=%d, want 3/5", res.LocalRowCount, res.AnchorRowCount)
	}
}

// ---------- tamper / forged / wrong-key ----------

// TestAnchor_TamperedMiddleRowDetected: a middle row is edited and the chain is
// rewritten in lockstep so the hash-only check passes, but the recomputed
// cumulative at the anchored count no longer matches the anchored head hash.
func TestAnchor_TamperedMiddleRowDetected(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	dbPath := dbPathOf(t, l)

	a := emitN(t, l, 4)
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec("UPDATE events SET detail = 'passed.example' WHERE id = 2"); err != nil {
		t.Fatalf("tamper middle row: %v", err)
	}
	rechainAll(t, db) // lockstep re-chain so the hash-only check is fooled
	db.Close()

	l2, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	// Hash-only verify is fooled by the lockstep re-chain.
	hashOnly, err := l2.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !hashOnly.Intact {
		t.Fatalf("hash-only verify should be fooled by the lockstep re-chain: %s", hashOnly.BrokenReason)
	}

	res, err := l2.VerifyAgainstAnchor(a, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if res.OK || res.Classification != "tampered" {
		t.Errorf("tampered middle row: OK=%v class=%q reason=%q, want tampered", res.OK, res.Classification, res.Reason)
	}
}

// TestAnchor_WrongKeyIsForged: an anchor signed by one key does not verify
// against a different key. The fingerprint guard fires first; if an attacker
// rewrites agent_id to the wrong key's fingerprint, the signature itself fails.
func TestAnchor_WrongKeyIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 3)

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unrelated key: %v", err)
	}
	if wrongPub.Equal(pub) {
		t.Fatal("unrelated key collided with the signing key")
	}

	// Wrong key: the anchor's agent_id names the real signer, so the identity
	// guard fires.
	res, err := l.VerifyAgainstAnchor(a, wrongPub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor(wrong key): %v", err)
	}
	if res.OK || res.Classification != "identity_mismatch" {
		t.Errorf("wrong key: class=%q reason=%q, want identity_mismatch", res.Classification, res.Reason)
	}

	// Attacker rewrites agent_id to the wrong key's fingerprint to slip past the
	// identity guard; the signature (made by the real key) then fails.
	forged := *a
	forged.AgentID = publicKeyFingerprint(wrongPub)
	res2, err := l.VerifyAgainstAnchor(&forged, wrongPub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor(rewritten agent_id): %v", err)
	}
	if res2.OK || res2.Classification != "forged" {
		t.Errorf("rewritten agent_id: class=%q reason=%q, want forged", res2.Classification, res2.Reason)
	}
}

// TestAnchor_TamperedAnchorFieldIsForged: editing any signed field of an
// otherwise valid anchor breaks its signature.
func TestAnchor_TamperedAnchorFieldIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 3)

	// Inflate the attested row_count (a truncation cover-up): the signature no
	// longer matches.
	forged := *a
	forged.RowCount = 99
	res, err := l.VerifyAgainstAnchor(&forged, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if res.OK || res.Classification != "forged" {
		t.Errorf("tampered row_count: class=%q reason=%q, want forged", res.Classification, res.Reason)
	}
}

// TestAnchor_NoKeyCannotAuthenticate: without a public key, an anchor cannot be
// authenticated, so verification fails closed (never a hash-only pass).
func TestAnchor_NoKeyCannotAuthenticate(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 2)
	res, err := l.VerifyAgainstAnchor(a, nil)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor(nil key): %v", err)
	}
	if res.OK || res.Classification != "no_key" {
		t.Errorf("nil key: class=%q reason=%q, want no_key", res.Classification, res.Reason)
	}
}

// TestAnchor_UnsupportedVersionIsForged rejects a future anchor version before
// any signature work.
func TestAnchor_UnsupportedVersionIsForged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 2)
	a.Version = 2
	res, err := l.VerifyAgainstAnchor(a, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if res.OK || res.Classification != "forged" || !containsAny(res.Reason, "version") {
		t.Errorf("unsupported version: class=%q reason=%q, want forged version error", res.Classification, res.Reason)
	}
}

// TestAnchor_EmitRequiresSigningKey: an unsigned logger cannot emit an anchor.
func TestAnchor_EmitRequiresSigningKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "events.db")
	l, err := NewLogger(dbPath, "") // no signing
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()
	if err := l.Log(sampleEvent(EventFilePassed, "filesystem", "/x", false, "s")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if _, err := l.EmitAnchor(); err == nil {
		t.Fatal("expected EmitAnchor to fail on an unsigned logger, got nil error")
	}
}

// TestAnchor_WriteReadRoundTrip: an emitted anchor survives WriteAnchor +
// ReadAnchor unchanged and verifies from disk, at 0600.
func TestAnchor_WriteReadRoundTrip(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 3)
	path := filepath.Join(t.TempDir(), "chain-anchor.json")
	if err := WriteAnchor(path, a); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat anchor: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("anchor perms = %o, want 600", fi.Mode().Perm())
	}
	got, err := ReadAnchor(path)
	if err != nil {
		t.Fatalf("ReadAnchor: %v", err)
	}
	if got.Sig != a.Sig || got.HeadHash != a.HeadHash || got.RowCount != a.RowCount || got.AgentID != a.AgentID || got.CreatedAt != a.CreatedAt || got.Version != a.Version {
		t.Errorf("round-tripped anchor differs: got %+v, want %+v", got, a)
	}
	res, err := l.VerifyAgainstAnchor(got, pub)
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor(from disk): %v", err)
	}
	if !res.OK {
		t.Errorf("anchor read from disk should verify: class=%q reason=%q", res.Classification, res.Reason)
	}
}

// TestAnchor_EmitVerifyOverStoredSignatureRoundTrip proves the emitted Sig is a
// real Ed25519 signature over the anchor's canonical bytes.
func TestAnchor_EmitVerifyOverStoredSignatureRoundTrip(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()

	a := emitN(t, l, 2)
	cb, err := anchorCanonicalBytes(a)
	if err != nil {
		t.Fatalf("anchorCanonicalBytes: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, cb, sig) {
		t.Error("emitted anchor signature does not verify over its canonical bytes")
	}
}

// copyFile copies src to dst byte-for-byte (used to snapshot/roll back a DB).
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open src %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("create dst %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatalf("copy %s -> %s: %v", src, dst, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close dst %s: %v", dst, err)
	}
}
