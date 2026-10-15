package logging

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// ---------- helpers ----------

// seedSigned appends n signed rows through the normal append path.
func seedSigned(t *testing.T, l *Logger, n int) {
	t.Helper()
	seedWalkChain(t, l, n)
}

// recordReceipt runs a full signed verification with the signing key so
// verifyChain records a verify_receipt, then returns the stored receipt. It is
// the only way a receipt is created: a key holder verifies a clean prefix.
func recordReceipt(t *testing.T, l *Logger, pub ed25519.PublicKey) *verifyReceipt {
	t.Helper()
	res, err := l.VerifyChainSigned(pub, true)
	if err != nil || res == nil || !res.Intact || res.SigState != "authentic" {
		t.Fatalf("recordReceipt: verification was not authentic: %+v %v", res, err)
	}
	r := readReceiptRaw(t, dbPathOf(t, l))
	if r == nil {
		t.Fatal("recordReceipt: no verify_receipt was written after an authentic verification")
	}
	return r
}

// readReceiptRaw reads the verify_receipt row with the production reader over a
// fresh connection, so a test sees exactly what verification would.
func readReceiptRaw(t *testing.T, dbPath string) *verifyReceipt {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin raw: %v", err)
	}
	defer tx.Rollback()
	r, err := loadVerifyReceipt(tx)
	if err != nil {
		t.Fatalf("loadVerifyReceipt: %v", err)
	}
	return r
}

// rawExec runs one statement against the DB file directly (the keyless writer).
func rawExec(t *testing.T, dbPath, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// receiptPresent reports whether a verify_receipt row exists.
func receiptPresent(t *testing.T, dbPath string) bool {
	t.Helper()
	return readReceiptRaw(t, dbPath) != nil
}

// verifyReceiptTableExists reports whether the verify_receipt table is present.
// It tolerates the table being absent (control 15 drops it to inject a write
// failure), which readReceiptRaw cannot.
func verifyReceiptTableExists(t *testing.T, dbPath string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='verify_receipt'").Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	return n > 0
}

// verifyNoSigner opens a read-only-style (no signing key) logger and verifies,
// so the oracle never writes a receipt of its own. receiptEnabled selects whether
// the receipt is consulted.
func verifyNoSigner(t *testing.T, dbPath string, pub ed25519.PublicKey, receiptEnabled bool) (*ChainVerifyResult, error) {
	t.Helper()
	l, err := NewLogger(dbPath, "")
	if err != nil {
		t.Fatalf("open no-signer logger: %v", err)
	}
	defer l.Close()
	verifyReceiptDisableRead = !receiptEnabled
	defer func() { verifyReceiptDisableRead = false }()
	return l.VerifyChainSigned(pub, true)
}

// assertReceiptEquivFull is the differential oracle: on the SAME database, the
// receipt-assisted verdict must equal the receipt-free full walk's, counter for
// counter, with the only allowed difference being that prefix signatures count as
// SigAttested under the receipt and as SigVerified in the full walk.
func assertReceiptEquivFull(t *testing.T, dbPath string, pub ed25519.PublicKey) (full, rec *ChainVerifyResult) {
	t.Helper()
	full, fullErr := verifyNoSigner(t, dbPath, pub, false)
	rec, recErr := verifyNoSigner(t, dbPath, pub, true)
	if (fullErr == nil) != (recErr == nil) {
		t.Fatalf("oracle: error mismatch full=%v rec=%v", fullErr, recErr)
	}
	if fullErr != nil {
		if !errors.Is(fullErr, ErrVerifyInterrupted) || !errors.Is(recErr, ErrVerifyInterrupted) {
			t.Fatalf("oracle: non-interruption errors full=%v rec=%v", fullErr, recErr)
		}
		return full, rec
	}
	if full.Intact != rec.Intact ||
		full.SigState != rec.SigState ||
		full.FirstBrokenID != rec.FirstBrokenID ||
		full.SigBrokenID != rec.SigBrokenID ||
		full.BrokenReason != rec.BrokenReason ||
		full.SigBrokenReason != rec.SigBrokenReason ||
		full.EntriesVerified != rec.EntriesVerified ||
		full.SignedEntries != rec.SignedEntries ||
		full.UnsignedEntries != rec.UnsignedEntries ||
		full.HeadHash != rec.HeadHash {
		t.Fatalf("oracle divergence:\n full=%+v\n rec =%+v", full, rec)
	}
	// SigVerified (this run) + SigAttested (receipt) must reconcile to the full
	// walk's SigVerified, and the receipt must never claim to verify in this run
	// what it only attests.
	if full.SigVerified != rec.SigVerified+rec.SigAttested {
		t.Fatalf("oracle: sig counters do not reconcile: full.SigVerified=%d rec.SigVerified=%d rec.SigAttested=%d",
			full.SigVerified, rec.SigVerified, rec.SigAttested)
	}
	if full.SigAttested != 0 {
		t.Fatalf("full walk must never attest: SigAttested=%d", full.SigAttested)
	}
	return full, rec
}

// ---------- negative controls ----------

// Control 1: a valid receipt plus k appended rows is authentic, and only the k
// new signatures are verified this run; the prefix is attested, not re-verified.
func TestReceiptControl1_AppendSkipsPrefixSignatures(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	const prefix, appended = 40, 7
	seedSigned(t, l, prefix)
	r := recordReceipt(t, l, pub)
	if r.ThroughID == 0 || r.ThroughCount != int64(prefix) {
		t.Fatalf("receipt should attest %d rows, got through_id=%d through_count=%d", prefix, r.ThroughID, r.ThroughCount)
	}
	seedSigned(t, l, appended)

	res, err := l.VerifyChainSigned(pub, true)
	if err != nil || !res.Intact || res.SigState != "authentic" {
		t.Fatalf("append verify not authentic: %+v %v", res, err)
	}
	if res.SigVerified != appended {
		t.Fatalf("expected only %d signatures verified this run, got %d", appended, res.SigVerified)
	}
	if res.SigAttested != prefix {
		t.Fatalf("expected %d prefix signatures attested by the receipt, got %d", prefix, res.SigAttested)
	}
	if res.SignedEntries != prefix+appended {
		t.Fatalf("signed entries = %d, want %d", res.SignedEntries, prefix+appended)
	}
	assertReceiptEquivFull(t, dbPathOf(t, l), pub)
}

// Control 2: a prefix row edited with no re-chain is tampered, the receipt is
// dropped, and the verdict matches the full walk.
func TestReceiptControl2_PrefixEditNoRechain(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	seedSigned(t, l, 20)
	recordReceipt(t, l, pub)
	dbPath := dbPathOf(t, l)
	l.Close()

	rawExec(t, dbPath, "UPDATE events SET detail = ? WHERE id = ?", "tampered-no-rechain", 5)
	full, rec := assertReceiptEquivFull(t, dbPath, pub)
	if full.Intact || full.SigState == "authentic" {
		t.Fatalf("content edit must be tampered, got %+v", full)
	}
	if rec.SigState != full.SigState {
		t.Fatalf("receipt verdict %q != full %q", rec.SigState, full.SigState)
	}
}

// Control 3: a prefix row edited WITH a keyless re-chain and laundered head
// (re-signed by a live signing Logger) is forged, caught by the digest even
// though linkage and the head signature now pass.
func TestReceiptControl3_PrefixEditRechainLaundered(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	seedSigned(t, l, 10)
	recordReceipt(t, l, pub)
	dbPath := dbPathOf(t, l)

	// Keyless edit + re-chain of a prefix row, then launder the head by appending
	// through the still-open signing Logger (it signs a head over the tampered
	// chain without re-verifying history).
	tamperRowAndRechain(t, dbPath, 4, "laundered")
	if err := l.Log(Event{Timestamp: time.Now(), EventType: EventType("walk"), Category: "test", Detail: "post", SessionID: "walk"}); err != nil {
		t.Fatal(err)
	}
	full, rec := assertReceiptEquivFull(t, dbPath, pub)
	if full.SigState != "forged" {
		t.Fatalf("laundered re-chain must be forged, got %q", full.SigState)
	}
	if rec.SigState != "forged" {
		t.Fatalf("receipt verdict %q != forged", rec.SigState)
	}
}

// Control 4: the laundered-head flow of TestHeadOnlyVerificationMissesLaunderedTamper,
// with a receipt present, is forged and EmitAnchor refuses.
func TestReceiptControl4_LaunderedHeadWithReceipt(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	for range 5 {
		if err := l.Log(Event{Timestamp: time.Now(), EventType: EventType("t"), Category: "c", Detail: "original", SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	recordReceipt(t, l, pub)
	dbPath := dbPathOf(t, l)
	tamperRowAndRechain(t, dbPath, 3, "tampered")
	if err := l.Log(Event{Timestamp: time.Now(), EventType: EventType("t"), Category: "c", Detail: "next", SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	res, err := l.VerifyChainSigned(pub, true)
	if err != nil || res.SigState != "forged" {
		t.Fatalf("laundered tamper under a receipt must be forged: %+v %v", res, err)
	}
	if _, err := l.EmitAnchor(); err == nil {
		t.Fatal("EmitAnchor must refuse the laundered chain")
	}
	assertReceiptEquivFull(t, dbPath, pub)
}

// Control 5: a prefix entry_sig altered or stripped is forged — the digest binds
// entry_sig even though the entry_hash is unchanged.
func TestReceiptControl5_PrefixSignatureTampered(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"stripped", "UPDATE events SET entry_sig = '' WHERE id = 6"},
		{"altered", "UPDATE events SET entry_sig = ? WHERE id = 6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, _, pub := newSigningLogger(t)
			seedSigned(t, l, 15)
			recordReceipt(t, l, pub)
			dbPath := dbPathOf(t, l)
			l.Close()

			if strings.Contains(tc.sql, "?") {
				// A syntactically valid but wrong signature.
				bogus := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				rawExec(t, dbPath, tc.sql, bogus)
			} else {
				rawExec(t, dbPath, tc.sql)
			}
			full, rec := assertReceiptEquivFull(t, dbPath, pub)
			if full.SigState != "forged" {
				t.Fatalf("prefix signature tamper must be forged, got %q", full.SigState)
			}
			if rec.SigState != "forged" {
				t.Fatalf("receipt verdict %q != forged", rec.SigState)
			}
		})
	}
}

// Control 6: a middle row deleted breaks linkage and is tampered under a receipt,
// matching the full walk.
func TestReceiptControl6_MiddleRowDeleted(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	seedSigned(t, l, 20)
	recordReceipt(t, l, pub)
	dbPath := dbPathOf(t, l)
	l.Close()

	rawExec(t, dbPath, "DELETE FROM events WHERE id = 8")
	full, rec := assertReceiptEquivFull(t, dbPath, pub)
	if full.Intact {
		t.Fatalf("a deleted middle row must break the chain, got %+v", full)
	}
	if rec.Intact != full.Intact || rec.BrokenReason != full.BrokenReason {
		t.Fatalf("receipt verdict diverged: rec=%+v full=%+v", rec, full)
	}
}

// Control 7: deleting the first row (prune-like) drops the receipt and is
// tampered; a real Prune re-chains, drops the receipt, and stays authentic.
func TestReceiptControl7_FirstRowDeleteVsRealPrune(t *testing.T) {
	t.Run("raw first-row delete", func(t *testing.T) {
		l, _, pub := newSigningLogger(t)
		seedSigned(t, l, 12)
		recordReceipt(t, l, pub)
		dbPath := dbPathOf(t, l)
		l.Close()
		rawExec(t, dbPath, "DELETE FROM events WHERE id = 1")
		full, _ := assertReceiptEquivFull(t, dbPath, pub)
		if full.Intact {
			t.Fatalf("raw first-row delete must be tampered, got %+v", full)
		}
	})
	t.Run("real prune", func(t *testing.T) {
		l, _, pub := newSigningLogger(t)
		defer l.Close()
		old := Event{Timestamp: time.Now().Add(-48 * time.Hour), EventType: EventType("walk"), Category: "test", Detail: "old", SessionID: "s"}
		for range 5 {
			if err := l.Log(old); err != nil {
				t.Fatal(err)
			}
		}
		seedSigned(t, l, 5)
		recordReceipt(t, l, pub)
		dbPath := dbPathOf(t, l)
		if !receiptPresent(t, dbPath) {
			t.Fatal("precondition: receipt should exist before prune")
		}
		if _, err := l.Prune(24 * time.Hour); err != nil {
			t.Fatalf("prune: %v", err)
		}
		if receiptPresent(t, dbPath) {
			t.Fatal("Prune must drop the verify_receipt")
		}
		res, err := l.VerifyChainSigned(pub, true)
		if err != nil || !res.Intact || res.SigState != "authentic" {
			t.Fatalf("pruned chain must stay authentic: %+v %v", res, err)
		}
	})
}

// Control 8: a keyless tail truncation with a rewritten head is never authentic
// under a receipt.
func TestReceiptControl8_TailTruncationRewrittenHead(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	seedSigned(t, l, 20)
	recordReceipt(t, l, pub)
	dbPath := dbPathOf(t, l)
	l.Close()
	// Remove the tail and re-chain keylessly (head rewritten, head_sig stale).
	rawExec(t, dbPath, "DELETE FROM events WHERE id > 12")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	rechainAll(t, db)
	db.Close()
	full, rec := assertReceiptEquivFull(t, dbPath, pub)
	if full.SigState == "authentic" {
		t.Fatalf("truncation with stale head must not be authentic, got %q", full.SigState)
	}
	if rec.SigState != full.SigState {
		t.Fatalf("receipt verdict %q != full %q", rec.SigState, full.SigState)
	}
}

// Control 10: a newer receipt pasted onto an older database (fewer rows) is
// ignored and the full walk runs.
func TestReceiptControl10_NewerReceiptOnOlderDB(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	seedSigned(t, l, 30)
	recordReceipt(t, l, pub) // attests 30 rows
	dbPath := dbPathOf(t, l)
	l.Close()
	// Roll the database back to fewer rows than the receipt attests, re-chaining
	// keylessly so the hash chain is internally consistent.
	rawExec(t, dbPath, "DELETE FROM events WHERE id > 10")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	rechainAll(t, db)
	db.Close()
	// The receipt (through_id 30) can no longer be reproduced; the full walk runs
	// and both verdicts agree.
	assertReceiptEquivFull(t, dbPath, pub)
}

// Control 11: forged receipts (unsigned, wrong key, replayed row/head signature,
// altered digest/head/count) are ignored; the full walk still decides.
func TestReceiptControl11_ForgedReceiptsIgnored(t *testing.T) {
	setup := func(t *testing.T) (string, ed25519.PublicKey) {
		l, _, pub := newSigningLogger(t)
		seedSigned(t, l, 15)
		recordReceipt(t, l, pub)
		dbPath := dbPathOf(t, l)
		l.Close()
		return dbPath, pub
	}
	cases := []struct {
		name string
		sql  string
		args []any
	}{
		{"unsigned", "UPDATE verify_receipt SET sig = '' WHERE id = 1", nil},
		{"replayed garbage sig", "UPDATE verify_receipt SET sig = ? WHERE id = 1", []any{base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}},
		{"altered digest", "UPDATE verify_receipt SET digest = ? WHERE id = 1", []any{strings.Repeat("ab", 32)}},
		{"altered head hash", "UPDATE verify_receipt SET through_head_hash = ? WHERE id = 1", []any{strings.Repeat("cd", 32)}},
		{"altered count", "UPDATE verify_receipt SET through_count = through_count + 1 WHERE id = 1", nil},
		{"unknown version", "UPDATE verify_receipt SET version = 99 WHERE id = 1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, pub := setup(t)
			rawExec(t, dbPath, tc.sql, tc.args...)
			// The chain itself is untouched: a forged receipt must leave the verdict
			// authentic (via a full walk), never let a bad receipt change it.
			full, rec := assertReceiptEquivFull(t, dbPath, pub)
			if full.SigState != "authentic" || rec.SigState != "authentic" {
				t.Fatalf("clean chain with a forged receipt must stay authentic: full=%q rec=%q", full.SigState, rec.SigState)
			}
			// Because the receipt was ignored, nothing was attested from it.
			if rec.SigAttested != 0 {
				t.Fatalf("ignored receipt must attest nothing, got SigAttested=%d", rec.SigAttested)
			}
		})
	}
}

// Control 12: a receipt from database B pasted into A (different bytes), and a
// receipt verified under a different key, are both ignored.
func TestReceiptControl12_CrossDBAndCrossKey(t *testing.T) {
	// Database A.
	la, _, pubA := newSigningLogger(t)
	seedSigned(t, la, 10)
	recordReceipt(t, la, pubA)
	dbA := dbPathOf(t, la)
	rA := readReceiptRaw(t, dbA)
	la.Close()

	// Database B (different content, same shape).
	lb, _, pubB := newSigningLogger(t)
	for i := range 10 {
		if err := lb.Log(Event{Timestamp: time.Now(), EventType: EventType("walk"), Category: "test", Detail: fmt.Sprintf("B-%d", i), SessionID: "walk"}); err != nil {
			t.Fatal(err)
		}
	}
	recordReceipt(t, lb, pubB)
	dbB := dbPathOf(t, lb)
	lb.Close()

	// Paste A's receipt into B. Its digest/head cannot reproduce B's rows, and its
	// fingerprint is A's key, so B ignores it and verifies in full.
	rawExec(t, dbB, "UPDATE verify_receipt SET key_fingerprint = ?, through_id = ?, through_count = ?, through_head_hash = ?, digest = ?, sig = ? WHERE id = 1",
		rA.KeyFingerprint, rA.ThroughID, rA.ThroughCount, rA.ThroughHeadHash, hex.EncodeToString(rA.Digest), rA.Sig)
	full, rec := assertReceiptEquivFull(t, dbB, pubB)
	if full.SigState != "authentic" || rec.SigAttested != 0 {
		t.Fatalf("cross-DB receipt must be ignored: full=%q attested=%d", full.SigState, rec.SigAttested)
	}

	// Cross-key: verify A with B's key. The receipt's fingerprint is A's, so B's
	// key never uses it; both runs agree (forged under the wrong key).
	full2, rec2 := assertReceiptEquivFull(t, dbA, pubB)
	if full2.SigState != rec2.SigState {
		t.Fatalf("cross-key verdict diverged: full=%q rec=%q", full2.SigState, rec2.SigState)
	}
	if rec2.SigAttested != 0 {
		t.Fatalf("a wrong-key receipt must attest nothing, got %d", rec2.SigAttested)
	}

	// Same-key, different content: the cross-DB and cross-key cases above are both
	// caught by the fingerprint check in validVerifyReceiptFor, so the rolling
	// digest `D` — the only receipt field that binds entry_sig, which the hash chain
	// does not cover — is never the deciding check. Isolate it: in a single DB,
	// strip a prefix row's entry_sig AFTER recording the receipt. The receipt row is
	// untouched, so the fingerprint and bound adoption metadata still match and
	// validVerifyReceiptFor admits it; at the boundary the through_id, through_count
	// and through_head_hash all still reproduce (entry_sig is not hashed), so ONLY
	// the digest comparison differs — the receipt is discarded on D alone and the
	// walk falls back to the full, forged verdict.
	lc, _, pubC := newSigningLogger(t)
	seedSigned(t, lc, 10)
	recordReceipt(t, lc, pubC)
	dbC := dbPathOf(t, lc)
	lc.Close()
	rawExec(t, dbC, "UPDATE events SET entry_sig = '' WHERE id = 5")
	full3, rec3 := assertReceiptEquivFull(t, dbC, pubC)
	if full3.SigState != "forged" || rec3.SigAttested != 0 {
		t.Fatalf("digest-binding case must discard the receipt and read forged: full=%q attested=%d", full3.SigState, rec3.SigAttested)
	}
}

// Control 13: changing adoption metadata the receipt binds (unsigned_through_id)
// makes the receipt no longer match the head, so it is ignored.
func TestReceiptControl13_AdoptionMetadataChanged(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	seedSigned(t, l, 12)
	recordReceipt(t, l, pub)
	dbPath := dbPathOf(t, l)
	l.Close()
	// Bump unsigned_through_id in chain_head only; the receipt bound the old value.
	rawExec(t, dbPath, "UPDATE chain_head SET unsigned_through_id = 3 WHERE id = 1")
	_, rec := verifyNoSignerPair(t, dbPath, pub)
	if rec.SigAttested != 0 {
		t.Fatalf("a receipt whose bound adoption metadata changed must be ignored, got SigAttested=%d", rec.SigAttested)
	}
}

// verifyNoSignerPair returns the full-walk and receipt-assisted results without
// asserting equivalence (used where the head was altered out from under the
// receipt so the two legitimately differ only in attestation).
func verifyNoSignerPair(t *testing.T, dbPath string, pub ed25519.PublicKey) (full, rec *ChainVerifyResult) {
	t.Helper()
	full, _ = verifyNoSigner(t, dbPath, pub, false)
	rec, _ = verifyNoSigner(t, dbPath, pub, true)
	return full, rec
}

// restoreReceipt rewrites the single verify_receipt row to r through the same
// upsert the production writer uses (verifyReceiptUpsertSQL), so the two cannot
// drift. Restoring the saved row (sig included, which covers only its own
// fields) leaves a valid receipt.
func restoreReceipt(t *testing.T, dbPath string, r *verifyReceipt) {
	t.Helper()
	rawExec(t, dbPath, verifyReceiptUpsertSQL,
		r.Version, r.KeyFingerprint, r.SignedGenesisAt, r.UnsignedThroughID, r.ThroughID, r.ThroughCount, r.ThroughHeadHash, hex.EncodeToString(r.Digest), r.Sig)
}

// Control 14: cancellation at row 0, mid-prefix, mid-suffix and the last row,
// injected by row count with a receipt present, never reads as authentic or
// tampered, and the next uninterrupted run completes with the identical verdict.
func TestReceiptControl14_InterruptionWithReceipt(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	const prefix = 2 * verifyCtxCheckInterval
	seedSigned(t, l, prefix)
	r0 := recordReceipt(t, l, pub) // attests through-prefix (id == prefix)
	dbPath := dbPathOf(t, l)
	seedSigned(t, l, 60) // suffix
	total := prefix + 60

	for _, cancelAt := range []int{0, verifyCtxCheckInterval, prefix + 10, total - 1} {
		t.Run(fmt.Sprintf("cancel@%d", cancelAt), func(t *testing.T) {
			// Reset the receipt to its through-prefix state before each subtest: the
			// previous subtest's follow-up full verify advanced it to `total`, which
			// would collapse the prefix/suffix boundary and stop the prefix+10 subtest
			// from cancelling mid-suffix (every row would be prefix).
			restoreReceipt(t, dbPath, r0)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			setWalkHook(t, func(n int) {
				if n == cancelAt {
					cancel()
				}
			})
			res, err := l.VerifyChainSignedContext(ctx, pub, true)
			if !errors.Is(err, ErrVerifyInterrupted) {
				t.Fatalf("want ErrVerifyInterrupted, got %v", err)
			}
			if res != nil {
				t.Fatalf("interrupted walk returned a verdict: %+v", res)
			}
			// A cancel mid-prefix (before the receipt boundary at `prefix`) advances no
			// attestable progress, so the interrupted walk writes no receipt and the
			// restored through-prefix receipt is untouched — never shrunk or laundered.
			if cancelAt == verifyCtxCheckInterval {
				if got := readReceiptRaw(t, dbPath); got == nil || got.ThroughID != prefix {
					t.Fatalf("mid-prefix interruption must leave the receipt at through-%d, got %+v", prefix, got)
				}
			}
			setWalkHook(t, nil)
			res, err = l.VerifyChainSigned(pub, true)
			if err != nil || !res.Intact || res.SigState != "authentic" || res.EntriesVerified != total {
				t.Fatalf("follow-up walk: %+v %v", res, err)
			}
		})
	}
}

// Control 15: a receipt write that fails leaves the verdict unchanged and writes
// nothing — proven two ways: a public-key-only verifier that never writes, and a
// key holder whose write hits a real failure (the verify_receipt table missing).
func TestReceiptControl15_WriteFailureIsHarmless(t *testing.T) {
	l, keyPath, pub := newSigningLogger(t)
	seedSigned(t, l, 10)
	dbPath := dbPathOf(t, l)
	l.Close()

	// (a) A plain no-signer logger never writes a receipt, so a verify here must
	// still be authentic and leave no receipt behind.
	res, err := verifyNoSigner(t, dbPath, pub, true)
	if err != nil || !res.Intact || res.SigState != "authentic" {
		t.Fatalf("no-signer verify must be authentic: %+v %v", res, err)
	}
	if receiptPresent(t, dbPath) {
		t.Fatal("a public-key-only verifier must never write a receipt")
	}

	// (b) Inject a REAL write failure: a key holder verifies while verify_receipt
	// is missing, so the receipt INSERT fails ("no such table"). The write is
	// best-effort, so the verdict stays authentic and nothing is written (a failed
	// INSERT cannot recreate the table). The table is dropped on a separate
	// connection AFTER the signer is open, because a Logger recreates it at open.
	signer, err := NewLogger(dbPath, "", WithExistingSigning(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	rawExec(t, dbPath, "DROP TABLE verify_receipt")
	if verifyReceiptTableExists(t, dbPath) {
		t.Fatal("precondition: the verify_receipt table should be dropped")
	}
	res, err = signer.VerifyChainSigned(pub, true)
	if err != nil || !res.Intact || res.SigState != "authentic" {
		t.Fatalf("a failed receipt write must not change the verdict: %+v %v", res, err)
	}
	if verifyReceiptTableExists(t, dbPath) {
		t.Fatal("a failed receipt write must not recreate the verify_receipt table")
	}
}

// Control 16: a chain broken at row j leaves the receipt at most through the last
// good row; a public-key-only verifier writes none.
func TestReceiptControl16_BrokenChainReceiptBounded(t *testing.T) {
	l, keyPath, pub := newSigningLogger(t)
	seedSigned(t, l, 20)
	recordReceipt(t, l, pub) // through 20
	dbPath := dbPathOf(t, l)
	l.Close()

	// Break row 12 (sig strip): rows 1..11 remain good.
	rawExec(t, dbPath, "UPDATE events SET entry_sig = '' WHERE id = 12")

	// A key holder re-verifies: the chain is forged, so verifyChain records a NEW
	// receipt bounded at prog's last fully-verified row — exactly row 11, the row
	// before the break — overwriting the stale through-20 receipt. The receipt is
	// re-proven on every use, so it can never attest past the last good row.
	signer, err := NewLogger(dbPath, "", WithExistingSigning(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	res, err := signer.VerifyChainSigned(pub, true)
	signer.Close()
	if err != nil || res.SigState != "forged" || res.SigBrokenID != 12 {
		t.Fatalf("want forged at row 12: %+v %v", res, err)
	}
	r := readReceiptRaw(t, dbPath)
	if r == nil || r.ThroughID != 11 {
		t.Fatalf("receipt must be bounded at exactly row 11 (last good before the break); through_id=%v", r)
	}

	// A public-key-only verifier on the broken chain writes nothing new.
	before := readReceiptRaw(t, dbPath)
	if _, err := verifyNoSigner(t, dbPath, pub, true); err != nil {
		t.Fatal(err)
	}
	after := readReceiptRaw(t, dbPath)
	if before.ThroughID != after.ThroughID {
		t.Fatalf("pub-key-only verify changed the receipt: %d -> %d", before.ThroughID, after.ThroughID)
	}
}

// Control 17: rows appended during verification do not enter the attested prefix;
// the receipt's through_count never exceeds the snapshot count.
func TestReceiptControl17_AppendDuringVerificationSnapshot(t *testing.T) {
	l, keyPath, pub := newSigningLogger(t)
	defer l.Close()
	seedSigned(t, l, 30)
	snapshot, err := l.VerifyChainSigned(pub, true)
	if err != nil || snapshot.SigState != "authentic" {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	r := readReceiptRaw(t, dbPathOf(t, l))
	if r == nil || r.ThroughCount > int64(snapshot.EntriesVerified) {
		t.Fatalf("receipt through_count %v exceeds snapshot %d", r, snapshot.EntriesVerified)
	}

	other, err := NewLogger(dbPathOf(t, l), "", WithExistingSigning(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	appended := false
	setWalkHook(t, func(n int) {
		if n == 10 && !appended {
			appended = true
			seedSigned(t, other, 5)
		}
	})
	res, err := l.VerifyChainSigned(pub, true)
	setWalkHook(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("hook never appended: the race was not exercised")
	}
	r2 := readReceiptRaw(t, dbPathOf(t, l))
	if r2.ThroughCount > int64(res.EntriesVerified) {
		t.Fatalf("receipt through_count %d exceeds the verified snapshot %d", r2.ThroughCount, res.EntriesVerified)
	}
}

// Control 9: a restored older complete database (its receipt included) is still
// authentic locally — the documented A2 limit — and the receipt, which moves and
// rolls back with the data, does not make the rollback any less detectable.
func TestReceiptControl9_ConsistentRollbackStillAuthentic(t *testing.T) {
	l, keyPath, pub := newSigningLogger(t)
	seedSigned(t, l, 20)
	recordReceipt(t, l, pub) // through 20
	dbPath := dbPathOf(t, l)
	backup := dbPath + ".bak"
	// Snapshot the complete older database (WAL checkpointed into the main file).
	if _, err := l.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	copyFile(t, dbPath, backup)
	seedSigned(t, l, 10)
	recordReceipt(t, l, pub) // advances to 30
	l.Close()

	// Restore the older, internally consistent database and its through-20 receipt.
	copyFile(t, backup, dbPath)
	r := readReceiptRaw(t, dbPath)
	if r == nil || r.ThroughCount != 20 {
		t.Fatalf("restored receipt should attest 20 rows, got %v", r)
	}
	ro, err := NewLogger(dbPath, "", WithExistingSigning(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	res, err := ro.VerifyChainSigned(pub, true)
	if err != nil || !res.Intact || res.SigState != "authentic" || res.EntriesVerified != 20 {
		t.Fatalf("a consistent older database must verify authentic (A2 limit): %+v %v", res, err)
	}
	if res.SigAttested != 20 {
		t.Fatalf("the restored receipt should attest its 20 rows, got %d", res.SigAttested)
	}
}

// Control 18: a differential property test. On random chains, after a random
// mutation, the receipt-assisted verdict must equal the full-walk verdict in
// every case.
func TestReceiptControl18_DifferentialProperty(t *testing.T) {
	mutations := []string{"noop", "append", "edit_rechain", "strip_sig", "delete_mid", "drop_receipt", "prune", "key_swap"}
	for seed := 0; seed < 60; seed++ {
		t.Run(fmt.Sprintf("seed%02d", seed), func(t *testing.T) {
			// A PCG stream seeded by the subtest number: a failure names its seed,
			// and re-running that seed replays the identical chain and mutation.
			rng := rand.New(rand.NewPCG(uint64(seed), 0))
			l, _, pub := newSigningLogger(t)
			n := 4 + rng.IntN(30)
			// Some old rows so a prune has something to remove.
			oldN := rng.IntN(n)
			for i := 0; i < oldN; i++ {
				if err := l.Log(Event{Timestamp: time.Now().Add(-72 * time.Hour), EventType: EventType("walk"), Category: "test", Detail: fmt.Sprintf("old-%d", i), SessionID: "s"}); err != nil {
					t.Fatal(err)
				}
			}
			seedSigned(t, l, n-oldN)
			recordReceipt(t, l, pub)
			dbPath := dbPathOf(t, l)

			verifyKey := pub
			mut := mutations[rng.IntN(len(mutations))]
			switch mut {
			case "noop":
				l.Close()
			case "append":
				seedSigned(t, l, 1+rng.IntN(8))
				l.Close()
			case "prune":
				if _, err := l.Prune(24 * time.Hour); err != nil {
					t.Fatalf("prune: %v", err)
				}
				l.Close()
			case "key_swap":
				l.Close()
				// Verify with an unrelated key: the receipt's fingerprint no longer
				// matches, so it is ignored and both runs agree under the wrong key.
				other, _, p2 := newSigningLogger(t)
				other.Close()
				verifyKey = p2
			case "edit_rechain":
				l.Close()
				tamperRowAndRechain(t, dbPath, int64(1+rng.IntN(n)), "mut")
			case "strip_sig":
				l.Close()
				rawExec(t, dbPath, "UPDATE events SET entry_sig = '' WHERE id = ?", int64(1+rng.IntN(n)))
			case "delete_mid":
				l.Close()
				if n >= 3 {
					rawExec(t, dbPath, "DELETE FROM events WHERE id = ?", int64(2+rng.IntN(n-2)))
				}
			case "drop_receipt":
				l.Close()
				rawExec(t, dbPath, "DELETE FROM verify_receipt")
			}
			assertReceiptEquivFull(t, dbPath, verifyKey)
		})
	}

	// A single random mutation never combines a detectable prefix signature break
	// with a LATER prefix link break, so the 60-seed sweep above cannot exercise the
	// bug where an early hash/link failure inside the attested prefix returns the
	// receipt walk's diagnostics instead of re-walking: strip_sig alone diverges only
	// at the boundary digest check, and delete_mid alone leaves SigBrokenID==0 on both
	// sides. This deterministic case builds the combination: row 4's signature is
	// stripped (the full walk records SigBrokenID=4; the receipt walk, skipping prefix
	// signatures, would not) and row 8's content is edited without re-chaining (an
	// entry_hash break that fires BEFORE the receipt boundary). Without the inPrefix
	// re-walk guards in walkEvents, the receipt verdict keeps FirstBrokenID=8 but
	// SigBrokenID=0, diverging from the full walk — assertReceiptEquivFull catches it.
	t.Run("sig_strip_then_link_break_in_prefix", func(t *testing.T) {
		l, _, pub := newSigningLogger(t)
		seedSigned(t, l, 12)
		recordReceipt(t, l, pub) // attests the whole 12-row prefix
		dbPath := dbPathOf(t, l)
		l.Close()
		rawExec(t, dbPath, "UPDATE events SET entry_sig = '' WHERE id = 4")      // prefix signature break
		rawExec(t, dbPath, "UPDATE events SET detail = 'tampered' WHERE id = 8") // later prefix hash break, no re-chain
		full, rec := assertReceiptEquivFull(t, dbPath, pub)
		// Guard the construction: the full walk must actually see both breaks, so the
		// equivalence above is non-vacuous (a later entry_hash verdict over an earlier
		// stripped signature).
		if full.FirstBrokenID != 8 || full.SigBrokenID != 4 {
			t.Fatalf("construction no longer exercises the combined break: FirstBrokenID=%d SigBrokenID=%d", full.FirstBrokenID, full.SigBrokenID)
		}
		if rec.FirstBrokenID != full.FirstBrokenID || rec.SigBrokenID != full.SigBrokenID {
			t.Fatalf("receipt diagnostics diverged: full=%+v rec=%+v", full, rec)
		}
	})
}

// Control 19: the mutation check. With the digest/integrity re-verification of the
// attested prefix disabled, prefix tampers that the controls catch (content edit,
// laundered re-chain, signature strip) must slip past the receipt path — proving
// the controls bite. With it enabled, every verdict matches the full walk.
func TestReceiptControl19_MutationBreaksControls(t *testing.T) {
	// Each case tampers the prefix while leaving chain_head validly signed (or
	// re-signed), so only the prefix re-verification stands between the tamper and
	// an "authentic" verdict.
	cases := []struct {
		name  string
		apply func(t *testing.T, l *Logger, dbPath string, pub ed25519.PublicKey)
	}{
		{"content edit (case 2)", func(t *testing.T, l *Logger, dbPath string, pub ed25519.PublicKey) {
			l.Close()
			rawExec(t, dbPath, "UPDATE events SET detail = 'm' WHERE id = 4")
		}},
		{"signature strip (case 5)", func(t *testing.T, l *Logger, dbPath string, pub ed25519.PublicKey) {
			l.Close()
			rawExec(t, dbPath, "UPDATE events SET entry_sig = '' WHERE id = 4")
		}},
		{"laundered re-chain (case 3)", func(t *testing.T, l *Logger, dbPath string, pub ed25519.PublicKey) {
			tamperRowAndRechain(t, dbPath, 4, "laundered")
			// Launder the head via the still-open signing Logger.
			if err := l.Log(Event{Timestamp: time.Now(), EventType: EventType("walk"), Category: "test", Detail: "post", SessionID: "walk"}); err != nil {
				t.Fatal(err)
			}
			l.Close()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _, pub := newSigningLogger(t)
			seedSigned(t, l, 12)
			recordReceipt(t, l, pub)
			dbPath := dbPathOf(t, l)
			tc.apply(t, l, dbPath, pub)

			full, _ := verifyNoSigner(t, dbPath, pub, false)

			// Seam ON: the prefix is trusted blindly, so the tamper is missed and the
			// verdict diverges from the full walk (the control bites). Reset via
			// t.Cleanup so a t.Fatalf inside the verify below cannot leak the global
			// seam into other tests.
			t.Cleanup(func() { verifyReceiptSkipDigestCheck = false })
			verifyReceiptSkipDigestCheck = true
			mutated, _ := verifyNoSigner(t, dbPath, pub, true)
			verifyReceiptSkipDigestCheck = false
			if mutated.SigState == full.SigState && mutated.Intact == full.Intact {
				t.Fatalf("mutation did not change the verdict; the control does not bite (full=%q mutated=%q)", full.SigState, mutated.SigState)
			}

			// Seam OFF: the receipt path reproduces the full verdict exactly.
			assertReceiptEquivFull(t, dbPath, pub)
		})
	}
}

// TestReceiptWriteSkippedUnderWriteContention is the contention case: a receipt
// write racing a held write lock (a live Logger append) must neither fail the
// verification nor block waiting on the lock. The write is skipped on its short
// deadline; the verdict is unchanged and no receipt appears.
func TestReceiptWriteSkippedUnderWriteContention(t *testing.T) {
	l, keyPath, pub := newSigningLogger(t)
	seedSigned(t, l, 10)
	dbPath := dbPathOf(t, l)
	l.Close()

	// Drop any receipt so a successful write would be observable.
	rawExec(t, dbPath, "DELETE FROM verify_receipt")

	// Hold the single SQLite write lock on a separate connection.
	holder, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.Exec("PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	htx, err := holder.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := htx.Exec("UPDATE chain_head SET row_count = row_count WHERE id = 1"); err != nil {
		t.Fatalf("acquire write lock: %v", err)
	}

	// A key holder verifies while the lock is held. The receipt write must give up
	// quickly on its own short deadline, not wait out the 5 s busy timeout.
	signer, err := NewLogger(dbPath, "", WithExistingSigning(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	old := verifyReceiptWriteTimeout
	verifyReceiptWriteTimeout = 150 * time.Millisecond
	defer func() { verifyReceiptWriteTimeout = old }()

	start := time.Now()
	res, err := signer.VerifyChainSigned(pub, true)
	elapsed := time.Since(start)
	if err != nil || !res.Intact || res.SigState != "authentic" {
		t.Fatalf("verification must be unaffected by the write contention: %+v %v", res, err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("verification waited on the write lock (%s); it must skip the receipt write instead", elapsed)
	}
	// The write was skipped, so no receipt appeared.
	if receiptPresent(t, dbPath) {
		t.Fatal("a receipt write under contention must be skipped, not forced")
	}

	// The held writer commits cleanly: it was never blocked by the verifier.
	if err := htx.Commit(); err != nil {
		t.Fatalf("held writer commit failed: %v", err)
	}
}

// TestVerifyReceiptTableAcceptedByReaders is the acceptance line that every
// events.db reader tolerates the new table: verify, export (ReadChainHead) and
// prune all run cleanly with a verify_receipt present, never reporting a schema
// mismatch or tampering.
func TestVerifyReceiptTableAcceptedByReaders(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	// Old rows so prune removes some.
	for i := 0; i < 4; i++ {
		if err := l.Log(Event{Timestamp: time.Now().Add(-72 * time.Hour), EventType: EventType("walk"), Category: "test", Detail: fmt.Sprintf("old-%d", i), SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	seedSigned(t, l, 6)
	recordReceipt(t, l, pub)
	dbPath := dbPathOf(t, l)
	if !receiptPresent(t, dbPath) {
		t.Fatal("precondition: receipt should exist")
	}

	// verify reader
	res, err := l.VerifyChainSigned(pub, true)
	if err != nil || !res.Intact || res.SigState != "authentic" {
		t.Fatalf("verify reader rejected the table: %+v %v", res, err)
	}
	// export reader (chain head)
	tx, err := l.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadChainHead(tx); err != nil || !ok {
		tx.Rollback()
		t.Fatalf("export reader rejected the table: ok=%v err=%v", ok, err)
	}
	tx.Rollback()
	// prune reader
	if _, err := l.Prune(24 * time.Hour); err != nil {
		t.Fatalf("prune reader rejected the table: %v", err)
	}
}

// TestWalkBudgetRestoresCompletion is the #222-gate release condition proved with
// a row hook, not 30 real seconds: a verification walk that exceeds a bounded CLI
// budget stops with ErrVerifyInterrupted (the regression Step 1 introduced), while
// an operator's unbounded walk budget runs the same long walk to completion. The
// CLI selects between the two by the walk context it passes (anchorCLIWalkTimeout).
func TestWalkBudgetRestoresCompletion(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	seedSigned(t, l, walkRows)

	// Bounded walk: the hook cancels the walk context at the row where the 30 s CLI
	// budget would have elapsed, standing in for a store too large to walk in time.
	bounded, cancelBounded := context.WithCancel(context.Background())
	defer cancelBounded()
	const budgetRow = verifyCtxCheckInterval
	setWalkHook(t, func(n int) {
		if n == budgetRow {
			cancelBounded()
		}
	})
	if a, err := l.EmitAnchorContext(bounded); !errors.Is(err, ErrVerifyInterrupted) || a != nil {
		t.Fatalf("bounded walk must stop with ErrVerifyInterrupted, got %v %v", a, err)
	}

	// Operator override: an unbounded walk budget runs the same long walk to
	// completion. The hook still reaches budgetRow, but with no deadline to trip.
	setWalkHook(t, func(n int) { _ = n })
	a, err := l.EmitAnchorContext(context.Background())
	if err != nil || a == nil || a.RowCount != walkRows {
		t.Fatalf("unbounded walk must complete, got %v %v", a, err)
	}
	setWalkHook(t, nil)
	if res, err := l.VerifyChainSigned(pub, true); err != nil || res.SigState != "authentic" {
		t.Fatalf("control: plain verify authentic, got %+v %v", res, err)
	}
}
