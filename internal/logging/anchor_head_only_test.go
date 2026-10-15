package logging

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// headOnlyCheck is the rejected "signed-head shortcut" from
// docs/design/anchor-verification-profile.md: recompute the keyless hash chain
// and verify only the chain_head signature, skipping per-row signatures.
func headOnlyCheck(t *testing.T, l *Logger, pub ed25519.PublicKey) bool {
	t.Helper()
	rows := loadProfileRows(t, l.db)
	prev := chainGenesisHashHex
	for _, r := range rows {
		cb := canonicalBytes(r.id, r.ts, EventType(r.et), r.cat, r.detail, r.blocked != 0, r.sid)
		h, err := chainEntryFromCanonical(cb, prev)
		if err != nil || r.prev != prev || r.hash != h {
			return false
		}
		prev = h
	}
	tx, err := l.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	head, err := readChainHeadRecord(tx)
	if err != nil {
		t.Fatal(err)
	}
	return head.hash == prev && head.rowCount == len(rows) &&
		verifyHeadSig(pub, head.hash, head.rowCount, head.meta, head.sig)
}

// TestHeadOnlyVerificationMissesLaunderedTamper shows why a signed-head-only
// check is not equivalent to full verification. A writer without the key edits
// a middle row and recomputes the keyless hash chain and head in SQLite. A
// long-lived signing Logger then appends, trusting chain_head without
// re-verifying history, and signs a head over the tampered chain. The head-only
// check passes; per-row signatures still fail. Negative control: before the
// tamper both checks pass.
func TestHeadOnlyVerificationMissesLaunderedTamper(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	for i := 0; i < 5; i++ {
		if err := l.Log(Event{Timestamp: time.Now(), EventType: EventType("t"), Category: "c", Detail: "original", SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	if !headOnlyCheck(t, l, pub) {
		t.Fatal("control: head-only check must pass on an untouched chain")
	}
	if res, err := l.VerifyChainSigned(pub, true); err != nil || !res.Intact || res.SigState != "authentic" {
		t.Fatalf("control: full verification must pass on an untouched chain: %+v %v", res, err)
	}

	// Keyless tamper: rewrite row 3 and re-chain rows 3..5 plus chain_head.
	rows := loadProfileRows(t, l.db)
	prev := rows[1].hash
	for i := 2; i < len(rows); i++ {
		r := rows[i]
		if i == 2 {
			r.detail = "tampered"
		}
		h, err := chainEntryFromCanonical(canonicalBytes(r.id, r.ts, EventType(r.et), r.cat, r.detail, r.blocked != 0, r.sid), prev)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.db.Exec("UPDATE events SET detail = ?, prev_hash = ?, entry_hash = ? WHERE id = ?", r.detail, prev, h, r.id); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
	if _, err := l.db.Exec("UPDATE chain_head SET entry_hash = ? WHERE id = 1", prev); err != nil {
		t.Fatal(err)
	}
	// The unlaundered tamper is caught by the head signature alone.
	if headOnlyCheck(t, l, pub) {
		t.Fatal("head-only check must fail while the head signature is stale")
	}

	// The still-open signing Logger appends and signs the tampered head.
	if err := l.Log(Event{Timestamp: time.Now(), EventType: EventType("t"), Category: "c", Detail: "next", SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	if !headOnlyCheck(t, l, pub) {
		t.Fatal("expected the head-only shortcut to be fooled by the laundered head")
	}
	res, err := l.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.SigState != "forged" {
		t.Fatalf("full verification must report forged for the laundered tamper, got %q (%s)", res.SigState, res.SigBrokenReason)
	}
	if _, err := l.EmitAnchor(); err == nil {
		t.Fatal("EmitAnchor must refuse to anchor the laundered chain")
	}
}
