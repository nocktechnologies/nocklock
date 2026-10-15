package logging

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// walkRows is more than two check intervals, so a walk has a row 0, interior
// check points (1024, 2048) and a last row after the final check.
const walkRows = 2*verifyCtxCheckInterval + 52

// setWalkHook installs verifyRowHook for one test. Tests using it must not run
// in parallel.
func setWalkHook(t *testing.T, hook func(rowsVerified int)) {
	t.Helper()
	verifyRowHook = hook
	t.Cleanup(func() { verifyRowHook = nil })
}

func seedWalkChain(t *testing.T, l *Logger, n int) {
	t.Helper()
	evs := make([]Event, n)
	for i := range evs {
		evs[i] = Event{Timestamp: time.Now(), EventType: EventType("walk"), Category: "test",
			Detail: fmt.Sprintf("row %d", i), SessionID: "walk"}
	}
	if err := l.LogBatch(evs); err != nil {
		t.Fatalf("LogBatch: %v", err)
	}
}

// TestVerifyWalkInterruptedAtExactRows is negative control 14: cancellation at
// row 0, mid-chain and the last row, injected by row count, never reads as
// authentic or tampered, and an uninterrupted walk afterwards still passes.
func TestVerifyWalkInterruptedAtExactRows(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	seedWalkChain(t, l, walkRows)

	// Positive control: an unexpired context verifies and anchors.
	res, err := l.VerifyChainSignedContext(context.Background(), pub, true)
	if err != nil || !res.Intact || res.SigState != "authentic" || res.EntriesVerified != walkRows {
		t.Fatalf("control: uncancelled walk: %+v %v", res, err)
	}
	if _, err := l.EmitAnchorContext(context.Background()); err != nil {
		t.Fatalf("control: uncancelled emit: %v", err)
	}

	for _, tc := range []struct {
		name     string
		cancelAt int
		// maxRows is the most rows the walk may reach: it stops at the next
		// check point, not the end. The last row has no later check point, so
		// the post-loop check must catch it.
		maxRows int
	}{
		{"row 0", 0, 0},
		{"mid-chain", 1500, 2 * verifyCtxCheckInterval},
		{"last row", walkRows - 1, walkRows - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reached := -1
			setWalkHook(t, func(n int) {
				reached = n
				if n == tc.cancelAt {
					cancel()
				}
			})
			res, err := l.VerifyChainSignedContext(ctx, pub, true)
			if !errors.Is(err, ErrVerifyInterrupted) || !errors.Is(err, context.Canceled) {
				t.Fatalf("want ErrVerifyInterrupted wrapping context.Canceled, got %v", err)
			}
			if res != nil {
				t.Fatalf("interrupted walk returned a verdict: %+v", res)
			}
			if reached > tc.maxRows {
				t.Fatalf("walk reached row %d after cancel at %d, want at most %d", reached, tc.cancelAt, tc.maxRows)
			}

			ctx2, cancel2 := context.WithCancel(context.Background())
			defer cancel2()
			setWalkHook(t, func(n int) {
				if n == tc.cancelAt {
					cancel2()
				}
			})
			a, err := l.EmitAnchorContext(ctx2)
			if !errors.Is(err, ErrVerifyInterrupted) || a != nil {
				t.Fatalf("emit: want ErrVerifyInterrupted and no anchor, got %v, %v", a, err)
			}
			if strings.Contains(err.Error(), "unauthentic") {
				t.Fatalf("interruption reported as tampering: %v", err)
			}

			// The next uninterrupted run completes with the same verdict.
			verifyRowHook = nil
			res, err = l.VerifyChainSignedContext(context.Background(), pub, true)
			if err != nil || !res.Intact || res.SigState != "authentic" || res.EntriesVerified != walkRows {
				t.Fatalf("follow-up walk: %+v %v", res, err)
			}
		})
	}
}

// TestVerifyWalkTamperIsNotInterruption is the negative control for the
// interruption path: a live context on a tampered chain still reports forged,
// not ErrVerifyInterrupted, and EmitAnchorContext refuses as unauthentic.
func TestVerifyWalkTamperIsNotInterruption(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	seedWalkChain(t, l, 5)
	tamperRowAndRechain(t, dbPathOf(t, l), 3, "tampered")
	res, err := l.VerifyChainSignedContext(context.Background(), pub, true)
	if err != nil || res.SigState != "forged" {
		t.Fatalf("want forged verdict, got %+v %v", res, err)
	}
	_, err = l.EmitAnchorContext(context.Background())
	if err == nil || errors.Is(err, ErrVerifyInterrupted) || !strings.Contains(err.Error(), "unauthentic") {
		t.Fatalf("want unauthentic refusal, got %v", err)
	}
}

// TestEmitAnchorBoundedByDeadline: with a real deadline, EmitAnchorContext
// returns ErrVerifyInterrupted at the deadline instead of finishing the walk.
// The hook only stalls the walk at check points, so the stop row is exact.
func TestEmitAnchorBoundedByDeadline(t *testing.T) {
	l, _, _ := newSigningLogger(t)
	defer l.Close()
	seedWalkChain(t, l, walkRows)

	const stall = 150 * time.Millisecond
	reached := -1
	setWalkHook(t, func(n int) {
		reached = n
		if n%verifyCtxCheckInterval == 0 {
			time.Sleep(stall)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), stall/2)
	defer cancel()
	start := time.Now()
	a, err := l.EmitAnchorContext(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrVerifyInterrupted) || !errors.Is(err, context.DeadlineExceeded) || a != nil {
		t.Fatalf("want ErrVerifyInterrupted at the deadline, got %v, %v", a, err)
	}
	// The walk stalls at row 0 and must stop there; finishing would take
	// three stalls (rows 0, 1024, 2048).
	if reached != 0 || elapsed >= 3*stall {
		t.Fatalf("walk ran past the deadline: reached row %d in %s", reached, elapsed)
	}

	// Control: the same stalls with room to spare complete and anchor.
	reached = -1
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel2()
	if a, err := l.EmitAnchorContext(ctx2); err != nil || a.RowCount != walkRows {
		t.Fatalf("control: unexpired deadline: %v, %v", a, err)
	}
}

// TestAnchorCoversSnapshotUnderConcurrentAppend is negative control 17: rows
// appended by another writer while the walk runs do not enter the anchor,
// which equals the head of the snapshot the walk read.
func TestAnchorCoversSnapshotUnderConcurrentAppend(t *testing.T) {
	l, keyPath, pub := newSigningLogger(t)
	defer l.Close()
	seedWalkChain(t, l, 50)
	snapshot, err := l.VerifyChainSigned(pub, true)
	if err != nil || snapshot.SigState != "authentic" {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
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
			seedWalkChain(t, other, 5)
		}
	})
	a, err := l.EmitAnchorContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("hook never appended: the test did not exercise the race")
	}
	if a.RowCount != snapshot.EntriesVerified || a.HeadHash != snapshot.HeadHash {
		t.Fatalf("anchor (%d rows, %s) is not the snapshot head (%d rows, %s)", a.RowCount, a.HeadHash, snapshot.EntriesVerified, snapshot.HeadHash)
	}

	// Control: the appended rows are real, and the next anchor covers them.
	verifyRowHook = nil
	next, err := l.EmitAnchorContext(context.Background())
	if err != nil || next.RowCount != snapshot.EntriesVerified+5 {
		t.Fatalf("next anchor: %+v, %v", next, err)
	}
}
