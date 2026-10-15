package cli

import (
	"context"
	"testing"
	"time"
)

// TestAnchorCLIWalkTimeoutDefaultUnbounded fixes the release-condition default:
// the interactive anchor/verify walk budget is unbounded unless an operator sets
// it, so anchor emit, verify --against-anchor and anchor push finish on a large
// store rather than stopping at the 30 s CLI timeout (N11800 regression).
func TestAnchorCLIWalkTimeoutDefaultUnbounded(t *testing.T) {
	if anchorCLIWalkTimeout != 0 {
		t.Fatalf("default anchorCLIWalkTimeout must be 0 (unbounded), got %v", anchorCLIWalkTimeout)
	}

	// With the default, the walk context carries no deadline: the walk runs to
	// completion however large the store.
	ctx, cancel := anchorCLIWalkContext(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("default walk context must have no deadline")
	}

	// An operator budget bounds the walk.
	orig := anchorCLIWalkTimeout
	anchorCLIWalkTimeout = 50 * time.Millisecond
	t.Cleanup(func() { anchorCLIWalkTimeout = orig })
	bctx, bcancel := anchorCLIWalkContext(context.Background())
	defer bcancel()
	if _, ok := bctx.Deadline(); !ok {
		t.Fatal("a positive walk budget must set a deadline on the walk context")
	}
}

// TestAnchorCLIContextsWalkNotCappedByLock guards the shadowing regression: the
// walk budget must derive from the caller's context, never from the 30 s lock
// context. With the default (unbounded) walk budget the walk context carries no
// deadline even though the lock context does.
func TestAnchorCLIContextsWalkNotCappedByLock(t *testing.T) {
	orig := anchorCLIWalkTimeout
	t.Cleanup(func() { anchorCLIWalkTimeout = orig })

	anchorCLIWalkTimeout = 0
	lockCtx, walkCtx, cancel := anchorCLIContexts(context.Background())
	defer cancel()
	if _, ok := lockCtx.Deadline(); !ok {
		t.Fatal("lock context must carry the anchorCLITimeout deadline")
	}
	if _, ok := walkCtx.Deadline(); ok {
		t.Fatal("default walk context must have no deadline (would re-introduce the 30s cap)")
	}

	// A positive walk budget longer than the lock budget still bounds the walk by
	// the walk budget (90s), not the 30s lock budget — the walk is never capped at
	// the lock deadline.
	anchorCLIWalkTimeout = 90 * time.Second
	_, walkCtx2, cancel2 := anchorCLIContexts(context.Background())
	defer cancel2()
	dl, ok := walkCtx2.Deadline()
	if !ok || time.Until(dl) <= anchorCLITimeout {
		t.Fatalf("walk budget must come from anchorCLIWalkTimeout (90s), not the %v lock budget", anchorCLITimeout)
	}
}

// TestWalkTimeoutFlagParsed confirms --walk-timeout is wired on the interactive
// commands and sets the walk budget.
func TestWalkTimeoutFlagParsed(t *testing.T) {
	orig := anchorCLIWalkTimeout
	t.Cleanup(func() { anchorCLIWalkTimeout = orig })
	for _, name := range []string{"emit", "push"} {
		anchorCLIWalkTimeout = 0
		cmd, _, err := anchorCmd.Find([]string{name})
		if err != nil {
			t.Fatalf("find anchor %s: %v", name, err)
		}
		if cmd.Flags().Lookup("walk-timeout") == nil {
			t.Fatalf("anchor %s is missing the --walk-timeout flag", name)
		}
		if err := cmd.Flags().Set("walk-timeout", "90s"); err != nil {
			t.Fatalf("set flag on anchor %s: %v", name, err)
		}
		applyWalkTimeoutFlag(cmd)
		if anchorCLIWalkTimeout != 90*time.Second {
			t.Fatalf("anchor %s --walk-timeout not applied: got %v", name, anchorCLIWalkTimeout)
		}
		cmd.Flags().Set("walk-timeout", "0")
	}
	if verifyCmd.Flags().Lookup("walk-timeout") == nil {
		t.Fatal("verify is missing the --walk-timeout flag")
	}
}
