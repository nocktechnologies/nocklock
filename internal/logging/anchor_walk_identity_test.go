//go:build linux || darwin

package logging

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestInterruptedWalkReleasesIdentityLockForPrune: the v2 walk holds the
// chain-identity lock, so Prune waits behind a running walk (control) and runs
// at once behind an interrupted one.
func TestInterruptedWalkReleasesIdentityLockForPrune(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	seedWalkChain(t, f.logger, 20)
	initIdentity(t, f)
	other, err := NewLogger(f.db, f.project, WithExistingSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	// Control: while a walk is running Prune is blocked on the lock.
	entered, release := make(chan struct{}), make(chan struct{})
	setWalkHook(t, func(n int) {
		if n == 0 {
			close(entered)
			<-release
		}
	})
	emitted := make(chan error, 1)
	go func() {
		_, err := f.logger.EmitAnchorV2Walk(context.Background(), context.Background())
		emitted <- err
	}()
	<-entered
	pruned := make(chan error, 1)
	go func() { _, err := other.Prune(24 * time.Hour); pruned <- err }()
	select {
	case err := <-pruned:
		close(release)
		t.Fatalf("prune ran while the walk held the identity lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-emitted; err != nil {
		t.Fatal(err)
	}
	if err := <-pruned; err != nil {
		t.Fatalf("prune after the walk finished: %v", err)
	}

	// Interrupted walk: the lock is released on return, Prune is not blocked.
	identityOldEvent(t, f.logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setWalkHook(t, func(int) { cancel() })
	if _, err := f.logger.EmitAnchorV2Walk(context.Background(), ctx); !errors.Is(err, ErrVerifyInterrupted) {
		t.Fatalf("want ErrVerifyInterrupted, got %v", err)
	}
	setWalkHook(t, nil)
	start := time.Now()
	n, err := other.Prune(24 * time.Hour)
	if err != nil || n != 1 || time.Since(start) > time.Second {
		t.Fatalf("prune behind an interrupted walk: removed %d, err %v, after %s", n, err, time.Since(start))
	}
}

// TestVerifyAgainstAnchorV2WalkInterrupted: an interrupted verify returns
// ErrVerifyInterrupted, never a tampered classification.
func TestVerifyAgainstAnchorV2WalkInterrupted(t *testing.T) {
	f := newIdentityFixture(t)
	seedWalkChain(t, f.logger, 20)
	initIdentity(t, f)
	anchor, err := f.logger.EmitAnchorV2()
	if err != nil {
		t.Fatal(err)
	}
	pub := f.logger.SigningPublicKey()
	if r, err := f.logger.VerifyAgainstAnchorV2Walk(context.Background(), context.Background(), anchor, pub); err != nil || !r.OK {
		t.Fatalf("control: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setWalkHook(t, func(int) { cancel() })
	r, err := f.logger.VerifyAgainstAnchorV2Walk(context.Background(), ctx, anchor, pub)
	if !errors.Is(err, ErrVerifyInterrupted) || r != nil {
		t.Fatalf("want ErrVerifyInterrupted and no classification, got %+v %v", r, err)
	}
}
