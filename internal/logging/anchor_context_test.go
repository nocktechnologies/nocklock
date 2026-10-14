//go:build linux || darwin

package logging

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAnchorIdentityOperationsRespectLockContext(t *testing.T) {
	for _, name := range []string{"initialize", "read", "directory", "register identity", "emit", "verify", "register anchor"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			id := initIdentity(t, f)
			anchor, err := f.logger.EmitAnchorV2()
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(f.record)
			if err != nil {
				t.Fatal(err)
			}
			callbacks := 0
			operation := func(ctx context.Context) error {
				switch name {
				case "initialize":
					_, err = f.logger.InitializeChainIdentityContext(ctx, strings.Repeat("0", 64))
				case "read":
					_, err = f.logger.ReadChainIdentityContext(ctx)
				case "directory":
					_, err = f.logger.ChainIdentityDirectoryContext(ctx)
				case "register identity":
					_, err = f.logger.RegisterChainIdentityContext(ctx, func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
						callbacks++
						return &ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
					})
				case "emit":
					_, err = f.logger.EmitAnchorV2Context(ctx)
				case "verify":
					_, err = f.logger.VerifyAgainstAnchorV2Context(ctx, anchor, f.logger.SigningPublicKey())
				case "register anchor":
					_, err = f.logger.RegisterAnchorV2Context(ctx, "fresh", nil, func(req AnchorRegistrationRequest) (*AnchorV2, error) {
						callbacks++
						return req.Anchor, nil
					})
				}
				return err
			}
			holder, err := f.logger.lockChainIdentityStore()
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			release := func() { once.Do(holder.close) }
			defer release()
			// A removed guard must finish and fail this test, rather than hang the suite.
			fallback := time.AfterFunc(2*time.Second, release)
			defer fallback.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			err = operation(ctx)
			if elapsed := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || elapsed > time.Second {
				t.Fatalf("identity lock ignored caller deadline: %v after %s", err, elapsed)
			}
			after, err := os.ReadFile(f.record)
			if err != nil || string(before) != string(after) || callbacks != 0 {
				t.Fatalf("timed-out operation changed trusted state or sent: err=%v callbacks=%d", err, callbacks)
			}
			cancelled, cancelNow := context.WithCancel(context.Background())
			cancelNow()
			if err := operation(cancelled); !errors.Is(err, context.Canceled) {
				t.Fatalf("identity lock ignored caller cancellation: %v", err)
			}
			release()
			if err := operation(context.Background()); err != nil {
				t.Fatalf("released lock control: %v", err)
			}
			if strings.HasPrefix(name, "register") && callbacks != 1 {
				t.Fatalf("allowed registration callbacks=%d", callbacks)
			}
		})
	}
}

func TestRegistrationCancellationFinishesDurableState(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "during pending write", true: "after confirmed response"}[confirmed], func(t *testing.T) {
			f := newIdentityFixture(t)
			id := initIdentity(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !confirmed {
				f.logger.identitySync = func(file *os.File) error { cancel(); return file.Sync() }
			}
			sent := false
			_, err := f.logger.RegisterChainIdentityContext(ctx, func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
				sent = true
				cancel()
				return &ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
			})
			if confirmed && err != nil {
				t.Fatalf("confirmed response lost to cancellation: %v", err)
			}
			if !confirmed && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled write result: %v", err)
			}
			if sent != confirmed {
				t.Fatalf("sent=%t, confirmed=%t", sent, confirmed)
			}
			actual, err := f.logger.ReadChainIdentity()
			expected := ChainRegistrationPending
			if confirmed {
				expected = ChainRegistrationEnrolled
			}
			if err != nil || actual.RegistrationState != expected {
				t.Fatalf("durable state: %+v, %v", actual, err)
			}
			assertIdentityPruneRefused(t, f.logger, "remote pin")
		})
	}
}
