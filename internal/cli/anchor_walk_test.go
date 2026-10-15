//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// TestFinishAnchorSessionWalkDeadline: a bounded walk that cannot finish writes
// no anchor and warns that it was interrupted, on both the v1 (no identity) and
// v2 teardown paths. With the default (unbounded) walk the same store anchors.
func TestFinishAnchorSessionWalkDeadline(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity bool
	}{{"v1", false}, {"v2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, keyPath := setupAnchorProject(t)
			seedSignedChain(t, dbPath, keyPath, 3)
			if tc.identity {
				emitRemoteAnchorNow(t, dbPath, keyPath)
			}
			t.Setenv(anchorclient.EnvURL, "")
			logger := remoteTestLogger(t, dbPath, keyPath)
			path := logging.DefaultAnchorPath(dbPath)
			os.Remove(path)

			// An already-expired walk deadline, independent of the push budget.
			orig := anchorWalkTimeout
			anchorWalkTimeout = time.Nanosecond
			t.Cleanup(func() { anchorWalkTimeout = orig })
			var out bytes.Buffer
			finishAnchorSession(&out, logger, dbPath)
			if !strings.Contains(out.String(), "chain anchor not written") || !strings.Contains(out.String(), "interrupted") {
				t.Fatalf("missing interruption warning: %q", out.String())
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("interrupted walk wrote an anchor: %v", err)
			}

			// Control: the default leaves the walk unbounded and anchors.
			anchorWalkTimeout = 0
			out.Reset()
			finishAnchorSession(&out, logger, dbPath)
			if out.Len() != 0 {
				t.Fatalf("unbounded teardown warned: %q", out.String())
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("unbounded teardown wrote no anchor: %v", err)
			}
		})
	}
}

// TestVerifyAgainstAnchorWalkTimeout: the interactive `verify --against-anchor`
// handler honors --walk-timeout (anchorCLIWalkTimeout) for BOTH a v1 anchor file
// and a v2 one. An already-expired walk budget stops the local chain walk with
// ErrVerifyInterrupted — the v1 regression was that the v1 path ignored the walk
// context entirely — while the default (unbounded) budget completes.
func TestVerifyAgainstAnchorWalkTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		v2   bool
	}{{"v1", false}, {"v2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, keyPath := setupAnchorProject(t)
			seedSignedChain(t, dbPath, keyPath, 3)
			path := filepath.Join(t.TempDir(), "chain-anchor.json")
			if tc.v2 {
				if err := logging.WriteAnchorV2(path, emitRemoteAnchorNow(t, dbPath, keyPath)); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := logging.WriteAnchor(path, emitAnchorNow(t, dbPath, keyPath)); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(anchorclient.EnvURL, "")

			orig := anchorCLIWalkTimeout
			t.Cleanup(func() { anchorCLIWalkTimeout = orig })

			// An already-expired walk budget interrupts the local walk; the identity
			// lock wait keeps its own (unexpired) 30 s budget.
			anchorCLIWalkTimeout = time.Nanosecond
			var out bytes.Buffer
			if err := runVerifyAgainstAnchor(context.Background(), &out, path, ""); !errors.Is(err, logging.ErrVerifyInterrupted) {
				t.Fatalf("bounded walk did not interrupt: err=%v out=%q", err, out.String())
			}

			// Control: the default budget leaves the walk unbounded and verifies OK.
			anchorCLIWalkTimeout = 0
			out.Reset()
			if err := runVerifyAgainstAnchor(context.Background(), &out, path, ""); err != nil {
				t.Fatalf("unbounded walk failed: err=%v out=%q", err, out.String())
			}
			if !strings.Contains(out.String(), "ANCHOR: OK") {
				t.Fatalf("unbounded walk did not verify OK: %q", out.String())
			}
		})
	}
}
