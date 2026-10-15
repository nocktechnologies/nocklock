//go:build linux || darwin

package cli

import (
	"bytes"
	"os"
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
