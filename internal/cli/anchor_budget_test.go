//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// stepRecord captures the budget a pushAnchorV2 step received at the moment it
// was handed out, so a test can prove a network step started with a full,
// unexpired deadline rather than the remains of an earlier walk's budget.
type stepRecord struct {
	issuedAt time.Time
	deadline time.Time
	hadDL    bool
}

func (r stepRecord) budget() time.Duration { return r.deadline.Sub(r.issuedAt) }

// TestPushAnchorV2WalksDoNotSpendNetworkBudget proves the teardown push gives
// FetchLatestV2 and PushV2 each a full, unexpired budget created right before
// the step, so a preflight verification walk that outlasts the push budget can
// no longer starve the network calls. The "slow walk" is modelled where it
// matters to the assertion: wall clock that elapses before the fetch step.
//
// Negative control: a single shared context (byte-for-byte the pre-fix
// behavior) is handed to every step; once the pre-fetch wall clock exceeds the
// budget, FetchLatestV2 runs on an expired context and the push drops — the
// store is never even contacted.
func TestPushAnchorV2WalksDoNotSpendNetworkBudget(t *testing.T) {
	origBudget := anchorPushTimeout
	anchorPushTimeout = 250 * time.Millisecond
	t.Cleanup(func() { anchorPushTimeout = origBudget })
	const slowWalk = 400 * time.Millisecond // longer than the push budget

	run := func(t *testing.T, shared bool) (err error, gets, posts int, records map[string]stepRecord) {
		records = map[string]stepRecord{}
		dbPath, keyPath := setupAnchorProject(t)
		seedSignedChain(t, dbPath, keyPath, 3)
		anchor := emitRemoteAnchorNow(t, dbPath, keyPath)
		pub, loadErr := logging.LoadPublicKeyFile(keyPath)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				gets++
				json.NewEncoder(w).Encode(anchor)
				return
			}
			posts++
			digest, _ := logging.AnchorV2SnapshotDigest(anchor, pub, anchor.AgentID, anchor.ChainID)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{
				"code": "stored", "agent_id": anchor.AgentID, "chain_id": anchor.ChainID,
				"legacy_anchor_digest": anchor.LegacyAnchorDigest, "snapshot_digest": digest,
				"registration_digest": digest, "anchor": anchor}})
		}))
		t.Cleanup(srv.Close)
		t.Setenv(anchorclient.EnvURL, srv.URL)
		t.Setenv(anchorclient.EnvToken, remoteTestToken)
		logger := remoteTestLogger(t, dbPath, keyPath)

		// pushAnchorV2 hands each lock wait / network step a budget by name.
		// Sleeping immediately before the fetch step stands in for the preflight
		// walks whose wall clock, in aggregate, outlasts a single push budget;
		// keying on the step name, not a call index, keeps the test honest if the
		// steps are ever reordered. sharedCtx models the single pre-fix push
		// context reused by every step.
		var sharedCtx context.Context
		var shCancel context.CancelFunc
		newStep := func(step string) (context.Context, context.CancelFunc) {
			if step == "fetch-latest" {
				time.Sleep(slowWalk)
			}
			if shared {
				if sharedCtx == nil {
					sharedCtx, shCancel = context.WithTimeout(context.Background(), anchorPushTimeout)
				}
				records[step] = recordOf(sharedCtx)
				return sharedCtx, func() {}
			}
			ctx, cancel := context.WithTimeout(context.Background(), anchorPushTimeout)
			records[step] = recordOf(ctx)
			return ctx, cancel
		}
		// Walks run unbounded here, exactly as in wrap teardown.
		err = pushAnchorV2(newStep, context.Background(), logger, anchor, pub, srv.URL, remoteTestToken)
		if shCancel != nil {
			shCancel()
		}
		return err, gets, posts, records
	}

	t.Run("fresh-per-step budget survives a slow preflight walk", func(t *testing.T) {
		err, gets, posts, records := run(t, false)
		if err != nil {
			t.Fatalf("push with fresh per-step budgets failed: %v", err)
		}
		if gets != 1 || posts != 1 {
			t.Fatalf("store not fully exercised: GET=%d POST=%d", gets, posts)
		}
		if len(records) != 5 {
			t.Fatalf("want 5 budgeted steps, got %d: %v", len(records), records)
		}
		// Both network steps must have started with a full, unexpired budget
		// despite the slow walk modelled before the fetch.
		for _, step := range []string{"fetch-latest", "push"} {
			rec, ok := records[step]
			if !ok || !rec.hadDL {
				t.Fatalf("step %q was never issued a deadline", step)
			}
			if rec.budget() < anchorPushTimeout-50*time.Millisecond {
				t.Fatalf("step %q started with only %v budget, want ~%v", step, rec.budget(), anchorPushTimeout)
			}
			if !rec.issuedAt.Before(rec.deadline) {
				t.Fatalf("step %q started already expired", step)
			}
		}
	})

	t.Run("single shared context starves the fetch (pre-fix control)", func(t *testing.T) {
		err, gets, posts, _ := run(t, true)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shared context should expire before the fetch, got %v", err)
		}
		if gets != 0 || posts != 0 {
			t.Fatalf("expired fetch must not reach the store: GET=%d POST=%d", gets, posts)
		}
	})
}

// recordOf snapshots the deadline a context carries at hand-out time.
func recordOf(ctx context.Context) stepRecord {
	rec := stepRecord{issuedAt: time.Now()}
	if dl, ok := ctx.Deadline(); ok {
		rec.deadline, rec.hadDL = dl, true
	}
	return rec
}

// TestEnrollmentPostVerifyIsNotBoundedByCLIBudget proves the post-enrollment
// verify (and its anchor write) are no longer cut off by the CLI budget the
// pre-enrollment walks already spent: the verification walk runs unbounded, so
// the enrolled remote pin always gets a matching local anchor.
//
// Negative control: the pre-fix path shared one CLI budget across the
// pre-enrollment walks and this verify. Modelling that spent budget with an
// already-done walk context cuts the verify off at row 0 (ErrVerifyInterrupted)
// and the old code returned before WriteAnchorV2 — leaving nothing false, but
// also no local anchor for an enrolled pin.
func TestEnrollmentPostVerifyIsNotBoundedByCLIBudget(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 3)
	remote := emitRemoteAnchorNow(t, dbPath, keyPath)
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	logger := remoteTestLogger(t, dbPath, keyPath)
	path := logging.DefaultAnchorPath(dbPath)
	os.Remove(path)

	// Control: the identity lock is acquired (live budget), then the verify walk
	// runs on the spent budget and is interrupted at the first row.
	live, cancelLive := context.WithTimeout(context.Background(), anchorCLITimeout)
	defer cancelLive()
	spentWalk, cancelSpent := context.WithCancel(context.Background())
	cancelSpent()
	if _, err := logger.VerifyAgainstAnchorV2Walk(live, spentWalk, remote, pub); !errors.Is(err, logging.ErrVerifyInterrupted) {
		t.Fatalf("control: a spent walk budget must interrupt the verify, got %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("control: the pre-fix path must write no anchor, found: %v", statErr)
	}

	// Fix: the post-enrollment verify runs unbounded by the CLI budget, so it
	// completes and writes the local anchor for the enrolled pin.
	var out bytes.Buffer
	if err := verifyAndRecordEnrollment(&out, logger, remote, pub, path); err != nil {
		t.Fatalf("post-enrollment verify should complete unbounded, got %v", err)
	}
	if !strings.Contains(out.String(), "ANCHOR: OK") {
		t.Fatalf("missing OK verdict: %q", out.String())
	}
	got, err := logging.ReadAnchorV2(path)
	if err != nil {
		t.Fatalf("post-enrollment verify wrote no anchor: %v", err)
	}
	if *got != *remote {
		t.Fatalf("written anchor differs from the enrolled remote pin")
	}
}
