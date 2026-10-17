//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

// casStore is an in-process v2 anchor store that applies the store's
// documented rules: authenticated pair, compare-and-swap on the previous
// snapshot digest, monotonic row count and equal-height head agreement.
type casStore struct {
	t   *testing.T
	pub ed25519.PublicKey
	srv *httptest.Server

	mu      sync.Mutex
	cur     *logging.AnchorV2
	history []uint64 // row count of every stored transition, in order

	posts     atomic.Int32
	conflicts atomic.Int32
	down      atomic.Bool // answer every request with 503
	inFlight  atomic.Int32
	maxFlight atomic.Int32

	// stall, when set, runs at the start of every request (outside mu).
	stall func(r *http.Request)
	// beforeCAS, when set, runs on a POST before the CAS check (outside mu).
	beforeCAS func()
}

// setHooks replaces the test hooks; handlers read them under mu.
func (s *casStore) setHooks(stall func(*http.Request), beforeCAS func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stall, s.beforeCAS = stall, beforeCAS
}

func (s *casStore) hooks() (func(*http.Request), func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stall, s.beforeCAS
}

func newCASStore(t *testing.T, pin *logging.AnchorV2, pub ed25519.PublicKey) *casStore {
	t.Helper()
	s := &casStore{t: t, pub: pub, cur: pin}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *casStore) current() *logging.AnchorV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *casStore) digest(a *logging.AnchorV2) string {
	d, err := logging.AnchorV2SnapshotDigest(a, s.pub, a.AgentID, a.ChainID)
	if err != nil {
		s.t.Errorf("fake store digest: %v", err)
	}
	return d
}

func (s *casStore) serve(w http.ResponseWriter, r *http.Request) {
	n := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		m := s.maxFlight.Load()
		if n <= m || s.maxFlight.CompareAndSwap(m, n) {
			break
		}
	}
	stall, beforeCAS := s.hooks()
	if stall != nil {
		stall(r)
	}
	if s.down.Load() {
		http.Error(w, "store down", http.StatusServiceUnavailable)
		return
	}
	cur := s.current()
	base := "/api/nocklock/anchors/v2/"
	if r.Method == http.MethodGet && r.URL.Path == base+cur.AgentID+"/"+cur.ChainID+"/latest/" {
		data, _ := logging.MarshalAnchorV2(cur)
		w.Write(data)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != base {
		http.NotFound(w, r)
		return
	}
	s.posts.Add(1)
	var body struct {
		Anchor           json.RawMessage `json:"anchor"`
		ExpectedPrevious string          `json:"expected_previous"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	a, err := logging.UnmarshalAnchorV2(body.Anchor)
	if err != nil || logging.VerifyAnchorV2(a, s.pub, cur.AgentID, cur.ChainID) != nil {
		http.Error(w, "unauthenticated anchor", http.StatusBadRequest)
		return
	}
	if beforeCAS != nil {
		beforeCAS()
	}
	s.mu.Lock()
	cur = s.cur
	code, status := "stored", http.StatusCreated
	switch {
	case body.ExpectedPrevious != s.digest(cur),
		a.RowCount < cur.RowCount,
		a.RowCount == cur.RowCount && a.HeadHash != cur.HeadHash:
		s.mu.Unlock()
		s.conflicts.Add(1)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "data": map[string]any{"code": "conflict"}})
		return
	case a.RowCount == cur.RowCount:
		code, status = "already_stored", http.StatusOK
	default:
		s.cur = a
		s.history = append(s.history, a.RowCount)
	}
	s.mu.Unlock()
	d := s.digest(a)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{
		"code": code, "agent_id": a.AgentID, "chain_id": a.ChainID, "legacy_anchor_digest": a.LegacyAnchorDigest,
		"snapshot_digest": d, "registration_digest": d, "anchor": a,
	}})
}

// checkpointFixture builds an enrolled signed chain of rows rows whose remote
// pin is its current head, a fake store holding that pin, and the wrap-side
// logger that keeps appending during the "run".
func checkpointFixture(t *testing.T, rows int) (dbPath string, store *casStore, wrapLog *logging.Logger) {
	t.Helper()
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, rows)
	pin := emitRemoteAnchorNow(t, dbPath, keyPath)
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	store = newCASStore(t, pin, pub)
	t.Setenv(anchorclient.EnvURL, store.srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)
	return dbPath, store, remoteTestLogger(t, dbPath, keyPath)
}

// openTestCheckpointer opens a real worker session (its own log handle, the
// production upload path) without starting the ticker loop, so tests drive
// uploadOnce directly and never depend on wall-clock ticks.
func openTestCheckpointer(t *testing.T, dbPath string, store *casStore, deadline time.Duration) *anchorCheckpointer {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	c := newAnchorCheckpointer(&anchorCheckpointConfig{Interval: time.Hour, Deadline: deadline}, func() (*checkpointSession, error) {
		return openCheckpointSession(dbPath, root, store.srv.URL, remoteTestToken)
	})
	session, err := c.open()
	if err != nil {
		t.Fatal(err)
	}
	c.session = session
	t.Cleanup(func() { session.close() })
	return c
}

func appendRows(t *testing.T, l *logging.Logger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.LogImmediate(logging.Event{Timestamp: time.Now(), EventType: logging.EventFileBlocked, Category: "filesystem", Detail: "/etc/shadow", Blocked: true, SessionID: "run"}); err != nil {
			t.Errorf("append: %v", err)
			return
		}
	}
}

func TestAnchorCheckpointSettings(t *testing.T) {
	cases := []struct {
		interval, deadline string
		want               *anchorCheckpointConfig
		wantErr            string
	}{
		{"", "", nil, ""},
		{"0", "", nil, ""},
		{"0s", "", nil, ""},
		{"0m", "", nil, ""},
		{"0ms", "", nil, ""},
		{"0s", "5s", nil, EnvAnchorCheckpointInterval},
		{"5s", "", &anchorCheckpointConfig{Interval: 5 * time.Second, Deadline: 5 * time.Second}, ""},
		{"", "5s", nil, EnvAnchorCheckpointInterval},
		{"60s", "", &anchorCheckpointConfig{Interval: time.Minute, Deadline: 10 * time.Second}, ""},
		{"3s", "", &anchorCheckpointConfig{Interval: 3 * time.Second, Deadline: 3 * time.Second}, ""},
		{"5m", "45s", &anchorCheckpointConfig{Interval: 5 * time.Minute, Deadline: 45 * time.Second}, ""},
		{"soon", "", nil, "must be a duration"},
		{"500ms", "", nil, "at least 1s"},
		{"-1m", "", nil, "must be a duration"},
		{"60s", "2m", nil, "no longer than the interval"},
		{"60s", "0", nil, "positive duration"},
	}
	for _, tc := range cases {
		t.Setenv(EnvAnchorCheckpointInterval, tc.interval)
		t.Setenv(EnvAnchorCheckpointDeadline, tc.deadline)
		got, err := anchorCheckpointSettings()
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("interval=%q deadline=%q: want error containing %q, got %v", tc.interval, tc.deadline, tc.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("interval=%q deadline=%q: %v", tc.interval, tc.deadline, err)
			continue
		}
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("interval=%q deadline=%q: got %+v, want %+v", tc.interval, tc.deadline, got, tc.want)
		}
	}
}

func TestStripAnchorEnvRemovesCheckpointSettings(t *testing.T) {
	env := []string{EnvAnchorCheckpointInterval + "=60s", EnvAnchorCheckpointDeadline + "=5s", "KEEP=1"}
	got := stripAnchorEnv(env)
	if len(got) != 1 || got[0] != "KEEP=1" {
		t.Fatalf("checkpoint settings reached the child env: %v", got)
	}
}

// A kill after a confirmed pin: no teardown runs, so nothing past the pin is
// pushed, and the remote stays exactly at the confirmed head. The local chain
// still reproduces that pin; rows written after it have no off-box protection.
func TestAnchorCheckpointKillAfterConfirmedPinLeavesRemoteAtPin(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	c := openTestCheckpointer(t, dbPath, store, 5*time.Second)

	appendRows(t, wrapLog, 4)
	if err := c.uploadOnce(context.Background()); err != nil {
		t.Fatalf("checkpoint upload: %v", err)
	}
	s := c.snapshot()
	if s.Confirmed != 1 || s.LastPin == nil || s.LastPin.RowCount != 7 {
		t.Fatalf("want one confirmed pin at 7 rows, got %+v", s)
	}
	if cur := store.current(); cur.RowCount != 7 || cur.HeadHash != s.LastPin.HeadHash {
		t.Fatalf("store holds %d/%s, want the confirmed pin %d/%s", cur.RowCount, cur.HeadHash, s.LastPin.RowCount, s.LastPin.HeadHash)
	}

	// The run keeps writing, then wrap is killed: no further tick, no teardown.
	appendRows(t, wrapLog, 5)
	postsAtKill := store.posts.Load()

	cur := store.current()
	if cur.RowCount != 7 || cur.HeadHash != s.LastPin.HeadHash || store.posts.Load() != postsAtKill {
		t.Fatalf("remote moved after the kill: %d/%s", cur.RowCount, cur.HeadHash)
	}
	remote, err := anchorclient.FetchLatestV2(context.Background(), store.srv.URL, remoteTestToken, cur.AgentID, cur.ChainID, store.pub)
	if err != nil {
		t.Fatal(err)
	}
	result, err := wrapLog.VerifyAgainstAnchorV2(remote, store.pub)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.AnchorRowCount != 7 || result.LocalRowCount != 12 {
		t.Fatalf("local chain must reproduce the confirmed pin (7 of 12 rows), got %+v", result)
	}
}

// Rollback after a confirmed pin is refused three ways and the pin never
// moves: the push path refuses a signed but stale candidate before sending,
// the store's CAS refuses a replayed older pin, and a truncated local chain
// is refused before any request reaches the store (recorded as a failure).
func TestAnchorCheckpointRollbackIsRefused(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	older := store.current()
	c := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	appendRows(t, wrapLog, 4)
	if err := c.uploadOnce(context.Background()); err != nil {
		t.Fatalf("checkpoint upload: %v", err)
	}
	pin := store.current()
	posts := store.posts.Load()
	unchanged := func(stage string) {
		t.Helper()
		if cur := store.current(); cur.RowCount != pin.RowCount || cur.HeadHash != pin.HeadHash {
			t.Fatalf("%s: remote pin moved to %d", stage, cur.RowCount)
		}
	}

	// 1. The older signed pin through the same push path the worker uses.
	newStep := func(string) (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 5*time.Second)
	}
	err := pushAnchorV2(newStep, context.Background(), wrapLog, older, store.pub, store.srv.URL, remoteTestToken)
	if err == nil || !strings.Contains(err.Error(), "older than the remote pin") {
		t.Fatalf("stale candidate: want a no-downgrade refusal, got %v", err)
	}
	if store.posts.Load() != posts {
		t.Fatal("stale candidate reached the store")
	}
	unchanged("stale candidate")

	// 2. The same older pin replayed straight to the store: its CAS refuses.
	digest, err := logging.AnchorV2SnapshotDigest(pin, store.pub, pin.AgentID, pin.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anchorclient.PushV2(context.Background(), store.srv.URL, remoteTestToken, older, store.pub, digest); !errors.Is(err, anchorclient.ErrAnchorConflict) {
		t.Fatalf("replayed older pin: want a CAS conflict, got %v", err)
	}
	unchanged("replay")
	posts = store.posts.Load()

	// 3. The local chain rolled back below the pin: the next checkpoint is
	// refused locally, recorded, and nothing is sent.
	truncateTo(t, dbPath, 5)
	if err := c.uploadOnce(context.Background()); err == nil {
		t.Fatal("checkpoint of a rolled-back chain succeeded")
	}
	if store.posts.Load() != posts {
		t.Fatal("a rolled-back candidate reached the store")
	}
	unchanged("local rollback")
	if s := c.snapshot(); s.Confirmed != 1 || s.Failed != 1 || s.LastErr == "" {
		t.Fatalf("rollback not recorded as a failure: %+v", s)
	}
}

// An outage records the failure and the lag, never panics or blocks past the
// deadline, and the next upload after recovery confirms the newer head.
func TestAnchorCheckpointOutageRecordsLagAndRecovers(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	c := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	appendRows(t, wrapLog, 2)
	if err := c.uploadOnce(context.Background()); err != nil {
		t.Fatalf("checkpoint upload: %v", err)
	}

	// The store answers 503.
	store.down.Store(true)
	appendRows(t, wrapLog, 3)
	if err := c.uploadOnce(context.Background()); err == nil {
		t.Fatal("upload succeeded against a down store")
	}
	s := c.snapshot()
	if s.Failed != 1 || !strings.Contains(s.LastErr, "503") || s.SeenRows != 8 || s.LastPin.RowCount != 5 {
		t.Fatalf("outage not recorded with its lag: %+v", s)
	}

	// The store hangs: the deadline ends the upload.
	store.down.Store(false)
	c.deadline = 200 * time.Millisecond
	release := make(chan struct{})
	store.setHooks(func(r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, nil)
	start := time.Now()
	err := c.uploadOnce(context.Background())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("want a deadline failure, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("upload ran %s past a 200ms deadline", elapsed)
	}
	close(release)
	store.setHooks(nil, nil)
	c.deadline = 5 * time.Second
	if s := c.snapshot(); s.Failed != 2 {
		t.Fatalf("hang not recorded: %+v", s)
	}

	// Recovery: the next tick confirms the newer head, closing the lag.
	if err := c.uploadOnce(context.Background()); err != nil {
		t.Fatalf("upload after recovery: %v", err)
	}
	if s := c.snapshot(); s.Confirmed != 2 || s.LastPin.RowCount != 8 {
		t.Fatalf("recovery not confirmed: %+v", s)
	}

	// Teardown during an outage: the summary reports the failure and the lag,
	// and the final flush fails open with today's warning.
	appendRows(t, wrapLog, 1)
	store.down.Store(true)
	var out bytes.Buffer
	finishAnchorSessionWithCheckpoints(&out, wrapLog, dbPath, c)
	for _, want := range []string{
		"NockLock: warning: chain anchor NOT pushed off-box",
		"NockLock: anchor checkpoints: 2 confirmed, 2 failed; last confirmed row_count=8",
		"lag at final emission 1 row,",
		"final flush not confirmed",
		"NockLock: warning: last anchor checkpoint failure at",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("teardown output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), remoteTestToken) {
		t.Error("teardown output leaks the token")
	}
}

// Two writers advancing the same chain: the one whose expected previous pin
// went stale loses the store's CAS, records the conflict, and succeeds on its
// next upload. The stored history only ever moves forward.
func TestAnchorCheckpointContentionFollowsCAS(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	a := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	b := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	appendRows(t, wrapLog, 2)

	var fired atomic.Bool
	var bErr error
	store.setHooks(nil, func() {
		// A's POST is at the store; B fetches the same pin, pushes a newer
		// head and wins the CAS first. (B's own POST passes straight through.)
		if fired.CompareAndSwap(false, true) {
			appendRows(t, wrapLog, 2)
			bErr = b.uploadOnce(context.Background())
		}
	})
	err := a.uploadOnce(context.Background())
	store.setHooks(nil, nil)
	if bErr != nil {
		t.Fatalf("writer B: %v", bErr)
	}
	if !errors.Is(err, anchorclient.ErrAnchorConflict) {
		t.Fatalf("writer A must lose the CAS, got %v", err)
	}
	if s := a.snapshot(); s.Failed != 1 || s.Confirmed != 0 || !strings.Contains(s.LastErr, "conditional update") {
		t.Fatalf("A's conflict not recorded: %+v", s)
	}
	if err := a.uploadOnce(context.Background()); err != nil {
		t.Fatalf("writer A retry: %v", err)
	}
	if s := a.snapshot(); s.Confirmed != 1 || s.LastPin.RowCount != 7 {
		t.Fatalf("A's retry not confirmed at the current head: %+v", s)
	}
	store.mu.Lock()
	history := append([]uint64(nil), store.history...)
	store.mu.Unlock()
	for i := 1; i < len(history); i++ {
		if history[i] <= history[i-1] {
			t.Fatalf("stored history moved backward or sideways: %v", history)
		}
	}
	if store.conflicts.Load() != 1 {
		t.Fatalf("want exactly one CAS conflict, got %d", store.conflicts.Load())
	}
}

// The worker loop and any concurrent caller share one upload at a time: the
// store never sees two checkpoint requests in flight.
func TestAnchorCheckpointNeverTwoUploadsAtOnce(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	store.setHooks(func(*http.Request) { time.Sleep(20 * time.Millisecond) }, nil)
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	c := newAnchorCheckpointer(&anchorCheckpointConfig{Interval: 2 * time.Millisecond, Deadline: 5 * time.Second}, func() (*checkpointSession, error) {
		return openCheckpointSession(dbPath, root, store.srv.URL, remoteTestToken)
	})
	c.start()
	deadline := time.Now().Add(10 * time.Second)
	for c.snapshot().Confirmed == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// Hammer uploadOnce from other goroutines while the loop keeps ticking.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				_ = c.uploadOnce(context.Background())
			}
		}()
	}
	appendRows(t, wrapLog, 3)
	wg.Wait()
	c.stop()
	s := c.snapshot()
	if s.Confirmed < 2 {
		t.Fatalf("worker did not keep confirming: %+v", s)
	}
	if got := store.maxFlight.Load(); got != 1 {
		t.Fatalf("store saw %d checkpoint requests in flight at once, want 1", got)
	}
	c.stop() // idempotent
}

// While an upload is stalled at the store, the run's own logger keeps
// writing: the worker's separate log handle never holds wrap's connection.
func TestAnchorCheckpointDoesNotBlockAuditWriter(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	c := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	store.setHooks(func(r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, nil)
	done := make(chan error, 1)
	go func() { done <- c.uploadOnce(context.Background()) }()
	<-entered
	start := time.Now()
	appendRows(t, wrapLog, 3)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("audit writes waited %s behind a checkpoint upload", elapsed)
	}
	store.setHooks(nil, nil)
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("stalled upload: %v", err)
	}
}

// A legacy (unenrolled) chain has no pin to advance: the worker stops on its
// first tick and says why at teardown.
func TestAnchorCheckpointStopsOnUnenrolledChain(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 2)
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	c := newAnchorCheckpointer(&anchorCheckpointConfig{Interval: 5 * time.Millisecond, Deadline: time.Second}, func() (*checkpointSession, error) {
		return openCheckpointSession(dbPath, root, "http://127.0.0.1:9", remoteTestToken)
	})
	c.start()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker kept running on an unenrolled chain")
	}
	var out bytes.Buffer
	c.report(&out, nil, false)
	if !strings.Contains(out.String(), "anchor checkpoints did not run") || !strings.Contains(out.String(), "not enrolled") {
		t.Fatalf("unexpected report: %q", out.String())
	}
}

// After a confirmed checkpoint, teardown reports the last pin, the lag the
// final flush had to close and the flush result, with no warning.
func TestAnchorCheckpointTeardownSummaryAfterFinalFlush(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	c := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	if err := c.uploadOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendRows(t, wrapLog, 2)
	var out bytes.Buffer
	finishAnchorSessionWithCheckpoints(&out, wrapLog, dbPath, c)
	got := out.String()
	if !strings.Contains(got, "NockLock: anchor checkpoints: 1 confirmed, 0 failed; last confirmed row_count=3") ||
		!strings.Contains(got, "lag at final emission 2 rows") || !strings.Contains(got, "final flush confirmed row_count=5") {
		t.Fatalf("unexpected summary:\n%s", got)
	}
	if strings.Contains(got, "warning") {
		t.Fatalf("clean teardown printed a warning:\n%s", got)
	}
	if cur := store.current(); cur.RowCount != 5 {
		t.Fatalf("final flush did not reach the store: %d", cur.RowCount)
	}
}

// wrap refuses to start on a malformed opt-in before launching the child, and
// with a valid opt-in the child's exit code survives and the settings never
// reach the child. Fences are off here (no Landlock, seccomp or netns); an
// unenrolled chain keeps the run to the fail-open teardown path.
func TestWrapAnchorCheckpointOptIn(t *testing.T) {
	project := t.TempDir()
	nockDir := filepath.Join(project, config.Dir)
	if err := os.MkdirAll(nockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Logging.DB = filepath.Join(config.Dir, "events.db")
	cfg.Filesystem.Root = ""
	cfg.Network.AllowAll = true
	cfg.Syscall.Enforcement = "off"
	cfg.Secrets.Pass = []string{"*"}
	cfg.Secrets.Block = []string{"NOCKLOCK_TEST_MATCHES_NOTHING"}
	if err := writeConfigTOML(filepath.Join(nockDir, config.File), &cfg); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "store down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv(anchorclient.EnvURL, srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)
	t.Setenv("NOCKLOCK_E2E_CONTROL", "visible")

	run := func(marker string) (error, string) {
		var runErr error
		wc := &cobra.Command{}
		wc.SetContext(context.Background())
		stderr := captureStderr(t, func() {
			runErr = wrapCmd.RunE(wc, []string{"--", "/bin/sh", "-c", `env > "$0"; exit 3`, marker})
		})
		return runErr, stderr
	}

	t.Setenv(EnvAnchorCheckpointInterval, "soon")
	marker := filepath.Join(t.TempDir(), "never.txt")
	if err, _ := run(marker); err == nil || !strings.Contains(err.Error(), EnvAnchorCheckpointInterval) {
		t.Fatalf("malformed interval must refuse the run, got %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the child ran despite a malformed checkpoint setting")
	}

	t.Setenv(EnvAnchorCheckpointInterval, "1s")
	t.Setenv(EnvAnchorCheckpointDeadline, "500ms")
	envOut := filepath.Join(t.TempDir(), "child-env.txt")
	runErr, stderr := run(envOut)
	var ece *exitCodeError
	if !asExitCodeError(runErr, &ece) || ece.code != 3 {
		t.Fatalf("child exit code must survive: want exit 3, got %v", runErr)
	}
	if !strings.Contains(stderr, "NockLock: anchor checkpoints:") {
		t.Fatalf("missing checkpoint summary on stderr:\n%s", stderr)
	}
	childEnv, err := os.ReadFile(envOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(childEnv), "NOCKLOCK_E2E_CONTROL=visible") {
		t.Fatal("control var missing: the child env dump is not trustworthy")
	}
	for _, key := range []string{EnvAnchorCheckpointInterval, EnvAnchorCheckpointDeadline} {
		if strings.Contains(string(childEnv), key) {
			t.Fatalf("the wrapped child can see %s", key)
		}
	}
}

// A failed final emission must not be reported as zero lag: there is no head
// to measure against, so the summary says the lag is unknown.
func TestAnchorCheckpointSummaryFailedFinalEmissionIsNotZeroLag(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	c := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	if err := c.uploadOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendRows(t, wrapLog, 2)
	var out bytes.Buffer
	c.report(&out, nil, false)
	got := out.String()
	if strings.Contains(got, "lag at final emission 0 rows") || strings.Contains(got, "lag at stop") {
		t.Fatalf("failed final emission reported a measured lag:\n%s", got)
	}
	if !strings.Contains(got, "lag at final emission unknown") || !strings.Contains(got, "final flush not confirmed") {
		t.Fatalf("unexpected summary:\n%s", got)
	}
	out.Reset()
	c2 := openTestCheckpointer(t, dbPath, store, 5*time.Second)
	c2.report(&out, nil, false)
	if !strings.Contains(out.String(), "none confirmed; lag at final emission unknown") {
		t.Fatalf("unexpected summary with no pin:\n%s", out.String())
	}
}

// Opening the worker's log handle while the run's writer is busy must neither
// fail nor wait on the busy timeout: on an enrolled chain the identity table
// already exists, so the open takes no write lock.
func TestAnchorCheckpointOpenDoesNotWaitOnLiveWriter(t *testing.T) {
	dbPath, store, wrapLog := checkpointFixture(t, 3)
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := wrapLog.LogImmediate(logging.Event{Timestamp: time.Now(), EventType: logging.EventFileBlocked, Category: "filesystem", Detail: "/etc/shadow", Blocked: true, SessionID: "run"}); err != nil {
				t.Errorf("append: %v", err)
				return
			}
		}
	}()
	for i := 0; i < 15; i++ {
		start := time.Now()
		s, err := openCheckpointSession(dbPath, root, store.srv.URL, remoteTestToken)
		if err != nil {
			t.Errorf("open %d: %v", i, err)
			break
		}
		s.close()
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("open %d waited %s behind the live writer", i, elapsed)
		}
	}
	close(stop)
	<-finished
}
