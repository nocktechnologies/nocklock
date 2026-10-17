package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// In-run anchor checkpoints (opt-in). Like NOCKLOCK_ANCHOR_URL and
// NOCKLOCK_ANCHOR_TOKEN, these are operator-environment settings, never project
// TOML: the project config is writable by the fenced child, and the child must
// not be able to switch checkpoints off or learn their cadence. Both are
// stripped from the child's environment with the other anchor settings.
const (
	// EnvAnchorCheckpointInterval enables in-run checkpoints when set to a
	// positive Go duration (for example "60s" or "5m"). Unset, empty or a
	// zero duration ("0", "0s") leaves checkpoints off, the default.
	EnvAnchorCheckpointInterval = "NOCKLOCK_ANCHOR_CHECKPOINT_INTERVAL"
	// EnvAnchorCheckpointDeadline bounds one whole checkpoint upload: the
	// verification walk, every identity-lock wait and every network step.
	// Default: the smaller of defaultAnchorCheckpointDeadline and the interval.
	EnvAnchorCheckpointDeadline = "NOCKLOCK_ANCHOR_CHECKPOINT_DEADLINE"
)

const (
	defaultAnchorCheckpointDeadline = 10 * time.Second
	minAnchorCheckpointInterval     = time.Second
)

// anchorCheckpointConfig is the parsed opt-in. A nil config means off.
type anchorCheckpointConfig struct {
	Interval time.Duration
	Deadline time.Duration
}

// anchorCheckpointSettings reads the opt-in from the operator environment. It
// returns nil when checkpoints are off. A malformed value is an error so wrap
// refuses to start rather than silently running without the checkpoints the
// operator asked for.
func anchorCheckpointSettings() (*anchorCheckpointConfig, error) {
	rawInterval := strings.TrimSpace(os.Getenv(EnvAnchorCheckpointInterval))
	rawDeadline := strings.TrimSpace(os.Getenv(EnvAnchorCheckpointDeadline))
	var interval time.Duration
	if rawInterval != "" {
		var err error
		interval, err = time.ParseDuration(rawInterval)
		if err != nil || interval < 0 || (interval > 0 && interval < minAnchorCheckpointInterval) {
			return nil, fmt.Errorf("%s=%q must be a duration of at least %s, such as 60s or 5m (unset it or use 0 to turn checkpoints off)", EnvAnchorCheckpointInterval, rawInterval, minAnchorCheckpointInterval)
		}
	}
	if interval == 0 {
		if rawDeadline != "" {
			return nil, fmt.Errorf("%s is set but %s is not; set an interval such as 60s to enable anchor checkpoints, or unset the deadline", EnvAnchorCheckpointDeadline, EnvAnchorCheckpointInterval)
		}
		return nil, nil
	}
	deadline := min(defaultAnchorCheckpointDeadline, interval)
	if rawDeadline != "" {
		var err error
		deadline, err = time.ParseDuration(rawDeadline)
		if err != nil || deadline <= 0 || deadline > interval {
			return nil, fmt.Errorf("%s=%q must be a positive duration no longer than the interval (%s)", EnvAnchorCheckpointDeadline, rawDeadline, interval)
		}
	}
	return &anchorCheckpointConfig{Interval: interval, Deadline: deadline}, nil
}

// errCheckpointNotEnrolled stops the worker: a legacy or unenrolled chain has
// no remote pin to advance, and teardown already says so.
var errCheckpointNotEnrolled = errors.New("v2 chain is not enrolled; run anchor enroll or anchor migrate")

// checkpointSession is the worker's own view of the audit chain and store.
type checkpointSession struct {
	// enrolled returns nil for an enrolled v2 chain, errCheckpointNotEnrolled
	// (wrapped) for a chain that can never be pushed, or another error for a
	// transient failure such as a lock wait that hit the deadline.
	enrolled func(ctx context.Context) error
	// upload emits the committed head and pushes it. It returns the candidate
	// it emitted (nil if emission failed) and nil only when the store confirmed
	// that exact head.
	upload func(ctx context.Context) (*logging.AnchorV2, error)
	close  func() error
}

// openCheckpointSession opens a SECOND handle on the audit log for the worker.
// wrap's own Logger runs on one SQLite connection (SetMaxOpenConns(1)), so a
// verification walk on it would hold that connection and stall every audit
// write until the walk ended. This handle has its own connection: in WAL mode
// its read snapshot never blocks wrap's writer, which is exactly how an
// 'anchor emit' + 'anchor push' from another process behaves during a run. It
// loads the existing key without adopting or re-signing the database.
func openCheckpointSession(dbPath, projectRoot, baseURL, token string) (*checkpointSession, error) {
	key, err := logging.DefaultSigningKeyPath()
	if err != nil {
		return nil, err
	}
	logger, err := logging.NewLogger(dbPath, projectRoot, logging.WithExistingSigning(key))
	if err != nil {
		return nil, err
	}
	return newCheckpointSession(logger, baseURL, token), nil
}

// newCheckpointSession builds the worker's session on an open logger. upload
// reuses the teardown push path unchanged: candidate preflight, authenticated
// fetch of the remote pin, prefix proof, no downgrade, and the store's
// compare-and-swap. Every step, the walk included, shares ctx's deadline.
func newCheckpointSession(logger *logging.Logger, baseURL, token string) *checkpointSession {
	return &checkpointSession{
		enrolled: func(ctx context.Context) error {
			id, err := logger.ReadChainIdentityContext(ctx)
			if errors.Is(err, logging.ErrChainIdentityMissing) {
				return fmt.Errorf("%w (legacy chain)", errCheckpointNotEnrolled)
			}
			if err != nil {
				return err
			}
			if id.RegistrationState != logging.ChainRegistrationEnrolled {
				return errCheckpointNotEnrolled
			}
			return nil
		},
		upload: func(ctx context.Context) (*logging.AnchorV2, error) {
			a, err := logger.EmitAnchorV2Walk(ctx, ctx)
			if err != nil {
				return nil, err
			}
			newStep := func(string) (context.Context, context.CancelFunc) { return context.WithCancel(ctx) }
			return a, pushAnchorV2(newStep, ctx, logger, a, logger.SigningPublicKey(), baseURL, token)
		},
		close: logger.Close,
	}
}

// anchorCheckpointStatus is what the worker reports at teardown.
type anchorCheckpointStatus struct {
	Confirmed int               // uploads the store confirmed
	Failed    int               // uploads that failed (stop-time cancellation excluded)
	LastPin   *logging.AnchorV2 // last head the store confirmed
	LastPinAt time.Time
	SeenRows  uint64 // committed rows in the newest emitted candidate
	LastErr   string
	LastErrAt time.Time
	Stopped   string // why the worker stopped early, if it did
}

// anchorCheckpointer uploads the committed head at an interval while wrap runs.
// One goroutine runs the loop, and uploadMu serializes every upload, so two
// uploads are never in flight. A failure is recorded and retried on the next
// tick; it never fails the run (an outage policy is a separate design).
type anchorCheckpointer struct {
	interval time.Duration
	deadline time.Duration
	open     func() (*checkpointSession, error)
	now      func() time.Time

	uploadMu sync.Mutex // held for each whole upload

	mu      sync.Mutex
	session *checkpointSession
	status  anchorCheckpointStatus

	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
}

func newAnchorCheckpointer(cfg *anchorCheckpointConfig, open func() (*checkpointSession, error)) *anchorCheckpointer {
	return &anchorCheckpointer{interval: cfg.Interval, deadline: cfg.Deadline, open: open, now: time.Now}
}

// startAnchorCheckpoints starts the worker when the opt-in is set and a store
// URL is configured. It returns at once: opening the second log handle and the
// enrollment check run on the worker goroutine, so no SQLite or identity-lock
// wait delays the child's launch. A nil result means checkpoints are off.
func startAnchorCheckpoints(w io.Writer, cfg *anchorCheckpointConfig, dbPath, projectRoot string) *anchorCheckpointer {
	if cfg == nil {
		return nil
	}
	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		fmt.Fprintf(w, "NockLock: warning: anchor checkpoints are off: %s is set but %s is not\n", EnvAnchorCheckpointInterval, "NOCKLOCK_ANCHOR_URL")
		return nil
	}
	c := newAnchorCheckpointer(cfg, func() (*checkpointSession, error) {
		return openCheckpointSession(dbPath, projectRoot, baseURL, token)
	})
	c.start()
	return c
}

// start launches the worker goroutine. Call it at most once.
func (c *anchorCheckpointer) start() {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.done = make(chan struct{})
	go c.run(ctx)
}

func (c *anchorCheckpointer) run(ctx context.Context) {
	defer close(c.done)
	session, err := c.open()
	if err != nil {
		c.stopEarly("cannot open the audit log for checkpoints: " + err.Error())
		return
	}
	c.mu.Lock()
	c.session = session
	c.mu.Unlock()
	defer func() {
		// Wait out any upload still holding the session before closing it.
		c.uploadMu.Lock()
		defer c.uploadMu.Unlock()
		c.mu.Lock()
		c.session = nil
		c.mu.Unlock()
		_ = session.close()
	}()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	checked := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !checked {
			// Checked on the first tick, not at launch, and under the upload
			// deadline, so a held identity lock never delays the child.
			checkCtx, cancel := context.WithTimeout(ctx, c.deadline)
			err := session.enrolled(checkCtx)
			cancel()
			if errors.Is(err, errCheckpointNotEnrolled) {
				c.stopEarly(err.Error())
				return
			}
			if err != nil {
				if ctx.Err() == nil {
					c.record(nil, err)
				}
				continue
			}
			checked = true
		}
		_ = c.uploadOnce(ctx)
	}
}

// uploadOnce runs one upload bounded by the deadline and records the result.
// It holds uploadMu for the whole upload, so concurrent callers queue rather
// than overlap. An upload cut short because parent was cancelled (wrap is
// stopping the worker) is neither a success nor a failure: the final flush
// supersedes it. It returns nil only when the store confirmed the head.
func (c *anchorCheckpointer) uploadOnce(parent context.Context) error {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("anchor checkpoint session is not open")
	}
	ctx, cancel := context.WithTimeout(parent, c.deadline)
	defer cancel()
	candidate, err := session.upload(ctx)
	if err != nil && parent.Err() != nil {
		return err
	}
	c.record(candidate, err)
	return err
}

func (c *anchorCheckpointer) record(candidate *logging.AnchorV2, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	if candidate != nil && candidate.RowCount > c.status.SeenRows {
		c.status.SeenRows = candidate.RowCount
	}
	if err == nil && candidate != nil {
		c.status.Confirmed++
		c.status.LastPin = candidate
		c.status.LastPinAt = now
		return
	}
	if err == nil {
		err = errors.New("upload returned no candidate")
	}
	c.status.Failed++
	c.status.LastErr = err.Error()
	c.status.LastErrAt = now
}

func (c *anchorCheckpointer) stopEarly(reason string) {
	c.mu.Lock()
	c.status.Stopped = reason
	c.mu.Unlock()
}

// stop cancels the loop and any in-flight upload, then waits for the worker to
// exit and close its log handle. It is nil-safe and idempotent.
func (c *anchorCheckpointer) stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.cancel == nil {
			return
		}
		c.cancel()
		<-c.done
	})
}

// snapshot returns a copy of the current status.
func (c *anchorCheckpointer) snapshot() anchorCheckpointStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// report writes the teardown summary: confirmed and failed counts, the last
// confirmed pin, the committed rows the checkpoints had not confirmed when wrap
// stopped (the lag the final flush must close), the final flush result and the
// last failure. final is the teardown anchor (nil if none was emitted) and
// flushed says whether the store confirmed it. It is nil-safe.
func (c *anchorCheckpointer) report(w io.Writer, final *logging.AnchorV2, flushed bool) {
	if c == nil {
		return
	}
	s := c.snapshot()
	if s.Stopped != "" {
		fmt.Fprintf(w, "NockLock: warning: anchor checkpoints did not run: %s\n", s.Stopped)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "NockLock: anchor checkpoints: %d confirmed, %d failed", s.Confirmed, s.Failed)
	// Lag is measured against the teardown emission, which reads the committed
	// head once the worker has stopped and before the flush pushes it. If that
	// emission failed there is no head to measure against, and SeenRows only
	// reflects the last tick, so the lag is reported as unknown rather than as
	// zero or a stale number.
	lagText := "unknown (no final head was emitted)"
	if final != nil {
		stopRows := max(s.SeenRows, final.RowCount)
		var pinned uint64
		if s.LastPin != nil {
			pinned = s.LastPin.RowCount
		}
		lag := uint64(0)
		if stopRows > pinned {
			lag = stopRows - pinned
		}
		lagText = rowsLabel(lag)
	}
	if s.LastPin != nil {
		fmt.Fprintf(&b, "; last confirmed row_count=%d head=%s at %s", s.LastPin.RowCount, s.LastPin.HeadHash, s.LastPinAt.Format(time.RFC3339))
		fmt.Fprintf(&b, "; lag at final emission %s, %s since last confirmed", lagText, c.now().UTC().Sub(s.LastPinAt).Round(time.Second))
	} else {
		fmt.Fprintf(&b, "; none confirmed; lag at final emission %s", lagText)
	}
	switch {
	case final != nil && flushed:
		fmt.Fprintf(&b, "; final flush confirmed row_count=%d", final.RowCount)
	default:
		b.WriteString("; final flush not confirmed")
	}
	fmt.Fprintln(w, b.String())
	if s.LastErr != "" {
		fmt.Fprintf(w, "NockLock: warning: last anchor checkpoint failure at %s: %s\n", s.LastErrAt.Format(time.RFC3339), s.LastErr)
	}
}

func rowsLabel(n uint64) string {
	if n == 1 {
		return "1 row"
	}
	return fmt.Sprintf("%d rows", n)
}
