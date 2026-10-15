package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// anchorPushTimeout bounds identity-lock waits and HTTP during wrap teardown.
// It does not bound the verification walk (anchorWalkTimeout does). Tests
// shorten it.
var anchorPushTimeout = 5 * time.Second

// anchorWalkTimeout bounds every chain verification walk during wrap teardown,
// separately from anchorPushTimeout. Zero, the default, leaves the walk
// unbounded, as before: a bound without the verified-prefix receipt (Step 2 of
// docs/design/anchor-verification-profile.md) would turn a slow but successful
// final anchor into a missing one on large stores. Tests set it.
var anchorWalkTimeout time.Duration

// anchorEnvKeys are wrap's off-box anchor settings. They are removed from the
// fenced child's environment so the agent can neither read the bearer token
// nor learn where its anchors are pinned.
var anchorEnvKeys = []string{anchorclient.EnvURL, anchorclient.EnvToken}

// stripAnchorEnv returns env without the anchor URL/token entries.
func stripAnchorEnv(env []string) []string {
	return removeEnvVars(env, anchorEnvKeys...)
}

// anchorRemoteConfig reads the anchor store URL and token from the environment.
// The token is environment-only by design: never a config-file key or a flag.
func anchorRemoteConfig() (baseURL, token string) {
	return os.Getenv(anchorclient.EnvURL), os.Getenv(anchorclient.EnvToken)
}

// anchorCLITimeout bounds an interactive 'anchor push' or a remote fetch by
// 'verify --against-remote-anchor'. Longer than the teardown budget because a
// person is waiting on the answer, not a session exit. It bounds each
// identity-lock wait and each network step; anchorCLIWalkTimeout bounds the
// local verification walk separately.
var anchorCLITimeout = 30 * time.Second

// anchorCLIWalkTimeout bounds ONLY the local verification walk of the interactive
// 'anchor emit', 'verify --against-anchor' and 'anchor push' commands, separately
// from anchorCLITimeout. Zero, the default, leaves the walk UNBOUNDED so these
// commands finish on a large store, restoring completion that the walk's
// context-bounding (N11800) otherwise cut off past ~30 s (~750k rows). A store
// with a signed verify_receipt finishes quickly even under a bound, because the
// verified prefix's signatures are skipped. Operators set a positive budget with
// --walk-timeout; tests set it directly.
var anchorCLIWalkTimeout time.Duration

// anchorCLIWalkContext derives the verification-walk context for an interactive
// anchor command from parent: bounded by anchorCLIWalkTimeout, or parent-tracking
// but unbounded when the budget is zero (the default), so the walk completes on a
// large store while still honoring an outer cancellation.
func anchorCLIWalkContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if anchorCLIWalkTimeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, anchorCLIWalkTimeout)
}

// anchorCLIContexts derives the two budgets an interactive anchor/verify command
// needs from the SAME caller context: lockCtx bounds each identity-lock wait at
// anchorCLITimeout, walkCtx bounds only the verification walk (anchorCLIWalkTimeout,
// unbounded by default). Both derive from parent — never walkCtx from lockCtx — so
// a large-store walk never inherits the 30 s lock cap. cancel releases both.
func anchorCLIContexts(parent context.Context) (lockCtx, walkCtx context.Context, cancel context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	lockCtx, cancelLock := context.WithTimeout(parent, anchorCLITimeout)
	walkCtx, cancelWalk := anchorCLIWalkContext(parent)
	return lockCtx, walkCtx, func() {
		cancelWalk()
		cancelLock()
	}
}

// errNoAnchorURL is the message for an unset NOCKLOCK_ANCHOR_URL.
const errNoAnchorURL = "no anchor URL configured (NOCKLOCK_ANCHOR_URL)"

// runAnchorPush pushes an anchor file (default: the wrap-teardown anchor next
// to events.db) to the off-box store, authenticated with the local managed
// public key, resolved exactly as verify resolves it.
func runAnchorPush(ctx context.Context, w io.Writer, file string) error {
	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		return errors.New(errNoAnchorURL)
	}
	dbPath, projectRoot, err := resolveAuditDBPath()
	if err != nil {
		return err
	}
	if file == "" {
		file = logging.DefaultAnchorPath(dbPath)
	}
	anchor, err := logging.ReadAnchorV2(file)
	if err != nil {
		return fmt.Errorf("v2 anchor required at %s; explicitly enroll or migrate, then emit a new anchor: %w", file, err)
	}
	pub, err := resolveVerifyPublicKey("")
	if err != nil {
		return err
	}
	if pub == nil {
		return errors.New("no signing public key found; cannot authenticate the anchor")
	}
	logger, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		return err
	}
	defer logger.Close()
	// Interactive push: a person is waiting, so every lock wait and network step
	// is bounded, each on its own fresh budget derived from the caller's context
	// so a slow preflight walk cannot spend a later step's budget. The verification
	// walk runs on its own separate budget (anchorCLIWalkTimeout, unbounded by
	// default) so a large store finishes rather than stopping at 30 s.
	walkCtx, cancelWalk := anchorCLIWalkContext(ctx)
	defer cancelWalk()
	newStep := func(string) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, anchorCLITimeout)
	}
	if err := pushAnchorV2(newStep, walkCtx, logger, anchor, pub, baseURL, token); err != nil {
		return fmt.Errorf("anchor push failed: %w", err)
	}
	fmt.Fprintf(w, "anchor pushed off-box (agent_id=%s, chain_id=%s, row_count=%d, head=%s)\n", anchor.AgentID, anchor.ChainID, anchor.RowCount, anchor.HeadHash)
	return nil
}

// runVerifyAgainstRemoteAnchor uses only the trusted v2 pair. Missing identity,
// unsupported routes and absent remote state fail closed without v1 fallback.
func runVerifyAgainstRemoteAnchor(ctx context.Context, w io.Writer, pubFlag string) error {
	defer writeVerificationCoverage(w, nil)
	fctx, cancel := context.WithTimeout(ctx, anchorCLITimeout)
	defer cancel()
	dbPath, projectRoot, err := resolveAuditDBPath()
	if err != nil {
		return err
	}
	pub, err := resolveVerifyPublicKey(pubFlag)
	if err != nil {
		return err
	}
	if pub == nil {
		return writeAnchorVerifyResult(w, &logging.AnchorVerifyResult{Classification: "no_key", Reason: "no public key available to authenticate the remote anchor"})
	}
	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		return writeAnchorVerifyResult(w, anchorUnavailable(errNoAnchorURL))
	}
	logger, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		return err
	}
	defer logger.Close()
	id, err := logger.ReadChainIdentityContext(fctx)
	if err != nil {
		return writeAnchorVerifyResult(w, anchorUnavailable(err.Error()))
	}
	a, err := anchorclient.FetchLatestV2(fctx, baseURL, token, id.AgentID, id.ChainID, pub)
	if err != nil {
		return writeAnchorVerifyResult(w, anchorUnavailable(err.Error()))
	}
	// The identity read and fetch above are bounded by fctx (anchorCLITimeout); the
	// local walk runs on its own separate budget so a large store finishes.
	walkCtx, cancelWalk := anchorCLIWalkContext(ctx)
	defer cancelWalk()
	result, err := logger.VerifyAgainstAnchorV2Walk(fctx, walkCtx, a, pub)
	if err != nil {
		return writeAnchorVerifyResult(w, anchorUnavailable(err.Error()))
	}
	return writeAnchorV2VerifyResult(w, result)
}

func anchorUnavailable(reason string) *logging.AnchorVerifyResult {
	return &logging.AnchorVerifyResult{Classification: "anchor_unavailable", Reason: reason}
}
