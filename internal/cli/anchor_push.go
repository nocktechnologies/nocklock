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

// anchorPushTimeout bounds the wrap-teardown push. A package var so tests can
// shorten it; production is a hard 5 seconds.
var anchorPushTimeout = 5 * time.Second

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
// person is waiting on the answer, not a session exit.
var anchorCLITimeout = 30 * time.Second

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
	pctx, cancel := context.WithTimeout(ctx, anchorCLITimeout)
	defer cancel()
	if err := pushAnchorV2(pctx, logger, anchor, pub, baseURL, token); err != nil {
		return fmt.Errorf("anchor push failed: %w", err)
	}
	fmt.Fprintf(w, "anchor pushed off-box (agent_id=%s, chain_id=%s, row_count=%d, head=%s)\n", anchor.AgentID, anchor.ChainID, anchor.RowCount, anchor.HeadHash)
	return nil
}

// runVerifyAgainstRemoteAnchor uses only the trusted v2 pair. Missing identity,
// unsupported routes and absent remote state fail closed without v1 fallback.
func runVerifyAgainstRemoteAnchor(ctx context.Context, w io.Writer, pubFlag string) error {
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
	id, err := logger.ReadChainIdentity()
	if err != nil {
		return writeAnchorVerifyResult(w, anchorUnavailable(err.Error()))
	}
	fctx, cancel := context.WithTimeout(ctx, anchorCLITimeout)
	defer cancel()
	a, err := anchorclient.FetchLatestV2(fctx, baseURL, token, id.AgentID, id.ChainID, pub)
	if err != nil {
		return writeAnchorVerifyResult(w, anchorUnavailable(err.Error()))
	}
	result, err := logger.VerifyAgainstAnchorV2(a, pub)
	if err != nil {
		return writeAnchorVerifyResult(w, anchorUnavailable(err.Error()))
	}
	return writeAnchorV2VerifyResult(w, result)
}

func anchorUnavailable(reason string) *logging.AnchorVerifyResult {
	return &logging.AnchorVerifyResult{Classification: "anchor_unavailable", Reason: reason}
}
