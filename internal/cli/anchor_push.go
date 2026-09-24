package cli

import (
	"context"
	"crypto/ed25519"
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

// pushAnchorOffBox is wrap teardown's off-box push. With NOCKLOCK_ANCHOR_URL
// unset it does nothing and prints nothing. Otherwise it pushes a under
// anchorPushTimeout and, on any failure, prints a loud warning to w and returns:
// the push is fail-open and never alters the wrapped command's exit code.
func pushAnchorOffBox(w io.Writer, a *logging.Anchor, pub ed25519.PublicKey) {
	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), anchorPushTimeout)
	defer cancel()
	if err := anchorclient.Push(ctx, baseURL, token, a, pub); err != nil {
		fmt.Fprintf(w, "NockLock: warning: chain anchor NOT pushed off-box: %v\n", err)
	}
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
		return fmt.Errorf(errNoAnchorURL)
	}
	if file == "" {
		dbPath, _, err := resolveAuditDBPath()
		if err != nil {
			return err
		}
		file = logging.DefaultAnchorPath(dbPath)
	}
	anchor, err := logging.ReadAnchor(file)
	if err != nil {
		return fmt.Errorf("failed to read anchor file %s: %w", file, err)
	}
	pub, err := resolveVerifyPublicKey("")
	if err != nil {
		return err
	}
	if pub == nil {
		return fmt.Errorf("no signing public key found; the anchor cannot be pushed without the key it is signed with")
	}
	if fp := logging.PublicKeyFingerprint(pub); anchor.AgentID != fp {
		return fmt.Errorf("anchor agent_id %s does not match the local signing key %s; refusing to push", anchor.AgentID, fp)
	}
	pctx, cancel := context.WithTimeout(ctx, anchorCLITimeout)
	defer cancel()
	if err := anchorclient.Push(pctx, baseURL, token, anchor, pub); err != nil {
		return fmt.Errorf("anchor push failed: %w", err)
	}
	fmt.Fprintf(w, "anchor pushed off-box (agent_id=%s, row_count=%d, head=%s)\n", anchor.AgentID, anchor.RowCount, anchor.HeadHash)
	return nil
}

// runVerifyAgainstRemoteAnchor fetches the latest anchor the off-box store
// holds for the local signing identity and verifies the local chain against it
// exactly as --against-anchor does. An unreachable store, an unset URL, or no
// stored anchor is ANCHOR: UNAVAILABLE and exits non-zero: absence of the
// off-box pin is reported, never read as a pass.
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
		// Without a key there is no identity to fetch by and nothing could be
		// authenticated; fail closed through the shared no_key verdict.
		return writeAnchorVerifyResult(w, &logging.AnchorVerifyResult{
			Classification: "no_key",
			Reason:         "no public key available to resolve the signing identity or authenticate the remote anchor (supply --ed25519-pub or run on the signing host)",
		})
	}

	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		return writeAnchorVerifyResult(w, anchorUnavailable(errNoAnchorURL))
	}
	fctx, cancel := context.WithTimeout(ctx, anchorCLITimeout)
	defer cancel()
	anchor, err := anchorclient.FetchLatest(fctx, baseURL, token, logging.PublicKeyFingerprint(pub))
	if err != nil {
		return writeAnchorVerifyResult(w, anchorUnavailable(err.Error()))
	}

	logger, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		return fmt.Errorf("failed to open event log: %w", err)
	}
	defer logger.Close()

	result, err := logger.VerifyAgainstAnchor(anchor, pub)
	if err != nil {
		return fmt.Errorf("anchor verification failed: %w", err)
	}
	return writeAnchorVerifyResult(w, result)
}

func anchorUnavailable(reason string) *logging.AnchorVerifyResult {
	return &logging.AnchorVerifyResult{Classification: "anchor_unavailable", Reason: reason}
}
