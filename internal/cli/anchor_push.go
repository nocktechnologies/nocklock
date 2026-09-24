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
