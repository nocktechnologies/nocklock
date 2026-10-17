package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

var anchorEnrollCmd = &cobra.Command{
	Use: "enroll", Short: "Explicitly register this signed audit chain as a new v2 stream",
	Long: "Verify this project's signed audit chain and explicitly establish a new remote pin.\n" +
		"No earlier remote rollback history is claimed. If this signing key has a legacy pin\n" +
		"belonging to another project, --acknowledge-no-legacy-history explicitly confirms that\n" +
		"this project has no claim to it. Use 'anchor migrate' for its actual owning project.\n" +
		"Uncertain responses retain pending; retry the same command and original mode.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ack, _ := cmd.Flags().GetBool("acknowledge-no-legacy-history")
		mode := "fresh"
		if ack {
			mode = "acknowledge_no_legacy_history"
		}
		cmd.SilenceUsage = true
		return runAnchorEnrollment(cmd.Context(), cmd.OutOrStdout(), mode)
	},
}

var anchorMigrateCmd = &cobra.Command{
	Use: "migrate", Short: "Explicitly migrate this project's retained legacy v1 pin to v2",
	Long: "Select this project as the owner of the retained v1 anchor, authenticate that anchor,\n" +
		"and prove its signed local chain reproduces the legacy prefix before migration.\n" +
		"Back up the DB, legacy anchor and trusted state first. A wrong project or divergent\n" +
		"history is refused. Completion requires remote v2 verification; retries retain the\n" +
		"exact original signed registration and legacy witness.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return runAnchorEnrollment(cmd.Context(), cmd.OutOrStdout(), "migrate")
	},
}

func init() {
	anchorEnrollCmd.Flags().Bool("acknowledge-no-legacy-history", false, "confirm this project has no claim to this key's existing legacy remote history")
	anchorCmd.AddCommand(anchorEnrollCmd, anchorMigrateCmd)
}

func runAnchorEnrollment(ctx context.Context, w io.Writer, mode string) error {
	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		return errors.New(errNoAnchorURL)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, anchorCLITimeout)
	defer cancel()
	dbPath, projectRoot, err := resolveAuditDBPath()
	if err != nil {
		return err
	}
	pub, err := resolveVerifyPublicKey("")
	if err != nil {
		return err
	}
	if pub == nil {
		return errors.New("enrollment requires this chain's existing signing key; create a signed audit trail with wrap first")
	}
	// Verify without adopting signing: enrollment cannot bless an unsigned or
	// stripped database simply by opening it with the private key.
	check, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		return err
	}
	verified, verifyErr := check.VerifyChainSigned(pub, true)
	check.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if !verified.Intact || verified.SigState != "authentic" {
		return fmt.Errorf("enrollment requires an authentic intact local chain: %s %s", verified.BrokenReason, verified.SigBrokenReason)
	}
	legacy, err := anchorclient.FetchLegacyForMigration(ctx, baseURL, token, logging.PublicKeyFingerprint(pub), pub)
	if err != nil && !errors.Is(err, anchorclient.ErrNoLegacyHistory) {
		return fmt.Errorf("cannot establish legacy history: %w", err)
	}
	digest := strings.Repeat("0", 64)
	if mode == "migrate" {
		if legacy == nil {
			return errors.New("no retained legacy anchor exists; use explicit anchor enroll for a new pin")
		}
		digest, err = logging.LegacyAnchorSnapshotDigest(legacy, pub)
		if err != nil {
			return err
		}
	} else {
		if legacy != nil && mode != "acknowledge_no_legacy_history" {
			return errors.New("this key has legacy remote history: select its owning project and use anchor migrate, or explicitly acknowledge this project's lack of legacy history with --acknowledge-no-legacy-history")
		}
		legacy = nil
	}
	key, err := logging.DefaultSigningKeyPath()
	if err != nil {
		return err
	}
	logger, err := logging.NewLogger(dbPath, projectRoot, logging.WithExistingSigning(key))
	if err != nil {
		return err
	}
	defer logger.Close()
	// Check migration ownership before creating identity. The locked operation
	// repeats both signed-chain and prefix checks to close the prune race.
	if legacy != nil {
		result, err := logger.VerifyAgainstAnchor(legacy, pub)
		if err != nil {
			return err
		}
		if !result.OK {
			return fmt.Errorf("legacy migration preflight refused: %s", result.Reason)
		}
	}
	if _, err := logger.InitializeChainIdentityContext(ctx, digest); err != nil {
		return err
	}
	id, err := logger.RegisterAnchorV2Context(ctx, mode, legacy, func(request logging.AnchorRegistrationRequest) (*logging.AnchorV2, error) {
		var result *anchorclient.V2Result
		var err error
		if request.Mode == "migrate" {
			result, err = anchorclient.MigrateV2(ctx, baseURL, token, request.Anchor, pub, request.Anchor.LegacyAnchorDigest)
		} else {
			result, err = anchorclient.RegisterV2(ctx, baseURL, token, request.Anchor, pub, request.Mode == "acknowledge_no_legacy_history")
		}
		if err != nil {
			return nil, err
		}
		return result.Anchor, nil
	})
	if err != nil {
		return err
	}
	// Enrollment is durable at the remote once RegisterAnchorV2Context returns, so
	// neither the fetch nor the verify below may run on the CLI budget the
	// pre-enrollment walks already spent. The fetch gets its own fresh budget so
	// the verify stays reachable even after slow registration walks.
	fetchCtx, cancelFetch := context.WithTimeout(context.Background(), anchorCLITimeout)
	remote, err := anchorclient.FetchLatestV2(fetchCtx, baseURL, token, id.AgentID, id.ChainID, pub)
	cancelFetch()
	if err != nil {
		return fmt.Errorf("registration is enrolled but remote verification is incomplete; retry verification before pushing: %w", err)
	}
	if err := verifyAndRecordEnrollment(w, logger, remote, pub, logging.DefaultAnchorPath(dbPath)); err != nil {
		return err
	}
	fmt.Fprintf(w, "anchor %s complete (agent_id=%s, chain_id=%s); remote v2 pin verified\n", mode, id.AgentID, id.ChainID)
	return nil
}

// verifyAndRecordEnrollment runs the post-enrollment verify and, on success,
// writes the local v2 anchor. The remote pin is already enrolled, so this verify
// must not be cut off by the CLI budget the pre-enrollment walks spent: the
// verification walk runs unbounded on context.Background(), and only the
// identity-lock wait is bounded, by its own fresh budget. An interrupted or
// refused verify writes no anchor, so an incomplete local verify never leaves a
// false record: rerun enrollment and it completes against the enrolled pin.
func verifyAndRecordEnrollment(w io.Writer, logger *logging.Logger, remote *logging.AnchorV2, pub ed25519.PublicKey, anchorPath string) error {
	lockCtx, cancel := context.WithTimeout(context.Background(), anchorCLITimeout)
	defer cancel()
	result, err := logger.VerifyAgainstAnchorV2Walk(lockCtx, context.Background(), remote, pub)
	if err != nil {
		return err
	}
	if err := writeAnchorV2VerifyResult(w, result); err != nil {
		return err
	}
	return logging.WriteAnchorV2(anchorPath, remote)
}

// pushAnchorV2 pushes a. newStep makes a fresh deadline for each lock wait and
// each network step, created immediately before that step, so a slow preflight
// walk cannot spend the budget a later FetchLatestV2 or PushV2 needs. The step
// label names the step for callers that log or vary budgets by step. walkCtx
// bounds the local verification walks themselves (in wrap teardown that is
// anchorWalkTimeout, unbounded by default).
func pushAnchorV2(newStep func(step string) (context.Context, context.CancelFunc), walkCtx context.Context, logger *logging.Logger, a *logging.AnchorV2, pub ed25519.PublicKey, baseURL, token string) error {
	idCtx, cancel := newStep("read-identity")
	id, err := logger.ReadChainIdentityContext(idCtx)
	cancel()
	if err != nil {
		return err
	}
	if id.RegistrationState != logging.ChainRegistrationEnrolled {
		return errors.New("v2 chain is not enrolled; retry explicit anchor enroll or anchor migrate before push")
	}
	candLockCtx, cancel := newStep("candidate-walk-lock")
	candidate, err := logger.VerifyAgainstAnchorV2Walk(candLockCtx, walkCtx, a, pub)
	cancel()
	if err != nil {
		return err
	}
	if !candidate.OK {
		return fmt.Errorf("candidate anchor preflight refused: %s", candidate.Reason)
	}
	fetchCtx, cancel := newStep("fetch-latest")
	previous, err := anchorclient.FetchLatestV2(fetchCtx, baseURL, token, id.AgentID, id.ChainID, pub)
	cancel()
	if err != nil {
		return err
	}
	prefixLockCtx, cancel := newStep("prefix-walk-lock")
	prefix, err := logger.VerifyAgainstAnchorV2Walk(prefixLockCtx, walkCtx, previous, pub)
	cancel()
	if err != nil {
		return err
	}
	if !prefix.OK {
		return fmt.Errorf("remote anchor preflight refused: %s", prefix.Reason)
	}
	if a.RowCount < previous.RowCount {
		return errors.New("candidate anchor is older than the remote pin; emit a current anchor before push")
	}
	digest, err := logging.AnchorV2SnapshotDigest(previous, pub, id.AgentID, id.ChainID)
	if err != nil {
		return err
	}
	pushCtx, cancel := newStep("push")
	defer cancel()
	_, err = anchorclient.PushV2(pushCtx, baseURL, token, a, pub, digest)
	return err
}

func writeAnchorV2VerifyResult(w io.Writer, result *logging.AnchorV2VerifyResult) error {
	label := strings.ToUpper(result.Classification)
	if result.Classification == "identity_mismatch" {
		label = "IDENTITY MISMATCH"
	}
	fmt.Fprintf(w, "ANCHOR: %s — %s\n", label, result.Reason)
	if result.OK {
		return nil
	}
	return &exitCodeError{code: 1}
}

// finishAnchorSession is wrap's teardown anchor: emit, write and (when a store
// is configured and the chain is enrolled) push the final head, fail-open.
func finishAnchorSession(w io.Writer, logger *logging.Logger, dbPath string) {
	finishAnchorSessionWithCheckpoints(w, logger, dbPath, nil)
}

// finishAnchorSessionWithCheckpoints stops the in-run checkpoint worker (if
// any) and waits for it, then runs the unchanged teardown push as the final
// flush, then reports the checkpoint summary. Stopping first means the final
// flush never races a checkpoint upload.
func finishAnchorSessionWithCheckpoints(w io.Writer, logger *logging.Logger, dbPath string, cp *anchorCheckpointer) {
	cp.stop()
	cp.report(w, flushAnchorSession(w, logger, dbPath))
}

// anchorFlushResult is the outcome of the teardown push.
type anchorFlushResult struct {
	Final     *logging.AnchorV2 // the v2 head emitted at teardown; nil if none
	Confirmed bool              // the store confirmed Final
	Err       error             // why the emission or the push failed
	Skipped   string            // why no push was attempted
}

// summary states the outcome in the words the checkpoint report uses.
func (r anchorFlushResult) summary() string {
	switch {
	case r.Confirmed && r.Final != nil:
		return fmt.Sprintf("final flush confirmed row_count=%d", r.Final.RowCount)
	case r.Err != nil:
		return "final flush failed: " + r.Err.Error()
	case r.Skipped != "":
		return "final flush not attempted: " + r.Skipped
	default:
		return "final flush not confirmed"
	}
}

// flushAnchorSession is the teardown push. It returns the v2 anchor it emitted
// (nil for a legacy chain or a failed emission), whether the store confirmed
// it, and why not. Failures warn on w and never change the run's exit code.
func flushAnchorSession(w io.Writer, logger *logging.Logger, dbPath string) anchorFlushResult {
	ctx, cancel := context.WithTimeout(context.Background(), anchorPushTimeout)
	defer cancel()
	// One walk budget covers every walk in this teardown: the emission walk and
	// the two push-preflight walks.
	walkCtx, cancelWalk := context.WithCancel(context.Background())
	if anchorWalkTimeout > 0 {
		cancelWalk()
		walkCtx, cancelWalk = context.WithTimeout(context.Background(), anchorWalkTimeout)
	}
	defer cancelWalk()
	path := logging.DefaultAnchorPath(dbPath)
	dir, err := logger.ChainIdentityDirectoryContext(ctx)
	if err == nil && dir == "" {
		a, emitErr := logger.EmitAnchorContext(walkCtx)
		if emitErr == nil {
			emitErr = logging.WriteAnchor(path, a)
		}
		if emitErr != nil {
			fmt.Fprintf(w, "NockLock: warning: chain anchor not written to %s: %v\n", path, emitErr)
		}
		if baseURL, _ := anchorRemoteConfig(); baseURL != "" {
			fmt.Fprintln(w, "NockLock: warning: chain anchor NOT pushed off-box: explicit anchor enroll or anchor migrate is required; no v1 fallback")
		}
		return anchorFlushResult{Skipped: "legacy chain; explicit anchor enroll or anchor migrate is required"}
	}
	if err != nil {
		fmt.Fprintf(w, "NockLock: warning: chain anchor not written: %v\n", err)
		return anchorFlushResult{Err: err}
	}
	a, err := logger.EmitAnchorV2Walk(ctx, walkCtx)
	if err == nil {
		err = logging.WriteAnchorV2(path, a)
	}
	if err != nil {
		fmt.Fprintf(w, "NockLock: warning: chain anchor not written to %s: %v\n", path, err)
		return anchorFlushResult{Err: err}
	}
	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		return anchorFlushResult{Final: a, Skipped: "NOCKLOCK_ANCHOR_URL is not set"}
	}
	// Every lock wait and network step in the push gets its own fresh budget,
	// created right before it, so the preflight walks (unbounded by walkCtx here)
	// cannot spend the budget FetchLatestV2 and PushV2 need. There is no caller
	// waiting on a session exit, so each step parents on context.Background().
	newStep := func(string) (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), anchorPushTimeout)
	}
	if err := pushAnchorV2(newStep, walkCtx, logger, a, logger.SigningPublicKey(), baseURL, token); err != nil {
		fmt.Fprintf(w, "NockLock: warning: chain anchor NOT pushed off-box: %v\n", err)
		return anchorFlushResult{Final: a, Err: err}
	}
	return anchorFlushResult{Final: a, Confirmed: true}
}
