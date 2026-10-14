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
	if _, err := logger.InitializeChainIdentity(digest); err != nil {
		return err
	}
	id, err := logger.RegisterAnchorV2(mode, legacy, func(request logging.AnchorRegistrationRequest) (*logging.AnchorV2, error) {
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
	remote, err := anchorclient.FetchLatestV2(ctx, baseURL, token, id.AgentID, id.ChainID, pub)
	if err != nil {
		return fmt.Errorf("registration is enrolled but remote verification is incomplete; retry verification before pushing: %w", err)
	}
	result, err := logger.VerifyAgainstAnchorV2(remote, pub)
	if err != nil {
		return err
	}
	if err := writeAnchorV2VerifyResult(w, result); err != nil {
		return err
	}
	if err := logging.WriteAnchorV2(logging.DefaultAnchorPath(dbPath), remote); err != nil {
		return err
	}
	fmt.Fprintf(w, "anchor %s complete (agent_id=%s, chain_id=%s); remote v2 pin verified\n", mode, id.AgentID, id.ChainID)
	return nil
}

func pushAnchorV2(ctx context.Context, logger *logging.Logger, a *logging.AnchorV2, pub ed25519.PublicKey, baseURL, token string) error {
	id, err := logger.ReadChainIdentity()
	if err != nil {
		return err
	}
	if id.RegistrationState != logging.ChainRegistrationEnrolled {
		return errors.New("v2 chain is not enrolled; retry explicit anchor enroll or anchor migrate before push")
	}
	candidate, err := logger.VerifyAgainstAnchorV2(a, pub)
	if err != nil {
		return err
	}
	if !candidate.OK {
		return fmt.Errorf("candidate anchor preflight refused: %s", candidate.Reason)
	}
	previous, err := anchorclient.FetchLatestV2(ctx, baseURL, token, id.AgentID, id.ChainID, pub)
	if err != nil {
		return err
	}
	prefix, err := logger.VerifyAgainstAnchorV2(previous, pub)
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
	_, err = anchorclient.PushV2(ctx, baseURL, token, a, pub, digest)
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

func finishAnchorSession(w io.Writer, logger *logging.Logger, dbPath string) {
	path := logging.DefaultAnchorPath(dbPath)
	dir, err := logger.ChainIdentityDirectory()
	if err == nil && dir == "" {
		a, emitErr := logger.EmitAnchor()
		if emitErr == nil {
			emitErr = logging.WriteAnchor(path, a)
		}
		if emitErr != nil {
			fmt.Fprintf(w, "NockLock: warning: chain anchor not written to %s: %v\n", path, emitErr)
		}
		if baseURL, _ := anchorRemoteConfig(); baseURL != "" {
			fmt.Fprintln(w, "NockLock: warning: chain anchor NOT pushed off-box: explicit anchor enroll or anchor migrate is required; no v1 fallback")
		}
		return
	}
	if err != nil {
		fmt.Fprintf(w, "NockLock: warning: chain anchor not written: %v\n", err)
		return
	}
	a, err := logger.EmitAnchorV2()
	if err == nil {
		err = logging.WriteAnchorV2(path, a)
	}
	if err != nil {
		fmt.Fprintf(w, "NockLock: warning: chain anchor not written to %s: %v\n", path, err)
		return
	}
	baseURL, token := anchorRemoteConfig()
	if baseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), anchorPushTimeout)
	defer cancel()
	if err := pushAnchorV2(ctx, logger, a, logger.SigningPublicKey(), baseURL, token); err != nil {
		fmt.Fprintf(w, "NockLock: warning: chain anchor NOT pushed off-box: %v\n", err)
	}
}
