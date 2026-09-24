package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

var anchorCmd = &cobra.Command{
	Use:   "anchor",
	Short: "Emit and manage external chain-head anchors for the audit log",
	Long: "An anchor is a small, signed record of the audit chain's head hash and row count at a\n" +
		"point in time, stored OUTSIDE events.db. Pushed off-box (e.g. to NockCC) it lets\n" +
		"'nocklock verify --against-anchor' detect tail truncation and rollback that the in-database\n" +
		"chain and its signed head cannot resist on their own.",
}

var anchorEmitCmd = &cobra.Command{
	Use:   "emit",
	Short: "Emit a signed anchor of the current audit chain head",
	Long: "Read the current chain_head and emit a signed anchor record\n" +
		"{version, agent_id, head_hash, row_count, created_at, sig} as compact JSON.\n\n" +
		"The anchor is signed with the same NockLock-managed Ed25519 key the audit log signs with;\n" +
		"agent_id is that key's fingerprint. Emitting requires the signing key (the anchor must be\n" +
		"authenticatable), so on a never-signed log this adopts signing, exactly as 'wrap' does.",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := cmd.Flags().GetString("out")
		return runAnchorEmit(cmd.OutOrStdout(), out)
	},
}

var anchorPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push a signed anchor to the off-box anchor store",
	Long: "Push an anchor file to the off-box anchor store at $NOCKLOCK_ANCHOR_URL, authenticated\n" +
		"with the bearer token in $NOCKLOCK_ANCHOR_TOKEN (environment only). The body carries the\n" +
		"anchor and the base64 Ed25519 public key it is signed with. The store refuses (HTTP 409) an\n" +
		"anchor whose row_count is below the latest one it holds for the same agent_id.\n\n" +
		"Defaults to the anchor 'wrap' writes on teardown next to events.db.",
	RunE: func(cmd *cobra.Command, args []string) error {
		file, _ := cmd.Flags().GetString("file")
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		cmd.SilenceUsage = true
		return runAnchorPush(ctx, cmd.OutOrStdout(), file)
	},
}

func init() {
	anchorEmitCmd.Flags().String("out", "", "write the anchor JSON to this file (0600) instead of stdout")
	anchorCmd.AddCommand(anchorEmitCmd)
	anchorPushCmd.Flags().String("file", "", "anchor file to push (default: <db-dir>/chain-anchor.json)")
	anchorCmd.AddCommand(anchorPushCmd)
	rootCmd.AddCommand(anchorCmd)
}

// runAnchorEmit opens the audit log WITH signing (the anchor must be signed to
// be authenticatable), emits an anchor of the current head, and writes it to
// --out or stdout. Opening with signing adopts signing on a never-signed log,
// the same write 'wrap' performs; this is a deliberate, documented side effect
// of anchoring, which is meaningless without a key.
func runAnchorEmit(w io.Writer, outPath string) error {
	dbPath, projectRoot, err := resolveAuditDBPath()
	if err != nil {
		return err
	}

	logger, err := logging.NewLogger(dbPath, projectRoot, signingLoggerOpts()...)
	if err != nil {
		return fmt.Errorf("failed to open event log: %w", err)
	}
	defer logger.Close()

	anchor, err := logger.EmitAnchor()
	if err != nil {
		return fmt.Errorf("failed to emit anchor: %w", err)
	}

	if outPath != "" {
		if err := logging.WriteAnchor(outPath, anchor); err != nil {
			return err
		}
		fmt.Fprintf(w, "anchor written to %s (row_count=%d, head=%s)\n", outPath, anchor.RowCount, anchor.HeadHash)
		return nil
	}

	data, err := logging.MarshalAnchor(anchor)
	if err != nil {
		return fmt.Errorf("failed to marshal anchor: %w", err)
	}
	fmt.Fprintf(w, "%s\n", data)
	return nil
}
