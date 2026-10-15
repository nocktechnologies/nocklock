package cli

import (
	"context"
	"errors"
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
	Long: "Verify the signed local chain and emit its head as compact JSON. A trusted chain\n" +
		"identity selects v2; a wholly legacy chain emits v1 for explicit file verification.\n" +
		"Emission requires the existing signing key and signing adoption; it never adopts\n" +
		"or re-signs an unsigned or stripped database. Use wrap to create a signed audit trail.",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := cmd.Flags().GetString("out")
		return runAnchorEmit(cmd.Context(), cmd.OutOrStdout(), out)
	},
}

var anchorPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push a signed anchor to the off-box anchor store",
	Long: "Push a v2 anchor to $NOCKLOCK_ANCHOR_URL using $NOCKLOCK_ANCHOR_TOKEN (environment\n" +
		"only). Explicit enrollment is required. Authenticate the trusted pair, candidate\n" +
		"local prefix and latest remote prefix before a conditional store update. Missing\n" +
		"pins and unsupported v2 routes fail; this command never falls back to v1.\n\n" +
		"Defaults to the anchor wrap writes on teardown next to events.db.",
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

// runAnchorEmit verifies existing signing without adopting or repairing the
// database, then emits the selected v1/v2 record to --out or stdout.
func runAnchorEmit(ctx context.Context, w io.Writer, outPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, anchorCLITimeout)
	defer cancel()
	dbPath, projectRoot, err := resolveAuditDBPath()
	if err != nil {
		return err
	}

	key, err := logging.DefaultSigningKeyPath()
	if err != nil {
		return err
	}
	logger, err := logging.NewLogger(dbPath, projectRoot, logging.WithExistingSigning(key))
	if err != nil {
		return fmt.Errorf("failed to open event log: %w", err)
	}
	defer logger.Close()

	if dir, err := logger.ChainIdentityDirectoryContext(ctx); err != nil {
		return err
	} else if dir != "" {
		anchor, err := logger.EmitAnchorV2Context(ctx)
		if err != nil {
			// Emission site: an interrupted verification walk signs nothing, so
			// say so here. ErrVerifyInterrupted itself stays neutral because it
			// is also raised by verify-only paths that write no anchor regardless.
			if errors.Is(err, logging.ErrVerifyInterrupted) {
				return fmt.Errorf("no anchor was written: %w", err)
			}
			return err
		}
		if outPath != "" {
			if err := logging.WriteAnchorV2(outPath, anchor); err != nil {
				return err
			}
			_, err := fmt.Fprintf(w, "anchor written to %s (row_count=%d, head=%s)\n", outPath, anchor.RowCount, anchor.HeadHash)
			return err
		}
		data, err := logging.MarshalAnchorV2(anchor)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", data)
		return err
	}

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
