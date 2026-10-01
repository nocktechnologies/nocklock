package cli

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active fenced sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.FindConfig()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "No config found. Run 'nocklock init' first.")
				return nil
			}
			return fmt.Errorf("failed to locate config: %w", err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		fmt.Println(version.BuildInfo())

		// Secret fence status
		blockCount := len(cfg.Secrets.Block)
		if len(cfg.Secrets.Pass) > 0 || blockCount > 0 {
			fmt.Printf("Secret fence: active (blocking %d patterns)\n", blockCount)
		} else {
			fmt.Println("Secret fence: not configured")
		}

		// Filesystem fence status
		if cfg.Filesystem.Root != "" {
			allowCount := len(cfg.Filesystem.Allow)
			allowRWCount := len(cfg.Filesystem.AllowRW)
			denyCount := len(cfg.Filesystem.Deny)
			fmt.Printf("Filesystem fence: active (allow %d read-only, %d read-write, deny %d)\n", allowCount, allowRWCount, denyCount)
			if runtime.GOOS == "darwin" {
				fmt.Println("Filesystem deny events: best-effort on macOS via the unified log")
			}
		} else {
			fmt.Println("Filesystem fence: not configured")
		}

		// Network fence status
		if cfg.Network.AllowAll {
			fmt.Println("Network fence: disabled (allow_all = true)")
		} else {
			domainCount := len(cfg.Network.Allow)
			fmt.Printf("Network fence: active (allowing %d domain(s))\n", domainCount)
		}

		// Event log summary
		dbPath, projectRoot, err := config.ResolveDBPath(cfg, configPath)
		if err != nil {
			cmd.SilenceUsage = true
			return err
		}
		// Show the RESOLVED path, not what the config says. A relative
		// logging.db no longer describes where the log is — it resolves into
		// the audit state directory outside the project — so echoing the config
		// value would point the operator at a file that is not there.
		relDB := dbPath

		if _, statErr := os.Stat(dbPath); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				fmt.Printf("Event log: %s (no events recorded)\n", relDB)
				return nil
			}
			fmt.Printf("Event log: error (%v)\n", statErr)
			return nil
		}

		logger, logErr := logging.NewLogger(dbPath, projectRoot)
		if logErr != nil {
			fmt.Printf("Event log: unavailable (%v)\n", logErr)
		} else {
			defer logger.Close()
			stats, statsErr := logger.Stats("")
			if statsErr != nil {
				fmt.Printf("Event log: unavailable (%v)\n", statsErr)
			} else {
				fmt.Printf("Event log: %s (%d events, %d sessions)\n", relDB, stats.TotalEvents, stats.SessionCount)
				if stats.LastEvent != nil {
					fmt.Printf("Last event: %s\n", stats.LastEvent.Local().Format("2006-01-02 15:04:05"))
				}
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
