package cli

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show configured fences and the event log (does not track running sessions)",
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

		out := cmd.OutOrStdout()
		fmt.Fprintln(out, version.BuildInfo())
		fmt.Fprintln(out, "Fences below are configured, no active session tracked; run 'nocklock doctor' for enforcement.")

		// Secret fence status
		blockCount := len(cfg.Secrets.Block)
		if len(cfg.Secrets.Pass) > 0 || blockCount > 0 {
			fmt.Fprintf(out, "Secret fence: configured (blocking %d patterns)\n", blockCount)
		} else {
			fmt.Fprintln(out, "Secret fence: not configured")
		}

		// Filesystem fence status
		if cfg.Filesystem.Root != "" {
			allowCount := len(cfg.Filesystem.Allow)
			allowRWCount := len(cfg.Filesystem.AllowRW)
			denyCount := len(cfg.Filesystem.Deny)
			fmt.Fprintf(out, "Filesystem fence: configured (allow %d read-only, %d read-write, deny %d)\n", allowCount, allowRWCount, denyCount)
			if runtime.GOOS == "darwin" {
				fmt.Fprintln(out, "Filesystem deny events: best-effort on macOS via the unified log")
			}
		} else {
			fmt.Fprintln(out, "Filesystem fence: not configured")
		}

		// Network fence status
		if cfg.Network.AllowAll {
			fmt.Fprintln(out, "Network fence: disabled (allow_all = true)")
		} else {
			domainCount := len(cfg.Network.Allow)
			fmt.Fprintf(out, "Network fence: configured (allowing %d domain(s))\n", domainCount)
		}
		if runtime.GOOS == "linux" {
			syscallActive := syscallEnforcementMode(cfg.Syscall.Enforcement) != syscallfence.ModeOff && syscallfence.Supported()
			level := effectiveEgressLevel("linux", "proxy", cfg.Network.AllowAll, syscallActive, cfg.Filesystem.Root != "", false)
			if level != egressLevelConfined {
				if cfg.Network.RequireUnixSocketIsolation {
					fmt.Fprintf(cmd.OutOrStdout(), "Unix-socket isolation: unavailable (wrap will refuse: network.require_unix_socket_isolation requires Linux CONFINED egress, but configured egress level is %s)\n", level)
				} else if cfg.Network.AllowAll {
					fmt.Fprintln(cmd.OutOrStdout(), "Unix-socket isolation: not applicable (network.allow_all = true)")
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "Unix-socket isolation: not applicable (configured egress level is %s; isolation requires Linux CONFINED egress)\n", level)
				}
			} else {
				abi, abiErr := landlock.DetectABI()
				status, _ := unixSocketBoundaryStatus(abi, abiErr)
				message := unixSocketBoundaryMessage(abi, abiErr)
				if status == "unavailable" && cfg.Network.RequireUnixSocketIsolation {
					message += " Wrap will refuse because network.require_unix_socket_isolation = true."
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Unix-socket isolation: %s (%s)\n", status, message)
			}
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
				fmt.Fprintf(out, "Event log: %s (no events recorded)\n", relDB)
				return nil
			}
			fmt.Fprintf(out, "Event log: error (%v)\n", statErr)
			return nil
		}

		logger, logErr := logging.NewLogger(dbPath, projectRoot)
		if logErr != nil {
			fmt.Fprintf(out, "Event log: unavailable (%v)\n", logErr)
		} else {
			defer logger.Close()
			stats, statsErr := logger.Stats("")
			if statsErr != nil {
				fmt.Fprintf(out, "Event log: unavailable (%v)\n", statsErr)
			} else {
				fmt.Fprintf(out, "Event log: %s (%d events, %d sessions)\n", relDB, stats.TotalEvents, stats.SessionCount)
				if stats.LastEvent != nil {
					fmt.Fprintf(out, "Last event: %s\n", stats.LastEvent.Local().Format("2006-01-02 15:04:05"))
				}
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
