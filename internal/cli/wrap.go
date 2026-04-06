package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var wrapCmd = &cobra.Command{
	Use:   "wrap -- <command> [args...]",
	Short: "Wrap a command with NockLock fences",
	Long:  "Wraps an AI agent command with filesystem, network, and secret isolation.",
	// Disable all flag parsing so every token is passed through as a raw argument.
	// Cobra will not consume any flags; we manually strip the leading "--" below.
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Strip leading "--" if present
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}

		if len(args) == 0 {
			return fmt.Errorf("no command specified. Usage: nocklock wrap -- <command> [args...]")
		}

		// Attempt to load config for fence setup.
		// FindConfig walks up the directory tree so subdirectory runs pick up
		// a parent-level .nock/config.toml rather than failing open.
		configPath, findErr := config.FindConfig()

		var childEnv []string
		if findErr != nil {
			if errors.Is(findErr, os.ErrNotExist) {
				// No config found anywhere up the tree — warn and run passthrough.
				fmt.Fprintf(os.Stderr, "%s — no config found, running without fences\n", version.BuildInfo())
				childEnv = os.Environ()
			} else {
				return fmt.Errorf("failed to locate config: %w", findErr)
			}
		} else {
			cfg, err := config.Load(configPath)
			if err != nil {
				// Config found but invalid — fail closed.
				return fmt.Errorf("failed to load config: %w", err)
			}
			// Apply secret fence.
			fence, fenceErr := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block)
			if fenceErr != nil {
				return fmt.Errorf("invalid secret fence config: %w", fenceErr)
			}
			var blockedNames []string
			childEnv, blockedNames = fence.Filter(os.Environ())

			if len(blockedNames) > 0 {
				fmt.Fprintf(os.Stderr, "NockLock: secret fence active — blocked %d environment variable(s)\n", len(blockedNames))
				if cfg.Logging.Level == "debug" {
					fmt.Fprintf(os.Stderr, "  blocked: %s\n", strings.Join(blockedNames, ", "))
				}
			} else {
				fmt.Fprintf(os.Stderr, "NockLock: secret fence active — no variables blocked\n")
			}
		}

		child := exec.Command(args[0], args[1:]...)
		child.Env = childEnv
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		if err := child.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code := exitErr.ExitCode()
				if code < 0 {
					// Negative exit code means signal termination (Unix) or abnormal exit.
					// Fall back to 1 for cross-platform safety.
					code = 1
				}
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				return &exitCodeError{code: code}
			}
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to run %q: %w", args[0], err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}
