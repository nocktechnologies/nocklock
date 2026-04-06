package cli

import (
	"fmt"
	"os"
	"os/exec"

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

		fmt.Fprintf(os.Stderr, "%s — fences not yet active (coming in PR #3-6)\n", version.BuildInfo())

		child := exec.Command(args[0], args[1:]...)
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		err := child.Run()
		if err == nil {
			return nil
		}
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
		return fmt.Errorf("failed to run %q: %w", args[0], err)
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}
