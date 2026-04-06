// Package cli defines the cobra command tree for NockLock.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// exitCodeError carries a child process exit code through cobra, avoiding os.Exit
// inside RunE so that any future deferred cleanup in the call chain can run.
type exitCodeError struct {
	code int
}

func (e *exitCodeError) Error() string {
	return fmt.Sprintf("exit status %d", e.code)
}

var rootCmd = &cobra.Command{
	Use:   "nocklock",
	Short: "AI agent security fence",
	Long:  "NockLock wraps AI coding agents with filesystem, network, and secret isolation.",
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
