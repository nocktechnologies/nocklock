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

// installLease is acquireInstallLease, replaceable in tests.
var installLease = acquireInstallLease

// Execute runs the root command.
func Execute() {
	lease, err := installLease()
	if err != nil {
		fmt.Fprintln(os.Stderr, "NockLock: installation unavailable:", err)
		os.Exit(2)
	}
	if lease != nil {
		defer lease.Close()
	}
	if err := rootCmd.Execute(); err != nil {
		var exitErr *exitCodeError
		if !errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(exitCode(err))
	}
}

// exitCode returns the process exit code for a command's error: 0 for nil,
// the code an exitCodeError carries, and 1 for any other error.
func exitCode(err error) int {
	var exitErr *exitCodeError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		return exitErr.code
	}
	return 1
}
