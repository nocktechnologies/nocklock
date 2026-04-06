// Package cli defines the cobra command tree for NockLock.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nocklock",
	Short: "AI agent security fence",
	Long:  "NockLock wraps AI coding agents with filesystem, network, and secret isolation.",
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
