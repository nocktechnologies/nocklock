package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View fence event log",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("No fence events recorded. Events will appear here once fences are active.")
	},
}

func init() {
	rootCmd.AddCommand(logCmd)
}
