package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active fenced sessions",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("No active fenced sessions.")
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
