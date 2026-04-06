package cli

import (
	"fmt"

	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print NockLock version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.BuildInfo())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
