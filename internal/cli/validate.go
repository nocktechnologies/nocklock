package cli

import (
	"fmt"
	"os"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate [config-path]",
	Short: "Validate a NockLock config file",
	Long:  "Validates a NockLock config file and prints the effective policy. Exits non-zero if the config is invalid.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var configPath string
		var err error

		if len(args) == 1 {
			configPath = args[0]
		} else {
			configPath, err = config.FindConfig()
			if err != nil {
				cmd.SilenceUsage = true
				return fmt.Errorf("no NockLock config found. Run 'nocklock init' first or pass a config path")
			}
		}

		cfg, loadErr := config.Load(configPath)
		if loadErr != nil {
			cmd.SilenceUsage = true
			fmt.Fprintf(os.Stderr, "NockLock: config invalid: %v\n", loadErr)
			return &exitCodeError{code: 1}
		}

		fmt.Fprintln(os.Stdout, cfg.EffectivePolicy())
		fmt.Fprintf(os.Stderr, "NockLock: config OK (%s)\n", configPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}
