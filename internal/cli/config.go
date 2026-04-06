package cli

import (
	"fmt"
	"os"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print current NockLock config",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := config.FindConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "No config found. Run `nocklock init` to create one.")
			return nil
		}

		// Parse config first to catch errors before printing anything.
		cfg, err := config.Load(configPath)
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("invalid config at %s: %w", configPath, err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config at %s: %w", configPath, err)
		}

		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write config to stdout: %w", err)
		}

		fmt.Printf("\n# Fence summary:\n")
		fmt.Printf("#   Secret fence: %d pass patterns, %d block patterns\n",
			len(cfg.Secrets.Pass), len(cfg.Secrets.Block))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
