package cli

import (
	"errors"
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
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "No config found. Run `nocklock init` to create one.")
				return nil
			}
			return fmt.Errorf("failed to locate config: %w", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config at %s: %w", configPath, err)
		}

		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write config to stdout: %w", err)
		}

		// Load parsed config to show fence summary.
		// Returns a non-zero exit code if the TOML is malformed.
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("config parse error: %w", err)
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
