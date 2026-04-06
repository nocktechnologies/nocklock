package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize NockLock config in current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		nockDir := ".nock"
		configPath := filepath.Join(nockDir, "config.toml")

		if _, err := os.Stat(configPath); err == nil {
			fmt.Printf("Config already exists at %s\n", configPath)
			return nil
		}

		if err := os.MkdirAll(nockDir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", nockDir, err)
		}

		if err := os.WriteFile(configPath, []byte(config.DefaultTOML()), 0o644); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}

		fmt.Printf("NockLock initialized. Config at %s\n", configPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
