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
		nockDir := config.Dir
		configPath := filepath.Join(nockDir, config.File)

		if err := os.MkdirAll(nockDir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", nockDir, err)
		}

		// Use O_CREATE|O_EXCL for atomic create-or-fail, avoiding TOCTOU race.
		f, err := os.OpenFile(configPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if os.IsExist(err) {
				fmt.Fprintf(os.Stderr, "Config already exists at %s\n", configPath)
				return nil
			}
			return fmt.Errorf("failed to create config at %s: %w", configPath, err)
		}
		if _, err := f.WriteString(config.DefaultTOML()); err != nil {
			f.Close()
			os.Remove(configPath) // best-effort cleanup of partial file
			return fmt.Errorf("failed to write config at %s: %w", configPath, err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to finalize config at %s: %w", configPath, err)
		}

		fmt.Fprintf(os.Stderr, "NockLock initialized. Config at %s\n", configPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
