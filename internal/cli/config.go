package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print current NockLock config",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := filepath.Join(config.Dir, config.File)

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No config found. Run `nocklock init` to create one.")
				return nil
			}
			return fmt.Errorf("failed to read config at %s: %w", configPath, err)
		}

		os.Stdout.Write(data)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
