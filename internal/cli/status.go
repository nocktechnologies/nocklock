package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active fenced sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := filepath.Join(config.Dir, config.File)
		cfg, err := config.Load(configPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "No config found. Run 'nocklock init' first.")
				return nil
			}
			return fmt.Errorf("failed to load config: %w", err)
		}

		fmt.Println(version.BuildInfo())

		// Secret fence status
		passCount := len(cfg.Secrets.Pass)
		blockCount := len(cfg.Secrets.Block)
		if passCount > 0 || blockCount > 0 {
			fmt.Printf("Secret fence: active (pass %d, block %d patterns)\n", passCount, blockCount)
		} else {
			fmt.Println("Secret fence: not configured")
		}

		// Placeholder for future fences
		fmt.Println("Filesystem fence: not active")
		fmt.Println("Network fence: not active")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
