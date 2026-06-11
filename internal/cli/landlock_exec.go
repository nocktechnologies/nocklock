package cli

import (
	"fmt"
	"os"

	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/spf13/cobra"
)

const landlockRulesEnv = "NOCKLOCK_LANDLOCK_RULES"

var landlockExecCmd = &cobra.Command{
	Use:                "__landlock-exec -- <command> [args...]",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return fmt.Errorf("missing command after --")
		}
		raw := os.Getenv(landlockRulesEnv)
		if raw == "" {
			return fmt.Errorf("%s is required", landlockRulesEnv)
		}
		spec, err := landlock.UnmarshalSpec(raw)
		if err != nil {
			return fmt.Errorf("invalid Landlock rules: %w", err)
		}
		if err := landlock.Apply(spec); err != nil {
			return fmt.Errorf("failed to apply Landlock rules: %w", err)
		}
		return landlock.Exec(args, removeEnvVars(os.Environ(), landlockRulesEnv))
	},
}

func init() {
	rootCmd.AddCommand(landlockExecCmd)
}
