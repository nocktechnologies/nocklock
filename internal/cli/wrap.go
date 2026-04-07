package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

var wrapCmd = &cobra.Command{
	Use:   "wrap -- <command> [args...]",
	Short: "Wrap a command with NockLock fences",
	Long:  "Wraps an AI agent command with filesystem, network, and secret isolation.",
	// Disable all flag parsing so every token is passed through as a raw argument.
	// Cobra will not consume any flags; we manually strip the leading "--" below.
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Strip leading "--" if present
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}

		if len(args) == 0 {
			return fmt.Errorf("no command specified. Usage: nocklock wrap -- <command> [args...]")
		}

		// Generate a session ID for event logging.
		sessionID := uuid.New().String()

		// Find and load config — fail closed if missing or invalid.
		configPath, err := config.FindConfig()
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("no NockLock config found. Run 'nocklock init' first")
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to load config at %s: %w", configPath, err)
		}

		// Open the event logger. If it fails, warn and continue without logging.
		var logger *logging.Logger
		dbPath, projectRoot := config.ResolveDBPath(cfg, configPath)
		logger, logErr := logging.NewLogger(dbPath, projectRoot)
		if logErr != nil {
			fmt.Fprintf(os.Stderr, "NockLock: warning: could not open event log: %v\n", logErr)
			logger = nil
		}
		if logger != nil {
			defer logger.Close()
		}

		// nil-safe logging helper.
		logEvent := func(eventType logging.EventType, category, detail string, blocked bool) {
			if logger == nil {
				return
			}
			_ = logger.Log(logging.Event{
				Timestamp: time.Now(),
				EventType: eventType,
				Category:  category,
				Detail:    detail,
				Blocked:   blocked,
				SessionID: sessionID,
			})
		}

		// Log session start with the command being run.
		logEvent(logging.EventSessionStart, "session", args[0], false)

		// Log config loaded with project name.
		logEvent(logging.EventConfigLoaded, "session", cfg.Project.Name, false)

		// Apply secret fence.
		fence, fenceErr := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block)
		if fenceErr != nil {
			return fmt.Errorf("invalid secret fence config: %w", fenceErr)
		}
		var blockedNames []string
		childEnv, blockedNames := fence.Filter(os.Environ())

		// Log all blocked env vars in a single transaction.
		if logger != nil && len(blockedNames) > 0 {
			batch := make([]logging.Event, len(blockedNames))
			for i, name := range blockedNames {
				batch[i] = logging.Event{
					Timestamp: time.Now(),
					EventType: logging.EventSecretBlocked,
					Category:  "secret",
					Detail:    name,
					Blocked:   true,
					SessionID: sessionID,
				}
			}
			_ = logger.LogBatch(batch)
		}

		// Log all passed env var names as one event.
		var passedNames []string
		for _, entry := range childEnv {
			name, _, hasEquals := strings.Cut(entry, "=")
			if hasEquals && name != "" {
				passedNames = append(passedNames, name)
			}
		}
		if len(passedNames) > 0 {
			logEvent(logging.EventSecretPassed, "secret", strings.Join(passedNames, ", "), false)
		}

		if len(blockedNames) > 0 {
			fmt.Fprintf(os.Stderr, "NockLock: secret fence active — blocked %d environment variable(s)\n", len(blockedNames))
			if cfg.Logging.Level == "debug" {
				fmt.Fprintf(os.Stderr, "  blocked: %s\n", strings.Join(blockedNames, ", "))
			}
		} else {
			fmt.Fprintf(os.Stderr, "NockLock: secret fence active — no variables blocked\n")
		}

		child := exec.Command(args[0], args[1:]...)
		child.Env = childEnv
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		if err := child.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code := exitErr.ExitCode()
				if code < 0 {
					// Negative exit code means signal termination (Unix) or abnormal exit.
					// Fall back to 1 for cross-platform safety.
					code = 1
				}
				logEvent(logging.EventSessionEnd, "session", fmt.Sprintf("exit_code=%d", code), false)
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				return &exitCodeError{code: code}
			}
			logEvent(logging.EventSessionEnd, "session", "exit_code=1", false)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to run %q: %w", args[0], err)
		}

		logEvent(logging.EventSessionEnd, "session", "exit_code=0", false)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}
