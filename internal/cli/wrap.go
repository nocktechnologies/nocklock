package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/network"
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

		// Apply filesystem fence (Linux only).
		var fsFenceEvents <-chan fsfence.FenceEvent
		var fsFence *fsfence.Fence
		var fsFenceCancel context.CancelFunc
		if cfg.Filesystem.Root != "" {
			if err := fsfence.CheckSupported(); err != nil {
				cmd.SilenceUsage = true
				return fmt.Errorf("filesystem fence configured but cannot activate: %w", err)
			}

			fsCfg, err := fsfence.ProcessConfig(cfg.Filesystem)
			if err != nil {
				return fmt.Errorf("invalid filesystem fence config: %w", err)
			}
			if fsCfg != nil {
				// Look for the shared library next to the nocklock binary or in standard paths.
				libPath := findLibFenceFS()
				if _, err := os.Stat(libPath); err != nil {
					return fmt.Errorf("filesystem fence library not found at %s. Build it with: make build-fence-fs", libPath)
				}

				fsFence, err = fsfence.NewFence(fsCfg, libPath)
				if err != nil {
					return fmt.Errorf("failed to initialize filesystem fence: %w", err)
				}
				defer fsFence.Close()

				// Add LD_PRELOAD and NOCKLOCK_FS_ALLOWED to child env.
				// Merge LD_PRELOAD with any existing value in childEnv.
				fenceEnv := fsFence.EnvVars()
				for i, fenceVar := range fenceEnv {
					if strings.HasPrefix(fenceVar, "LD_PRELOAD=") {
						fenceLib := strings.TrimPrefix(fenceVar, "LD_PRELOAD=")
						for j, childVar := range childEnv {
							if strings.HasPrefix(childVar, "LD_PRELOAD=") {
								existing := strings.TrimPrefix(childVar, "LD_PRELOAD=")
								if existing == "" {
									childEnv[j] = "LD_PRELOAD=" + fenceLib
								} else {
									childEnv[j] = "LD_PRELOAD=" + fenceLib + ":" + existing
								}
								fenceEnv = append(fenceEnv[:i], fenceEnv[i+1:]...)
								break
							}
						}
						break
					}
				}
				childEnv = append(childEnv, fenceEnv...)

				// Start listening for events.
				var ctx context.Context
				ctx, fsFenceCancel = context.WithCancel(context.Background())
				defer fsFenceCancel()
				fsFenceEvents = fsFence.Listen(ctx)

				fmt.Fprintf(os.Stderr, "NockLock: filesystem fence active — root %s (%s)\n", fsCfg.Root, fsCfg.Mode)
				logEvent(logging.EventFilePassed, "filesystem", fmt.Sprintf("root=%s mode=%s", fsCfg.Root, fsCfg.Mode), false)
			}
		}

		// Apply network fence.
		// Strip ALL ambient proxy vars unconditionally — even when allow_all = true.
		// Rationale: if the fence is active, an inherited proxy bypasses the allowlist.
		// If allow_all = true, we want the child to have direct network access rather
		// than an operator proxy whose scope we don't control. This is a deliberate
		// security-over-convenience tradeoff; document it if it surprises users.
		childEnv = removeEnvVars(childEnv,
			"HTTP_PROXY", "http_proxy",
			"HTTPS_PROXY", "https_proxy",
			"ALL_PROXY", "all_proxy",
			"NO_PROXY", "no_proxy",
		)

		if !cfg.Network.AllowAll {
			proxy := network.NewProxyServer(cfg.Network, logger, sessionID)
			addr, proxyErr := proxy.Start()
			if proxyErr != nil {
				// Degrade gracefully per design — agent still runs, but logs the failure.
				// NOTE: This is a deliberate design tradeoff (see PR #7 spec). For stricter
				// enforcement, change this to: return fmt.Errorf("network fence failed: %w", proxyErr)
				fmt.Fprintf(os.Stderr, "NockLock: warning: network fence failed to start: %v\n", proxyErr)
				logEvent(logging.EventNetworkError, "network", fmt.Sprintf("proxy start failed: %v", proxyErr), false)
			} else {
				defer proxy.Stop()
				proxyURL := "http://" + addr
				childEnv = append(childEnv,
					"HTTP_PROXY="+proxyURL,
					"HTTPS_PROXY="+proxyURL,
					"http_proxy="+proxyURL,
					"https_proxy="+proxyURL,
					"ALL_PROXY="+proxyURL,
					"all_proxy="+proxyURL,
				)
				fmt.Fprintf(os.Stderr, "NockLock: network fence active — allowing %d domain(s)\n", len(cfg.Network.Allow))
				logEvent(logging.EventNetworkPassed, "network", fmt.Sprintf("proxy=%s domains=%d", addr, len(cfg.Network.Allow)), false)
			}
		} else {
			fmt.Fprintf(os.Stderr, "NockLock: network fence disabled (allow_all = true)\n")
		}

		child := exec.Command(args[0], args[1:]...)
		child.Env = childEnv
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		// Start consuming events in background before running child.
		var eventsWg sync.WaitGroup
		if fsFenceEvents != nil {
			eventsWg.Add(1)
			go func() {
				defer eventsWg.Done()
				for ev := range fsFenceEvents {
					logEvent(logging.EventFileBlocked, "filesystem",
						fmt.Sprintf("op=%s path=%s reason=%s", ev.Operation, ev.Path, ev.Reason), true)
				}
			}()
		}

		childErr := child.Run()

		// Cancel the fence context to stop the listener, then wait for event goroutine.
		if fsFenceCancel != nil {
			fsFenceCancel()
		}
		eventsWg.Wait()

		if childErr != nil {
			if exitErr, ok := childErr.(*exec.ExitError); ok {
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
			return fmt.Errorf("failed to run %q: %w", args[0], childErr)
		}

		logEvent(logging.EventSessionEnd, "session", "exit_code=0", false)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}

// removeEnvVars returns env with any entries whose key matches one of the given
// keys removed. Keys are matched case-sensitively by prefix ("KEY=").
func removeEnvVars(env []string, keys ...string) []string {
	filtered := env[:0:len(env)]
	for _, entry := range env {
		keep := true
		for _, key := range keys {
			if strings.HasPrefix(entry, key+"=") || entry == key {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// findLibFenceFS searches for the filesystem fence shared library.
// Security: check trusted paths first (next to binary, system paths)
// before falling back to working directory paths.
func findLibFenceFS() string {
	// 1. Next to the current executable.
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "libfence_fs.so")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 2. Standard system paths.
	for _, dir := range []string{"/usr/local/lib/nocklock", "/usr/lib/nocklock"} {
		candidate := filepath.Join(dir, "libfence_fs.so")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 3. Build output directory (least trusted — only for development).
	candidate := filepath.Join("internal", "fence", "fs", "interposer", "libfence_fs.so")
	if _, err := os.Stat(candidate); err == nil {
		abs, err := filepath.Abs(candidate)
		if err == nil {
			return abs
		}
		return candidate
	}

	// Default: bare name (will fail os.Stat check in caller).
	return "libfence_fs.so"
}
