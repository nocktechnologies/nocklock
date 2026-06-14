package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
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
		// Parse NockLock flags (before "--") and child args (after "--").
		wrapFlags, args, flagErr := parseWrapFlags(args)
		if flagErr != nil {
			return flagErr
		}

		if len(args) == 0 && !wrapFlags.DryRun {
			return fmt.Errorf("no command specified. Usage: nocklock wrap [--dry-run] [--allow-private-ranges] -- <command> [args...]")
		}

		// Find and load config — fail closed if missing or invalid.
		configPath, err := config.FindConfig()
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("no NockLock config found. Run 'nocklock init' first to create %s/%s", config.Dir, config.File)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to load config at %s: %w", configPath, err)
		}
		if err := validateWrapRuntimeConfig(cfg); err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("invalid config at %s: %w", configPath, err)
		}
		effectiveCfg := effectiveWrapConfig(cfg, wrapFlags)
		if wrapFlags.DryRun {
			fmt.Fprintln(os.Stdout, effectiveCfg.EffectivePolicy())
			fmt.Fprintf(os.Stderr, "NockLock: dry run OK (%s)\n", configPath)
			return nil
		}

		// Generate a session ID for event logging.
		sessionID := uuid.New().String()

		// Open the event logger. The audit trail is not optional — NockLock's
		// guarantee is that every fence decision is recorded — so a logger that
		// cannot open FAILS CLOSED: the agent does not start. This is the same
		// posture as the network fence (cf. the removed --allow-unfenced flag):
		// running unrecorded would silently break the "every decision is recorded"
		// promise, which is worse than not running at all.
		dbPath, projectRoot := config.ResolveDBPath(cfg, configPath)
		logger, logErr := logging.NewLogger(dbPath, projectRoot)
		if logErr != nil {
			return fmt.Errorf("could not open the event log at %s: %w\nThe audit trail is required — refusing to run unrecorded. Fix the .nock directory's permissions or free disk space", dbPath, logErr)
		}
		defer logger.Close()

		// logEvent records one event. logger is guaranteed non-nil here (the open
		// above fails closed), so no nil guard is needed.
		logEvent := func(eventType logging.EventType, category, detail string, blocked bool) {
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
		if len(blockedNames) > 0 {
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

		// Apply filesystem fence. Linux: LD_PRELOAD interposition. macOS: Seatbelt
		// (sandbox-exec) — fsSandboxPrefix wraps the child argv at launch.
		var fsFenceEvents <-chan fsfence.FenceEvent
		var fsFence *fsfence.Fence
		var fsFenceCancel context.CancelFunc
		var fsSandboxPrefix []string
		var landlockPrefix []string
		if cfg.Filesystem.Root != "" {
			// Fence the audit log from the CHILD so the fenced agent can't delete
			// or corrupt the record of its own actions (the unfenced parent still
			// writes it). Critical on the macOS denylist fence, where the child can
			// otherwise reach the db unless it's explicitly denied.
			cfg.Filesystem.Deny = append(cfg.Filesystem.Deny, auditDenyPath(dbPath, projectRoot))

			fsCfg, err := fsfence.ProcessConfig(cfg.Filesystem)
			if err != nil {
				return fmt.Errorf("invalid filesystem fence config: %w", err)
			}
			if fsCfg != nil {
				switch runtime.GOOS {
				case "linux":
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

					enforcement := linuxEnforcementMode(cfg.Filesystem.LinuxEnforcement)
					if enforcement != linuxEnforcementOff {
						abi, detectErr := landlock.DetectABI()
						if detectErr != nil {
							return fmt.Errorf("failed to detect Landlock support: %w", detectErr)
						}
						if abi == 0 {
							msg := "NockLock: warning: Linux Landlock unavailable; filesystem fence is userspace-only"
							if enforcement == linuxEnforcementRequired {
								return fmt.Errorf("filesystem fence requires Linux Landlock, but this kernel does not support it")
							}
							fmt.Fprintln(os.Stderr, msg)
							logEvent(logging.EventFilePassed, "filesystem", "kernel fence unavailable, userspace-only", false)
						} else {
							exe, err := os.Executable()
							if err != nil {
								return fmt.Errorf("cannot resolve nocklock executable for Landlock shim: %w", err)
							}
							spec, err := landlock.RulesFromConfig(fsCfg, nil, abi)
							if err != nil {
								return fmt.Errorf("failed to build Landlock rules: %w", err)
							}
							encoded, err := landlock.MarshalSpec(spec)
							if err != nil {
								return fmt.Errorf("failed to serialize Landlock rules: %w", err)
							}
							childEnv = append(removeEnvVars(childEnv, landlockRulesEnv), landlockRulesEnv+"="+encoded)
							landlockPrefix = []string{exe, "__landlock-exec", "--"}
							fmt.Fprintf(os.Stderr, "NockLock: Linux Landlock filesystem fence active — ABI v%d\n", spec.ABI)
							logEvent(logging.EventFilePassed, "filesystem", fmt.Sprintf("landlock abi=%d paths=%d", spec.ABI, len(spec.Paths)), false)
						}
					}

					// Start listening for events.
					var ctx context.Context
					ctx, fsFenceCancel = context.WithCancel(cmd.Context())
					defer fsFenceCancel()
					fsFenceEvents = fsFence.Listen(ctx)

					fmt.Fprintf(os.Stderr, "NockLock: filesystem fence active — root %s (%s)\n", fsCfg.Root, fsCfg.Mode)
					logEvent(logging.EventFilePassed, "filesystem", fmt.Sprintf("root=%s mode=%s", fsCfg.Root, fsCfg.Mode), false)

				case "darwin":
					// Seatbelt (sandbox-exec) interim. NOTE: this enforces a DENYLIST
					// (deny sensitive paths, allow the rest), not the Linux allowlist
					// (allow root only). Documented interim divergence; the strict
					// allowlist returns with the Endpoint Security implementation.
					// Fail closed at every step.
					if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
						return fmt.Errorf("filesystem fence cannot be enforced (fail-closed): %w", err)
					}
					sensitive := append(fsfence.DefaultSensitivePaths(), fsCfg.DenyPaths...)
					profile, err := fsfence.GenerateProfile(sensitive)
					if err != nil {
						return fmt.Errorf("filesystem fence profile generation failed (fail-closed): %w", err)
					}
					profilePath, err := fsfence.WriteProfile(profile)
					if err != nil {
						return fmt.Errorf("filesystem fence profile write failed (fail-closed): %w", err)
					}
					defer os.Remove(profilePath)
					fsSandboxPrefix = []string{fsfence.SandboxExecPath, "-f", profilePath}

					fmt.Fprintf(os.Stderr, "NockLock: filesystem fence active (macOS Seatbelt, denylist interim) — %d path(s) fenced\n", len(sensitive))
					logEvent(logging.EventFilePassed, "filesystem", fmt.Sprintf("seatbelt deny_paths=%d", len(sensitive)), false)

				default:
					return fmt.Errorf("filesystem fence configured but not supported on %s", runtime.GOOS)
				}
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

		// childCtx is cancelled by the proxy watchdog if the proxy dies unexpectedly.
		// This terminates the child process, enforcing fail-closed behaviour.
		childCtx, childCancel := context.WithCancel(cmd.Context())
		defer childCancel()
		var proxyFailed atomic.Bool

		if !cfg.Network.AllowAll {
			proxyCfg := effectiveCfg.Network
			proxy := network.NewProxyServer(proxyCfg, logger, sessionID)
			addr, proxyErr := proxy.Start()
			if proxyErr != nil {
				logEvent(logging.EventNetworkError, "network", fmt.Sprintf("proxy start failed: %v", proxyErr), false)
				fmt.Fprintf(os.Stderr, "NockLock: fatal: network fence failed to start: %v\n", proxyErr)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				return &exitCodeError{code: 2}
			} else {
				if readyErr := network.WaitForProxyReady(cmd.Context(), addr, 5*time.Second); readyErr != nil {
					_ = proxy.Stop()
					logEvent(logging.EventNetworkError, "network", fmt.Sprintf("proxy readiness failed: %v", readyErr), true)
					fmt.Fprintf(os.Stderr, "NockLock: fatal: network fence proxy is not healthy: %v\n", readyErr)
					cmd.SilenceUsage = true
					cmd.SilenceErrors = true
					return &exitCodeError{code: 2}
				}
				defer proxy.Stop()

				// Launch watchdog: if proxy crashes mid-session, cancel childCtx to kill the child.
				watchdogCtx, watchdogCancel := context.WithCancel(cmd.Context())
				defer watchdogCancel()
				watchdog := network.NewProxyWatchdog(addr, 5*time.Second, 2, func() {
					proxyFailed.Store(true)
					proxy.MarkDegraded("proxy watchdog: proxy died")
					logEvent(logging.EventNetworkError, "network", "proxy watchdog: proxy died, killing child", true)
					fmt.Fprintf(os.Stderr, "NockLock: fatal: network proxy died unexpectedly — terminating child process\n")
					childCancel()
				})
				watchdog.Start(watchdogCtx)

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

		// On macOS the filesystem fence wraps the child argv with sandbox-exec
		// (kernel-enforced, inherited by all descendants). On Linux fsSandboxPrefix
		// is empty and the child runs directly with the LD_PRELOAD env above.
		childArgv := args
		if len(landlockPrefix) > 0 {
			childArgv = append(append([]string{}, landlockPrefix...), childArgv...)
		}
		if len(fsSandboxPrefix) > 0 {
			childArgv = append(append([]string{}, fsSandboxPrefix...), args...)
		}
		child := exec.CommandContext(childCtx, childArgv[0], childArgv[1:]...)
		child.Env = childEnv
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		// Place the child in its own process group (Setpgid) and, on Linux,
		// set Pdeathsig so descendants are killed if nocklock exits unexpectedly.
		child.SysProcAttr = childSysProcAttr()

		// When the child context is cancelled (e.g. by the proxy watchdog), kill
		// the entire process group — not just the direct child — so no descendant
		// can escape the fence by forking before the parent dies.
		child.Cancel = func() error {
			if child.Process != nil {
				// Negative pid targets the process group (POSIX).
				// ESRCH is returned if the group is already gone; ignore it.
				_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
			}
			return nil
		}

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
			if proxyFailed.Load() {
				logEvent(logging.EventSessionEnd, "session", "exit_code=2 proxy_failed=true", true)
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				return &exitCodeError{code: 2}
			}
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

		if proxyFailed.Load() {
			logEvent(logging.EventSessionEnd, "session", "exit_code=2 proxy_failed=true", true)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return &exitCodeError{code: 2}
		}

		logEvent(logging.EventSessionEnd, "session", "exit_code=0", false)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}

func effectiveWrapConfig(cfg *config.Config, flags WrapFlags) config.Config {
	effective := *cfg
	// CLI flag is additive: if either config-file or flag permits private ranges, allow them.
	effective.Network.AllowPrivateRanges = cfg.Network.AllowPrivateRanges || flags.AllowPrivateRanges
	return effective
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

func validateWrapRuntimeConfig(cfg *config.Config) error {
	if _, err := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block); err != nil {
		return fmt.Errorf("invalid secret fence config: %w", err)
	}

	if cfg.Filesystem.Root != "" {
		if !fsfence.IsSupported() {
			return fmt.Errorf("filesystem fence configured but not supported on %s", runtime.GOOS)
		}
		if _, err := fsfence.ProcessConfig(cfg.Filesystem); err != nil {
			return fmt.Errorf("invalid filesystem fence config: %w", err)
		}
	}

	return nil
}

type linuxEnforcement string

const (
	linuxEnforcementRequired  linuxEnforcement = "required"
	linuxEnforcementPreferred linuxEnforcement = "preferred"
	linuxEnforcementOff       linuxEnforcement = "off"
)

func linuxEnforcementMode(raw string) linuxEnforcement {
	if raw == "" {
		return linuxEnforcementRequired
	}
	return linuxEnforcement(raw)
}

func landlockAuditAllowPaths(dbPath string) []landlock.AllowPath {
	return []landlock.AllowPath{
		{Path: dbPath, Access: landlock.AccessReadWrite},
		{Path: dbPath + "-wal", Access: landlock.AccessReadWrite},
		{Path: dbPath + "-shm", Access: landlock.AccessReadWrite},
		{Path: dbPath + "-journal", Access: landlock.AccessReadWrite},
	}
}

// findLibFenceFS searches for the filesystem fence shared library.
// Security: check trusted paths first (next to binary, system paths)
// before falling back to working directory paths.
// auditDenyPath returns the path to add to the filesystem fence's deny list so a
// fenced child cannot tamper with its own audit log. It denies the whole audit
// directory (covering the db and blocking rename/delete of the log) unless the
// log sits directly in the project root — in which case it denies only the db
// file, so the root itself is never accidentally denied.
//
// The root comparison resolves symlinks (matching the fence's own path
// canonicalization): on macOS /tmp and /var are symlinks to /private/*, so a
// string-only compare could see the audit dir and a symlinked root as different
// and deny the entire root (breaking the agent) — or as equal and skip the dir.
func auditDenyPath(dbPath, projectRoot string) string {
	auditDir := filepath.Dir(dbPath)
	if resolvePathBestEffort(auditDir) != resolvePathBestEffort(projectRoot) {
		return auditDir
	}
	return dbPath
}

// resolvePathBestEffort canonicalizes a path the way the fence does (resolving
// symlinks), falling back to a lexical clean when the path cannot be resolved
// (e.g. it does not exist yet).
func resolvePathBestEffort(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

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
