package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/nocktechnologies/nocklock/internal/fence/network/netns"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

var ensureSandboxExecAvailable = fsfence.EnsureSandboxExecAvailable

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

		if wrapFlags.Profile == "list" {
			printProfiles(os.Stdout)
			return nil
		}
		if len(args) == 0 && !wrapFlags.DryRun {
			return fmt.Errorf("no command specified. Usage: nocklock wrap [--profile <name>] [--dry-run] [--allow-private-ranges] -- <command> [args...]")
		}

		cfg, configPath, err := loadWrapConfig(wrapFlags)
		if err != nil {
			cmd.SilenceUsage = true
			return err
		}
		if err := validateWrapRuntimeConfig(cfg); err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("invalid config at %s: %w", configPath, err)
		}
		effectiveCfg := effectiveWrapConfig(cfg, wrapFlags)

		// --net-fence=netns opts into the kernel-enforced network-namespace
		// default-drop floor (Nock #9916, Phase-1 foundation). It is Linux-only;
		// on any other platform there is no equivalent, so we FAIL CLOSED (refuse)
		// rather than silently fall back to the userspace proxy. Checked before the
		// dry-run branch so `--dry-run` on a non-Linux host reports the refusal too.
		useNetns := wrapFlags.NetFence == "netns"
		if useNetns && runtime.GOOS != "linux" {
			cmd.SilenceUsage = true
			return fmt.Errorf("--net-fence=netns requires Linux kernel network namespaces; refusing to run without the kernel-enforced egress floor")
		}

		// Generate a session ID for event logging.
		sessionID := uuid.New().String()

		// Open the event logger. The audit trail is not optional — NockLock's
		// guarantee is that every fence decision is recorded — so a logger that
		// cannot open FAILS CLOSED: the agent does not start. This is the same
		// posture as the network fence (cf. the removed --allow-unfenced flag):
		// running unrecorded would silently break the "every decision is recorded"
		// promise, which is worse than not running at all.
		dbPath, projectRoot, dbErr := config.ResolveDBPath(cfg, configPath)
		if dbErr != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("could not resolve the event log location: %w\nThe audit trail is required — refusing to run unrecorded", dbErr)
		}
		auditDir, auditDirErr := resolveAuditDirectory(filepath.Dir(dbPath))
		if auditDirErr != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("refusing to start: cannot resolve logging.db directory %s: %w; fix the audit directory path and permissions", filepath.Dir(dbPath), auditDirErr)
		}
		resolvedProjectRoot, projectRootErr := filepath.EvalSymlinks(filepath.Clean(projectRoot))
		if projectRootErr != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("refusing to start: cannot resolve project root %s: %w; fix the project directory path and permissions", projectRoot, projectRootErr)
		}
		if filepath.Clean(auditDir) == filepath.Clean(resolvedProjectRoot) {
			cmd.SilenceUsage = true
			root := filepath.Clean(resolvedProjectRoot)
			refusal := fmt.Errorf(
				"refusing to start: logging.db resolves to the project root %s; move it with its SQLite sidecars and chain anchor under %s/.nock/ and set [logging] db = \".nock/events.db\", or use the NockLock state directory with [logging] db = \"events.db\"",
				root, root,
			)
			if wrapFlags.DryRun {
				return refusal
			}
			logger, logErr := logging.NewLogger(dbPath, projectRoot, signingLoggerOpts()...)
			if logErr != nil {
				return fmt.Errorf("%w; could not record the refusal in the audit log: %v", refusal, logErr)
			}
			logErr = logger.Log(logging.Event{
				Timestamp: time.Now(),
				EventType: logging.EventFileBlocked,
				Category:  "filesystem",
				Detail:    "refused root-level logging.db before launching child",
				Blocked:   true,
				SessionID: sessionID,
			})
			var anchorErr error
			if logErr == nil {
				anchor, emitErr := logger.EmitAnchor()
				anchorErr = emitErr
				if anchorErr == nil {
					anchorErr = logging.WriteAnchor(logging.DefaultAnchorPath(dbPath), anchor)
				}
			}
			closeErr := logger.Close()
			if logErr != nil || anchorErr != nil || closeErr != nil {
				return fmt.Errorf("%w; could not finalize the refusal audit entry: %v", refusal, errors.Join(logErr, anchorErr, closeErr))
			}
			return refusal
		}
		if wrapFlags.DryRun {
			fmt.Fprintln(os.Stdout, effectiveCfg.EffectivePolicy())
			if useNetns {
				fmt.Fprintln(os.Stderr, "NockLock: --net-fence=netns selected — kernel tproxy enforcement uses network.allow for HTTP(S)+DNS; all other egress remains default-drop and passwordless sudo is required at run time")
			}
			if wrapFlags.Profile != "" {
				fmt.Fprintf(os.Stderr, "NockLock: profile %q is the base; %s overlays may only tighten it\n", wrapFlags.Profile, filepath.Join(config.Dir, config.File))
			}
			fmt.Fprintf(os.Stderr, "NockLock: dry run OK (%s)\n", configPath)
			return nil
		}

		// Sign the audit trail with the NockLock-managed Ed25519 key so each
		// recorded decision is authentic, not merely internally consistent. The
		// key is generated 0600 on first use. If its path cannot be resolved we
		// fall back to an unsigned (still hash-chained) open rather than refusing
		// to run; the logger itself fails closed on any write to a log that has
		// already adopted signing.
		logger, logErr := logging.NewLogger(dbPath, projectRoot, signingLoggerOpts()...)
		if logErr != nil {
			return fmt.Errorf("could not open the event log at %s: %w\nThe audit trail is required — refusing to run unrecorded. Fix the .nock directory's permissions or free disk space", dbPath, logErr)
		}
		defer logger.Close()

		// Auto-emit an external chain-head anchor on teardown (N10647). This is the
		// hook a future NockCC push consumes so tail truncation and rollback become
		// detectable off-box. Best-effort but LOGGED: a failure must not crash
		// teardown (the session already ran), yet is never silently swallowed. LIFO
		// defer order places this BEFORE logger.Close (it needs the open signer) and
		// AFTER the SessionEnd event that every return path logs last. The anchor
		// lands next to events.db, inside the audit dir the fenced child is denied.
		//
		// When NOCKLOCK_ANCHOR_URL is set, the written anchor is then pushed off-box
		// under a hard timeout. The push is FAIL-OPEN: the session already ran, so
		// a push failure prints a loud warning and never changes the exit code (this
		// defer does not touch RunE's return value). With the URL unset nothing
		// further happens.
		defer func() {
			anchorPath := logging.DefaultAnchorPath(dbPath)
			anchor, err := logger.EmitAnchor()
			if err == nil {
				err = logging.WriteAnchor(anchorPath, anchor)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "NockLock: warning: chain anchor not written to %s: %v\n", anchorPath, err)
				return
			}
			pushAnchorOffBox(os.Stderr, anchor, logger.SigningPublicKey())
		}()

		// Record the resolved policy before any child setup or launch. The config
		// file lives inside the project root by default, so the fenced child can
		// change it for a later run; this signed row makes that change visible.
		if err := recordConfigDigest(logger, &effectiveCfg, configPath, dbPath, sessionID, resolvedNetworkFenceMode(wrapFlags), cmd.ErrOrStderr()); err != nil {
			return fmt.Errorf("could not record the effective config digest: %w\nThe audit trail is required — refusing to run unrecorded", err)
		}

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
		// macOS filesystem-fence state is an enforcement prerequisite, unlike
		// ordinary best-effort access telemetry: the child must not run unless
		// ENGAGED or the explicit DEGRADED escape hatch is durably recorded.
		recordMacOSFilesystemFenceState := func(state, detail string, blocked bool) error {
			return logger.Log(logging.Event{
				Timestamp: time.Now(),
				EventType: logging.EventFilesystemFenceState,
				Category:  "filesystem",
				Detail:    "macOS filesystem-fence " + state + ": " + detail,
				Blocked:   blocked,
				SessionID: sessionID,
			})
		}

		// Log config loaded with project name.
		logEvent(logging.EventConfigLoaded, "session", cfg.Project.Name, false)

		// Apply secret fence.
		fence, fenceErr := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block)
		if fenceErr != nil {
			return fmt.Errorf("invalid secret fence config: %w", fenceErr)
		}
		var blockedNames []string
		childEnv, blockedNames := fence.Filter(os.Environ())
		// The off-box anchor store's URL and bearer token are wrap's, never the
		// fenced agent's: strip them before the child env is logged or launched.
		childEnv = stripAnchorEnv(childEnv)

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
		if err := runSecretPreflight(cmd.Context(), cfg, configPath, childEnv, sessionID, logger.LogBatch, cmd.ErrOrStderr()); err != nil {
			cmd.SilenceUsage = true
			return err
		}

		if len(blockedNames) > 0 {
			fmt.Fprintf(os.Stderr, "NockLock: secret fence active — blocked %d environment variable(s)\n", len(blockedNames))
			if cfg.Logging.Level == "debug" {
				fmt.Fprintf(os.Stderr, "  blocked: %s\n", strings.Join(blockedNames, ", "))
			}
		} else {
			fmt.Fprintf(os.Stderr, "NockLock: secret fence active — no variables blocked\n")
		}

		// Create the per-session egress decision-log (netns path only) BEFORE the
		// filesystem fence assembles its deny list, so its directory can be denied
		// to the child below. The fenced child runs as the SAME uid as wrap, so an
		// undenied decision log lets a hardened child append FORGED allow/deny
		// records that wrap would then sign into the audit chain — a forgeable
		// egress receipt in exactly the config meant to be trustworthy. It is
		// wrap-user-owned, mode 0600, in a 0700 per-session dir UNDER THE AUDIT
		// STATE ROOT (never the system temp dir — see egressDecisionDir for why
		// that location is Landlock-enforceable, N10710); the transparent proxy
		// opens it as root before it drops to nobody, and wrap's reader streams it
		// into the signed log.
		var decisionLogPath string
		var decisionLogDir string
		if useNetns {
			dir := egressDecisionDir(dbPath, sessionID)
			if dirErr := os.MkdirAll(dir, 0o700); dirErr != nil {
				return fmt.Errorf("create egress decision-log directory: %w", dirErr)
			}
			// Remove the whole <state>/sessions/<id> tree on exit. Best-effort:
			// a SIGKILL skips this defer, so a stale per-session dir can survive
			// under .nock — harmless (it is denied to the child and re-created per
			// session), same as the old temp-dir cleanup.
			defer os.RemoveAll(filepath.Dir(dir))
			decisionLogDir = dir
			decisionLogPath = filepath.Join(dir, "decisions.log")
			decisionFile, fileErr := os.OpenFile(decisionLogPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if fileErr != nil {
				return fmt.Errorf("create egress decision-log file: %w", fileErr)
			}
			_ = decisionFile.Close()
		}

		// Apply filesystem fence. Linux: LD_PRELOAD interposition. macOS: Seatbelt
		// (sandbox-exec) — fsSandboxPrefix wraps the child argv at launch.
		var fsFenceEvents <-chan fsfence.FenceEvent
		var fsFence *fsfence.Fence
		var fsFenceCancel context.CancelFunc
		var fsSandboxPrefix []string
		macOSDenialLog := false
		var landlockPrefix []string
		var fsCfg *fsfence.FenceConfig
		if cfg.Filesystem.Root != "" {
			// Fence the audit log from the CHILD so the fenced agent can't delete
			// or corrupt the record of its own actions (the unfenced parent still
			// writes it). Critical on the macOS denylist fence, where the child can
			// otherwise reach the db unless it's explicitly denied. On the netns
			// path this also denies the whole egress decision-log dir (see
			// egressChildDenyPaths) so the child cannot forge signed egress rows.
			// Like the audit DB, the decision log's integrity against the child
			// requires the fs fence ON; with no fs fence the child can already
			// tamper events.db directly, so this is consistent, not a new gap.
			cfg.Filesystem.Deny = append(cfg.Filesystem.Deny, egressChildDenyPaths(dbPath, decisionLogDir)...)

			var err error
			fsCfg, err = fsfence.ProcessConfig(cfg.Filesystem)
			if err != nil {
				if runtime.GOOS == "darwin" {
					if logErr := recordMacOSFilesystemFenceState("REFUSED-TO-START", "invalid filesystem configuration", true); logErr != nil {
						return fmt.Errorf("cannot record macOS filesystem fence refusal; refusing to start: %w", logErr)
					}
				}
				return fmt.Errorf("invalid filesystem fence config: %w", err)
			}
			if fsCfg != nil {
				// An audit directory inside the fence root has to stay
				// unwritable, which costs the root-mutation grant (see
				// fs.FenceConfig.ProtectedRootSubdir). The question is only
				// where the audit directory actually is -- not whether the log
				// is "legacy" -- because filesystem.root and the project root
				// can differ, and an audit dir outside filesystem.root needs no
				// protection and must not cost the grant.
				if auditDir := filepath.Dir(dbPath); pathIsWithinDir(auditDir, fsCfg.Root) {
					fsCfg.ProtectedRootSubdir = auditDir
					fmt.Fprintf(os.Stderr,
						"NockLock: the audit trail is inside the fence root (%s), so the agent cannot create or remove entries directly in %s.\n"+
							"NockLock: work inside existing subdirectories is unaffected. To lift the restriction, move %s and its SQLite sidecars and chain-anchor.json together outside the fence root while no session is running; configure logging.db for that location.\n",
						auditDir, fsCfg.Root, dbPath)
				}
				switch runtime.GOOS {
				case "linux":
					// Look for the shared library next to the nocklock binary or in standard paths.
					libPath, err := findLibFenceFS()
					if err != nil {
						return err
					}

					fsFence, err = fsfence.NewFence(fsCfg, libPath)
					if err != nil {
						return fmt.Errorf("failed to initialize filesystem fence: %w", err)
					}
					defer fsFence.Close()

					// Add LD_PRELOAD and NOCKLOCK_FS_ALLOWED to child env.
					// mergeFSFenceEnv strips any inherited NOCKLOCK_FS_ALLOWED
					// (security: glibc getenv first-match — see N8185) and merges
					// the fence's LD_PRELOAD ahead of any inherited value.
					childEnv = mergeFSFenceEnv(childEnv, fsFence.EnvVars())

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
							extra := landlock.ExistingExtraAllowPaths(landlockProcSelfAllowPaths()...)
							spec, err := landlock.RulesFromConfig(fsCfg, extra, abi)
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
					// Seatbelt keeps its allow-default base because deny-default aborts
					// common macOS processes. The generated profile nevertheless
					// confines WRITES to filesystem.root and essential runtime paths,
					// while retaining the Phase 1 sensitive read/write denies.
					degradeOrRefuse := func(stage string, setupErr error) error {
						if cfg.Filesystem.MacOSAllowUnfenced {
							if logErr := recordMacOSFilesystemFenceState("DEGRADED", stage+"; explicit filesystem.macos_allow_unfenced=true", false); logErr != nil {
								return fmt.Errorf("cannot record macOS filesystem fence degradation; refusing to start: %w", logErr)
							}
							fmt.Fprintf(os.Stderr, "NockLock: WARNING: macOS filesystem fence DEGRADED — %s; starting unfenced because filesystem.macos_allow_unfenced = true (temporary; removed in v0.6)\n", stage)
							return nil
						}
						if logErr := recordMacOSFilesystemFenceState("REFUSED-TO-START", stage, true); logErr != nil {
							return fmt.Errorf("cannot record macOS filesystem fence refusal; refusing to start: %w", logErr)
						}
						return fmt.Errorf("filesystem fence cannot be enforced (fail-closed): %s: %w", stage, setupErr)
					}

					if err := ensureSandboxExecAvailable(); err != nil {
						if setupErr := degradeOrRefuse("sandbox-exec unavailable", err); setupErr != nil {
							return setupErr
						}
						break
					}

					defaultSensitive := fsfence.DefaultSensitivePaths()
					if len(defaultSensitive) == 0 {
						if setupErr := degradeOrRefuse("default sensitive paths unavailable", errors.New("cannot resolve the current user's home directory")); setupErr != nil {
							return setupErr
						}
						break
					}
					sensitive := append(defaultSensitive, fsCfg.DenyPaths...)
					// The audit state is written only by this unfenced parent. It
					// is already included in sensitive through egressChildDenyPaths,
					// so never grant its directory to the fenced child.
					profile, pathCount, err := fsfence.GenerateTaggedWriteConfinementProfile(
						sensitive, fsCfg.Root, fsCfg.Mode, cfg.Filesystem.Hardened, fsfence.DenialTag(sessionID),
					)
					if err != nil {
						if setupErr := degradeOrRefuse("profile generation failed", err); setupErr != nil {
							return setupErr
						}
						break
					}

					profilePath, err := fsfence.WriteProfile(profile)
					if err != nil {
						if setupErr := degradeOrRefuse("profile write failed", err); setupErr != nil {
							return setupErr
						}
						break
					}
					defer os.Remove(profilePath)

					if err := fsfence.ValidateProfile(profilePath); err != nil {
						if setupErr := degradeOrRefuse("profile rejected", err); setupErr != nil {
							return setupErr
						}
						break
					}

					sandboxArgv, err := fsfence.WrapArgv(profilePath, args)
					if err != nil {
						if setupErr := degradeOrRefuse("sandbox-exec argv construction failed", err); setupErr != nil {
							return setupErr
						}
						break
					}
					fsSandboxPrefix = sandboxArgv[:len(sandboxArgv)-len(args)]
					macOSDenialLog = true

					if err := recordMacOSFilesystemFenceState("ENGAGED", fmt.Sprintf("Seatbelt root-write confinement applied; root=%s mode=%s sensitive_paths=%d", fsCfg.Root, fsCfg.Mode, pathCount), false); err != nil {
						return fmt.Errorf("cannot record macOS filesystem fence engagement; refusing to start: %w", err)
					}
					fmt.Fprintf(os.Stderr, "NockLock: macOS filesystem fence ENGAGED — Seatbelt root-write confinement active for %s (%s); %d sensitive path(s) denied\n", fsCfg.Root, fsCfg.Mode, pathCount)

				default:
					return fmt.Errorf("filesystem fence configured but not supported on %s", runtime.GOOS)
				}
			}
		} else if runtime.GOOS == "darwin" {
			if err := recordMacOSFilesystemFenceState("DEGRADED", "explicitly disabled by filesystem.root = \"\"", false); err != nil {
				return fmt.Errorf("cannot record macOS filesystem fence degradation; refusing to start: %w", err)
			}
			fmt.Fprintln(os.Stderr, "NockLock: WARNING: macOS filesystem fence DEGRADED — explicitly disabled by filesystem.root = \"\"")
		}

		// Apply syscall fence (Linux seccomp-BPF). Opt-in and nil-safe: when
		// enforcement is "off" buildSyscallPolicy returns ok=false and nothing
		// changes. On Linux, when active, it routes the child through the same
		// __landlock-exec shim that applies Landlock — extended to apply the
		// seccomp filter just before execve (see landlock_exec.go). On non-Linux
		// the syscall fence is a no-op and we skip the wiring entirely.
		syscallProxyModeActive := false
		syscallFenceActive := false
		if runtime.GOOS == "linux" {
			// Tell the syscall fence which network mode is active EXPLICITLY, so
			// it can grant the child inet/inet6 sockets under the netns egress
			// floor while keeping unix-only for the userspace proxy (N10710).
			netFence := wrapNetworkFenceMode(useNetns, cfg.Network.AllowAll)
			if policy, ok := buildSyscallPolicy(cfg, netFence); ok {
				syscallFenceActive = syscallfence.Supported()
				syscallProxyModeActive = syscallFenceActive && netFence == networkFenceProxy
				encoded, err := marshalSyscallPolicy(policy)
				if err != nil {
					return fmt.Errorf("failed to serialize syscall policy: %w", err)
				}
				childEnv = append(removeEnvVars(childEnv, syscallPolicyEnv), syscallPolicyEnv+"="+encoded)
				// Ensure the child runs through the shim even when Landlock was
				// unavailable or the filesystem fence is disabled.
				if len(landlockPrefix) == 0 {
					exe, err := os.Executable()
					if err != nil {
						return fmt.Errorf("cannot resolve nocklock executable for syscall fence shim: %w", err)
					}
					landlockPrefix = []string{exe, "__landlock-exec", "--"}
				}
				fmt.Fprintf(os.Stderr, "NockLock: Linux syscall fence active — seccomp-BPF (%s)\n", policy.Mode)
				logEvent(logging.EventFilePassed, "syscall", fmt.Sprintf("seccomp mode=%s socket_families=%d allow_namespaces=%t", policy.Mode, len(policy.AllowedSocketFamilies), policy.AllowNamespaces), false)
			}
		}
		egressLevel := effectiveEgressLevel(
			runtime.GOOS,
			resolvedNetworkFenceMode(wrapFlags),
			cfg.Network.AllowAll,
			syscallFenceActive,
			fsFence != nil,
		)
		if egressLevel == egressLevelUnreachable {
			detail := egressRequirementMessage(egressLevel, runtime.GOOS)
			logEvent(logging.EventNetworkError, "network", detail, true)
			fmt.Fprintln(cmd.ErrOrStderr(), egressBanner(egressLevel, len(cfg.Network.Allow)))
			fmt.Fprintf(cmd.ErrOrStderr(), "NockLock: fix: %s\n", strings.TrimPrefix(detail, "effective egress level is UNREACHABLE; "))
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return &exitCodeError{code: 2}
		}
		if (cfg.Network.RequireEnforced || wrapFlags.RequireEnforcedEgress) && !egressLevelMeetsRequirement(egressLevel) {
			detail := egressRequirementMessage(egressLevel, runtime.GOOS)
			logEvent(logging.EventNetworkError, "network", detail, true)
			fmt.Fprintf(cmd.ErrOrStderr(), "NockLock: fatal: enforced egress required — %s\n", detail)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return &exitCodeError{code: 2}
		}

		// Validate the interposer's field budget now that we know whether the
		// __landlock-exec shim will engage. The shim injects self-proc allow
		// entries (allowSelfProcFS) that consume budget; a pure userspace-only
		// fence (no shim) gets the interposer's full budget.
		if runtime.GOOS == "linux" && fsCfg != nil {
			reserve := 0
			if len(landlockPrefix) > 0 {
				reserve = len(fsfence.SelfProcFiles())
			}
			if err := fsfence.CheckInterposerBudget(fsCfg, reserve); err != nil {
				return fmt.Errorf("invalid filesystem fence config: %w", err)
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
		var netnsEgress *netns.EgressConfig

		// Egress decision-log plumbing (Nock N10649). The fenced transparent proxy
		// makes every allow/deny decision but runs as the shared nobody uid with no
		// DB handle or signing key, so it cannot sign an audit row. It instead
		// appends plain records to a wrap-owned decision-log file; this parent —
		// which holds the signing key — streams those records into the signed,
		// hash-chained event log below. decisionLogPath/decisionLogDir are created
		// above (before the fs fence) so the child can be denied the log; these
		// carry the reader lifecycle and are used only on the useNetns path.
		// decisionFailed is set (once) if the reader cannot open or sign the log, so
		// the session FAILS CLOSED rather than reporting success with a lost receipt.
		var decisionReaderWg sync.WaitGroup
		decisionDone := make(chan struct{})
		var decisionFailed atomic.Bool
		var decisionFailErr error

		if useNetns {
			// Kernel-enforced network egress floor. Confirm the privileged helper
			// is reachable via passwordless sudo (the DECIDED acquisition path)
			// BEFORE launching the child. Fail closed if it is not — there is no
			// advisory/degraded network fallback (spec 2026-08-24).
			if err := netnsHelperPreflight(cmd.Context()); err != nil {
				logEvent(logging.EventNetworkError, "network", fmt.Sprintf("netns preflight failed: %v", err), true)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				fmt.Fprintf(os.Stderr, "NockLock: fatal: network egress fence (netns) unavailable: %v\n", err)
				return &exitCodeError{code: 2}
			}
			if effectiveCfg.Network.AllowAll {
				return fmt.Errorf("--net-fence=netns requires network.allow entries; allow_all bypasses the transparent allowlist")
			}
			// Send a valid candidate bridge to the privileged helper. The helper will
			// attempt to reserve it; on collision it regenerates candidates and retries.
			candidate, err := netns.GenerateBridgeCandidate()
			if err != nil {
				return fmt.Errorf("generate bridge candidate: %w", err)
			}
			netnsEgress = &netns.EgressConfig{
				Allow:              append([]string(nil), effectiveCfg.Network.Allow...),
				AllowPrivateRanges: effectiveCfg.Network.AllowPrivateRanges,
				Bridge:             candidate,
			}
			// The decision-log file was created above (before the fs fence) so its
			// directory could be added to the child's deny list; hand its path to
			// the sidecars so the transparent proxy appends decisions to it.
			netnsEgress.DecisionLogPath = decisionLogPath

			logEvent(logging.EventNetworkPassed, "network", fmt.Sprintf("egress level=%s netns tproxy domains=%d", egressLevel, len(netnsEgress.Allow)), false)
			fmt.Fprintln(os.Stderr, egressBanner(egressLevel, len(netnsEgress.Allow)))
		} else if !cfg.Network.AllowAll {
			proxyCfg := effectiveCfg.Network
			proxy := network.NewProxyServer(proxyCfg, logger, sessionID)
			var addr string
			var proxyErr error
			var proxyUnixSocket string
			if syscallProxyModeActive {
				if runtime.GOOS != "linux" || fsFence == nil {
					logEvent(logging.EventNetworkError, "network", "unix proxy bridge requires Linux LD_PRELOAD interposer", true)
					return fmt.Errorf("network fence with syscall enforcement requires the Linux filesystem interposer so loopback proxy connects can be mapped onto a Unix socket")
				}
				proxyDir, err := createUnixProxyDir()
				if err != nil {
					return fmt.Errorf("create unix proxy socket directory: %w", err)
				}
				defer os.RemoveAll(proxyDir)
				proxyUnixSocket = filepath.Join(proxyDir, "proxy.sock")
				if err := validateUnixProxySocketPath(proxyUnixSocket); err != nil {
					return err
				}
				addr, err = reserveLoopbackProxyAddr()
				if err != nil {
					return fmt.Errorf("reserve loopback proxy token address: %w", err)
				}
				addr, proxyErr = proxy.StartUnix(proxyUnixSocket, addr)
			} else {
				addr, proxyErr = proxy.Start()
			}
			if proxyErr != nil {
				logEvent(logging.EventNetworkError, "network", fmt.Sprintf("proxy start failed: %v", proxyErr), false)
				fmt.Fprintf(os.Stderr, "NockLock: fatal: network fence failed to start: %v\n", proxyErr)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				return &exitCodeError{code: 2}
			} else {
				var readyErr error
				if proxyUnixSocket != "" {
					readyErr = network.WaitForProxyReadyUnix(cmd.Context(), proxyUnixSocket, 5*time.Second)
				} else {
					readyErr = network.WaitForProxyReady(cmd.Context(), addr, 5*time.Second)
				}
				if readyErr != nil {
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
				var watchdog *network.ProxyWatchdog
				onProxyFailure := func() {
					proxyFailed.Store(true)
					proxy.MarkDegraded("proxy watchdog: proxy died")
					logEvent(logging.EventNetworkError, "network", "proxy watchdog: proxy died, killing child", true)
					fmt.Fprintf(os.Stderr, "NockLock: fatal: network proxy died unexpectedly — terminating child process\n")
					childCancel()
				}
				if proxyUnixSocket != "" {
					watchdog = network.NewUnixProxyWatchdog(proxyUnixSocket, 5*time.Second, 2, onProxyFailure)
				} else {
					watchdog = network.NewProxyWatchdog(addr, 5*time.Second, 2, onProxyFailure)
				}
				watchdog.Start(watchdogCtx)

				proxyURL := "http://" + addr
				childEnv = removeEnvVars(childEnv,
					"NOCKLOCK_PROXY_TCP_ADDR",
					"NOCKLOCK_PROXY_UNIX_SOCKET",
				)
				childEnv = append(childEnv,
					"HTTP_PROXY="+proxyURL,
					"HTTPS_PROXY="+proxyURL,
					"http_proxy="+proxyURL,
					"https_proxy="+proxyURL,
					"ALL_PROXY="+proxyURL,
					"all_proxy="+proxyURL,
				)
				if proxyUnixSocket != "" {
					childEnv = append(childEnv,
						"NOCKLOCK_PROXY_TCP_ADDR="+addr,
						"NOCKLOCK_PROXY_UNIX_SOCKET="+proxyUnixSocket,
					)
				}
				fmt.Fprintln(os.Stderr, egressBanner(egressLevel, len(cfg.Network.Allow)))
				logEvent(logging.EventNetworkPassed, "network", fmt.Sprintf("egress level=%s proxy=%s domains=%d", egressLevel, addr, len(cfg.Network.Allow)), false)
			}
		} else {
			fmt.Fprintln(os.Stderr, egressBanner(egressLevel, 0))
			logEvent(logging.EventNetworkPassed, "network", "egress level=OFF allow_all=true", false)
		}

		// Record the effective egress level in the signed session-start row only
		// after the configured bridge and network fence have initialized.
		if err := logger.Log(logging.Event{
			Timestamp:   time.Now(),
			EventType:   logging.EventSessionStart,
			Category:    "session",
			Detail:      args[0],
			EgressLevel: string(egressLevel),
			SessionID:   sessionID,
		}); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "NockLock: fatal: cannot record effective egress level in the signed audit trail: %v — refusing to start\n", err)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return &exitCodeError{code: 2}
		}

		// On macOS the filesystem fence wraps the child argv with sandbox-exec
		// (kernel-enforced, inherited by all descendants). On Linux fsSandboxPrefix
		// is empty and the child runs directly with the LD_PRELOAD env above.
		childArgv := composeChildArgv(args, landlockPrefix, fsSandboxPrefix)
		// Export this run's session id to the child (N10647) so a co-located tool
		// can stamp the SAME id. Done here, after every other env mutation and
		// immediately before the single point where childEnv is consumed, so it
		// covers all launch paths: the plain exec below, the Linux netns helper
		// request, and the macOS sandbox-exec / Linux landlock shim prefixes (all of
		// which inherit or forward childEnv). Any inherited value is overwritten.
		childEnv = setSessionIDEnv(childEnv, sessionID)
		var child *exec.Cmd
		if useNetns {
			// Hand the fully-composed child (any fs/syscall shim prefix included) to
			// the privileged netns helper via `sudo -n <helper> setup`.
			// The helper creates the namespace + default-drop base, drops the
			// child's capabilities from all five sets, drops to this (invoking)
			// user, and execve's the child inside the namespace. The request —
			// argv, env, and the unprivileged credential — travels in a 0600
			// request FILE (path on argv) so it never rides the fixed sudoers
			// argument vector AND never consumes the child's stdin. The sudo command
			// inherits the caller's real stdin, which the helper hands through to the
			// child unchanged, so an interactive or piped agent under
			// --net-fence=netns keeps its input stream (N10711).
			nc, err := buildNetnsChild(childCtx, childArgv, childEnv, netnsEgress, decisionLogDir)
			if err != nil {
				return err
			}
			child = nc
		} else {
			child = exec.CommandContext(childCtx, childArgv[0], childArgv[1:]...)
			child.Env = childEnv
			child.Stdin = os.Stdin
		}
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

		// failDecision records a fatal egress-audit failure exactly once and forces
		// the session closed: it surfaces an EventNetworkError, cancels the child
		// (harmless if the child has already exited), and stores the error for the
		// SessionEnd verdict. Called from the reader goroutine on an open, read, or
		// signing failure — a fail-closed receipts feature must never report success
		// after losing or failing to sign a decision.
		failDecision := func(err error) {
			if decisionFailed.CompareAndSwap(false, true) {
				decisionFailErr = err
				// Surface on stderr FIRST: the failure modes that trigger this
				// (disk full, DB lock, signing key) are exactly the ones that also
				// break logEvent below, and SilenceErrors on the exitCodeError means
				// a fail-closed exit would otherwise carry zero diagnostic. Mirrors
				// the proxy-watchdog death path.
				fmt.Fprintf(os.Stderr, "NockLock: fatal: egress decision audit failed: %v — terminating session\n", err)
				logEvent(logging.EventNetworkError, "network", fmt.Sprintf("egress decision audit failed: %v", err), true)
				childCancel()
			}
		}

		// Stream the egress decision-log line-by-line WHILE the child runs, then
		// drain the remaining complete lines after it exits. The transparent proxy
		// appends one full record per Write, so the scanner only ever acts on
		// complete, newline-terminated lines; a trailing partial is held until its
		// terminator arrives. Each complete record is signed into the audit trail;
		// any open/read/sign failure fails the whole session closed via failDecision.
		//
		// Draining on child exit is provably complete, not a race: the transparent
		// proxy is a sidecar of the privileged helper (SetupEgressAndSupervise),
		// which supervises the fenced child and only then returns — its deferred
		// stopSidecar SIGTERMs the proxy and BLOCKS on cmd.Wait() (reaping it) before
		// the helper process returns, which is before wrap's child.Run() returns
		// here. recordDecision writes via *os.File.Write (a direct write(2), no
		// userspace buffer), so every record a returned recordDecision produced is
		// already durable in the file by the time the proxy is reaped. Thus once
		// decisionDone is closed no further records can appear, and reading to EOF
		// captures them all.
		if decisionLogPath != "" {
			decisionReaderWg.Add(1)
			go func() {
				defer decisionReaderWg.Done()
				f, err := os.Open(decisionLogPath)
				if err != nil {
					// Very low reachability (same-uid file wrap just created O_EXCL),
					// but a reader that cannot open the log would silently drop every
					// egress row — surface it and fail closed rather than swallow.
					failDecision(fmt.Errorf("open egress decision-log for reading: %w", err))
					return
				}
				defer f.Close()
				scanner := newDecisionLogScanner(logger, sessionID)
				readBuf := make([]byte, 4096)
				for {
					// Drain everything currently available. A clean io.EOF (no data
					// right now) returns nil; any other read error or a signing
					// failure fails the session closed rather than looking like a
					// clean end (N3).
					if err := drainDecisionReader(f, scanner, readBuf); err != nil {
						failDecision(err)
						return
					}
					// Caught up to the current end of file. If the child has exited,
					// the proxy is stopped and no more records can appear (see the
					// proof above): do one final drain of anything written since, then
					// stop.
					select {
					case <-decisionDone:
						if err := drainDecisionReader(f, scanner, readBuf); err != nil {
							failDecision(err)
							return
						}
						// The writer is provably gone (proof above), so a leftover
						// unterminated partial can never complete — it means a torn
						// final record (e.g. a proxy-side short write on ENOSPC). Fail
						// closed rather than report success with an incomplete audit.
						// (Only the FINAL drain checks this; a mid-stream partial is
						// normal — more bytes may still arrive.)
						if scanner.Pending() {
							failDecision(errors.New("incomplete egress decision record at end of decision log"))
						}
						return
					default:
						time.Sleep(50 * time.Millisecond)
					}
				}
			}()
		}

		// Best-effort: file denials of the Seatbelt fence reach the audit chain
		// through the unified log. The tailer never blocks or fails the child;
		// its problems become one warning row.
		var denialTailer *fsfence.DenialTailer
		if macOSDenialLog {
			denialTailer = fsfence.StartDenialTailer(fsfence.DenialTailerConfig{
				Argv: denialLogArgv(),
				Tag:  fsfence.DenialTag(sessionID),
				OnDenial: func(d fsfence.Denial) {
					logEvent(logging.EventFileBlocked, "filesystem", d.Detail(), true)
				},
				OnSuppressed: func(overCap, repeats int) {
					logEvent(logging.EventFileBlocked, "filesystem",
						fmt.Sprintf("macOS denial log: %d denial events suppressed (%d over the %d-per-session cap, %d repeats of an already-logged operation and path)",
							overCap+repeats, overCap, fsfence.DefaultMaxDenialEvents, repeats), true)
				},
				OnWarning: func(msg string) {
					logEvent(logging.EventFilePassed, "filesystem", "macOS denial log (best-effort): "+msg, false)
				},
			})
		}

		childErr := child.Run()

		if denialTailer != nil {
			denialTailer.Stop()
		}

		// The child (and thus the proxy that writes the decision-log) has exited.
		// Signal the reader to do its final drain and wait for it before the
		// deferred logger.Close, so no signed egress row is lost.
		close(decisionDone)
		decisionReaderWg.Wait()

		// Cancel the fence context to stop the listener, then wait for event goroutine.
		if fsFenceCancel != nil {
			fsFenceCancel()
		}
		eventsWg.Wait()

		// FAIL CLOSED on any egress-audit failure: an allowed/denied decision that
		// could not be signed (or a decision-log that could not be read) means the
		// audit trail is incomplete, so the session must not report success — even
		// if the child itself exited 0. Checked before the childErr branch so this
		// verdict wins. The reader goroutine has finished (Wait above), establishing
		// happens-before for decisionFailErr.
		if decisionFailed.Load() {
			logEvent(logging.EventSessionEnd, "session", fmt.Sprintf("exit_code=2 decision_audit_failed=true err=%v", decisionFailErr), true)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return &exitCodeError{code: 2}
		}

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

func loadWrapConfig(flags WrapFlags) (*config.Config, string, error) {
	if flags.Profile == "" {
		configPath, err := config.FindConfig()
		if err != nil {
			return nil, "", fmt.Errorf("no NockLock config found. Run 'nocklock init' first to create %s/%s", config.Dir, config.File)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, configPath, fmt.Errorf("failed to load config at %s: %w", configPath, err)
		}
		return cfg, configPath, nil
	}

	base, err := config.LoadProfile(flags.Profile)
	if err != nil {
		return nil, "", err
	}
	configPath, findErr := config.FindConfig()
	if findErr != nil {
		if !errors.Is(findErr, os.ErrNotExist) {
			return nil, "", fmt.Errorf("failed to find config overlay: %w", findErr)
		}
		return base, "embedded profile " + flags.Profile, nil
	}
	cfg, err := config.LoadOverlay(*base, configPath)
	if err != nil {
		return nil, configPath, fmt.Errorf("failed to load config overlay at %s: %w", configPath, err)
	}
	return cfg, configPath, nil
}

func printProfiles(w io.Writer) {
	fmt.Fprintln(w, "NockLock profiles:")
	for _, profile := range config.Profiles() {
		fmt.Fprintf(w, "  %s: %s\n", profile.Name, profile.Summary)
	}
}

func effectiveWrapConfig(cfg *config.Config, flags WrapFlags) config.Config {
	effective := *cfg
	// CLI flag is additive: if either config-file or flag permits private ranges, allow them.
	effective.Network.AllowPrivateRanges = cfg.Network.AllowPrivateRanges || flags.AllowPrivateRanges
	// A CLI requirement is also part of the effective policy recorded in the
	// signed config digest, not only a launch-time check.
	effective.Network.RequireEnforced = cfg.Network.RequireEnforced || flags.RequireEnforcedEgress
	return effective
}

func resolvedNetworkFenceMode(flags WrapFlags) string {
	if flags.NetFence == "netns" {
		return "netns"
	}
	return "proxy"
}

func composeChildArgv(args []string, prefixes ...[]string) []string {
	childArgv := append([]string{}, args...)
	for _, prefix := range prefixes {
		if len(prefix) == 0 {
			continue
		}
		childArgv = append(append([]string{}, prefix...), childArgv...)
	}
	return childArgv
}

// mergeFSFenceEnv merges the filesystem fence's environment (fenceEnv, from
// fsfence.Fence.EnvVars) into the child's environment (childEnv) for the Linux
// userspace (LD_PRELOAD) fence.
//
// Security (N8185): the interposer reads its SOLE policy from
// NOCKLOCK_FS_ALLOWED via glibc getenv(), which returns the FIRST matching
// entry in the environment block. childEnv comes from
// secrets.Filter(os.Environ()), so an inherited / attacker-controlled
// NOCKLOCK_FS_ALLOWED sits EARLIER than the fence's own and would win — forging
// an allow-all policy and neutering the fence. We therefore strip any inherited
// NOCKLOCK_FS_ALLOWED from childEnv before appending the fence's value, so
// exactly one entry (the fence's) remains effective. This mirrors the sibling
// landlock (landlockRulesEnv) and syscall (syscallPolicyEnv) paths, which
// already removeEnvVars before appending.
//
// LD_PRELOAD is handled differently: a legitimately inherited LD_PRELOAD is
// preserved by prepending the fence library (it must load first) rather than
// dropped, so it is merged in place instead of stripped.
func mergeFSFenceEnv(childEnv, fenceEnv []string) []string {
	// Strip any inherited NOCKLOCK_FS_ALLOWED so only the fence's value is
	// effective (getenv first-match). LD_PRELOAD is intentionally NOT stripped
	// here — it is merged below to preserve a legitimate inherited value.
	childEnv = removeEnvVars(childEnv, fsfence.EnvFSAllowed)

	// Merge the fence's LD_PRELOAD with any existing value in childEnv so the
	// fence library loads first.
	for i, fenceVar := range fenceEnv {
		if strings.HasPrefix(fenceVar, fsfence.EnvLDPreload+"=") {
			fenceLib := strings.TrimPrefix(fenceVar, fsfence.EnvLDPreload+"=")
			for j, childVar := range childEnv {
				if strings.HasPrefix(childVar, fsfence.EnvLDPreload+"=") {
					existing := strings.TrimPrefix(childVar, fsfence.EnvLDPreload+"=")
					if existing == "" {
						childEnv[j] = fsfence.EnvLDPreload + "=" + fenceLib
					} else {
						childEnv[j] = fsfence.EnvLDPreload + "=" + fenceLib + ":" + existing
					}
					fenceEnv = append(fenceEnv[:i], fenceEnv[i+1:]...)
					break
				}
			}
			break
		}
	}
	return append(childEnv, fenceEnv...)
}

// denialLogArgv returns the command that streams Seatbelt denials; tests
// replace it to simulate an unavailable or scripted unified log.
var denialLogArgv = fsfence.LogStreamArgv

// sessionIDEnv is the env var through which wrap tells the child which audit
// session it belongs to. The id is not a secret; it lets a co-located tool
// (NockGuard) stamp the same id so one verifier can join both chains.
const sessionIDEnv = "NOCKLOCK_SESSION_ID"

// setSessionIDEnv returns env with NOCKLOCK_SESSION_ID set to sessionID. Any
// inherited value is removed first, so a stale or spoofed id from the parent
// environment can never survive: the child sees only this run's real id.
func setSessionIDEnv(env []string, sessionID string) []string {
	return append(removeEnvVars(env, sessionIDEnv), sessionIDEnv+"="+sessionID)
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
		fsCfg, err := fsfence.ProcessConfig(cfg.Filesystem)
		if err != nil {
			return fmt.Errorf("invalid filesystem fence config: %w", err)
		}
		// Floor check with reserve=0: catches configs that exceed the
		// interposer's absolute budget regardless of shim engagement.
		// The exact check (with the real reserve) runs later in wrap,
		// after the ABI probe and syscall-fence decision are final.
		if runtime.GOOS == "linux" {
			if err := fsfence.CheckInterposerBudget(fsCfg, 0); err != nil {
				return fmt.Errorf("invalid filesystem fence config: %w", err)
			}
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
	if raw == "" || raw == string(linuxEnforcementPreferred) {
		return linuxEnforcementRequired
	}
	return linuxEnforcement(raw)
}

// egressChildDenyPaths returns the audit directory and, on the netns path, the
// whole egress decision-log directory the fenced child must be denied so it
// cannot tamper with the records the unfenced parent signs into the audit trail.
// Denying the directory, not just the file, stops the child (which shares
// wrap's uid) from truncating the log, creating sibling files, or traversing in
// to forge the signed egress rows. A project-root audit directory is refused
// before this list is built.
func egressChildDenyPaths(dbPath, decisionLogDir string) []string {
	paths := []string{filepath.Dir(dbPath)}
	if decisionLogDir != "" {
		paths = append(paths, decisionLogDir)
	}
	return paths
}

// egressDecisionDir returns the per-session directory that holds the egress
// decision log, under the audit state root (the directory that holds events.db)
// as <state>/sessions/<sessionID>/egress — NEVER the system temp dir. The dir
// is denied to the child (egressChildDenyPaths) so it cannot forge signed egress
// rows.
//
// Why the state root and not /tmp (N10710): the default filesystem preset GRANTs
// /tmp, and Landlock is allow-only, so a deny path under a granted tree fails
// rule generation (assertDenyPathsEnforceable). The audit state root now lives
// outside the project entirely (config.AuditStateDir), so this directory sits
// outside every granted tree by construction — it no longer depends on the
// Landlock ruleset skipping a ".nock" child of the fence root, which is how this
// held before the audit state moved out. A logging.db pointed back inside a
// granted tree by an absolute path reintroduces the overlap, exactly as it does
// for the audit DB's own deny. Factored out so the path is
// unit-testable without root.
func egressDecisionDir(dbPath, sessionID string) string {
	return filepath.Join(filepath.Dir(dbPath), "sessions", sessionID, "egress")
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

// landlockProcSelfAllowPaths grants the child read-only access to the specific
// files in fsfence.SelfProcFiles under its OWN /proc/<pid>, via the /proc/self
// symlink. This is what Node needs for process.memoryUsage() (reads
// /proc/self/stat) and fs reads of /proc/self/status; without it the calls
// throw EACCES and can crash the agent.
//
// Correctness hinges on the exec model: the __landlock-exec shim builds the
// Landlock ruleset and then execve's the child IN PLACE (unix.Exec preserves the
// pid — see landlock_exec.go). So the literal string "/proc/self/<file>",
// opened when the shim applies the ruleset, binds to a file inode inside the
// very directory that becomes the child's own /proc/<pid> — never a sibling's
// or another user's. It must stay the literal "/proc/self/<file>": resolving
// the symlink (as the config allow list does) would bind it to some other
// process's pid dir.
//
// It grants FILES, never the /proc/<pid> DIRECTORY: a directory-level Landlock
// rule covers every entry beneath it (RulesFromConfig grants a directory
// read+readdir+execute over its whole subtree), which would reopen environ,
// cmdline, mem, maps and fd — the same-UID leak #115 removed. Landlock rules
// are also inherited by every future descendant of the process they were
// applied to, so a directory grant would let a GRANDCHILD of the wrapped
// process read the wrapped process's own environ too — reopening the leak one
// level down (round 2). A file-level grant is inode-bound to that one file, so
// an inheriting descendant can only re-read those same few files, never
// environ/cmdline/mem/maps/fd (see
// TestWrapClaudeCodePresetBlocksDescendantParentProcEnviron).
//
// The grant reaches only the wrapped child's own /proc/<pid>/<file> entries.
// That never widens the fence boundary — no process outside the wrapped
// command's own descendants is exposed, and even descendants only inherit
// read on this same curated file list. (A grandchild that later execs under a
// DIFFERENT pid does not get its OWN /proc/self grant — Landlock is
// inode-bound to the original pid's files. Fixing that without re-granting the
// broad /proc tree #115 removed needs a pid namespace + fresh proc mount,
// which the syscall fence's allow_namespaces=false posture precludes — an
// ACCEPTED limitation, assessed and recorded in ADR-005. The file-level grant
// is pinned by TestLandlockProcSelfAllowPathsStaysNarrow so it cannot be
// widened silently.)
func landlockProcSelfAllowPaths() []landlock.AllowPath {
	files := fsfence.SelfProcFiles()
	paths := make([]landlock.AllowPath, 0, len(files))
	for _, f := range files {
		paths = append(paths, landlock.AllowPath{Path: "/proc/self/" + f, Access: landlock.AccessReadOnly})
	}
	return paths
}

// findLibFenceFS searches only trusted locations for the filesystem fence shared
// library. It never falls back to project-relative or bare paths because the
// result feeds LD_PRELOAD before Linux kernel fences are applied.
func findLibFenceFS() (string, error) {
	var exePath string
	if exe, err := os.Executable(); err == nil {
		exePath = exe
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot resolve current working directory for filesystem fence library trust check: %w", err)
	}
	return findTrustedLibFenceFS(exePath, cwd, nil, fileExists)
}

func reserveLoopbackProxyAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return "", err
	}
	return addr, nil
}

func createUnixProxyDir() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = filepath.Join("/run/user", fmt.Sprintf("%d", os.Getuid()))
		if st, statErr := os.Stat(base); statErr != nil || !st.IsDir() {
			base = "/tmp"
		}
	}
	return os.MkdirTemp(base, "nlp-*")
}

func validateUnixProxySocketPath(path string) error {
	const sunPathLimit = 108

	if len(path) >= sunPathLimit {
		return fmt.Errorf("unix proxy socket path is %d bytes; must be shorter than %d bytes for sockaddr_un.sun_path", len(path), sunPathLimit)
	}
	return nil
}

func findTrustedLibFenceFS(exePath, workingDir string, extraCandidates []string, exists func(string) (bool, error)) (string, error) {
	if exists == nil {
		exists = fileExists
	}

	candidates := make([]string, 0, len(extraCandidates)+3)
	if exePath != "" {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), "libfence_fs.so"))
	}
	candidates = append(candidates,
		filepath.Join("/usr/local/lib/nocklock", "libfence_fs.so"),
		filepath.Join("/usr/lib/nocklock", "libfence_fs.so"),
	)
	candidates = append(candidates, extraCandidates...)

	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		ok, err := exists(abs)
		if err != nil {
			return "", fmt.Errorf("cannot inspect trusted filesystem fence library candidate %q: %w", abs, err)
		}
		if !ok {
			continue
		}
		if pathIsWithinDir(abs, workingDir) {
			continue
		}
		return abs, nil
	}

	return "", fmt.Errorf("trusted filesystem fence library not found. Install libfence_fs.so next to the nocklock binary, at /usr/local/lib/nocklock/libfence_fs.so, or at /usr/lib/nocklock/libfence_fs.so; refusing to launch with an untrusted LD_PRELOAD path")
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func pathIsWithinDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	resolvedPath := resolvePathBestEffort(path)
	resolvedDir := resolvePathBestEffort(dir)
	if resolvedDir == filepath.Dir(resolvedDir) {
		return false
	}
	rel, err := filepath.Rel(resolvedDir, resolvedPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// resolveAuditDirectory resolves the nearest existing ancestor of a fresh audit
// directory, preserving its missing suffix. Existing but broken symlinks and
// errors other than ENOENT must not bypass the project-root refusal.
func resolveAuditDirectory(path string) (string, error) {
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return resolved, err
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolved, err = resolveAuditDirectory(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}
