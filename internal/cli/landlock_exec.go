package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
	"github.com/spf13/cobra"
)

// The hidden __landlock-exec shim is the single fail-closed re-exec point on
// Linux. It applies, in order, the kernel fences that MUST be set on the thread
// that will execve, then execs the child:
//
//	1. Landlock restrict_self  (filesystem) — also sets NO_NEW_PRIVS first
//	2. syscallfence.Apply      (seccomp-BPF, syscall surface)
//	3. execve
//
// HEADLINE PROPERTY — all-or-nothing: it NEVER execs on a partial apply. If any
// stage fails, the shim returns an error and the child is never started. The
// fences only ever tighten the process (NO_NEW_PRIVS, a Landlock ruleset, a
// seccomp filter), so a failure between stages leaves a MORE-restricted, never a
// less-restricted, process — and we refuse to exec it regardless.
//
// Ordering note: Landlock is applied before seccomp on purpose. Landlock's
// restrict_self needs NO_NEW_PRIVS but does not need any syscall the seccomp
// baseline denies, so doing FS first avoids a chicken-and-egg where the seccomp
// filter could interfere with the Landlock setup syscalls.

const (
	landlockRulesEnv = "NOCKLOCK_LANDLOCK_RULES"
	syscallPolicyEnv = "NOCKLOCK_SYSCALL_POLICY"
)

var landlockExecCmd = &cobra.Command{
	Use:                "__landlock-exec -- <command> [args...]",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Pin this goroutine to its OS thread for the whole shim. Landlock's
		// restrict_self is per-THREAD (unlike seccomp's TSYNC, which syncs the
		// filter to every thread); if the Go runtime migrated this goroutine to a
		// different OS thread between restrict_self and execve, the child would
		// execve on an UN-restricted task — a silent FS-fence fail-open. Locking
		// (and never unlocking, since the goroutine ends in execve) guarantees
		// restrict_self and execve run on the same task. No UnlockOSThread: execve
		// replaces the process image, so the locked thread is never returned.
		runtime.LockOSThread()

		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return fmt.Errorf("missing command after --")
		}

		// Stage 1: Landlock (filesystem). Optional — the shim is also used when
		// only the syscall fence is active, so an absent rules env means "no FS
		// fence", not an error.
		if raw := os.Getenv(landlockRulesEnv); raw != "" {
			spec, err := landlock.UnmarshalSpec(raw)
			if err != nil {
				return fmt.Errorf("invalid Landlock rules: %w", err)
			}
			if err := landlock.Apply(spec); err != nil {
				return fmt.Errorf("failed to apply Landlock rules: %w", err)
			}
		}

		// Stage 2: syscall fence (seccomp-BPF). Also optional. Apply itself sets
		// NO_NEW_PRIVS first and is all-or-nothing internally.
		if raw := os.Getenv(syscallPolicyEnv); raw != "" {
			var policy syscallfence.Policy
			if err := json.Unmarshal([]byte(raw), &policy); err != nil {
				return fmt.Errorf("invalid syscall policy: %w", err)
			}
			if err := applySyscallFence(policy); err != nil {
				return err
			}
		}

		// Stage 3: execve. Strip the shim's control env so the child does not see
		// the serialized rules/policy, and grant the child its own /proc/<pid> to
		// the userspace interposer (see allowSelfProcFS).
		childEnv := removeEnvVars(os.Environ(), landlockRulesEnv, syscallPolicyEnv)
		childEnv = allowSelfProcFS(childEnv)
		return landlock.Exec(args, childEnv)
	},
}

// applySyscallFence installs the syscall fence, honouring the policy Mode for
// fail-closed vs fail-open behaviour when the kernel lacks seccomp support. It
// NEVER returns nil after a partial apply: syscallfence.Apply is all-or-nothing,
// so any error here aborts the exec.
func applySyscallFence(policy syscallfence.Policy) error {
	if policy.IsZero() {
		return nil
	}
	if !syscallfence.Supported() {
		switch policy.Mode {
		case syscallfence.ModeRequired:
			return fmt.Errorf("syscall fence requires seccomp-BPF, but this kernel does not support it")
		default:
			// preferred: warn and continue unfenced-at-the-syscall-layer.
			fmt.Fprintln(os.Stderr, "NockLock: warning: seccomp-BPF unavailable; syscall fence not enforced")
			return nil
		}
	}
	if err := syscallfence.Apply(policy); err != nil {
		// A supported kernel that still refuses the filter is always fatal,
		// regardless of Mode — we will not exec a child we failed to fence.
		return fmt.Errorf("failed to apply syscall fence: %w", err)
	}
	return nil
}

// allowSelfProcFS grants the LD_PRELOAD filesystem interposer read access to
// THIS process's own fsfence.SelfProcFiles under /proc/<pid>, so Node's
// process.memoryUsage() and reads of /proc/self/status are not blocked by the
// userspace fence. It is the interposer companion to landlockProcSelfAllowPaths
// (wrap.go); both grant exactly the same file list.
//
// The shim IS the child — unix.Exec (below) execve's in place and preserves the
// pid — so os.Getpid() is the child's real pid. The concrete pid is required,
// not "/proc/self": the interposer realpaths accessed paths, so /proc/self/stat
// arrives as /proc/<pid>/stat and only a concrete /proc/<pid>/<file> entry
// matches. The interposer's prefix match is component-boundary aware, so
// /proc/<pid> never matches a sibling sharing a numeric prefix — no other
// process is exposed.
//
// Only the specific files are granted, never the /proc/<pid> directory: a
// directory-wide allow entry would also make environ, cmdline, mem, maps and
// fd match the interposer's allow check — the same-UID leak #115 removed,
// reachable one level down through any descendant that inherits this fence's
// posture. See landlockProcSelfAllowPaths for the Landlock-side rationale,
// which is the actual kernel backstop even if this userspace list were ever
// wider.
//
// This runs only in the __landlock-exec shim, which wrap inserts whenever
// Landlock or the syscall fence is active — always so for the hardened presets
// that need this. A pure userspace-only fs fence has no shim and does not reach
// here; that degraded posture is out of scope. No-op when NOCKLOCK_FS_ALLOWED is
// unset or empty.
func allowSelfProcFS(env []string) []string {
	pid := os.Getpid()
	for i, entry := range env {
		name, val, ok := strings.Cut(entry, "=")
		if !ok || name != fsfence.EnvFSAllowed || val == "" {
			continue
		}
		for _, f := range fsfence.SelfProcFiles() {
			val = fsfence.AppendSerializedAllow(val, fmt.Sprintf("/proc/%d/%s", pid, f))
		}
		env[i] = fsfence.EnvFSAllowed + "=" + val
		break
	}
	return env
}

func init() {
	rootCmd.AddCommand(landlockExecCmd)
}
