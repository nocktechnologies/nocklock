package cli

import (
	"encoding/json"
	"fmt"
	"os"

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
		// the serialized rules/policy.
		childEnv := removeEnvVars(os.Environ(), landlockRulesEnv, syscallPolicyEnv)
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

func init() {
	rootCmd.AddCommand(landlockExecCmd)
}
