package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/fence/network/netns"
	"github.com/spf13/cobra"
)

// The hidden __netns-helper subcommand is NockLock's privileged network-egress
// helper. It is the process invoked as root via passwordless sudo under the
// DECIDED capability model (spec amendment 2026-08-24) with exactly one of two
// fixed argument vectors:
//
//	__netns-helper check   — non-mutating preflight (is the privileged path reachable?)
//	__netns-helper setup    — read a JSON netns.Request from STDIN, create the
//	                          namespace + default-drop base, drop the child's
//	                          capabilities from all five sets, drop to the
//	                          unprivileged child credential, and execve the child.
//
// The child argv/env/credential travel on stdin, never on argv, so the fixed
// two-vector sudoers policy is a real boundary rather than an argument-injection
// surface. `setup` never returns on success (it execve's the child); any return
// is an error and the caller (wrap) fails closed.
//
// Install note (deferred to the host installer, out of this foundation's scope):
// production installs this as a root-owned `/usr/libexec/nocklock-egress-helper`
// with the constrained sudoers policy from the spec. Here the same binary is
// invoked via its own resolved path; the privileged LOGIC is identical.
var netnsHelperCmd = &cobra.Command{
	Use:                "__netns-helper <check|setup>",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("__netns-helper requires a verb: check or setup")
		}
		cmd.SilenceUsage = true
		switch args[0] {
		case "check":
			return netns.Check()
		case "setup":
			var req netns.Request
			dec := json.NewDecoder(os.Stdin)
			if err := dec.Decode(&req); err != nil {
				return fmt.Errorf("failed to read netns setup request from stdin: %w", err)
			}
			// SetupAndExec fails closed and does not return on success.
			return netns.SetupAndExec(req)
		default:
			return fmt.Errorf("unknown __netns-helper verb %q (expected check or setup)", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(netnsHelperCmd)
}

// netnsHelperPreflight runs the non-mutating `check` verb through passwordless
// sudo — the DECIDED availability probe (spec 2026-08-24: test with the complete
// `sudo -n <helper> check` command, never `sudo -n true`). A non-nil error means
// the privileged path is not reachable and wrap must fail closed.
func netnsHelperPreflight(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve nocklock executable for the netns helper: %w", err)
	}
	cmd := exec.CommandContext(ctx, "sudo", "-n", self, "__netns-helper", "check")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("passwordless sudo to the netns helper is not available (need NOPASSWD sudo for `%s __netns-helper`): %w\n%s", self, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildNetnsChild constructs the `sudo -n <self> __netns-helper setup` command
// that hands the composed child to the privileged helper. The child argv, env,
// and the unprivileged credential to drop to are JSON-encoded onto stdin so they
// never ride the fixed sudoers argument vector.
func buildNetnsChild(ctx context.Context, childArgv, childEnv []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot resolve nocklock executable for the netns helper: %w", err)
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, fmt.Errorf("cannot read supplementary groups for the netns child: %w", err)
	}
	// unix.Exec in the helper does NOT search PATH, so resolve a bare child
	// command to an absolute path here — in the unprivileged parent whose PATH
	// matches the user the child will run as. A command that already contains a
	// slash (e.g. the __landlock-exec shim's absolute path) is used as-is.
	if !strings.ContainsRune(childArgv[0], os.PathSeparator) {
		resolved, lookErr := exec.LookPath(childArgv[0])
		if lookErr != nil {
			return nil, fmt.Errorf("cannot resolve child command %q on PATH: %w", childArgv[0], lookErr)
		}
		childArgv = append([]string{resolved}, childArgv[1:]...)
	}
	// Drop to the INVOKING user (this parent runs unprivileged as that user), so
	// the agent is a non-root child inside the namespace.
	req := netns.Request{
		Argv:   childArgv,
		Env:    childEnv,
		UID:    os.Getuid(),
		GID:    os.Getgid(),
		Groups: groups,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot encode netns setup request: %w", err)
	}
	cmd := exec.CommandContext(ctx, "sudo", "-n", self, "__netns-helper", "setup")
	cmd.Stdin = bytes.NewReader(reqBytes)
	// sudo resets the environment; the CHILD env is carried in the request and
	// applied by the helper at execve. This env is only sudo's own.
	cmd.Env = os.Environ()
	return cmd, nil
}
