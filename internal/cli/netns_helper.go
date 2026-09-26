package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nocktechnologies/nocklock/internal/fence/network/netns"
	"github.com/spf13/cobra"
)

const netnsHelperPath = "/usr/libexec/nocklock-egress-helper"

// The hidden __netns-helper subcommand contains NockLock's privileged
// network-egress helper logic. The installed helper exposes that logic at the
// fixed, root-owned netnsHelperPath and is invoked via passwordless sudo under
// the DECIDED capability model (spec amendment 2026-08-24) with one of two fixed
// argument vectors:
//
//	check                       — non-mutating preflight (is the path reachable?)
//	setup --request-file <path> — read a JSON netns.Request from the 0600 file at
//	        <path> (owned by the sudo-invoking user), create the namespace +
//	        default-drop base, drop the child's capabilities from all five sets,
//	        drop to the unprivileged child credential, and execve the child.
//
// The child argv/env/credential travel in the request FILE, never on argv (only
// the file path rides argv), so the sudoers policy is still a fixed vector rather
// than an argument-injection surface. The request moved OFF stdin (N10711) so the
// helper leaves its stdin untouched and hands the caller's real stdin through to
// the child — an interactive or piped agent under `--net-fence=netns` keeps its
// input stream. The file is validated (regular, mode 0600, owned by SUDO_UID,
// opened O_NOFOLLOW) and unlinked after read; validateChildCredential remains the
// real credential boundary. `setup` never returns on success (it execve's the
// child); any return is an error and the caller (wrap) fails closed.
//
// SUDOERS POLICY: the production NOPASSWD grant must permit
// `setup --request-file *` (previously bare `setup`); see the ADR under
// .claude/decisions/ and CHANGELOG for N10711.
//
// Install note (deferred to the host installer, out of this foundation's scope):
// production installs the helper at netnsHelperPath with the constrained
// sudoers policy from the spec.
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
			reqPath, err := setupRequestPath(args[1:])
			if err != nil {
				return err
			}
			req, err := readSetupRequest(reqPath)
			if err != nil {
				return err
			}
			// SetupAndExec fails closed and does not return on success for the
			// foundation path. Phase 1b's supervisor returns a typed child exit
			// after it has stopped both proxies and removed the private bridge.
			if err := netns.SetupAndExec(req); err != nil {
				var childExit *netns.ChildExitError
				if errors.As(err, &childExit) {
					return &exitCodeError{code: childExit.Code}
				}
				return err
			}
			return nil
		default:
			return fmt.Errorf("unknown __netns-helper verb %q (expected check or setup)", args[0])
		}
	},
}

var netnsProxyCmd = &cobra.Command{
	Use:                "__netns-proxy",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var cfg netns.EgressConfig
		if err := netns.ReadSidecarPayload(&cfg); err != nil {
			return fmt.Errorf("failed to read transparent proxy configuration: %w", err)
		}
		return netns.RunTransparentProxy(cfg)
	},
}

var netnsHostProxyCmd = &cobra.Command{
	Use:                "__netns-host-proxy",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var cfg netns.EgressConfig
		if err := netns.ReadSidecarPayload(&cfg); err != nil {
			return fmt.Errorf("failed to read host proxy configuration: %w", err)
		}
		return netns.RunHostProxy(cfg)
	},
}

var netnsChildCmd = &cobra.Command{
	Use:                "__netns-child",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var req netns.Request
		if err := netns.ReadSidecarPayload(&req); err != nil {
			return fmt.Errorf("failed to read netns child request: %w", err)
		}
		return netns.DropAndExecChild(req)
	},
}

var netnsCleanupCmd = &cobra.Command{
	Use:                "__netns-cleanup",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var bridge netns.BridgeSpec
		if err := json.NewDecoder(os.Stdin).Decode(&bridge); err != nil {
			return fmt.Errorf("failed to read netns cleanup request from stdin: %w", err)
		}
		return netns.RunDeferredBridgeCleanup(bridge)
	},
}

var netnsChildKillWatchdogCmd = &cobra.Command{
	Use:                "__netns-child-kill-watchdog",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var req netns.ChildGroupKillWatchdogRequest
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			return fmt.Errorf("failed to read child kill watchdog request from stdin: %w", err)
		}
		return netns.RunChildGroupKillWatchdog(req)
	},
}

func init() {
	rootCmd.AddCommand(netnsHelperCmd)
	rootCmd.AddCommand(netnsProxyCmd)
	rootCmd.AddCommand(netnsHostProxyCmd)
	rootCmd.AddCommand(netnsChildCmd)
	rootCmd.AddCommand(netnsCleanupCmd)
	rootCmd.AddCommand(netnsChildKillWatchdogCmd)
}

// netnsHelperPreflight runs the non-mutating `check` verb through passwordless
// sudo — the DECIDED availability probe (spec 2026-08-24: test with the complete
// `sudo -n <helper> check` command, never `sudo -n true`). A non-nil error means
// the privileged path is not reachable and wrap must fail closed.
func netnsHelperPreflight(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sudo", "-n", netnsHelperPath, "check")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("passwordless sudo to the netns helper is not available (need NOPASSWD sudo for `%s check`): %w\n%s", netnsHelperPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildNetnsChild constructs the `sudo -n <helper> setup --request-file <path>`
// command that hands the composed child to the privileged helper. The child argv,
// env, and the unprivileged credential to drop to are JSON-encoded into a 0600
// file under requestDir (a wrap-owned, per-session directory) whose path — and
// only the path — rides argv, so they never ride the fixed sudoers argument
// vector. Moving the request off stdin lets the sudo command inherit the caller's
// real stdin, which the helper hands through to the child unchanged (N10711).
func buildNetnsChild(ctx context.Context, childArgv, childEnv []string, egress *netns.EgressConfig, requestDir string) (*exec.Cmd, error) {
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
		Egress: egress,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot encode netns setup request: %w", err)
	}
	reqPath, err := writeSetupRequest(requestDir, reqBytes)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "sudo", "-n", netnsHelperPath, "setup", "--request-file", reqPath)
	// Hand the caller's real stdin straight to sudo → helper → child. The setup
	// request travels in the file above, not on stdin, so nothing consumes it.
	cmd.Stdin = os.Stdin
	// sudo resets the environment; the CHILD env is carried in the request and
	// applied by the helper at execve. This env is only sudo's own.
	cmd.Env = os.Environ()
	return cmd, nil
}

// writeSetupRequest writes the JSON setup request to a fresh 0600 file under dir
// (a wrap-owned, 0700 per-session directory) and returns its path. The helper
// validates the owner/mode and unlinks it after read; wrap's per-session cleanup
// removes any file left behind on an error path.
func writeSetupRequest(dir string, reqBytes []byte) (string, error) {
	if dir == "" {
		return "", errors.New("netns setup request directory is empty")
	}
	f, err := os.CreateTemp(dir, "setup-request-*.json")
	if err != nil {
		return "", fmt.Errorf("create netns setup request file: %w", err)
	}
	path := f.Name()
	// os.CreateTemp already creates the file 0600; be explicit so the helper's
	// mode check is guaranteed regardless of umask quirks.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("chmod netns setup request file: %w", err)
	}
	if _, err := f.Write(reqBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write netns setup request file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close netns setup request file: %w", err)
	}
	return path, nil
}

// setupRequestPath extracts the request-file path from the `setup` verb's
// arguments. It accepts exactly `--request-file <path>` (the form buildNetnsChild
// emits and the only form the `setup --request-file *` sudoers grant matches) and
// refuses anything else, so a malformed invocation fails closed rather than
// falling back to a stdin read that would consume the child's input stream.
func setupRequestPath(args []string) (string, error) {
	const flag = "--request-file"
	if len(args) == 2 && args[0] == flag && args[1] != "" {
		return args[1], nil
	}
	return "", fmt.Errorf("__netns-helper setup requires %s <path> (the JSON setup request; N10711 moved it off stdin so the child keeps the caller's stdin)", flag)
}

// readSetupRequest opens, validates, decodes, and unlinks the setup request file.
// It runs as root (under sudo), so every step is done relative to one retained
// directory fd (os.OpenRoot), binding validation and unlink to the same directory
// identity. The file is opened O_NOFOLLOW and must be a regular 0600 file owned by
// the sudo-invoking user before it is decoded — a caller can only ever make the
// helper read a file it already owns. validateChildCredential inside
// SetupAndExec remains the real credential boundary; this is defense-in-depth
// plus a fail-closed setup channel.
func readSetupRequest(path string) (netns.Request, error) {
	var req netns.Request
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return req, fmt.Errorf("open netns setup request directory for %q: %w", path, err)
	}
	defer root.Close()
	name := filepath.Base(path)
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return req, fmt.Errorf("open netns setup request %q: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return req, fmt.Errorf("stat netns setup request %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return req, fmt.Errorf("netns setup request %q is not a regular file; refusing", path)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return req, fmt.Errorf("netns setup request %q has mode %#o, want 0600; refusing", path, perm)
	}
	if err := assertSetupRequestOwner(fi); err != nil {
		return req, err
	}
	// SECURITY: only NOW — the file is confirmed a regular 0600 file owned by the
	// sudo-invoking user — is it safe to unlink it as root. An earlier unlink would
	// hand the NOPASSWD grant an arbitrary root file-deletion primitive (e.g.
	// --request-file /etc/sudoers.d/nocklock-egress). The unlink goes through the
	// retained directory fd (unlinkat), never the path string. The inode re-check
	// only narrows the residual Lstat→unlinkat window; that window is bounded to
	// caller-owned entries (unlink does not follow a final-component symlink and
	// protected_hardlinks blocks planting a root-owned hardlink), so at worst a
	// caller can make the helper delete a file it already owns. Deferred so the
	// single-use request is still cleaned on a decode failure; wrap's per-session
	// RemoveAll is the backstop.
	defer removeValidatedRequest(root, name, fi)
	if err := json.NewDecoder(f).Decode(&req); err != nil {
		return req, fmt.Errorf("decode netns setup request %q: %w", path, err)
	}
	return req, nil
}

// removeValidatedRequest unlinks name from root's retained directory fd unless the
// entry no longer names the inode that was validated (fi). The Lstat and unlinkat
// are separate syscalls, so this narrows rather than closes the window.
func removeValidatedRequest(root *os.Root, name string, fi os.FileInfo) {
	if cur, err := root.Lstat(name); err == nil && os.SameFile(fi, cur) {
		_ = root.Remove(name)
	}
}

// assertSetupRequestOwner refuses a setup request file not owned by the
// sudo-invoking user (SUDO_UID). Absent SUDO_UID means we are not under the
// expected sudo invocation, which is a refusal, never a pass.
func assertSetupRequestOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine netns setup request owner on this platform; refusing")
	}
	sudoUID := os.Getenv("SUDO_UID")
	if sudoUID == "" {
		return errors.New("SUDO_UID is not set; the netns helper only runs under sudo; refusing")
	}
	want, err := strconv.Atoi(sudoUID)
	if err != nil {
		return fmt.Errorf("SUDO_UID=%q is not an integer: %w", sudoUID, err)
	}
	if int(st.Uid) != want {
		return fmt.Errorf("netns setup request owner uid %d does not match the sudo-invoking user %d; refusing", st.Uid, want)
	}
	return nil
}
