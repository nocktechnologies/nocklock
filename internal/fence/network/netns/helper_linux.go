//go:build linux

package netns

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Request is the setup request the privileged helper reads from stdin under the
// DECIDED sudo contract (spec amendment 2026-08-24): the helper is invoked as
// `sudo -n <helper> setup` with NO command-line arguments; the child argv,
// environment, and the unprivileged credential to drop to are carried on stdin
// as a single JSON object.
//
// Keeping the request off argv is NECESSARY (the fixed sudoers policy pins the
// two argument vectors `check`/`setup`, so a variable request cannot ride argv)
// but NOT sufficient on its own — stdin is just as caller-controlled as argv
// would be. The actual boundary is validateChildCredential below: the helper
// refuses any credential that is root or that does not match the sudo-invoking
// user, so the NOPASSWD grant buys exactly "run a fenced agent as myself," not a
// general run-anything-as-root primitive.
type Request struct {
	// Argv is the child command and its arguments, exec'd inside the namespace.
	// Argv[0] must be an absolute path — unix.Exec does not search PATH — which
	// the unprivileged parent (buildNetnsChild) resolves before sending.
	Argv []string `json:"argv"`
	// Env is the child environment. sudo resets the environment, so the parent
	// carries the fence-composed child env explicitly rather than relying on
	// inheritance.
	Env []string `json:"env"`
	// UID/GID are the unprivileged credential the helper drops to before exec, so
	// the agent runs as the invoking user — never as root — inside the namespace
	// (spec: "hands a non-root child ... into it").
	UID int `json:"uid"`
	GID int `json:"gid"`
	// Groups are the supplementary groups to set for the child. Empty clears them.
	Groups []int `json:"groups"`
}

// trustedToolDirs is the FIXED search path for the setup tools. A root helper
// must not resolve `ip`/`nft` through the inherited PATH: the shipped sudoers
// policy is not guaranteed to set secure_path, so a binary planted earlier on the
// invoking user's PATH would otherwise execute AS ROOT before any capability is
// dropped. These are the standard locations for iproute2/nftables.
var trustedToolDirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"}

// resolveTool finds a setup tool by absolute path in trustedToolDirs, ignoring
// the inherited PATH entirely.
func resolveTool(name string) (string, error) {
	for _, dir := range trustedToolDirs {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("required tool %q not found in trusted directories %v (a root helper must not resolve tools via the inherited PATH)", name, trustedToolDirs)
}

// Check is the non-mutating `check` verb: a preflight the unprivileged parent
// runs (via `sudo -n <helper> check`) to confirm the privileged-helper path is
// reachable BEFORE it composes a real setup request. It verifies the process is
// privileged and that the setup tools are present at their trusted absolute
// paths. It mutates nothing.
func Check() error {
	if os.Geteuid() != 0 {
		return errors.New("netns helper must run as root (via sudo); euid is not 0")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := resolveTool(tool); err != nil {
			return err
		}
	}
	return nil
}

// validateChildCredential refuses any child credential that would escalate
// privilege. This is the real security boundary for the stdin request: without
// it, a caller holding the NOPASSWD grant could pipe {"uid":0,...} and have the
// helper execve an arbitrary argv as root. It rejects root/uid<=0, a gid 0 in the
// supplementary groups, and — critically — any credential that does not match the
// sudo-invoking user. sudo always sets SUDO_UID/SUDO_GID (even under env_reset),
// so an absent or unparseable value means we are NOT under the expected sudo
// invocation; that is a refusal, never a pass.
func validateChildCredential(req Request) error {
	if req.UID <= 0 || req.GID <= 0 {
		return fmt.Errorf("refusing to run the netns child as root/uid<=0 (uid=%d gid=%d); it must be unprivileged", req.UID, req.GID)
	}
	for _, g := range req.Groups {
		if g == 0 {
			return errors.New("refusing to run the netns child with gid 0 among its supplementary groups")
		}
	}
	sudoUID, err := envInt("SUDO_UID")
	if err != nil {
		return fmt.Errorf("cannot confirm the sudo-invoking user: %w (the helper only runs under sudo)", err)
	}
	if sudoUID != req.UID {
		return fmt.Errorf("netns child uid %d does not match the sudo-invoking user %d; refusing", req.UID, sudoUID)
	}
	sudoGID, err := envInt("SUDO_GID")
	if err != nil {
		return fmt.Errorf("cannot confirm the sudo-invoking group: %w (the helper only runs under sudo)", err)
	}
	if sudoGID != req.GID {
		return fmt.Errorf("netns child gid %d does not match the sudo-invoking group %d; refusing", req.GID, sudoGID)
	}
	return nil
}

// envInt reads an integer environment variable, treating absent or unparseable
// as an error (so the caller can fail closed).
func envInt(name string) (int, error) {
	s := os.Getenv(name)
	if s == "" {
		return 0, fmt.Errorf("%s is not set", name)
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not an integer: %w", name, s, err)
	}
	return v, nil
}

// SetupAndExec is the `setup` verb and the whole privileged floor: it validates
// the requested child credential, creates a fresh network namespace, brings
// loopback up, installs the DefaultDropRuleset base, drops the fence capabilities
// from all five sets, drops to the requested unprivileged credential, latches
// NO_NEW_PRIVS, and finally execve's the child INTO that namespace.
//
// FAIL-CLOSED: it returns an error at the first failed step and NEVER execs a
// child it could not fully fence. On success it does not return — execve
// replaces the process image — so a nil return is impossible and any returned
// error means the child was not started. There is no advisory/degraded fallback
// (spec: "REFUSE to exec — no advisory/degraded network fallback").
func SetupAndExec(req Request) error {
	if len(req.Argv) == 0 {
		return errors.New("netns setup request has no argv to exec")
	}
	if os.Geteuid() != 0 {
		return errors.New("netns helper must run as root (via sudo); euid is not 0")
	}
	// Validate the credential BEFORE any mutation, so a bad request is refused
	// without side effects.
	if err := validateChildCredential(req); err != nil {
		return err
	}

	// Namespace membership and per-thread capability state are BOTH per-thread,
	// and Go may migrate a goroutine across OS threads at any preemption point. If
	// the thread we unshare the netns on is not the thread we finally execve on,
	// the child would launch in the HOST namespace with caps dropped — a silent
	// fence fail-OPEN that no test catches. Lock this goroutine to its OS thread
	// and NEVER unlock: every step below (unshare, the ip/nft subprocess forks,
	// the cap drop, the credential drop, and unix.Exec) runs on this one thread,
	// and the goroutine ends in execve so the thread is never returned to the
	// runtime. Mirrors landlock_exec.go and the Q6 child (runChild).
	runtime.LockOSThread()

	// Create the fresh network namespace (CLONE_NEWNET). Only THIS thread moves
	// into it; subprocesses forked from this locked thread inherit it, which is
	// exactly how the ip/nft configuration below and the final execve land inside
	// the new namespace.
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("create network namespace (CLONE_NEWNET): %w", err)
	}

	// Bring the loopback interface up (link state). The base installs no loopback
	// allowance yet — see DefaultDropRuleset — but later increments (proxy
	// listener, in-namespace DNS stub) need a live `lo`.
	if out, err := runInNS("ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("bring loopback up: %w\n%s", err, out)
	}

	// Install the default-drop base. nft reads the ruleset from stdin and, because
	// it is forked from this locked (already-unshared) thread, configures THIS
	// namespace's tables.
	if out, err := runInNSStdin(DefaultDropRuleset, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("install default-drop nftables base: %w\n%s", err, out)
	}

	// Drop CAP_NET_ADMIN + CAP_SYS_ADMIN (+ the temporary CAP_SETPCAP) from all
	// five capability sets, then verify the drop directly — the receipted Q6
	// harness (caps_linux.go). After this the child cannot rewrite the fence even
	// though it briefly shares the root uid.
	if err := dropCaps(); err != nil {
		return fmt.Errorf("drop fence capabilities: %w", err)
	}
	if err := assertCapsDropped(); err != nil {
		return fmt.Errorf("verify fence capabilities dropped: %w", err)
	}

	// Drop to the unprivileged invoking user so the agent runs as a NON-root child
	// (spec). dropCaps left CAP_SETUID/CAP_SETGID intact, and euid is still 0, so
	// the credential change is permitted; switching to a non-root uid then clears
	// any residual effective/permitted capabilities as a belt-and-braces on top of
	// the five-set drop above.
	if err := dropPrivilege(req); err != nil {
		return fmt.Errorf("drop to unprivileged child credential: %w", err)
	}

	// Latch NO_NEW_PRIVS so the child (and its descendants) can never regain
	// privilege by exec'ing a setuid-root binary — a cheap one-way second lock on
	// top of the bounding-set drop, consistent with the Landlock/seccomp path.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set NO_NEW_PRIVS: %w", err)
	}

	// execve the child into the configured namespace. This does not return on
	// success.
	if err := unix.Exec(req.Argv[0], req.Argv, req.Env); err != nil {
		return fmt.Errorf("exec child %q in namespace: %w", req.Argv[0], err)
	}
	return errors.New("unreachable: execve returned without error")
}

// dropPrivilege sets the supplementary groups, gid, and uid to the requested
// unprivileged credential. gid is set before uid: once the process is no longer
// root it can no longer change its gid, so the order is load-bearing. The
// credential itself is already validated (validateChildCredential); the final
// guard here is a defense-in-depth check that the uid actually dropped.
func dropPrivilege(req Request) error {
	if err := unix.Setgroups(req.Groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setresgid(req.GID, req.GID, req.GID); err != nil {
		return fmt.Errorf("setresgid(%d): %w", req.GID, err)
	}
	if err := unix.Setresuid(req.UID, req.UID, req.UID); err != nil {
		return fmt.Errorf("setresuid(%d): %w", req.UID, err)
	}
	// Refuse to proceed if the uid did not actually change to non-root — we must
	// never execve the agent still holding a root euid.
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("uid did not drop to the unprivileged child credential")
	}
	return nil
}

// runInNS runs a configuration tool with a C locale (stable error strings). It is
// only ever called AFTER unshare on the locked thread, so the forked subprocess
// inherits the new network namespace.
func runInNS(name string, args ...string) (string, error) {
	return runInNSStdin("", name, args...)
}

// runInNSStdin is runInNS with stdin fed from s. It resolves the tool to a
// trusted absolute path (never the inherited PATH — this runs as root).
func runInNSStdin(s, name string, args ...string) (string, error) {
	bin, err := resolveTool(name)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "LANGUAGE=")
	cmd.Stdin = strings.NewReader(s)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
