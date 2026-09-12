//go:build linux

package netns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/network"
	"golang.org/x/sys/unix"
)

// ChildExitError preserves the fenced command's exit status after the helper has
// stopped its sidecars and removed the private bridge.
type ChildExitError struct {
	Code   int
	Detail string
}

func (e *ChildExitError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("netns child exited %d", e.Code)
}

// ChildGroupKillWatchdogRequest instructs the watchdog subprocess to monitor
// a parent process's exit and kill the child process group when the parent dies.
type ChildGroupKillWatchdogRequest struct {
	ChildPGID int `json:"child_pgid"`
}

// SetupEgressAndSupervise builds the Phase-1b private bridge, starts both policy
// proxies, installs the child namespace's tproxy/DNS policy, and supervises the
// unprivileged child. It never leaves the child with a default route or a direct
// path to a resolver or upstream host.
func SetupEgressAndSupervise(req Request) (resultErr error) {
	if err := validateEgressConfig(req.Egress, req.UID); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("netns helper must run as root (via sudo); euid is not 0")
	}

	// setns and all configuration subprocesses must stay on this thread. See the
	// matching explanation in SetupAndExec for why a Go thread migration here is
	// a fence fail-open.
	runtime.LockOSThread()

	bridge := req.Egress.Bridge
	bridgeCreated := false
	cleanupTransferred := false
	defer func() {
		cleanupFailedBridge(bridge, bridgeCreated, cleanupTransferred, &resultErr, removeBridge)
	}()
	if err := createBridge(bridge); err != nil {
		return err
	}
	bridgeCreated = true
	if err := startDeferredBridgeCleanup(bridge); err != nil {
		return err
	}
	cleanupTransferred = true

	hostProxy, err := startSidecar("__netns-host-proxy", *req.Egress)
	if err != nil {
		return fmt.Errorf("start host allowlist proxy: %w", err)
	}
	defer stopSidecar(hostProxy)
	if err := network.WaitForProxyReady(context.Background(), bridge.hostProxyAddr(), 5*time.Second); err != nil {
		return fmt.Errorf("host allowlist proxy readiness failed: %w", err)
	}

	nsPath := filepath.Join("/run/netns", bridge.Namespace)
	nsFD, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open private network namespace %q: %w", bridge.Namespace, err)
	}
	defer unix.Close(nsFD)
	if err := unix.Setns(nsFD, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter private network namespace %q: %w", bridge.Namespace, err)
	}

	cleanupResolver, err := mountStubResolver()
	if err != nil {
		return err
	}
	defer cleanupResolver()
	if err := configureEgressNamespace(*req.Egress); err != nil {
		return err
	}

	transparentProxy, err := startSidecar("__netns-proxy", *req.Egress)
	if err != nil {
		return fmt.Errorf("start transparent policy proxy: %w", err)
	}
	defer stopSidecar(transparentProxy)
	// net/http dials on runtime goroutines, not necessarily the locked setns
	// thread. The veth address names this proxy from both host and child netns;
	// loopback would accidentally probe the host's unrelated loopback listener.
	if err := network.WaitForProxyReady(context.Background(), bridge.childHealthAddr(), 5*time.Second); err != nil {
		return fmt.Errorf("transparent policy proxy readiness failed: %w", err)
	}

	child, err := startSidecar("__netns-child", req)
	if err != nil {
		return fmt.Errorf("start fenced netns child: %w", err)
	}

	// Start watchdog to kill the child process group if this parent helper dies.
	// This ensures descendants survive only while the parent is alive.
	if err := startChildGroupKillWatchdog(child.Process.Pid); err != nil {
		stopSidecar(child)
		return fmt.Errorf("start child group kill watchdog: %w", err)
	}

	resultErr = superviseChild(child, []string{
		bridge.childHealthAddr(),
		bridge.hostProxyAddr(),
	})

	// A named network namespace can be held by Go runtime threads other than the
	// locked setup thread. The host-side cleanup process waits for this helper to
	// exit before removing the veth and namespace, preventing an early-error leak.
	return resultErr
}

func cleanupFailedBridge(bridge BridgeSpec, bridgeCreated, cleanupTransferred bool, resultErr *error, cleanup func(BridgeSpec) error) {
	if bridgeCreated && *resultErr != nil && !cleanupTransferred {
		*resultErr = errors.Join(*resultErr, cleanup(bridge))
	}
}

// DropAndExecChild applies the receipted five-set capability drop, changes to the
// caller's credential, and execs the actual fenced command. It is a separate
// process so the root supervisor can kill it when either proxy becomes unhealthy.
func DropAndExecChild(req Request) error {
	if len(req.Argv) == 0 {
		return errors.New("netns setup request has no argv to exec")
	}
	if err := validateChildCredential(req); err != nil {
		return err
	}
	if err := dropCaps(); err != nil {
		return fmt.Errorf("drop fence capabilities: %w", err)
	}
	if err := assertCapsDropped(); err != nil {
		return fmt.Errorf("verify fence capabilities dropped: %w", err)
	}
	if err := dropPrivilege(req); err != nil {
		return fmt.Errorf("drop to unprivileged child credential: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set NO_NEW_PRIVS: %w", err)
	}
	if err := unix.Exec(req.Argv[0], req.Argv, req.Env); err != nil {
		return fmt.Errorf("exec child %q in namespace: %w", req.Argv[0], err)
	}
	return errors.New("unreachable: execve returned without error")
}

// RunHostProxy serves the host-side half of the private bridge. The transparent
// proxy can only open CONNECT tunnels to this listener; this proxy repeats the
// allowlist check and is the component that uses the host resolver to dial a real
// destination.
func RunHostProxy(cfg EgressConfig) error {
	if err := validateEgressConfig(&cfg, 1); err != nil {
		return err
	}
	if err := dropProxyIdentity(); err != nil {
		return fmt.Errorf("drop host policy proxy identity: %w", err)
	}
	p := network.NewProxyServerAt(config.NetworkConfig{Allow: cfg.Allow, AllowPrivateRanges: cfg.AllowPrivateRanges}, nil, "", cfg.Bridge.hostProxyAddr())
	if _, err := p.Start(); err != nil {
		return err
	}
	defer p.Stop()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	<-signals
	return nil
}

func createBridge(bridge BridgeSpec) error {
	return createBridgeWith(bridge, runInNS)
}

func createBridgeWith(bridge BridgeSpec, run func(string, ...string) (string, error)) (resultErr error) {
	createdLink := false
	createdNamespace := false
	defer func() {
		if resultErr == nil {
			return
		}
		if createdLink {
			if out, err := run("ip", "link", "del", bridge.HostInterface); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback veth: %w: %s", err, out))
			}
		}
		if createdNamespace {
			if out, err := run("ip", "netns", "del", bridge.Namespace); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback namespace: %w: %s", err, out))
			}
		}
		if err := ReleaseSubnetReservation(bridge.ReservationID); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("rollback subnet reservation: %w", err))
		}
	}()
	if out, err := run("ip", "netns", "add", bridge.Namespace); err != nil {
		return fmt.Errorf("create private network namespace: %w\n%s", err, out)
	}
	createdNamespace = true
	if out, err := run("ip", "link", "add", bridge.HostInterface, "type", "veth", "peer", "name", bridge.ChildInterface); err != nil {
		return fmt.Errorf("create private bridge veth: %w\n%s", err, out)
	}
	createdLink = true
	if out, err := run("ip", "addr", "add", bridge.hostCIDR(), "dev", bridge.HostInterface); err != nil {
		return fmt.Errorf("assign host private bridge address: %w\n%s", err, out)
	}
	if out, err := run("ip", "link", "set", "dev", bridge.HostInterface, "up"); err != nil {
		return fmt.Errorf("bring host private bridge up: %w\n%s", err, out)
	}
	if out, err := run("ip", "link", "set", "dev", bridge.ChildInterface, "netns", bridge.Namespace); err != nil {
		return fmt.Errorf("move child private bridge into namespace: %w\n%s", err, out)
	}
	return nil
}

func removeBridge(bridge BridgeSpec) error {
	var errs []error
	if out, err := runInNS("ip", "link", "del", bridge.HostInterface); err != nil && !strings.Contains(strings.ToLower(out), "cannot find device") {
		errs = append(errs, fmt.Errorf("delete host private bridge interface: %w\n%s", err, out))
	}
	if out, err := runInNS("ip", "netns", "del", bridge.Namespace); err != nil {
		errs = append(errs, fmt.Errorf("delete private network namespace: %w\n%s", err, out))
	}
	// Release the subnet reservation to allow other runs to use this /30.
	if err := ReleaseSubnetReservation(bridge.ReservationID); err != nil {
		errs = append(errs, fmt.Errorf("release subnet reservation: %w", err))
	}
	return errors.Join(errs...)
}

// deferredCleanupWriters deliberately keep the write end of each cleaner pipe
// open until this helper process exits. Cleanup must wait until every Go runtime
// thread has released the named namespace, not merely until the locked setup
// thread has returned.
var deferredCleanupWriters []*os.File

func startDeferredBridgeCleanup(bridge BridgeSpec) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create private bridge cleanup pipe: %w", err)
	}
	encoded, err := json.Marshal(bridge)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return fmt.Errorf("encode private bridge cleanup request: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return fmt.Errorf("resolve helper executable for private bridge cleanup: %w", err)
	}
	cmd := exec.Command(self, "__netns-cleanup")
	cmd.Stdin = bytes.NewReader(encoded)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{reader} // fd 3 signals parent helper exit by EOF.
	if err := cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return fmt.Errorf("start private bridge cleanup process: %w", err)
	}
	if err := reader.Close(); err != nil {
		_ = writer.Close()
		return fmt.Errorf("close private bridge cleanup pipe reader: %w", err)
	}
	deferredCleanupWriters = append(deferredCleanupWriters, writer)
	return nil
}

// RunDeferredBridgeCleanup waits until the setup helper exits, then removes the
// host veth and named namespace from a process that never entered that namespace.
func RunDeferredBridgeCleanup(bridge BridgeSpec) error {
	if err := validateEgressConfig(&EgressConfig{Bridge: bridge}, 1); err != nil {
		return fmt.Errorf("validate private bridge cleanup request: %w", err)
	}
	parentExit := os.NewFile(uintptr(3), "nocklock-parent-exit")
	if parentExit == nil {
		return errors.New("private bridge cleanup did not receive its parent-exit pipe")
	}
	defer parentExit.Close()
	if _, err := io.Copy(io.Discard, parentExit); err != nil {
		return fmt.Errorf("wait for netns helper exit before cleanup: %w", err)
	}
	return removeBridge(bridge)
}

// startChildGroupKillWatchdog spawns a watchdog process that monitors parent
// death and kills the child process group when the parent exits. This ensures
// that if the privileged helper is killed (SIGKILL or crash), the entire child
// process tree is terminated, not just the immediate child leader.
func startChildGroupKillWatchdog(childPID int) error {
	// Get the child's process group ID. Since the child is started with Setpgid,
	// its PGID should be its own PID.
	childPGID := childPID

	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create child kill watchdog pipe: %w", err)
	}
	encoded, err := json.Marshal(ChildGroupKillWatchdogRequest{ChildPGID: childPGID})
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return fmt.Errorf("encode child kill watchdog request: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return fmt.Errorf("resolve helper executable for child kill watchdog: %w", err)
	}
	cmd := exec.Command(self, "__netns-child-kill-watchdog")
	cmd.Stdin = bytes.NewReader(encoded)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{reader} // fd 3 signals parent helper exit by EOF.
	if err := cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return fmt.Errorf("start child kill watchdog process: %w", err)
	}
	if err := reader.Close(); err != nil {
		_ = writer.Close()
		return fmt.Errorf("close child kill watchdog pipe reader: %w", err)
	}
	deferredCleanupWriters = append(deferredCleanupWriters, writer)
	return nil
}

// RunChildGroupKillWatchdog reads from the parent-exit pipe and kills the
// child's process group when the parent dies. This is called in a subprocess
// via the "__netns-child-kill-watchdog" verb.
func RunChildGroupKillWatchdog(req ChildGroupKillWatchdogRequest) error {
	parentExit := os.NewFile(uintptr(3), "nocklock-parent-exit")
	if parentExit == nil {
		return errors.New("child kill watchdog did not receive its parent-exit pipe")
	}
	defer parentExit.Close()
	if _, err := io.Copy(io.Discard, parentExit); err != nil {
		return fmt.Errorf("wait for parent exit: %w", err)
	}
	// Parent has exited. Kill the entire child process group to clean up
	// any descendants that may have been spawned by the child leader.
	// Negative PGID kills all processes in the group.
	if err := syscall.Kill(-req.ChildPGID, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("kill child process group %d: %w", req.ChildPGID, err)
	}
	return nil
}

func mountStubResolver() (func(), error) {
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return nil, fmt.Errorf("create private resolver mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return nil, fmt.Errorf("make resolver mount namespace private: %w", err)
	}
	file, err := os.CreateTemp("", "nocklock-resolv-")
	if err != nil {
		return nil, fmt.Errorf("create stub resolver file: %w", err)
	}
	path := file.Name()
	if _, err := file.WriteString("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write stub resolver file: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("close stub resolver file: %w", err)
	}
	if err := unix.Mount(path, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("bind mount stub resolver: %w", err)
	}
	return func() {
		_ = unix.Unmount("/etc/resolv.conf", unix.MNT_DETACH)
		_ = os.Remove(path)
	}, nil
}

func configureEgressNamespace(cfg EgressConfig) error {
	b := cfg.Bridge
	for _, argv := range [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "set", "dev", b.ChildInterface, "up"},
		{"ip", "addr", "add", b.childCIDR(), "dev", b.ChildInterface},
		{"ip", "route", "replace", b.HostAddress + "/32", "dev", b.ChildInterface},
		{"ip", "rule", "add", "fwmark", "0x1", "lookup", "100"},
		{"ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"},
		{"ip", "-6", "rule", "add", "fwmark", "0x1", "lookup", "100"},
		{"ip", "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", "100"},
	} {
		out, err := runInNS(argv[0], argv[1:]...)
		if err != nil {
			return fmt.Errorf("configure private namespace (%s): %w\n%s", strings.Join(argv, " "), err, out)
		}
	}
	if out, err := runInNSStdin(EgressRuleset(cfg), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("install tproxy egress ruleset: %w\n%s", err, out)
	}
	return nil
}

func startSidecar(verb string, payload any) (*exec.Cmd, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", verb, err)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve helper executable for %s: %w", verb, err)
	}
	cmd := exec.Command(self, verb)
	cmd.Stdin = bytes.NewReader(encoded)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func stopSidecar(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

func superviseChild(child *exec.Cmd, healthAddrs []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return superviseChildContext(ctx, child, healthAddrs, 2*time.Second)
}

func superviseChildContext(ctx context.Context, child *exec.Cmd, healthAddrs []string, interval time.Duration) error {
	// Also retire descendants when the leader exits normally.
	defer syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
			<-done
			return &ChildExitError{Code: 2, Detail: "fenced child cancelled; terminated process group"}
		case err := <-done:
			if err == nil {
				return nil
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return &ChildExitError{Code: exitErr.ExitCode()}
			}
			return fmt.Errorf("wait for fenced child: %w", err)
		case <-ticker.C:
			healthy := true
			for _, addr := range healthAddrs {
				if err := network.WaitForProxyReady(context.Background(), addr, time.Second); err != nil {
					healthy = false
					break
				}
			}
			if healthy {
				failures = 0
				continue
			}
			failures++
			if failures < 2 {
				continue
			}
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
			<-done
			return &ChildExitError{Code: 2, Detail: "transparent policy proxy died; terminated fenced child"}
		}
	}
}
