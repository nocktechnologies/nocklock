//go:build linux

package syscallfence

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// LIVE enforcement tests: these install a real seccomp-BPF filter and then make
// the denied/allowed syscall, asserting the kernel returns the expected errno.
//
// They CANNOT run in the same process as the rest of the suite (a seccomp filter
// is irrevocable for the life of the process), so each scenario re-execs this
// test binary into a helper subprocess via the NOCKLOCK_SCFENCE_SCENARIO env var.
// The helper applies the policy, performs the syscall, and exits with a code the
// parent decodes. The parent skips when seccomp is unsupported (older CI kernel).
//
// These are the "Linux-gated bypass tests" the task requires. On the macOS dev
// host they do not build (linux tag); they run on the Linux CI runner.

const scenarioEnv = "NOCKLOCK_SCFENCE_SCENARIO"

// TestMain intercepts helper-subprocess invocations before the test framework
// runs, so the child does exactly one syscall under the fence and exits.
func TestMain(m *testing.M) {
	if scenario := os.Getenv(scenarioEnv); scenario != "" {
		os.Exit(runScenario(scenario))
	}
	os.Exit(m.Run())
}

// Exit codes the helper uses so the parent can assert precise outcomes.
const (
	exitDeniedEPERM       = 10 // syscall returned EPERM (denied as expected)
	exitDeniedENOSYS      = 11 // syscall returned ENOSYS
	exitAllowed           = 12 // syscall succeeded / was permitted
	exitOtherErrno        = 13 // some other errno (still "not allowed", but unexpected)
	exitApplyFailed       = 20 // Apply itself failed
	exitUnsupported       = 21 // seccomp unsupported on this kernel
	exitFenceNotInstalled = 22 // Apply returned nil but OUR filter is provably not the gate
)

// canaryPolicy is the policy every fenced deny scenario applies. It is the
// baseline denylist PLUS a socket-family allowlist, so that the OUR-filter
// liveness probe (fenceInstalled) has a non-ambient canary to fire on. AF_NETLINK
// is deliberately NOT in the allowlist.
var canaryPolicy = Policy{
	Mode:                  ModeRequired,
	AllowedSocketFamilies: []string{"unix", "inet", "inet6"},
}

// fenceInstalled PROVES that OUR seccomp-BPF filter — not merely some ambient
// filter — is the active gate, via an active canary syscall.
//
// PR_GET_SECCOMP is NOT sufficient: a sandboxed CI (Docker's default profile,
// gVisor, a hardened GitHub runner) installs its OWN seccomp filter, so
// PR_GET_SECCOMP already reports SECCOMP_MODE_FILTER(2) even when our Apply() was
// a complete no-op. (Verified: in golang:bookworm under Docker, PR_GET_SECCOMP==2
// before we install anything.) Relying on the mode alone re-opens the exact gap
// being closed — a no-op fence would still look "installed".
//
// Instead we fire a CANARY that:
//   - OUR canaryPolicy denies (socket(AF_NETLINK) is outside the family allowlist,
//     so the deny-the-complement filter returns EPERM), and
//   - is AMBIENTLY ALLOWED: creating an AF_NETLINK socket needs no capability and
//     is permitted by Docker's default seccomp profile, so a process WITHOUT our
//     filter creates it successfully.
//
// Therefore: canary EPERM <=> our filter is the gate. canary success <=> our
// filter is absent (no-op Apply), which is a hard failure, never a pass.
func fenceInstalled() bool {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err == nil {
		// The canary syscall SUCCEEDED — our family-allowlist filter is NOT the
		// gate. Either Apply() was a no-op or the filter does not actually deny the
		// complement. Not installed (for our purposes).
		unix.Close(fd)
		return false
	}
	// AF_NETLINK is ambiently allowed, so the ONLY thing that turns it into EPERM
	// is our deny-the-complement socket filter. EPERM => our filter is live.
	return err == unix.EPERM
}

func runScenario(scenario string) int {
	if !Supported() {
		return exitUnsupported
	}
	switch scenario {
	case "init_module":
		if err := Apply(canaryPolicy); err != nil {
			return exitApplyFailed
		}
		// init_module returns EPERM ambiently in an unprivileged process (no
		// CAP_SYS_MODULE), so EPERM alone does NOT prove the fence did anything.
		// Require OUR filter to be the live gate (proven by the AF_NETLINK canary)
		// first; only then is the EPERM below provably fence-caused rather than the
		// ambient capability check.
		if !fenceInstalled() {
			return exitFenceNotInstalled
		}
		_, _, errno := unix.Syscall(uintptr(mustNr("init_module")), 0, 0, 0)
		return classifyErrno(errno)

	case "unshare_newuser":
		if err := Apply(canaryPolicy); err != nil {
			return exitApplyFailed
		}
		if !fenceInstalled() {
			return exitFenceNotInstalled
		}
		err := unix.Unshare(unix.CLONE_NEWUSER)
		return classifyErr(err)

	case "ptrace":
		if err := Apply(canaryPolicy); err != nil {
			return exitApplyFailed
		}
		if !fenceInstalled() {
			return exitFenceNotInstalled
		}
		// PTRACE_TRACEME is the simplest call that must be blocked.
		_, _, errno := unix.Syscall6(uintptr(mustNr("ptrace")),
			uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
		return classifyErrno(errno)

	case "socket_packet_denied":
		if err := Apply(canaryPolicy); err != nil {
			return exitApplyFailed
		}
		// socket(AF_PACKET, SOCK_RAW) returns EPERM ambiently without CAP_NET_RAW,
		// so — like init_module — the EPERM must be proven to come from the
		// installed filter, not the missing capability. Require the fence live via
		// the AF_NETLINK canary (ambiently allowed, denied only by our filter).
		if !fenceInstalled() {
			return exitFenceNotInstalled
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
		if err == nil {
			unix.Close(fd)
			return exitAllowed
		}
		return classifyErr(err)

	case "socket_inet_allowed":
		if err := Apply(canaryPolicy); err != nil {
			return exitApplyFailed
		}
		// Allowed half of the socket-family delta: AF_INET must SUCCEED even with
		// the filter live. Verify the fence is installed so this allow is proven to
		// pass THROUGH the filter (the deny half, socket_packet_denied, fails it).
		if !fenceInstalled() {
			return exitFenceNotInstalled
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err == nil {
			unix.Close(fd)
			return exitAllowed
		}
		return classifyErr(err)

	case "socket_packet_unfenced":
		// CONTROL (no Apply): perform socket(AF_PACKET, SOCK_RAW) with NO fence
		// installed. On a CAP_NET_RAW-granted runner this SUCCEEDS (exitAllowed),
		// which — paired with socket_packet_denied returning EPERM under the fence —
		// is a genuine red->green: the same syscall flips from allowed to denied
		// solely because of the filter. On a runner WITHOUT CAP_NET_RAW it returns
		// EPERM ambiently; the parent only demands the success delta when the
		// NOCKLOCK_TEST_CAP_NET_RAW gate says the capability is present.
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
		if err == nil {
			unix.Close(fd)
			return exitAllowed
		}
		return classifyErr(err)

	case "init_module_unfenced":
		// CONTROL (no Apply): init_module with NO fence. In an unprivileged process
		// this is ambiently EPERM (no CAP_SYS_MODULE), so it does not by itself
		// prove anything — it exists to document the baseline next to the fenced
		// scenario, whose fence-causation is established by the AF_NETLINK canary
		// (fenceInstalled) rather than by this control.
		_, _, errno := unix.Syscall(uintptr(mustNr("init_module")), 0, 0, 0)
		return classifyErrno(errno)

	case "pthread_create":
		// pthread_create uses clone(2) (no CLONE_NEW*) and, on glibc>=2.34,
		// probes clone3 first. Our filter must let goroutine/thread creation
		// proceed: spawn OS threads after applying the fence and confirm they run.
		if err := Apply(Policy{Mode: ModeRequired}); err != nil {
			return exitApplyFailed
		}
		if spawnThreadsWorks() {
			return exitAllowed
		}
		return exitOtherErrno

	default:
		return 99
	}
}

func classifyErrno(errno unix.Errno) int {
	switch errno {
	case 0:
		return exitAllowed
	case unix.EPERM:
		return exitDeniedEPERM
	case unix.ENOSYS:
		return exitDeniedENOSYS
	default:
		return exitOtherErrno
	}
}

func classifyErr(err error) int {
	if err == nil {
		return exitAllowed
	}
	if errno, ok := err.(unix.Errno); ok {
		return classifyErrno(errno)
	}
	return exitOtherErrno
}

func mustNr(name string) uint32 {
	nr, ok := syscallNr(name, nativeArch)
	if !ok {
		panic("no syscall number for " + name + " on " + nativeArch)
	}
	return nr
}

// spawnThreadsWorks creates several OS threads (which force new clone(2) calls)
// after the fence is installed and confirms they all run. If the clone filter
// were wrong (e.g. clone3 -> EPERM, or a too-broad clone deny), thread creation
// would fail and the process would abort or deadlock.
func spawnThreadsWorks() bool {
	const n = 8
	done := make(chan bool, n)
	for i := 0; i < n; i++ {
		go func() {
			// Pin to an OS thread to maximise the chance of a fresh clone(2).
			done <- true
		}()
	}
	for i := 0; i < n; i++ {
		if !<-done {
			return false
		}
	}
	return true
}

// runHelper re-execs this test binary into the given scenario and returns its
// exit code.
func runHelper(t *testing.T, scenario string) int {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), scenarioEnv+"="+scenario)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 && testing.Verbose() {
		t.Logf("scenario %q output: %s", scenario, strings.TrimSpace(string(out)))
	}
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	t.Fatalf("scenario %q run error: %v", scenario, err)
	return -1
}

// requireSupported gates the live assertions. The ONLY green-skip condition is a
// kernel that genuinely lacks seccomp-BPF (CONFIG_SECCOMP off). Everything else —
// an Apply that failed, or an Apply that returned nil but did NOT install a live
// filter — is a HARD FAILURE. Previously these were t.Skip, which meant a
// completely broken / no-op fence produced a green suite (a silent no-op fence
// would skip all four scenarios rather than fail). A skip is not a pass.
func requireSupported(t *testing.T, code int) {
	t.Helper()
	if code == exitUnsupported {
		t.Skip("seccomp-BPF unsupported on this kernel (CONFIG_SECCOMP off)")
	}
	if code == exitApplyFailed {
		t.Fatalf("Apply() failed to install the seccomp filter — fence is not enforcing (exit %d). "+
			"A broken/no-op fence must FAIL, not skip.", code)
	}
	if code == exitFenceNotInstalled {
		t.Fatalf("Apply() returned nil but the AF_NETLINK canary proved OUR filter is not the gate (exit %d) — "+
			"the fence never installed (or does not deny the complement), so any EPERM observed is "+
			"ambient, not fence-caused.", code)
	}
}

func TestEnforce_InitModuleDenied(t *testing.T) {
	code := runHelper(t, "init_module")
	requireSupported(t, code)
	// EPERM here is provably fence-caused: the scenario first fires the AF_NETLINK
	// canary (ambiently ALLOWED, denied ONLY by our family-allowlist filter); if
	// the canary is not blocked the scenario exits exitFenceNotInstalled, which
	// requireSupported turns into a hard FAILURE. So a no-op Apply can no longer
	// pass this test on the ambient CAP_SYS_MODULE EPERM.
	if code != exitDeniedEPERM {
		t.Errorf("init_module: exit %d, want EPERM(%d)", code, exitDeniedEPERM)
	}
}

// TestEnforce_InitModuleUnfencedBaseline documents that init_module is ambiently
// EPERM for an unprivileged process WITHOUT any fence. It exists so the suite is
// explicit that the fenced scenario's fence-causation rests on the
// PR_GET_SECCOMP==2 check, not on a deny/no-deny errno delta (which init_module
// cannot provide without CAP_SYS_MODULE). On the rare runner that DOES hold
// CAP_SYS_MODULE the unfenced call could succeed; we only assert it is NOT a
// crash/unexpected errno, never that it must be EPERM.
func TestEnforce_InitModuleUnfencedBaseline(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp-BPF unsupported on this kernel (CONFIG_SECCOMP off)")
	}
	code := runHelper(t, "init_module_unfenced")
	switch code {
	case exitDeniedEPERM, exitDeniedENOSYS, exitAllowed:
		// All acceptable baselines: EPERM (no CAP_SYS_MODULE, the common case),
		// ENOSYS (no module support), or ALLOWED (privileged runner).
	default:
		t.Errorf("init_module UNFENCED control: unexpected exit %d", code)
	}
}

func TestEnforce_UnshareNewUserDenied(t *testing.T) {
	code := runHelper(t, "unshare_newuser")
	requireSupported(t, code)
	if code != exitDeniedEPERM {
		t.Errorf("unshare(CLONE_NEWUSER): exit %d, want EPERM(%d)", code, exitDeniedEPERM)
	}
}

func TestEnforce_PtraceDenied(t *testing.T) {
	code := runHelper(t, "ptrace")
	requireSupported(t, code)
	if code != exitDeniedEPERM {
		t.Errorf("ptrace(PTRACE_TRACEME): exit %d, want EPERM(%d)", code, exitDeniedEPERM)
	}
}

func TestEnforce_RawPacketSocketDenied(t *testing.T) {
	code := runHelper(t, "socket_packet_denied")
	requireSupported(t, code)
	if code != exitDeniedEPERM {
		t.Errorf("socket(AF_PACKET): exit %d, want EPERM(%d)", code, exitDeniedEPERM)
	}
	// The fenced EPERM above is proven fence-caused by the in-scenario
	// PR_GET_SECCOMP==SECCOMP_MODE_FILTER check (a no-op Apply would have exited
	// exitFenceNotInstalled and failed via requireSupported). On a runner that
	// grants CAP_NET_RAW, also assert the genuine red->green: the SAME syscall
	// SUCCEEDS unfenced (control) and is DENIED fenced — the flip is solely the
	// filter, not the missing capability. Gate the control on the capability so it
	// is meaningful (an unprivileged runner returns ambient EPERM either way).
	if os.Getenv("NOCKLOCK_TEST_CAP_NET_RAW") == "1" {
		ctrl := runHelper(t, "socket_packet_unfenced")
		requireSupported(t, ctrl)
		if ctrl != exitAllowed {
			t.Errorf("control socket(AF_PACKET) UNFENCED: exit %d, want ALLOWED(%d) — "+
				"with CAP_NET_RAW the unfenced call must succeed so the fenced EPERM is a true red->green",
				ctrl, exitAllowed)
		}
	}
}

func TestEnforce_InetSocketAllowed(t *testing.T) {
	code := runHelper(t, "socket_inet_allowed")
	requireSupported(t, code)
	if code != exitAllowed {
		t.Errorf("socket(AF_INET): exit %d, want ALLOWED(%d)", code, exitAllowed)
	}
}

func TestEnforce_PthreadCreateStillWorks(t *testing.T) {
	code := runHelper(t, "pthread_create")
	requireSupported(t, code)
	if code != exitAllowed {
		t.Errorf("pthread_create under fence: exit %d, want ALLOWED(%d) — clone3->ENOSYS fallback must keep threads working", code, exitAllowed)
	}
}
