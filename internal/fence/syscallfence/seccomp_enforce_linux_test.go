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
	exitDeniedEPERM  = 10 // syscall returned EPERM (denied as expected)
	exitDeniedENOSYS = 11 // syscall returned ENOSYS
	exitAllowed      = 12 // syscall succeeded / was permitted
	exitOtherErrno   = 13 // some other errno (still "not allowed", but unexpected)
	exitApplyFailed  = 20 // Apply itself failed
	exitUnsupported  = 21 // seccomp unsupported on this kernel
)

func runScenario(scenario string) int {
	if !Supported() {
		return exitUnsupported
	}
	switch scenario {
	case "init_module":
		if err := Apply(Policy{Mode: ModeRequired}); err != nil {
			return exitApplyFailed
		}
		_, _, errno := unix.Syscall(uintptr(mustNr("init_module")), 0, 0, 0)
		return classifyErrno(errno)

	case "unshare_newuser":
		if err := Apply(Policy{Mode: ModeRequired}); err != nil {
			return exitApplyFailed
		}
		err := unix.Unshare(unix.CLONE_NEWUSER)
		return classifyErr(err)

	case "ptrace":
		if err := Apply(Policy{Mode: ModeRequired}); err != nil {
			return exitApplyFailed
		}
		// PTRACE_TRACEME is the simplest call that must be blocked.
		_, _, errno := unix.Syscall6(uintptr(mustNr("ptrace")),
			uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
		return classifyErrno(errno)

	case "socket_packet_denied":
		if err := Apply(Policy{Mode: ModeRequired, AllowedSocketFamilies: []string{"unix", "inet", "inet6"}}); err != nil {
			return exitApplyFailed
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
		if err == nil {
			unix.Close(fd)
			return exitAllowed
		}
		return classifyErr(err)

	case "socket_inet_allowed":
		if err := Apply(Policy{Mode: ModeRequired, AllowedSocketFamilies: []string{"unix", "inet", "inet6"}}); err != nil {
			return exitApplyFailed
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err == nil {
			unix.Close(fd)
			return exitAllowed
		}
		return classifyErr(err)

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

func requireSupported(t *testing.T, code int) {
	t.Helper()
	if code == exitUnsupported {
		t.Skip("seccomp-BPF unsupported on this kernel/CI runner")
	}
	if code == exitApplyFailed {
		t.Skip("Apply failed (likely no NO_NEW_PRIVS permission in this CI sandbox)")
	}
}

func TestEnforce_InitModuleDenied(t *testing.T) {
	code := runHelper(t, "init_module")
	requireSupported(t, code)
	if code != exitDeniedEPERM {
		t.Errorf("init_module: exit %d, want EPERM(%d)", code, exitDeniedEPERM)
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
