//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// probeCloneNewUserRaw performs the operation the syscall probe attempts: a
// fork/exec of a trivial program with CLONE_NEWUSER. Go passes
// SIGCHLD|CLONE_NEWUSER as the clone(2) flags, which the syscall fence denies
// with EPERM through its namespace mask (cloneNamespaceMask).
// The child execs /bin/true and exits, so the probe never runs the nocklock CLI
// in the child. unshare(CLONE_NEWUSER) is deliberately not used in-process: the
// kernel returns EINVAL in any multithreaded process, and a Go process always is.
var probeCloneNewUserRaw = func() error {
	path, err := trivialProgram()
	if err != nil {
		return err
	}
	pid, err := syscall.ForkExec(path, []string{path}, &syscall.ProcAttr{
		Sys: &syscall.SysProcAttr{Cloneflags: uintptr(unix.CLONE_NEWUSER)},
	})
	if err != nil {
		return err
	}
	return waitCloneChild(pid)
}

// waitCloneChild reaps the clone child and reports a non-clean exit as an error.
func waitCloneChild(pid int) error {
	var ws unix.WaitStatus
	for {
		_, err := unix.Wait4(pid, &ws, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("waiting for clone child: %w", err)
		}
		break
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("clone child did not exit cleanly (wait status %#x)", uint32(ws))
	}
	return nil
}

// probeSyscall attempts clone(CLONE_NEWUSER) and classifies the outcome. Only
// EPERM is a denial. Success means the operation ran unfenced. Any other errno
// (EINVAL included) is inconclusive: the probe is not attempted and never
// counts as proof of a fence.
func probeSyscall() probeResult {
	err := probeCloneNewUserRaw()
	if err == nil {
		return probeResult{Fence: "syscall", Attempted: true, Blocked: false, Detail: "clone(CLONE_NEWUSER) succeeded"}
	}
	if errors.Is(err, unix.EPERM) {
		return probeResult{Fence: "syscall", Attempted: true, Blocked: true, Detail: "clone(CLONE_NEWUSER) denied with EPERM"}
	}
	if errors.Is(err, unix.EINVAL) {
		return probeResult{Fence: "syscall", Attempted: false, Blocked: false, Detail: "clone(CLONE_NEWUSER) inconclusive: EINVAL, not a denial"}
	}
	return probeResult{Fence: "syscall", Attempted: false, Blocked: false, Detail: fmt.Sprintf("clone(CLONE_NEWUSER) inconclusive: %v", err)}
}

// trivialProgram returns the first fixed system path to a true(1) binary. A
// fixed path avoids resolving the probe's exec target through PATH.
func trivialProgram() (string, error) {
	for _, candidate := range []string{"/bin/true", "/usr/bin/true"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", errors.New("no /bin/true or /usr/bin/true to exec for the clone probe")
}
