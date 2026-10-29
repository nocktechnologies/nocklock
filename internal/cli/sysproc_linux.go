//go:build linux

package cli

import "syscall"

// childSysProcAttr returns process attributes for the wrapped child on Linux.
// Setpgid puts the child in its own process group so all descendants can be
// killed as a unit. Pdeathsig delivers SIGKILL to the child if the nocklock
// wrapper process exits unexpectedly, preventing a fenceless grandparent scenario.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}

// probeSysProcAttr returns process attributes for doctor's bounded probes on
// Linux. The probe gets its own process group so a timeout can kill all of it;
// that group is not the terminal's foreground group, so Ctrl-C does not reach
// it, and Pdeathsig kills the probe if doctor dies first.
func probeSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}
