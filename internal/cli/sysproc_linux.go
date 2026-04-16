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
