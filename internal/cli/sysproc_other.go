//go:build !linux

package cli

import "syscall"

// childSysProcAttr returns process attributes for the wrapped child on non-Linux
// platforms. Pdeathsig is Linux-only; only process group isolation is applied.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}

// probeSysProcAttr returns process attributes for doctor's bounded probes on
// non-Linux platforms: their own process group, so a timeout can kill all of
// it. Pdeathsig is Linux-only.
func probeSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}
