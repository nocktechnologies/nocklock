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
