//go:build linux

package cli

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

var probeSyscallRaw = unix.Syscall

func probeSyscall() probeResult {
	_, _, errno := probeSyscallRaw(unix.SYS_UNSHARE, uintptr(unix.CLONE_NEWUSER), 0, 0)
	if errno == 0 {
		return probeResult{Fence: "syscall", Attempted: true, Blocked: false, Detail: "unshare(CLONE_NEWUSER) succeeded"}
	}
	if errors.Is(errno, unix.EPERM) {
		return probeResult{Fence: "syscall", Attempted: true, Blocked: true, Detail: "unshare(CLONE_NEWUSER) denied with EPERM"}
	}
	return probeResult{Fence: "syscall", Attempted: false, Blocked: false, Detail: fmt.Sprintf("unshare(CLONE_NEWUSER) unavailable: %v", errno)}
}
