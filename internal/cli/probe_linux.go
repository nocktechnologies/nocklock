//go:build linux

package cli

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func probeSyscall() probeResult {
	_, _, errno := unix.Syscall(unix.SYS_UNSHARE, 0, 0, 0)
	if errno == 0 {
		return probeResult{Fence: "syscall", Attempted: true, Blocked: false, Detail: "unshare(0) succeeded"}
	}
	if errors.Is(errno, unix.EPERM) {
		return probeResult{Fence: "syscall", Attempted: true, Blocked: true, Detail: "unshare(0) denied with EPERM"}
	}
	return probeResult{Fence: "syscall", Attempted: false, Blocked: false, Detail: fmt.Sprintf("unshare(0) unavailable: %v", errno)}
}
