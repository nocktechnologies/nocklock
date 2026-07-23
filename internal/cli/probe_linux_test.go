//go:build linux

package cli

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestProbeSyscallRequestsUserNamespace(t *testing.T) {
	orig := probeSyscallRaw
	defer func() { probeSyscallRaw = orig }()

	var gotTrap, gotArg1 uintptr
	probeSyscallRaw = func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, unix.Errno) {
		gotTrap = trap
		gotArg1 = a1
		return 0, 0, unix.EPERM
	}

	result := probeSyscall()
	if !result.Attempted || !result.Blocked {
		t.Fatalf("probeSyscall() = %+v, want attempted blocked", result)
	}
	if gotTrap != unix.SYS_UNSHARE {
		t.Fatalf("syscall trap = %d, want SYS_UNSHARE %d", gotTrap, unix.SYS_UNSHARE)
	}
	if gotArg1 != uintptr(unix.CLONE_NEWUSER) {
		t.Fatalf("unshare arg = %#x, want CLONE_NEWUSER %#x", gotArg1, uintptr(unix.CLONE_NEWUSER))
	}
}
