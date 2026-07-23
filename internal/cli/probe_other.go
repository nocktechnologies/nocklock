//go:build !linux

package cli

func probeSyscall() probeResult {
	return probeResult{Fence: "syscall", Attempted: false, Blocked: false, Detail: "syscall probe is only implemented on Linux"}
}
