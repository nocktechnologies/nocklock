//go:build !linux

package syscallfence

// On non-Linux platforms there is no seccomp-BPF. The syscall fence is a no-op
// and reports unsupported so callers fail-closed or skip according to Mode. The
// macOS syscall-surface hardening is handled separately, in the Seatbelt/SBPL
// profile (internal/fence/fs/sbpl.go), not here.

// Supported reports whether the syscall fence can be enforced on this platform.
func Supported() bool { return false }

// Apply is a no-op on non-Linux platforms.
func Apply(_ Policy) error { return nil }
