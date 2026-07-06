//go:build unix

package logging

import "syscall"

// oNoFollow makes os.OpenFile fail with ELOOP if the final path component is a
// symlink, closing the TOCTOU window between the pre-open lstat check and the
// open itself. Available on all unix targets NockLock supports (Linux, macOS).
const oNoFollow = syscall.O_NOFOLLOW
