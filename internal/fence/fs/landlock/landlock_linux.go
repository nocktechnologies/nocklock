//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type rulesetAttr struct {
	HandledAccessFS  uint64
	HandledAccessNet uint64
	Scoped           uint64
}

func DetectABI() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION))
	if errno != 0 {
		if errors.Is(errno, unix.ENOSYS) || errors.Is(errno, unix.EOPNOTSUPP) {
			return 0, nil
		}
		return 0, errno
	}
	return int(abi), nil
}

func Supported() bool {
	abi, err := DetectABI()
	return err == nil && abi > 0
}

// Apply restricts the calling OS thread. Callers must lock their goroutine to
// that thread before calling Apply and keep it locked through the protected
// operations or exec. Other existing threads are not restricted by this call.
func Apply(spec Spec) error {
	if spec.ABI <= 0 || spec.HandledAccessFS == 0 {
		return fmt.Errorf("invalid Landlock ruleset")
	}
	if spec.Scoped&^ScopeAbstractUnixSocket != 0 {
		return fmt.Errorf("invalid Landlock scope flags %#x", spec.Scoped)
	}
	if spec.Scoped != 0 && spec.ABI < 6 {
		return fmt.Errorf("Landlock ABI v%d does not support scoped Unix sockets", spec.ABI)
	}
	if spec.HandledAccessFS&RightResolveUnix != 0 && spec.ABI < MinUnixSocketABI {
		return fmt.Errorf("Landlock ABI v%d does not support pathname Unix-socket resolution", spec.ABI)
	}

	attr := rulesetAttr{HandledAccessFS: spec.HandledAccessFS, Scoped: spec.Scoped}
	attrSize := unsafe.Offsetof(attr.Scoped)
	if spec.Scoped != 0 {
		attrSize = unsafe.Sizeof(attr)
	}
	fd, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		attrSize,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("create ruleset: %w", errno)
	}
	rulesetFD := int(fd)
	defer unix.Close(rulesetFD)

	for _, rule := range spec.Paths {
		if rule.Path == "" || rule.Rights == 0 {
			return fmt.Errorf("invalid Landlock path rule for %q", rule.Path)
		}
		pathFD, err := unix.Open(rule.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open allow path %q: %w", rule.Path, err)
		}
		pathAttr := unix.LandlockPathBeneathAttr{
			Allowed_access: rule.Rights,
			Parent_fd:      int32(pathFD),
		}
		_, _, errno = unix.Syscall(
			unix.SYS_LANDLOCK_ADD_RULE,
			uintptr(rulesetFD),
			uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
			uintptr(unsafe.Pointer(&pathAttr)),
		)
		closeErr := unix.Close(pathFD)
		if errno != 0 {
			return fmt.Errorf("add rule for %q: %w", rule.Path, errno)
		}
		if closeErr != nil {
			return fmt.Errorf("close allow path %q: %w", rule.Path, closeErr)
		}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0)
	if errno != 0 {
		return fmt.Errorf("restrict self: %w", errno)
	}
	return nil
}

func Exec(argv []string, env []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("missing command after --")
	}
	return unix.Exec(argv[0], argv, env)
}

func ExistingExtraAllowPaths(paths ...AllowPath) []AllowPath {
	extras := make([]AllowPath, 0, len(paths))
	for _, path := range paths {
		if _, err := os.Stat(path.Path); err == nil {
			extras = append(extras, path)
		}
	}
	return extras
}
