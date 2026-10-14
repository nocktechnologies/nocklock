//go:build linux || darwin

package logging

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

const identityNonBlock = syscall.O_NONBLOCK
const identityLockSupported = true

func lockIdentityFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

func validateIdentityFileOwner(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return fmt.Errorf("trusted chain identity file must be owned by the current user and have exactly one hard link")
	}
	return nil
}
