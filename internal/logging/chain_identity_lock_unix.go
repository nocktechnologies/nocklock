//go:build linux || darwin

package logging

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"
)

const identityNonBlock = syscall.O_NONBLOCK
const identityLockSupported = true

func lockIdentityFile(f *os.File) error {
	return lockIdentityFileContext(context.Background(), f)
}

func lockIdentityFileContext(ctx context.Context, f *os.File) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
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
