//go:build !linux && !darwin

package logging

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

const identityNonBlock = 0
const identityLockSupported = false

func lockIdentityFile(f *os.File) error { return lockIdentityFileContext(context.Background(), f) }

func lockIdentityFileContext(context.Context, *os.File) error {
	return errors.New("trusted chain identity locking requires Linux or macOS")
}

func validateIdentityFileOwner(fs.FileInfo) error {
	return errors.New("trusted chain identity ownership checks require Linux or macOS")
}
