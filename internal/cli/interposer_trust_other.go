//go:build !linux && !darwin

package cli

import "errors"

func trustedInterposerPath(string) (string, error) {
	return "", errors.New("filesystem interposer ownership checks require Linux or macOS; refusing to load a library")
}

func trustedInterposerDirectory(string) (string, error) {
	return "", errors.New("filesystem interposer ownership checks require Linux or macOS; refusing executable scratch")
}
