//go:build !linux

package landlock

import "fmt"

func DetectABI() (int, error) {
	return 0, nil
}

func Supported() bool {
	return false
}

func Apply(spec Spec) error {
	return fmt.Errorf("Landlock is only supported on Linux")
}

func Exec(argv []string, env []string) error {
	return fmt.Errorf("Landlock exec is only supported on Linux")
}

func ExistingExtraAllowPaths(paths ...AllowPath) []AllowPath {
	return nil
}
