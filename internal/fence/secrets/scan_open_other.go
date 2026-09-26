//go:build !linux && !darwin

package secrets

import (
	"fmt"
	"os"
)

func openScanFile(root *os.Root, path string) (*os.File, error) {
	return nil, fmt.Errorf("file scanning requires Linux or macOS")
}

func openScanChild(parent *os.File, name string) (*os.File, error) {
	return nil, fmt.Errorf("file scanning requires Linux or macOS")
}
