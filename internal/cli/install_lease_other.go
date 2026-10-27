//go:build !linux

package cli

import "os"

func acquireInstallLease() (*os.File, error) { return nil, nil }
