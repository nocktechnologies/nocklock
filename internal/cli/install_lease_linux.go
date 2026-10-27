package cli

import (
	"os"

	"github.com/nocktechnologies/nocklock/internal/installstate"
)

func acquireInstallLease() (*os.File, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return installstate.AcquireInvocation(exe, installstate.Base, installstate.Link)
}
