package config

import (
	"fmt"
	"os"
)

// AllowUntrustedConfigEnv is the operator escape hatch for a config file that
// lives in a layout the trust walk would otherwise refuse -- a shared build
// directory owned by a trusted service account, for instance. Set it to a truthy
// value ("1", "true", "yes", "on") to skip the ownership and permission walk. It
// is read from the operator environment, never from the config file, so a fenced
// child cannot turn it on for the next run.
//
// The constant lives here, untagged, because every platform's build (and
// callers such as the CLI test harness) references it, while the walk it gates
// is a POSIX-ownership concept and lives in the unix-tagged file.
const AllowUntrustedConfigEnv = "NOCKLOCK_ALLOW_UNTRUSTED_CONFIG"

// configTrustLstat is a seam for deterministic, unprivileged tests. Production
// uses the real filesystem; tests swap in a fake view so crafted ownership and
// permission cases need no chmod, no chown and no root.
var configTrustLstat = os.Lstat

// readConfigFile reads path with no trust walk, wrapping a failure in the
// loader's error message.
func readConfigFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, configReadError(path, err)
	}
	return data, nil
}

// configReadError wraps an I/O failure reading the config at path, keeping the
// cause matchable with errors.Is.
func configReadError(path string, err error) error {
	return fmt.Errorf("failed to read config at %s: %w", path, err)
}
