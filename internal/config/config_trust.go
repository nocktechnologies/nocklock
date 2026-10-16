package config

import "os"

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

// Seams for deterministic, unprivileged tests. Production uses the real
// filesystem and the invoking user's real UID; tests swap in a fake view so
// crafted ownership and permission cases need no chmod, no chown and no root.
// configTrustUID uses the REAL uid, not the effective one and never SUDO_UID,
// matching the deliberate choice in the interposer trust walk.
var (
	configTrustLstat = os.Lstat
	configTrustUID   = func() uint32 { return uint32(os.Getuid()) }
)
