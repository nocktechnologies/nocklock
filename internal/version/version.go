// Package version provides build version information for NockLock.
package version

import "fmt"

// Version defaults to "dev" and is overridden at build time via ldflags.
// Tagged/release builds set this to the semver string (e.g. "0.2.0").
var Version = "dev"

// BuildInfo returns a human-readable version string.
// Dev builds (Version == "dev") return "NockLock (dev)".
// Tagged builds return "NockLock vX.Y.Z".
func BuildInfo() string {
	if Version == "dev" {
		return "NockLock (dev)"
	}
	return fmt.Sprintf("NockLock v%s", Version)
}
