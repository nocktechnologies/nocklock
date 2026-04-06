// Package version provides build version information for NockLock.
package version

import "fmt"

// Version defaults to "0.1.0" and can be overridden at build time via ldflags.
var Version = "0.1.0"

// BuildInfo returns a human-readable version string in the form "NockLock vX.Y.Z (dev)".
func BuildInfo() string {
	return fmt.Sprintf("NockLock v%s (dev)", Version)
}
