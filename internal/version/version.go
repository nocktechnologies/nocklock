// internal/version/version.go
package version

import "fmt"

// Version is set at build time via ldflags.
var Version = "0.1.0"

// IsDevBuild is set at build time via ldflags. Defaults to true for unset builds.
var IsDevBuild = "true"

// BuildInfo returns the formatted version string.
func BuildInfo() string {
	if IsDevBuild == "false" {
		return fmt.Sprintf("NockLock v%s", Version)
	}
	return fmt.Sprintf("NockLock v%s (dev)", Version)
}
