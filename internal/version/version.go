// internal/version/version.go
package version

import "fmt"

// Version is set at build time via ldflags.
var Version = "0.1.0"

// BuildInfo returns the formatted version string.
func BuildInfo() string {
	return fmt.Sprintf("NockLock v%s (dev)", Version)
}
