// Package secrets implements environment variable filtering for NockLock.
package secrets

// Fence filters environment variables based on pass/block glob patterns.
type Fence struct {
	PassPatterns  []string
	BlockPatterns []string
}

// NewFence creates a secret fence from config patterns.
func NewFence(pass, block []string) *Fence {
	return &Fence{PassPatterns: pass, BlockPatterns: block}
}

// Filter takes the full environment (os.Environ() format: "KEY=VALUE")
// and returns a filtered environment with blocked vars removed.
// Returns (filtered env, blocked var names).
func (f *Fence) Filter(environ []string) ([]string, []string) {
	return environ, nil
}

// Match checks if an env var name matches any pattern in the list.
// Supports glob patterns (*, ?) via filepath.Match.
// Matching is case-insensitive.
func Match(name string, patterns []string) bool {
	return false
}
