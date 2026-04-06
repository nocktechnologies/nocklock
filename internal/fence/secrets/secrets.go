// Package secrets implements environment variable filtering for NockLock.
package secrets

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Fence filters environment variables based on pass/block glob patterns.
type Fence struct {
	PassPatterns  []string
	BlockPatterns []string
}

// NewFence creates a secret fence from config patterns.
// Returns an error if any pattern is an invalid glob (fail closed).
func NewFence(pass, block []string) (*Fence, error) {
	for _, p := range pass {
		if _, err := filepath.Match(p, ""); err != nil {
			return nil, fmt.Errorf("invalid pass pattern %q: %w", p, err)
		}
	}
	for _, p := range block {
		if _, err := filepath.Match(p, ""); err != nil {
			return nil, fmt.Errorf("invalid block pattern %q: %w", p, err)
		}
	}
	return &Fence{PassPatterns: pass, BlockPatterns: block}, nil
}

// Filter takes the full environment (os.Environ() format: "KEY=VALUE")
// and returns a filtered environment with blocked vars removed.
// Returns (filtered env, blocked var names).
func (f *Fence) Filter(environ []string) ([]string, []string) {
	var filtered []string
	var blocked []string

	for _, entry := range environ {
		name, _, hasEquals := strings.Cut(entry, "=")

		// Entries with no = sign or empty name: pass through unchanged.
		if !hasEquals || name == "" {
			filtered = append(filtered, entry)
			continue
		}

		// Rule 1: If var matches any block pattern → BLOCKED.
		if Match(name, f.BlockPatterns) {
			blocked = append(blocked, name)
			continue
		}

		// Rule 2: If pass list is empty → all non-blocked vars pass.
		// Rule 3: If pass list is non-empty → var must match a pass pattern.
		if len(f.PassPatterns) == 0 || Match(name, f.PassPatterns) {
			filtered = append(filtered, entry)
		} else {
			blocked = append(blocked, name)
		}
	}

	return filtered, blocked
}

// Match checks if an env var name matches any pattern in the list.
// Supports glob patterns (*, ?) via filepath.Match.
// Matching is case-insensitive.
func Match(name string, patterns []string) bool {
	lowerName := strings.ToLower(name)
	for _, p := range patterns {
		matched, err := filepath.Match(strings.ToLower(p), lowerName)
		if err != nil {
			// Invalid pattern — skip it rather than crashing.
			continue
		}
		if matched {
			return true
		}
	}
	return false
}
