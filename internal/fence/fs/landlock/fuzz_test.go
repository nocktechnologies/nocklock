package landlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
)

// FuzzRulesFromConfigContainment fuzzes the Landlock ruleset builder — the layer
// that actually decides GRANT vs DENY — with an adversarial root-child name that
// may be a symlink escaping the configured root. It closes the invariant that
// FuzzFsFencePathDecision cannot reach from package fs: a path that resolves
// outside a granted root must never be granted, and a deny that overlaps a
// granted tree must never be silently dropped. These are the N8537 (root symlink
// escape) and N8441 (deny/allow overlap) regressions, generalised.
//
// Invariants asserted (fail-closed, as they hold in rules.go):
//
//  1. No panic on any root-child name.
//  2. Containment: if RulesFromConfig succeeds, EVERY emitted PathRule.Path lies
//     inside the resolved root. A root child whose canonical target escapes the
//     root must be REJECTED (error), never emitted as a grant (rules.go:224-227).
//  3. Deny enforceability: if RulesFromConfig succeeds, NO configured deny path
//     overlaps any granted tree. An overlapping deny must be rejected, because
//     Landlock is allow-only and cannot carve a hole (rules.go:166-181).
func FuzzRulesFromConfigContainment(f *testing.F) {
	seeds := []struct {
		leaf   string
		escape bool
	}{
		{"child", false},
		{"link", true},
		{"..", true},
		{".", false},
		{"", false},
		{"deep name", true},
		{".hidden", true},
		{"a\x00b", true},
		{"café", true},
		{strings.Repeat("x", 64), true},
	}
	for _, s := range seeds {
		f.Add(s.leaf, s.escape)
	}

	f.Fuzz(func(t *testing.T, leaf string, escape bool) {
		leaf = sanitizeLeafName(leaf)
		if leaf == "" {
			return
		}

		const abi = 3 // a valid ABI with a non-empty rights mask

		root := t.TempDir()
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return
		}
		child := filepath.Join(root, leaf)
		if escape {
			outside := t.TempDir() // a target OUTSIDE the root
			if err := os.Symlink(outside, child); err != nil {
				return
			}
		} else {
			if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
				return
			}
		}

		// --- Run A: containment. No deny paths, so a successful build must have
		// every emitted rule inside the resolved root; an escaping symlink child
		// must have been rejected rather than granted. ---
		if spec, err := RulesFromConfig(&fsfence.FenceConfig{
			Root: root,
			Mode: "read-write",
		}, nil, abi); err == nil {
			for _, rule := range spec.Paths {
				if !pathInsideRoot(resolvedRoot, rule.Path) {
					t.Errorf("RulesFromConfig emitted a grant OUTSIDE the root: rule %q not inside %q "+
						"(leaf=%q escape=%t) — fence FAILS OPEN", rule.Path, resolvedRoot, leaf, escape)
				}
			}
		}

		// --- Run B: deny enforceability. Configure a deny at the same child path.
		// If the build succeeds, that deny must not overlap any granted tree —
		// Landlock is allow-only and cannot honor an overlapping deny. ---
		denyPath := filepath.Join(resolvedRoot, leaf)
		if spec, err := RulesFromConfig(&fsfence.FenceConfig{
			Root:      root,
			Mode:      "read-write",
			DenyPaths: []string{denyPath},
		}, nil, abi); err == nil {
			for _, rule := range spec.Paths {
				if pathsOverlap(filepath.Clean(denyPath), rule.Path) {
					t.Errorf("RulesFromConfig kept deny %q overlapping granted tree %q "+
						"(leaf=%q escape=%t) — deny silently dropped, fence FAILS OPEN",
						denyPath, rule.Path, leaf, escape)
				}
			}
		}
	})
}

// sanitizeLeafName reduces an arbitrary fuzz string to a single legal path
// component usable as a directory entry, or "" if it cannot be one.
func sanitizeLeafName(s string) string {
	if s == "" || s == "." || s == ".." {
		return ""
	}
	if strings.ContainsAny(s, "/\x00") {
		return ""
	}
	if len(s) > 200 {
		return ""
	}
	return s
}
