package fs

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// SBPL (Sandbox Profile Language) generation for the macOS filesystem fence.
//
// macOS has no LD_PRELOAD; the fence is enforced by the kernel Seatbelt sandbox
// via `sandbox-exec`. Two facts, both established empirically (macOS 26.5), drive
// this generator and are NOT negotiable:
//
//  1. A from-scratch `(deny default)` allowlist SIGABRTs every process — even
//     /bin/echo — because process/dyld startup needs far more allows than are
//     practical to enumerate. So the interim profile is `(allow default)` plus
//     an explicit DENY of the sensitive paths (a denylist). This is weaker than
//     the Linux allowlist and is documented as such; strict-allowlist parity is
//     deferred to the Endpoint Security implementation.
//
//  2. macOS canonicalizes access paths before matching a `(subpath ...)` rule
//     (e.g. /tmp -> /private/tmp, /var -> /private/var, and any symlinked dir).
//     A rule built from a NON-canonical path SILENTLY NEVER MATCHES — the fence
//     FAILS OPEN. Therefore every path is resolved to its real, symlink-free
//     form before it is emitted, and a path that cannot be resolved is a hard
//     error so the caller fails CLOSED rather than ship an unmatched rule.

// GenerateProfile builds the Seatbelt profile string that denies read and write
// access to every path in sensitivePaths while allowing everything else (so the
// agent and its toolchain run normally). Each path is canonicalized; an
// unresolvable path returns an error so the caller can refuse to start.
//
// The profile is deterministic: paths are canonicalized, de-duplicated, and
// sorted, so the same input always yields byte-identical output (testable).
func GenerateProfile(sensitivePaths []string) (string, error) {
	if len(sensitivePaths) == 0 {
		return "", fmt.Errorf("refusing to generate a fence profile with no sensitive paths (would be a no-op fence)")
	}

	seen := make(map[string]struct{}, len(sensitivePaths))
	canonical := make([]string, 0, len(sensitivePaths))
	for _, p := range sensitivePaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		c, err := canonicalizeForProfile(p)
		if err != nil {
			// Fail closed: never emit a rule we cannot guarantee will match.
			return "", fmt.Errorf("cannot canonicalize sensitive path %q (refusing to emit a fence that may fail open): %w", p, err)
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		canonical = append(canonical, c)
	}
	if len(canonical) == 0 {
		return "", fmt.Errorf("refusing to generate a fence profile with no resolvable sensitive paths")
	}
	sort.Strings(canonical)

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString(";; NockLock macOS filesystem fence (Seatbelt interim).\n")
	b.WriteString(";; allow-default base; deny the sensitive paths below. Paths are\n")
	b.WriteString(";; canonical realpaths — required, or the kernel match fails open.\n")
	b.WriteString("(allow default)\n")
	b.WriteString("(deny file-read* file-write*\n")
	for _, c := range canonical {
		b.WriteString("    (subpath ")
		b.WriteString(sbplString(c))
		b.WriteString(")\n")
	}
	b.WriteString(")\n")
	return b.String(), nil
}

// canonicalizeForProfile resolves path to an absolute, symlink-free form
// suitable for a Seatbelt (subpath ...) rule. It handles paths that do not yet
// exist (e.g. ~/.aws on a machine that has never used the AWS CLI) by resolving
// the symlinks of the deepest existing ancestor and re-appending the remainder,
// so /tmp/does-not-exist still canonicalizes the /tmp -> /private/tmp prefix.
func canonicalizeForProfile(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("absolutize: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	// Path (or a tail component) does not exist: resolve the longest existing
	// ancestor, then re-append the non-existent tail.
	dir := abs
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(dir)
		if err == nil {
			parts := append([]string{resolved}, reversed(tail)...)
			return filepath.Join(parts...), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached the root without resolving anything; give up.
			return "", fmt.Errorf("no resolvable ancestor for %q", path)
		}
		tail = append(tail, filepath.Base(dir))
		dir = parent
	}
}

// sbplString returns s as an SBPL double-quoted string literal with backslashes
// and double quotes escaped (SBPL string-literal escaping).
func sbplString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

func reversed(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
