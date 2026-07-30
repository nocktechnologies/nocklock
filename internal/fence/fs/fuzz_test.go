package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// FuzzFsFencePathDecision fuzzes the filesystem-fence path-normalization surface
// that every emitted rule depends on: resolvePath (Linux LD_PRELOAD serialized
// rules), canonicalizeForProfile / GenerateProfile (macOS Seatbelt SBPL), and
// ProcessConfig (the resolver both feed from). An adversarial input path is run
// through each, and the results are held to the fence's fail-closed contract,
// made DIFFERENTIAL against filepath.EvalSymlinks as ground truth.
//
// Invariants asserted (the ones that hold in THIS codebase):
//
//  1. No panic on any input path (a panic here fails the fuzz automatically).
//  2. FAIL-OPEN guard, generalised from sbpl_test.go:112-139 and the config_test
//     TOCTOU case: a resolved path that itself resolves further via EvalSymlinks
//     is an UNRESOLVED SYMLINK left in a rule — on macOS the (subpath ...) match
//     is against the canonical path, so such a rule silently never matches and
//     the fence fails open. Every successful resolver output must satisfy
//     EvalSymlinks(out) == out (when it resolves at all). Not-yet-existing paths
//     are exempt by contract (sbpl.go:128-132, the ~/.aws case).
//  3. resolvePath output is always absolute.
//  4. Symlink differential: a real symlink pointing OUTSIDE a granted root, fed
//     through the resolver + profile generator, must yield a rule carrying the
//     RESOLVED target and NEVER the raw symlink path — else the outside target is
//     silently granted (fail open). Ground truth is filepath.EvalSymlinks.
//
// Note: "a path that resolves outside a granted root must not be GRANTED" is not
// decided in package fs (ProcessConfig only resolves; it does no containment
// check). That decision lives in the landlock subpackage and is fuzzed by
// FuzzRulesFromConfigContainment in internal/fence/fs/landlock.
func FuzzFsFencePathDecision(f *testing.F) {
	seeds := []string{
		"",                     // empty
		"   ",                  // whitespace only
		".",                    // dot
		"..",                   // parent
		"/etc/passwd",          // absolute plain
		"etc/passwd",           // relative plain
		"../../etc/passwd",     // traversal
		"/tmp/",                // trailing slash
		"/tmp//doubled//slash", // doubled separators
		"/a/./b/../c",          // . and .. mid-path
		"/etc/\x00passwd",      // embedded NUL
		"secrets\x1fsplit",     // field-separator byte (\x1f)
		"~",                    // tilde home
		"~/.ssh",               // tilde-prefixed
		"~/.aws/credentials",   // not-yet-existing under home
		"/tmp/․․/x",            // unicode look-alike dots (U+2024 ONE DOT LEADER)
		"/private/tmp",         // macOS canonical form
		"café/naïve",           // non-ASCII
		"link-secrets",         // a plausible symlink leaf name
		strings.Repeat("a/", 64) + "deep",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pathInput string) {
		// Hermetic HOME so tilde seeds don't walk the host and make any discovered
		// crasher machine-dependent.
		t.Setenv("HOME", t.TempDir())

		// --- Layer 1: raw resolvers on the adversarial path. ---
		if out, err := canonicalizeForProfile(pathInput); err == nil {
			assertSymlinkFree(t, "canonicalizeForProfile", pathInput, out)
		}
		if out, err := resolvePath(pathInput); err == nil {
			if !filepath.IsAbs(out) {
				t.Errorf("resolvePath(%q) = %q, which is not absolute", pathInput, out)
			}
			assertSymlinkFree(t, "resolvePath", pathInput, out)
		}

		// --- Layer 2: ProcessConfig with the adversarial path as allow AND deny
		// under a real root. Every resolved path must be symlink-free. ---
		root := t.TempDir()
		if fc, err := ProcessConfig(config.FilesystemConfig{
			Root:  root,
			Mode:  "read-write",
			Allow: []string{pathInput},
			Deny:  []string{pathInput},
		}); err == nil && fc != nil {
			for _, p := range fc.AllowPaths {
				assertSymlinkFree(t, "ProcessConfig.Allow", pathInput, p)
			}
			for _, p := range fc.DenyPaths {
				assertSymlinkFree(t, "ProcessConfig.Deny", pathInput, p)
			}
		}

		// --- Layer 3: symlink differential (the fail-open regression, generalised).
		// Use the adversarial input as the LEAF name of a symlink that points
		// outside a granted root, then assert the resolver + profile generator
		// carry the RESOLVED target and never the raw symlink. ---
		leaf := sanitizeLeaf(pathInput)
		if leaf == "" {
			return
		}
		base := t.TempDir()
		outside := t.TempDir() // the target OUTSIDE base — a symlink escape target
		link := filepath.Join(base, leaf)
		if err := os.Symlink(outside, link); err != nil {
			return // OS rejected the leaf as a link name; nothing to assert
		}
		resolvedOutside, err := filepath.EvalSymlinks(outside)
		if err != nil {
			return
		}

		// Ground-truth differential: the resolver must agree with EvalSymlinks.
		if got, err := canonicalizeForProfile(link); err == nil && got != resolvedOutside {
			t.Errorf("canonicalizeForProfile(%q) = %q, EvalSymlinks ground truth = %q "+
				"(unresolved symlink in rule => fail open)", link, got, resolvedOutside)
		}
		if got, err := resolvePath(link); err == nil && got != resolvedOutside {
			t.Errorf("resolvePath(%q) = %q, EvalSymlinks ground truth = %q", link, got, resolvedOutside)
		}

		// Emitted SBPL profile must deny the RESOLVED target, never the symlink.
		if prof, err := GenerateProfile([]string{link}); err == nil {
			if !strings.Contains(prof, sbplString(resolvedOutside)) {
				t.Errorf("profile for symlink %q missing RESOLVED target %q — fence FAILS OPEN:\n%s",
					link, resolvedOutside, prof)
			}
			if resolvedOutside != link && strings.Contains(prof, sbplString(link)) {
				t.Errorf("profile contains the UNRESOLVED symlink path %q — fence FAILS OPEN:\n%s", link, prof)
			}
		}
	})
}

// assertSymlinkFree fails if out still resolves through a symlink to a different
// path — i.e. an unresolved symlink was left in a fence rule (fail open). Paths
// that do not exist on disk are exempt: canonicalizeForProfile deliberately
// emits rules for not-yet-existing paths (sbpl.go:128-132), so EvalSymlinks
// returning an error is not a violation.
func assertSymlinkFree(t *testing.T, fn, input, out string) {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(out)
	if err != nil {
		return // path (or a tail component) does not exist — exempt by contract
	}
	if resolved != out {
		t.Errorf("%s(%q) = %q still resolves via symlink to %q: an unresolved "+
			"symlink in a fence rule fails open", fn, input, out, resolved)
	}
}

// sanitizeLeaf reduces an arbitrary fuzz string to a single legal path component
// usable as a symlink leaf, or "" if it cannot be one. Rejects empty, ".", "..",
// and anything containing a path separator or NUL; caps the length so the OS does
// not reject it purely on ENAMETOOLONG.
func sanitizeLeaf(s string) string {
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
