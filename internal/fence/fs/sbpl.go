package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	profile, _, err := GenerateProfileAndCount(sensitivePaths, false)
	return profile, err
}

// GenerateHardenedProfile is the opt-in ([filesystem] hardened = true) variant.
// It produces the same allow-default path denylist as GenerateProfile and ADDS a
// curated set of non-filesystem syscall-surface denials that approximate, on
// macOS, what the Linux seccomp fence does:
//
//	(deny mach-priv-host-port)  — block privileged host-port lookups (a step
//	                              toward task_for_pid / cross-process control)
//	(deny iokit-open)           — block opening IOKit device user-clients (raw
//	                              hardware / driver attack surface, ~ Linux ioperm)
//	(deny system-socket)        — block PF_SYSTEM / kernel-control sockets (raw
//	                              kernel I/O, ~ Linux AF_PACKET/AF_NETLINK denial)
//
// plus a tightened /dev (read-only, denying the raw/BSD device nodes a fenced
// agent never needs). Crucially it does NOT flip the base to (deny default):
// that SIGABRTs every process on macOS (documented above), so hardening stays
// additive on top of (allow default). No-op on non-macOS callers (they never set
// hardened=true).
func GenerateHardenedProfile(sensitivePaths []string) (string, error) {
	profile, _, err := GenerateProfileAndCount(sensitivePaths, true)
	return profile, err
}

// GenerateProfileAndCount builds a baseline or hardened Seatbelt profile and
// returns the number of distinct canonical sensitive paths it fences. The count
// lets callers audit the exact applied policy without over-reporting duplicate
// configuration entries.
func GenerateProfileAndCount(sensitivePaths []string, hardened bool) (string, int, error) {
	return generateProfile(sensitivePaths, hardened, nil)
}

// GenerateWriteConfinementProfile builds the macOS Seatbelt profile used when
// filesystem.root is configured. It denies every file write first, then grants
// writes only to the canonical root (unless mode is read-only), the NockLock
// state directory, and the per-user runtime paths needed to launch common
// tools. Sensitive paths remain denied for both reads and writes after those
// grants, so a sensitive path under root never becomes accessible.
func GenerateWriteConfinementProfile(sensitivePaths []string, root, mode, stateDir string, hardened bool) (string, int, error) {
	if strings.TrimSpace(root) == "" {
		return "", 0, fmt.Errorf("refusing to generate write-confinement profile with an empty root")
	}
	if strings.TrimSpace(stateDir) == "" {
		return "", 0, fmt.Errorf("refusing to generate write-confinement profile with an empty state directory")
	}
	if mode != "read-write" && mode != "read-only" {
		return "", 0, fmt.Errorf("invalid filesystem mode %q: must be \"read-write\" or \"read-only\"", mode)
	}

	writePaths, err := writeConfinementPaths(root, mode, stateDir)
	if err != nil {
		return "", 0, err
	}
	return generateProfile(sensitivePaths, hardened, writePaths)
}

func generateProfile(sensitivePaths []string, hardened bool, writePaths []string) (string, int, error) {
	canonical, err := canonicalProfilePaths(sensitivePaths, "sensitive")
	if err != nil {
		return "", 0, err
	}
	if len(canonical) == 0 {
		return "", 0, fmt.Errorf("refusing to generate a fence profile with no resolvable sensitive paths")
	}

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString(";; NockLock macOS filesystem fence (Seatbelt interim).\n")
	b.WriteString(";; allow-default base; paths are canonical realpaths — required,\n")
	b.WriteString(";; or the kernel match fails open.\n")
	b.WriteString("(allow default)\n")
	if len(writePaths) > 0 {
		b.WriteString(";; Root write confinement: deny all writes, then grant only\n")
		b.WriteString(";; the canonical root/runtime paths below.\n")
		b.WriteString("(deny file-write*)\n")
		b.WriteString("(allow file-write*\n")
		for _, p := range writePaths {
			b.WriteString("    (subpath ")
			b.WriteString(sbplString(p))
			b.WriteString(")\n")
		}
		b.WriteString("    (literal \"/dev/null\")\n")
		b.WriteString("    (literal \"/dev/tty\")\n")
		b.WriteString("    (regex #\"^/dev/tty.*$\")\n")
		b.WriteString("    (literal \"/dev/fd\")\n")
		b.WriteString("    (regex #\"^/dev/fd/\"))\n")
	}
	b.WriteString(";; Sensitive paths remain denied for reads and writes, including\n")
	b.WriteString(";; when they are nested below a write-allowed root.\n")
	b.WriteString("(deny file-read* file-write*\n")
	for _, c := range canonical {
		b.WriteString("    (subpath ")
		b.WriteString(sbplString(c))
		b.WriteString(")\n")
	}
	b.WriteString(")\n")

	if hardened {
		b.WriteString(";; hardened = true: additive syscall-surface denials. This is\n")
		b.WriteString(";; NOT a deny-default flip, which SIGABRTs every macOS process.\n")
		b.WriteString("(deny mach-priv-host-port)\n")
		b.WriteString("(deny iokit-open)\n")
		b.WriteString("(deny system-socket)\n")
		b.WriteString(";; tighten /dev: deny write to the raw/BSD device nodes a fenced\n")
		b.WriteString(";; agent never needs, while leaving the common pseudo-devices.\n")
		b.WriteString("(deny file-write*\n")
		b.WriteString("    (subpath \"/dev\"))\n")
		b.WriteString("(allow file-write-data\n")
		b.WriteString("    (literal \"/dev/null\")\n")
		b.WriteString("    (literal \"/dev/zero\")\n")
		b.WriteString("    (literal \"/dev/random\")\n")
		b.WriteString("    (literal \"/dev/urandom\")\n")
		b.WriteString("    (literal \"/dev/tty\")\n")
		b.WriteString("    (regex #\"^/dev/tty[a-z0-9]+$\")\n")
		b.WriteString("    (regex #\"^/dev/pty[a-z0-9]+$\")\n")
		b.WriteString("    (regex #\"^/dev/ptmx$\")\n")
		b.WriteString("    (regex #\"^/dev/fd/\"))\n")
	}

	return b.String(), len(canonical), nil
}

// writeConfinementPaths returns the directories that are allowed to receive
// writes under the macOS root-confinement profile. The Go standard library is
// the source of the invoking user's temporary and cache locations. On macOS,
// reject an arbitrary TMPDIR outside the system's per-user temp locations so a
// caller cannot silently widen the boundary through its environment.
func writeConfinementPaths(root, mode, stateDir string) ([]string, error) {
	tempDir, err := canonicalizeForProfile(os.TempDir())
	if err != nil {
		return nil, fmt.Errorf("cannot canonicalize user temporary directory: %w", err)
	}
	if runtime.GOOS == "darwin" && tempDir != "/private/tmp" && !strings.HasPrefix(tempDir, "/private/var/folders/") {
		return nil, fmt.Errorf("refusing to allow temporary directory outside /private/tmp or /private/var/folders: %s", tempDir)
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine user cache directory: %w", err)
	}
	if strings.TrimSpace(cacheDir) == "" {
		return nil, fmt.Errorf("cannot determine user cache directory: empty result")
	}

	paths := []string{
		"/private/tmp",
		tempDir,
		cacheDir,
		stateDir,
	}
	// macOS gives each invoking user a paired T (temp) and C (cache) directory
	// under /private/var/folders. os.TempDir identifies the T directory; add its
	// sibling C directory without granting any other user's folder.
	if strings.HasPrefix(tempDir, "/private/var/folders/") {
		paths = append(paths, filepath.Join(filepath.Dir(tempDir), "C"))
	}
	if mode == "read-write" {
		paths = append(paths, root)
	}

	canonical, err := canonicalProfilePaths(paths, "write-allowed")
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func canonicalProfilePaths(paths []string, purpose string) ([]string, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("refusing to generate a fence profile with no %s paths", purpose)
	}

	seen := make(map[string]struct{}, len(paths))
	canonical := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		c, err := canonicalizeForProfile(p)
		if err != nil {
			// Fail closed: never emit a rule we cannot guarantee will match.
			return nil, fmt.Errorf("cannot canonicalize %s path %q (refusing to emit a fence that may fail open): %w", purpose, p, err)
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		canonical = append(canonical, c)
	}
	sort.Strings(canonical)
	return canonical, nil
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
