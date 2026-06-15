package fs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Seatbelt (macOS) filesystem-fence helpers. These build the `sandbox-exec`
// invocation that enforces the fence; the profile itself is produced by
// GenerateProfile (see sbpl.go). Enforcement is kernel-level and inherited by
// all descendants of the sandboxed process — no code injection, unlike the
// Linux LD_PRELOAD path. This is the interim mechanism; see the design spec.

// DefaultSensitivePaths returns the credential/secret directories the macOS
// fence denies by default. This is a conservative, curated denylist (NOT the
// broad ~/.config, which would break toolchains). User config can extend it.
// Paths that do not exist on a given machine are fine — GenerateProfile
// canonicalizes their existing prefix so the rule still matches if created.
func DefaultSensitivePaths() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	rel := []string{
		".ssh",
		".aws",
		".gnupg",
		".kube",
		".config/gcloud",
		filepath.Join("Library", "Keychains"),
		// Pure credential stores an autonomously-fenced agent never needs to
		// READ — consistent with .ssh/.kube already being fenced (the agent
		// operates without the user's SSH/k8s creds, so it should not reach
		// these either). Mixed config+credential paths (~/.npmrc, ~/.pypirc)
		// are intentionally NOT defaulted — fencing them breaks legitimate
		// package installs; users opt those in via config.
		".netrc",           // plaintext curl/git/ftp credentials — classic exfil target
		".docker",          // registry auth tokens (same class as the already-fenced .kube)
		".git-credentials", // plaintext git HTTPS credentials (consistent with .ssh fenced)
	}
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, filepath.Join(home, r))
	}
	return out
}

// SandboxExecPath is the macOS Seatbelt CLI. Deprecated by Apple but present
// and functional; the fence fails closed if it is missing (see EnsureAvailable).
const SandboxExecPath = "/usr/bin/sandbox-exec"

// EnsureSandboxExecAvailable returns an error if sandbox-exec is not usable, so
// the caller can refuse to start (fail closed) rather than run the agent unfenced.
func EnsureSandboxExecAvailable() error {
	if _, err := exec.LookPath(SandboxExecPath); err != nil {
		if _, statErr := os.Stat(SandboxExecPath); statErr != nil {
			return fmt.Errorf("sandbox-exec not found at %s (filesystem fence cannot be enforced on this macOS): %w", SandboxExecPath, err)
		}
	}
	return nil
}

// WriteProfile writes profile to a 0600 temp file and returns its path. The
// caller must remove it (and should keep it for the lifetime of the fenced
// process, since sandbox-exec reads it at launch). Fails closed on any error.
func WriteProfile(profile string) (string, error) {
	f, err := os.CreateTemp("", "nocklock-fence-*.sb")
	if err != nil {
		return "", fmt.Errorf("cannot create fence profile temp file: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("cannot chmod fence profile: %w", err)
	}
	if _, err := f.WriteString(profile); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("cannot write fence profile: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("cannot close fence profile: %w", err)
	}
	return f.Name(), nil
}

// WrapArgv returns the argv that runs childArgv under the Seatbelt profile at
// profilePath: `sandbox-exec -f <profilePath> <childArgv...>`.
func WrapArgv(profilePath string, childArgv []string) ([]string, error) {
	if profilePath == "" {
		return nil, fmt.Errorf("empty profile path")
	}
	if len(childArgv) == 0 {
		return nil, fmt.Errorf("empty child argv")
	}
	return append([]string{SandboxExecPath, "-f", profilePath}, childArgv...), nil
}
