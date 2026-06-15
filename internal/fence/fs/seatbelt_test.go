package fs

import (
	"os"
	"path/filepath"
	"testing"
)

// The macOS filesystem fence is an interim denylist (a from-scratch deny-default
// SBPL allowlist SIGABRTs every process — see the macOS fence design spec), so
// the strength of the fence IS the coverage of this default set. This test locks
// in the credential stores an autonomously-fenced agent must never be able to
// read by default.
func TestDefaultSensitivePaths_CoversCredentialStores(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("no home dir: %v", err)
	}
	got := DefaultSensitivePaths()
	set := make(map[string]bool, len(got))
	for _, p := range got {
		set[p] = true
	}
	// Pure credential stores the agent never needs to read. Includes the
	// originals plus the credential paths added alongside them; if you remove
	// one, you are widening the fence's blind spot — do it deliberately.
	mustFence := []string{
		".ssh", ".aws", ".gnupg", ".kube", ".config/gcloud",
		filepath.Join("Library", "Keychains"),
		".netrc", ".docker", ".git-credentials",
	}
	for _, rel := range mustFence {
		want := filepath.Join(home, rel)
		if !set[want] {
			t.Errorf("DefaultSensitivePaths missing credential store %q (fence blind spot)", want)
		}
	}
}

// Mixed config+credential paths are intentionally NOT in the default set:
// fencing them breaks legitimate agent workflows (package installs), so users
// opt them in via config rather than getting silent breakage by default.
func TestDefaultSensitivePaths_ExcludesMixedConfigCredPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("no home dir: %v", err)
	}
	set := make(map[string]bool)
	for _, p := range DefaultSensitivePaths() {
		set[p] = true
	}
	for _, rel := range []string{".npmrc", ".pypirc"} {
		if set[filepath.Join(home, rel)] {
			t.Errorf("%q should NOT be default-fenced (breaks installs); it belongs in user opt-in config", rel)
		}
	}
}
