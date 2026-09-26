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
		".ssh", ".aws", ".config", ".gnupg", ".kube",
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

func TestWrapArgv_UsesEndOfOptionsMarker(t *testing.T) {
	argv, err := WrapArgv("/tmp/nocklock.sb", []string{"/bin/echo", "ok"})
	if err != nil {
		t.Fatalf("WrapArgv: %v", err)
	}
	want := []string{SandboxExecPath, "-f", "/tmp/nocklock.sb", "--", "/bin/echo", "ok"}
	if len(argv) != len(want) {
		t.Fatalf("WrapArgv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("WrapArgv[%d] = %q, want %q", i, argv[i], want[i])
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
