package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateProfile_EmptyErrors(t *testing.T) {
	if _, err := GenerateProfile(nil); err == nil {
		t.Fatal("expected error for empty path list (a no-op fence is a footgun), got nil")
	}
	if _, err := GenerateProfile([]string{"", "   "}); err == nil {
		t.Fatal("expected error when all paths are blank, got nil")
	}
}

func TestGenerateProfile_Structure(t *testing.T) {
	dir := t.TempDir() // a real, existing dir so canonicalization succeeds
	prof, err := GenerateProfile([]string{dir})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	for _, want := range []string{
		"(version 1)",
		"(allow default)",
		"(deny file-read* file-write*",
		"(subpath ",
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q:\n%s", want, prof)
		}
	}
	// Must NOT use (deny default) — that SIGABRTs every process (proven).
	if strings.Contains(prof, "(deny default)") {
		t.Errorf("profile must not use (deny default) — it SIGABRTs processes:\n%s", prof)
	}
}

func TestGenerateProfile_PlainHasNoHardeningRules(t *testing.T) {
	dir := t.TempDir()
	prof, err := GenerateProfile([]string{dir})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	for _, mustNotHave := range []string{"mach-priv-host-port", "iokit-open", "system-socket"} {
		if strings.Contains(prof, mustNotHave) {
			t.Errorf("non-hardened profile must NOT contain %q (opt-in only):\n%s", mustNotHave, prof)
		}
	}
}

func TestGenerateHardenedProfile_AddsDenialsWithoutDenyDefault(t *testing.T) {
	dir := t.TempDir()
	prof, err := GenerateHardenedProfile([]string{dir})
	if err != nil {
		t.Fatalf("GenerateHardenedProfile: %v", err)
	}
	// Still allow-default based (deny-default SIGABRTs every macOS process).
	if !strings.Contains(prof, "(allow default)") {
		t.Errorf("hardened profile must keep (allow default):\n%s", prof)
	}
	if strings.Contains(prof, "(deny default)") {
		t.Errorf("hardened profile must NOT flip to (deny default) — it SIGABRTs:\n%s", prof)
	}
	// The additive syscall-surface denials must be present.
	for _, want := range []string{
		"(deny mach-priv-host-port)",
		"(deny iokit-open)",
		"(deny system-socket)",
		"(deny file-write*",
		"/dev",
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("hardened profile missing %q:\n%s", want, prof)
		}
	}
	// The path denylist from the base profile must still be there.
	if !strings.Contains(prof, "(deny file-read* file-write*") {
		t.Errorf("hardened profile must still carry the path denylist:\n%s", prof)
	}
}

func TestGenerateHardenedProfile_EmptyErrors(t *testing.T) {
	if _, err := GenerateHardenedProfile(nil); err == nil {
		t.Fatal("expected error for empty path list, got nil")
	}
}

func TestGenerateProfile_DeterministicAndDeduped(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	p1, err := GenerateProfile([]string{a, b, a}) // duplicate a
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	p2, err := GenerateProfile([]string{b, a}) // different order, no dup
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	if p1 != p2 {
		t.Errorf("profile not deterministic/deduped:\n--- p1 ---\n%s\n--- p2 ---\n%s", p1, p2)
	}
	if n := strings.Count(p1, "(subpath "); n != 2 {
		t.Errorf("expected 2 deduped subpath rules, got %d", n)
	}
}

// TestCanonicalize_ResolvesSymlink is the FAIL-OPEN regression test. macOS
// matches sandbox rules against the canonical path, so a rule built from a
// symlinked path silently never matches and the fence fails open (this exact
// bug — /tmp vs /private/tmp — was observed in the design spike). Here we build
// our own symlink so the test is meaningful on any OS, and assert the emitted
// rule contains the RESOLVED target, never the symlink path.
func TestCanonicalize_ResolvesSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real-secrets")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link-secrets")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	prof, err := GenerateProfile([]string{link})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	if !strings.Contains(prof, sbplString(resolvedTarget)) {
		t.Errorf("profile must contain the RESOLVED target %q, not the symlink — else it fails open:\n%s", resolvedTarget, prof)
	}
	if strings.Contains(prof, sbplString(link)) {
		t.Errorf("profile contains the un-resolved symlink path %q — FAIL-OPEN bug:\n%s", link, prof)
	}
}

// TestCanonicalize_NonexistentPathResolvesPrefix verifies a sensitive path that
// does not exist yet (e.g. ~/.aws on a fresh machine) still canonicalizes its
// existing symlinked prefix, so the deny rule will match if the path is created.
func TestCanonicalize_NonexistentPathResolvesPrefix(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	resolvedTarget, _ := filepath.EvalSymlinks(target)

	// Reference a not-yet-existing child under the symlinked dir.
	got, err := canonicalizeForProfile(filepath.Join(link, "nope", "creds"))
	if err != nil {
		t.Fatalf("canonicalizeForProfile: %v", err)
	}
	want := filepath.Join(resolvedTarget, "nope", "creds")
	if got != want {
		t.Errorf("non-existent path prefix not resolved: got %q want %q", got, want)
	}
}

func TestSbplString_Escaping(t *testing.T) {
	cases := map[string]string{
		`/a/b`:    `"/a/b"`,
		`/a b/c`:  `"/a b/c"`,
		`/a"q`:    `"/a\"q"`,
		`/a\back`: `"/a\\back"`,
	}
	for in, want := range cases {
		if got := sbplString(in); got != want {
			t.Errorf("sbplString(%q) = %q, want %q", in, got, want)
		}
	}
}
