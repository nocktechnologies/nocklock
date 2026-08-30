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

// TestGenerateProfile_TableEmitsRulePerPath is the table-driven proof that a
// config of N sensitive paths yields exactly N canonical (subpath "…") deny
// rules — one per path, each carrying the RESOLVED path (acceptance: "given a
// config with N sensitive paths, the generated profile contains a correct
// (deny … (subpath "<canonical>")) for each").
func TestGenerateProfile_TableEmitsRulePerPath(t *testing.T) {
	const n = 4
	inputs := make([]string, 0, n)
	wantCanonical := make([]string, 0, n)
	for i := 0; i < n; i++ {
		d := t.TempDir() // each is a distinct real dir, so nothing dedups away
		resolved, err := filepath.EvalSymlinks(d)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, d)
		wantCanonical = append(wantCanonical, resolved)
	}

	prof, err := GenerateProfile(inputs)
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	for _, c := range wantCanonical {
		want := "(subpath " + sbplString(c) + ")"
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing per-path rule %s:\n%s", want, prof)
		}
	}
	if got := strings.Count(prof, "(subpath "); got != n {
		t.Errorf("expected exactly %d (subpath …) rules, got %d:\n%s", n, got, prof)
	}
}

// TestGenerateProfile_PreambleOrdering asserts the spec's validated preamble
// ORDER (acceptance: profile "ALWAYS begins with the (version 1)(allow default)
// preamble"). The spec's working shape puts these on separate lines with
// comments between (see the design spec), so this checks order — (version 1)
// first, (allow default) before the first (deny …) — not byte-contiguity, and
// re-asserts (deny default) is absent.
func TestGenerateProfile_PreambleOrdering(t *testing.T) {
	prof, err := GenerateProfile([]string{t.TempDir()})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	if !strings.HasPrefix(prof, "(version 1)") {
		t.Errorf("profile must start with (version 1):\n%s", prof)
	}
	allowIdx := strings.Index(prof, "(allow default)")
	denyIdx := strings.Index(prof, "(deny ")
	if allowIdx < 0 {
		t.Fatalf("profile missing (allow default):\n%s", prof)
	}
	if denyIdx < 0 {
		t.Fatalf("profile missing a (deny …) rule:\n%s", prof)
	}
	if allowIdx > denyIdx {
		t.Errorf("(allow default) must precede the first (deny …) [allow@%d deny@%d]:\n%s", allowIdx, denyIdx, prof)
	}
	if strings.Contains(prof, "(deny default)") {
		t.Errorf("profile must never contain (deny default) — it SIGABRTs:\n%s", prof)
	}
}

// TestGenerateProfile_UnresolvablePathFailsClosed is the fail-CLOSED negative
// control (acceptance: "non-canonicalizable path → error, no rule emitted"). A
// path that cannot be resolved must make GenerateProfile ERROR and emit NO
// profile, never silently drop the rule (which would leave the sensitive path
// unfenced — fail open). We force the unresolvable case by removing the working
// directory so filepath.Abs of a relative path fails.
func TestGenerateProfile_UnresolvablePathFailsClosed(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp) // restored on cleanup, before tmp's own removal cleanup runs
	if err := os.Remove(tmp); err != nil {
		t.Skipf("cannot remove cwd to simulate an unresolvable path: %v", err)
	}
	// With the cwd gone, os.Getwd fails, so filepath.Abs of a relative path
	// fails and the path cannot be canonicalized.
	if _, err := canonicalizeForProfile("relative/secret"); err == nil {
		t.Skip("filepath.Abs unexpectedly succeeded with a removed cwd; cannot exercise the fail-closed path here")
	}

	prof, err := GenerateProfile([]string{"relative/secret"})
	if err == nil {
		t.Fatalf("expected a fail-closed error for an unresolvable path, got a profile:\n%s", prof)
	}
	if prof != "" {
		t.Errorf("fail-closed must emit NO profile (no partial rule), got:\n%s", prof)
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
