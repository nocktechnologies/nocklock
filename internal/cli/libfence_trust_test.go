package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func me(uid uint32) bool { return uid == 0 || uid == uint32(os.Geteuid()) }

// libFenceLayout builds <base>/<name>/libfence_fs.so with the given modes.
// base is the trust boundary the tests pass as trustedFrom: /tmp above it is
// sticky and world-writable, so it cannot be part of a safe chain.
func libFenceLayout(t *testing.T, base, name string, dirMode, fileMode os.FileMode) (dir, lib string) {
	t.Helper()
	dir = filepath.Join(base, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lib = filepath.Join(dir, "libfence_fs.so")
	if err := os.WriteFile(lib, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for p, m := range map[string]os.FileMode{dir: dirMode, lib: fileMode} {
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	return
}

func newBase(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestCheckLibFenceTrustAcceptsSafeLayout(t *testing.T) {
	base := newBase(t)
	_, lib := libFenceLayout(t, base, "lib", 0o755, 0o755)
	if err := checkLibFenceTrust(lib, base, me); err != nil {
		t.Fatalf("safe layout refused: %v", err)
	}
}

func TestCheckLibFenceTrustRefusesWritableFile(t *testing.T) {
	base := newBase(t)
	_, lib := libFenceLayout(t, base, "lib", 0o755, 0o666)
	err := checkLibFenceTrust(lib, base, me)
	if err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("expected writable-file refusal, got %v", err)
	}
}

func TestCheckLibFenceTrustRefusesWritableAncestor(t *testing.T) {
	base := newBase(t)
	dir, lib := libFenceLayout(t, base, "lib", 0o775, 0o755)
	err := checkLibFenceTrust(lib, base, me)
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("expected refusal naming %s, got %v", dir, err)
	}
}

func TestCheckLibFenceTrustRefusesUntrustedOwner(t *testing.T) {
	base := newBase(t)
	_, lib := libFenceLayout(t, base, "lib", 0o755, 0o755)
	err := checkLibFenceTrust(lib, base, func(uint32) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("expected owner refusal, got %v", err)
	}
}

func TestCheckLibFenceTrustSymlinks(t *testing.T) {
	base := newBase(t)
	_, evil := libFenceLayout(t, base, "evil", 0o777, 0o755)
	_, good := libFenceLayout(t, base, "good", 0o755, 0o755)
	safeDir, _ := libFenceLayout(t, base, "safe", 0o755, 0o755)

	// Symlink swap: a link in a safe directory now points into a writable one.
	swapped := filepath.Join(safeDir, "swapped.so")
	if err := os.Symlink(evil, swapped); err != nil {
		t.Fatal(err)
	}
	if err := checkLibFenceTrust(swapped, base, me); err == nil || !strings.Contains(err.Error(), "through symlink") {
		t.Fatalf("expected symlink-target refusal, got %v", err)
	}

	// Negative control: the same link pointing at a safe file is accepted.
	fine := filepath.Join(safeDir, "fine.so")
	if err := os.Symlink(good, fine); err != nil {
		t.Fatal(err)
	}
	if err := checkLibFenceTrust(fine, base, me); err != nil {
		t.Fatalf("safe symlink to safe file refused: %v", err)
	}

	// A link whose own owner is untrusted is refused even with a safe target.
	if err := checkLibFenceTrust(fine, base, func(uint32) bool { return false }); err == nil {
		t.Fatal("expected refusal when the link owner is untrusted")
	}
}

func TestFindTrustedLibFenceFSOldResolverAcceptsUnsafeNewRefuses(t *testing.T) {
	base := newBase(t)
	_, lib := libFenceLayout(t, base, "lib", 0o777, 0o666)
	exe := filepath.Join(t.TempDir(), "nocklock")
	exists := func(p string) (bool, error) { return p == lib, nil }

	// Negative control: the pre-fix behavior (no trust check) accepts it.
	if got, err := findTrustedLibFenceFS(exe, t.TempDir(), []string{lib}, exists, trustAllLibFence); err != nil || got != lib {
		t.Fatalf("old resolver should accept the unsafe candidate, got %q, %v", got, err)
	}
	got, err := findTrustedLibFenceFS(exe, t.TempDir(), []string{lib}, exists, func(p string) error { return checkLibFenceTrust(p, base, me) })
	if err == nil || got != "" || !strings.Contains(err.Error(), "refusing unsafe filesystem fence library") {
		t.Fatalf("expected explicit refusal, got %q, %v", got, err)
	}
}

func TestFindTrustedLibFenceFSFallsThroughUnsafeToSafe(t *testing.T) {
	base := newBase(t)
	_, bad := libFenceLayout(t, base, "bad", 0o755, 0o666)
	_, good := libFenceLayout(t, base, "good", 0o755, 0o755)
	verify := func(p string) error { return checkLibFenceTrust(p, base, me) }
	got, err := findTrustedLibFenceFS("", t.TempDir(), []string{bad, good},
		func(p string) (bool, error) { return p == bad || p == good, nil }, verify)
	if err != nil || got != good {
		t.Fatalf("expected safe fallback %q, got %q, %v", good, got, err)
	}
}

func TestLibFenceTrustDoctorCheck(t *testing.T) {
	caps := doctorCapabilities{goos: "linux", unsafeLibFence: func() []string { return []string{"/x/libfence_fs.so: writable"} }}
	check, ok := libFenceTrustDoctorCheck(caps)
	if !ok || check.Severity != doctorWarning || check.Status != "unsafe-library" || !strings.Contains(check.Message, "/x/libfence_fs.so") {
		t.Fatalf("expected unsafe-library warning, got %+v ok=%v", check, ok)
	}
	caps.unsafeLibFence = func() []string { return nil }
	if _, ok := libFenceTrustDoctorCheck(caps); ok {
		t.Fatal("no check expected when candidates are safe")
	}
	caps.goos = "darwin"
	caps.unsafeLibFence = func() []string { return []string{"x"} }
	if _, ok := libFenceTrustDoctorCheck(caps); ok {
		t.Fatal("no check expected off Linux")
	}
}
