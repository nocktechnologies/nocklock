//go:build linux

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestWrapComposedDefaultEgressAudit is the COMPOSED-DEFAULT acceptance bar for
// N10710. It drives `nocklock wrap --net-fence=netns` with EVERY fence ON —
// Landlock (linux_enforcement=required), seccomp (syscall.enforcement=required),
// the netns egress floor, and the signed audit log — and proves they compose.
//
// The sibling TestWrapNetnsEgressDecisionAudit deliberately switches Landlock
// and seccomp OFF and sets filesystem.root="/", so green CI there does NOT prove
// the full stack. This test keeps all enforcement on and leaves filesystem.root
// at the project dir (the realistic default, NOT "/"), so a green run proves the
// two N10710 fixes hold IN COMPOSITION:
//
//	(a) the egress decision dir lives under <root>/.nock, not /tmp, so Landlock
//	    rule generation no longer rejects the default; and
//	(b) seccomp in netns mode allows the child's inet/inet6 sockets, so an
//	    allowlisted fetch can actually leave the namespace.
//
// One allowed fetch (example.com:443) and one denied fetch (blocked.test:80)
// both land signed in .nock/events.db, and `nocklock verify --audit` confirms
// the chain and signatures. (The nock's ACCEPTANCE line says "verify reports
// PROTECTED"; PROTECTED is the `nocklock doctor` verdict name, while
// `verify --audit` is the authoritative signed-chain check and is what the
// sibling acceptance test uses — so we assert that here.)
//
// It reuses requireNetnsHelperSudo / nocklockBinary / hasDecisionRow /
// detailList from wrap_egress_audit_linux_test.go, so it self-skips on any host
// without the privileged helper reachable via passwordless sudo (and, under
// NOCKLOCK_AUDIT_REQUIRE=1, HARD-FAILS instead of skipping).
//
// SAFETY: CI-only, exactly like the sibling test — never run on the resident host.
func TestWrapComposedDefaultEgressAudit(t *testing.T) {
	requireNetnsHelperSudo(t)
	bin := nocklockBinary(t)

	projectDir := t.TempDir()
	nockDir := filepath.Join(projectDir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("create .nock dir: %v", err)
	}

	// Compose the DEFAULT posture: Landlock + seccomp + netns + audit all ON.
	// filesystem.root is the project dir (NOT "/"), so .nock — and the egress
	// decision dir now under it — sit outside every Landlock-granted tree
	// (landlock.rootPathRules skips the literal ".nock" child of the root). The
	// system directories curl needs are granted read-only via allow (read-only
	// Landlock grants still carry the execute right, so the loader and TLS work).
	// /tmp is intentionally NOT granted here: with the project under /tmp,
	// granting it would make .nock overlap a granted tree — the composed test's
	// job is the full-stack run, while the /tmp-collision regression is pinned by
	// the unprivileged TestEgressDecisionDirIsLandlockEnforceable unit test.
	config := `[project]
name = "n10710-composed-default"

[filesystem]
root = "` + projectDir + `"
mode = "read-write"
linux_enforcement = "required"
allow = ["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/", "/dev/", "/proc/"]
deny = []

[network]
allow = ["example.com"]
allow_all = false

[syscall]
enforcement = "required"
`
	if err := os.WriteFile(filepath.Join(nockDir, "config.toml"), []byte(config), 0o644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	// ABSOLUTE paths only. With Landlock + seccomp ON the child runs through the
	// __landlock-exec shim, which execve's argv[0] directly (unix.Exec, no PATH
	// search) — so a bare `sh` would ENOENT. (The sibling egress-audit test gets
	// away with bare `sh` because it disables both fences, so no shim is inserted
	// and wrap's exec.LookPath resolves the command.) /usr/bin/curl is likewise
	// explicit to avoid a PATH walk across ungranted dirs.
	//
	// curl writes to stdout (the wrap-inherited pipe), never to a file: the
	// project root itself is NOT Landlock-granted (rootPathRules grants existing
	// CHILDREN of root, not root), and /dev/null is granted read-only, so a
	// `-o file` or `>/dev/null` write would be denied. Streaming to stdout needs
	// no filesystem write at all. The audit rows, not curl's exit status, are the
	// bar; trailing `true` makes the session exit 0 regardless of curl's result.
	script := "/usr/bin/curl -s --max-time 20 https://example.com/; " +
		"/usr/bin/curl -s --max-time 20 http://blocked.test/; true"
	wrap := exec.Command(bin, "wrap", "--net-fence=netns", "--", "/bin/sh", "-c", script)
	wrap.Dir = projectDir
	wrap.Env = os.Environ()
	if out, err := wrap.CombinedOutput(); err != nil {
		t.Fatalf("composed-default nocklock wrap --net-fence=netns failed: %v\n%s", err, out)
	}

	// Both decisions must land signed, and the chain must verify — the same
	// post-run verdict as the sibling egress-audit test.
	assertBothEgressDecisionsSigned(t, bin, projectDir)
}
