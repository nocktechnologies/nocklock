//go:build linux

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestWrapClaudeCodePresetDeviceAndSystemPaths is the non-root acceptance bar
// for N10748 parts (b) and (c): a child wrapped with the claude-code preset —
// Landlock, seccomp, and the userspace proxy all ON — can write /dev/null and
// run `git status` (which needs the standard system read paths and /dev/null).
// Both failed outright in the field: /dev/null writes were denied and the child
// could not even exec because /usr and friends were unreachable.
//
// The network half of N10748's acceptance (an allowlisted HTTPS request through
// the proxy succeeds; a direct-IP connect fails) is NOT asserted here: under the
// syscall fence the child is unix-socket-only and no standard client speaks a
// unix-socket HTTP proxy, so reaching the loopback proxy needs an interposer
// socket()/connect() translation that is tracked as a separate design decision.
// git status and /dev/null need no network, so they run regardless.
//
// Self-skips (like the sibling egress tests) unless run as an unprivileged user
// with the nocklock binary and its libfence_fs.so available; under
// NOCKLOCK_AUDIT_REQUIRE=1 a missing prerequisite fails instead of skipping.
func TestWrapClaudeCodePresetDeviceAndSystemPaths(t *testing.T) {
	if os.Geteuid() == 0 {
		const msg = "claude-code preset acceptance test must run as an unprivileged user (the preset is the strongest NON-root fence)"
		if auditStrictlyRequired() {
			t.Fatalf("%s; strict-required mode forbids running as root", msg)
		}
		t.Skipf("%s; skipping", msg)
	}
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	// The preset grants /tmp read-only, so a root UNDER /tmp collides with the
	// audit-dir deny (assertDenyPathsEnforceable). Real deployments root at a
	// project dir elsewhere; place this repo under the test's working directory,
	// which is the package dir, not /tmp.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repo, err := os.MkdirTemp(cwd, "preset-e2e-")
	if err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(repo) })

	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@t"},
		{"config", "user.name", "t"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// One wrapped shell: write /dev/null, then run git status. Any fence denial
	// (exec failure, EACCES on /dev/null) makes the shell exit non-zero.
	cmd := exec.Command(bin, "wrap", "--profile", "claude-code", "--",
		"/bin/sh", "-c", "echo x > /dev/null && git status >/dev/null 2>&1")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapped child failed (device write or git status denied under the preset): %v\n%s", err, out)
	}
}

// TestWrapClaudeCodePresetBlocksSiblingProcEnviron proves the claude-code
// preset does not let a wrapped process read environment variables from another
// process owned by the same user. Linux's usual ptrace policy does not block
// those reads, so a broad /proc grant would expose unrelated API keys.
func TestWrapClaudeCodePresetBlocksSiblingProcEnviron(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("claude-code preset procfs test must run as an unprivileged user")
	}
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	const siblingEnvironment = "NOCKLOCK_PROC_SIBLING_TEST_SECRET=present"
	sibling := exec.Command("/bin/sleep", "60")
	sibling.Env = append(os.Environ(), siblingEnvironment)
	if err := sibling.Start(); err != nil {
		t.Fatalf("start same-UID sibling: %v", err)
	}
	t.Cleanup(func() {
		_ = sibling.Process.Kill()
		_ = sibling.Wait()
	})

	siblingEnviron := filepath.Join("/proc", strconv.Itoa(sibling.Process.Pid), "environ")
	var (
		unenclosed []byte
		err        error
	)
	for deadline := time.Now().Add(time.Second); ; {
		unenclosed, err = os.ReadFile(siblingEnviron)
		if err == nil && bytes.Contains(unenclosed, []byte(siblingEnvironment)) {
			break
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Skipf("host already blocks same-UID sibling procfs reads at %s: %v", siblingEnviron, err)
			}
			t.Skipf("host did not expose same-UID sibling environment at %s", siblingEnviron)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root, err := os.MkdirTemp(cwd, "preset-e2e-")
	if err != nil {
		t.Fatalf("mkdir project root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	cmd := exec.Command(bin, "wrap", "--profile", "claude-code", "--",
		"/bin/sh", "-c", `test ! -r "$1" && ! /bin/cat "$1" >/dev/null 2>&1`, "sh", siblingEnviron)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapped child read same-UID sibling environment %s: %v\n%s", siblingEnviron, err, out)
	}
}

// requireInterposerBeside skips (or, under strict-required mode, fails) unless
// libfence_fs.so sits next to the binary — the preset's required Linux fence
// refuses to launch without the trusted interposer.
func requireInterposerBeside(t *testing.T, bin string) {
	t.Helper()
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatalf("resolve binary path: %v", err)
	}
	so := filepath.Join(filepath.Dir(abs), "libfence_fs.so")
	if _, err := os.Stat(so); err != nil {
		msg := "claude-code preset acceptance test needs libfence_fs.so next to the nocklock binary (" + so + ")"
		if auditStrictlyRequired() {
			t.Fatalf("%s; strict-required mode forbids skipping: %v", msg, err)
		}
		t.Skipf("%s; skipping: %v", msg, err)
	}
}
