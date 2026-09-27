//go:build linux

package cli

import (
	"bytes"
	"errors"
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
	requirePresetUnprivileged(t)
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	// Keep the repo out of /tmp, which the preset grants read-only: nesting the
	// fence root inside another granted tree is not how real deployments are
	// laid out, and it muddies which grant a result came from. Place it under
	// the test's working directory, which is the package dir.
	repo, err := os.MkdirTemp(mustGetwd(t), "preset-e2e-")
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

// TestWrapClaudeCodePresetDeniesSiblingProcExposure is the negative control for
// N10748 round 2 part (c): a child wrapped with the claude-code preset must NOT
// read a same-UID SIBLING process's /proc/<pid> exposure — neither its `environ`
// (the nock's stated API-key vector) nor its `cmdline` (secrets passed as argv,
// e.g. `--token=…`). The preset used to allow "/proc/"; removing it closes both.
//
// A POSITIVE CONTROL guards against a green result that is merely an artifact of
// the host (hidepid, a different UID, kernel hardening): the test first proves
// both markers ARE readable in the sibling UNWRAPPED, then proves neither appears
// in the wrapped child's output. It asserts on CONTENT, not exit code.
//
// One subtlety, observed on the fleet host and documented for the record: with
// "/proc/" granted, a wrapped child read a sibling's `cmdline`/`stat`/`status`/
// `comm` but NOT its `environ` or `maps` — a split a path-based grant cannot
// produce (the `environ`/`maps` reads are additionally ptrace-gated, and a
// sandboxed reader is not permitted to introspect an unrelated sibling). So the
// environ half of this test stays denied even if "/proc/" is reintroduced, while
// the `cmdline` half is what gives the test teeth against a "/proc/" regression:
// `cmdline` is world-readable, so it WAS reachable with the grant and is denied
// only because the grant is gone. Both matter; the cmdline leak (tokens on a
// command line) is the one a "/proc/" regression reopens.
func TestWrapClaudeCodePresetDeniesSiblingProcExposure(t *testing.T) {
	requirePresetUnprivileged(t)
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	// A same-UID sibling that idles with a distinctive secret in BOTH its
	// environment and its command line. The argv marker rides in on argv[0]:
	// exec.Cmd sets the child's argv from Args independently of the binary Path,
	// so overriding Args[0] plants the sentinel in /proc/<pid>/cmdline with no
	// on-disk fixture.
	const envMarker = "NOCKLOCK_N10748_SIBLING_SECRET=super-secret-sentinel-value"
	const argMarker = "nocklock-n10748-cmdline-sentinel"
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep(1) unavailable: %v", err)
	}
	sibling := exec.Command(sleepPath, "60")
	sibling.Args[0] = argMarker
	sibling.Env = append(os.Environ(), envMarker)
	if err := sibling.Start(); err != nil {
		t.Fatalf("start sibling: %v", err)
	}
	t.Cleanup(func() {
		_ = sibling.Process.Kill()
		_, _ = sibling.Process.Wait()
	})
	procDir := filepath.Join("/proc", strconv.Itoa(sibling.Process.Pid))
	environPath := filepath.Join(procDir, "environ")
	cmdlinePath := filepath.Join(procDir, "cmdline")

	// POSITIVE CONTROL: unwrapped, this test process (same UID) reads BOTH markers
	// out of the sibling's /proc. If it cannot, the host already hides them and the
	// negative assertion would be vacuous — skip (fail under strict). /proc settles
	// once per exec, so a single poll gates both files; Start() returns on exec
	// success but the read can still race a scheduler tick.
	found := false
	var lastErr error
	for i := 0; i < 50; i++ {
		env, envErr := os.ReadFile(environPath)
		cmd, cmdErr := os.ReadFile(cmdlinePath)
		if envErr == nil && cmdErr == nil &&
			bytes.Contains(env, []byte(envMarker)) && bytes.Contains(cmd, []byte(argMarker)) {
			found = true
			break
		}
		lastErr = errors.Join(envErr, cmdErr)
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		const msg = "positive control failed: cannot read the sibling's /proc/<pid>/{environ,cmdline} markers unwrapped (hidepid, kernel hardening, or a race), so the negative assertion would be vacuous"
		if auditStrictlyRequired() {
			t.Fatalf("%s; strict-required mode forbids skipping (readErr=%v)", msg, lastErr)
		}
		t.Skipf("%s; skipping (readErr=%v)", msg, lastErr)
	}

	// Build a static Go reader inside the fence root. It issues the open/read
	// syscalls itself, so LD_PRELOAD cannot manufacture this denial: EACCES proves
	// the kernel Landlock policy blocks the sibling environ read.
	repo, err := os.MkdirTemp(mustGetwd(t), "preset-proc-neg-")
	if err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(repo) })
	readerSource := filepath.Join(repo, "proc-reader.go")
	readerBinary := filepath.Join(repo, "proc-reader")
	const readerProgram = `package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func main() {
	fd, err := syscall.Open(os.Args[1], syscall.O_RDONLY, 0)
	if errors.Is(err, fs.ErrPermission) {
		fmt.Println("DENIED")
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(2)
	}
	defer syscall.Close(fd)
	buf := make([]byte, 1<<20)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(2)
	}
	os.Stdout.Write(buf[:n])
	os.Exit(1)
}
`
	if err := os.WriteFile(readerSource, []byte(readerProgram), 0o600); err != nil {
		t.Fatalf("write raw-syscall reader: %v", err)
	}
	build := exec.Command("go", "build", "-o", readerBinary, readerSource)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build static raw-syscall reader: %v\n%s", err, out)
	}

	// NEGATIVE: the static reader must report a kernel denial for environ. The
	// shell then reads cmdline as a regression control: re-granting broad /proc
	// access leaks its marker and fails even on hosts where ptrace also protects
	// environ. Assert on content so a masked command status cannot make this green.
	startupMarker := "NOCKLOCK_PRESET_TEST_STARTED_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	cmd := exec.Command(bin, "wrap", "--profile", "claude-code", "--",
		"/bin/sh", "-c", `echo "$1"; "$2" "$3"; cat "$4"`,
		"preset-proc-test", startupMarker, readerBinary, environPath, cmdlinePath)
	cmd.Dir = repo
	out, _ := cmd.CombinedOutput()
	if !bytes.Contains(out, []byte(startupMarker)) {
		t.Fatalf("wrapped child did not emit its startup marker — the negative assertion would be vacuous; output:\n%s", out)
	}
	if !bytes.Contains(out, []byte("DENIED")) {
		t.Fatalf("static raw-syscall reader did not print DENIED for sibling environ — Landlock enforcement was not proved; output:\n%s", out)
	}
	t.Log("raw-syscall sibling environ control: DENIED")
	for _, m := range []string{envMarker, argMarker} {
		if bytes.Contains(out, []byte(m)) {
			t.Fatalf("wrapped child leaked the sibling's %q marker — the preset must deny /proc/<pid> reads; output:\n%s", m, out)
		}
	}
}

// requirePresetUnprivileged skips (or, under strict-required mode, fails) when
// the test runs as root: the claude-code preset is the strongest NON-root fence,
// so running it as root would not measure what it claims to measure.
func requirePresetUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	const msg = "claude-code preset acceptance test must run as an unprivileged user (the preset is the strongest NON-root fence)"
	if auditStrictlyRequired() {
		t.Fatalf("%s; strict-required mode forbids running as root", msg)
	}
	t.Skipf("%s; skipping", msg)
}

// mustGetwd returns the current working directory or fails the test. The preset
// grants /tmp read-only, so a repo under /tmp collides with the audit-dir deny;
// the package dir (the test's cwd) sits elsewhere.
func mustGetwd(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return cwd
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
