//go:build linux

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// TestClaudeCodePresetGrantsProcSystemFiles is the UNCONDITIONAL guard for the
// claude-code preset's procfs grants (nocklock #10757). It needs no built binary
// or node, so it runs on every `go test ./...` — the standing coverage behind
// the two integration tests below, which self-skip when the binary is absent.
//
// os.cpus() reads the system-wide /proc/cpuinfo and /proc/stat; without them it
// silently returns an empty array. Those files are not per-process, so the
// preset grants them directly. It must NOT grant the broad "/proc/" tree (that
// is the same-UID sibling /proc/<pid>/environ leak #115 removed) nor "/proc/self"
// (config path resolution follows that symlink to the WRAPPER's pid, not the
// child's — the child's own files are granted by the wrap/shim code path
// instead, and only the specific files Node needs, never the directory).
func TestClaudeCodePresetGrantsProcSystemFiles(t *testing.T) {
	cfg, err := config.LoadProfile("claude-code")
	if err != nil {
		t.Fatalf("load claude-code preset: %v", err)
	}
	allow := make(map[string]bool, len(cfg.Filesystem.Allow))
	for _, p := range cfg.Filesystem.Allow {
		allow[p] = true
	}
	for _, want := range []string{"/proc/cpuinfo", "/proc/stat", "/proc/meminfo"} {
		if !allow[want] {
			t.Errorf("claude-code preset filesystem.allow is missing %q (os.cpus/memoryUsage need it); got %v", want, cfg.Filesystem.Allow)
		}
	}
	for _, forbidden := range []string{"/proc", "/proc/", "/proc/self", "/proc/self/"} {
		if allow[forbidden] {
			t.Errorf("claude-code preset filesystem.allow must not contain %q — it re-opens the sibling /proc/<pid>/environ path (#115) or binds to the wrapper's pid", forbidden)
		}
	}
}

// TestWrapClaudeCodePresetNodeRuntimeIntrospection is the positive acceptance
// bar for #10757: under the full claude-code fence posture (Landlock + seccomp
// required, plus the LD_PRELOAD interposer) a Node process can introspect itself
// — process.memoryUsage().rss > 0, os.cpus().length > 0, and a read of
// /proc/self/status succeeds — where before the /proc grants it threw EACCES and
// os.cpus() returned an empty array.
//
// It self-skips without a built nocklock binary (with libfence_fs.so beside it)
// or node; under NOCKLOCK_AUDIT_REQUIRE=1 (CI) a would-be skip HARD-FAILS. The
// config mirrors the claude-code preset's enforcement posture and adds the system
// runtime directories node's loader needs (identical rationale to
// TestWrapComposedDefaultEgressAudit); the preset's own /proc grants are asserted
// unconditionally by TestClaudeCodePresetGrantsProcSystemFiles above.
func TestWrapClaudeCodePresetNodeRuntimeIntrospection(t *testing.T) {
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)
	node := requireNode(t)

	projectDir := t.TempDir()
	writeProcTestConfig(t, projectDir, "/usr/", "/lib/", "/lib64/", "/bin/", "/etc/", "/dev/", "/proc/cpuinfo", "/proc/stat", "/proc/meminfo")

	// Report rss, cpu count, and whether /proc/self/status is readable on one
	// line so a failure shows exactly which introspection call regressed.
	const script = `const os=require("os");` +
		`const rss=process.memoryUsage().rss;` +
		`const cpus=os.cpus().length;` +
		`require("fs").readFileSync("/proc/self/status");` +
		`console.log("RESULT rss="+rss+" cpus="+cpus);`
	cmd := exec.Command(bin, "wrap", "--", node, "-e", script)
	cmd.Dir = projectDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrap node introspection failed: %v\n%s", err, out)
	}
	rss, cpus := parseResult(t, out)
	if rss <= 0 {
		t.Errorf("process.memoryUsage().rss = %d, want > 0\n%s", rss, out)
	}
	if cpus <= 0 {
		t.Errorf("os.cpus().length = %d, want > 0\n%s", cpus, out)
	}
}

// TestWrapClaudeCodePresetBlocksSiblingProcEnviron is the negative control that
// proves the grants stay narrow AT THE KERNEL LAYER. A CGO_ENABLED=0 reader
// issues raw Go syscalls (no libc, so the LD_PRELOAD interposer never sees them),
// yet under the fence it must still be DENIED a same-UID sibling's
// /proc/<pid>/environ and /proc/<pid>/cmdline — that denial is Landlock, not the
// userspace fence. The same reader confirms the positive side in the same run:
// its OWN /proc/self/stat and the granted /proc/cpuinfo read fine.
//
// The reader is built into the project root so Landlock (which grants existing
// root children at ruleset-build time) lets it exec; being static, it needs no
// /usr grant. Self-skips without the binary, hard-fails under NOCKLOCK_AUDIT_REQUIRE=1.
func TestWrapClaudeCodePresetBlocksSiblingProcEnviron(t *testing.T) {
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	projectDir := t.TempDir()
	writeProcTestConfig(t, projectDir, "/proc/cpuinfo", "/proc/stat", "/proc/meminfo")
	reader := buildProcReader(t, projectDir)

	// A same-UID sibling, started OUTSIDE the fence, whose /proc/<pid> the fenced
	// reader must not be able to read. `sleep` keeps it alive for the read.
	sibling := exec.Command("sleep", "30")
	if err := sibling.Start(); err != nil {
		t.Fatalf("start sibling process: %v", err)
	}
	defer func() {
		_ = sibling.Process.Kill()
		_ = sibling.Wait()
	}()
	sibPID := strconv.Itoa(sibling.Process.Pid)

	// Order: two positive controls (own dir + granted system file), two negatives
	// (sibling secrets). The reader prints "READ <p>" or "DENIED <p>" per arg.
	cmd := exec.Command(bin, "wrap", "--",
		reader,
		"/proc/self/stat",
		"/proc/cpuinfo",
		"/proc/"+sibPID+"/environ",
		"/proc/"+sibPID+"/cmdline",
	)
	cmd.Dir = projectDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrap sibling-proc reader failed: %v\n%s", err, out)
	}
	got := string(out)

	for _, allowed := range []string{"/proc/self/stat", "/proc/cpuinfo"} {
		if !strings.Contains(got, "READ "+allowed) {
			t.Errorf("expected the fenced reader to READ its own %q, but it did not\n%s", allowed, out)
		}
	}
	for _, denied := range []string{"/proc/" + sibPID + "/environ", "/proc/" + sibPID + "/cmdline"} {
		if !strings.Contains(got, "DENIED "+denied) {
			t.Errorf("expected the fenced reader to be DENIED a sibling's %q (Landlock), but it was not\n%s", denied, out)
		}
	}
}

// TestWrapClaudeCodePresetBlocksDescendantParentProcEnviron is the regression
// test for Gander's round-2 MAJOR finding on #10757: granting the whole
// /proc/self DIRECTORY (rather than the specific files Node needs) binds
// Landlock to the wrapped child's /proc/<pid> dir inode, and Landlock rules are
// inherited by every future descendant — so a grandchild of the wrapped process
// could read the wrapped process's OWN /proc/<pid>/environ and cmdline, the
// same-UID sibling leak #115 removed, reopened one level down.
//
// The reader (CGO_ENABLED=0, raw syscalls, no LD_PRELOAD) re-execs itself as a
// child ("--descendant"), and that child — a grandchild relative to `wrap` —
// tries to read its PARENT's (the wrapped process's) own /proc/<ppid> entries.
// It must READ stat (the file actually granted, whose grant a descendant
// legitimately inherits) but be DENIED environ and cmdline (never granted, at
// any level).
func TestWrapClaudeCodePresetBlocksDescendantParentProcEnviron(t *testing.T) {
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	projectDir := t.TempDir()
	writeProcTestConfig(t, projectDir, "/proc/cpuinfo", "/proc/stat", "/proc/meminfo")
	reader := buildProcReader(t, projectDir)

	cmd := exec.Command(bin, "wrap", "--", reader, "--descendant", "stat", "environ", "cmdline")
	cmd.Dir = projectDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrap descendant-proc reader failed: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	hasResult := func(verb, suffix string) bool {
		for _, line := range lines {
			if strings.HasPrefix(line, verb+" ") && strings.HasSuffix(line, suffix) {
				return true
			}
		}
		return false
	}

	if !hasResult("READ", "/stat") {
		t.Errorf("expected the grandchild to READ the wrapped parent's granted stat file, but it did not\n%s", out)
	}
	for _, denied := range []string{"environ", "cmdline"} {
		if !hasResult("DENIED", "/"+denied) {
			t.Errorf("expected the grandchild to be DENIED the wrapped parent's %q (Landlock), but it was not\n%s", denied, out)
		}
	}
}

// requireNode returns an absolute path to node, or self-skips (hard-fails under
// NOCKLOCK_AUDIT_REQUIRE=1). The absolute path matters: with Landlock + seccomp
// on, the child runs through the __landlock-exec shim, which execve's argv[0]
// directly (no PATH search).
func requireNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if auditStrictlyRequired() {
			t.Fatalf("node runtime-introspection acceptance test needs node on PATH; strict-required mode forbids skipping: %v", err)
		}
		t.Skipf("node runtime-introspection acceptance test needs node on PATH: %v", err)
	}
	return node
}

// writeProcTestConfig writes a .nock/config.toml (via the shared
// writeTestConfig helper) carrying the claude-code enforcement posture
// (Landlock + seccomp required, hardened interposer) that grants the given
// filesystem allow paths. Network is disabled (allow_all) so the test needs
// no proxy or egress; the filesystem fence is the subject.
func writeProcTestConfig(t *testing.T, projectDir string, allowPaths ...string) {
	t.Helper()
	quoted := make([]string, len(allowPaths))
	for i, p := range allowPaths {
		quoted[i] = strconv.Quote(p)
	}
	cfg := `[project]
name = "n10757-proc"

[filesystem]
root = "."
mode = "read-write"
linux_enforcement = "required"
allow = [` + strings.Join(quoted, ", ") + `]
deny = []
hardened = true

[network]
allow_all = true

[syscall]
enforcement = "required"
`
	writeTestConfig(t, projectDir, cfg)
}

// buildProcReader compiles a static (CGO_ENABLED=0) helper into the project root
// and returns its path. Pure Go means its file reads are raw syscalls the
// LD_PRELOAD interposer never intercepts, so a denial it reports is Landlock's.
// Building it INTO projectDir makes it an existing root child, which Landlock
// grants execute at ruleset-build time.
//
// One invocation mode beyond the plain "read every argv path" default:
// "--descendant <name>...", which resolves each name against the CALLER's
// own pid (its own /proc/<pid>/<name>) and re-execs itself with those
// resolved paths in the default mode — so the actual read happens from a
// grandchild-of-wrap's perspective, against its PARENT's proc entries.
func buildProcReader(t *testing.T, projectDir string) string {
	t.Helper()
	src := `package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// readAndPrint reports DENIED only for an actual permission error (Landlock's
// EACCES/EPERM). Anything else (ENOENT, a process-exit race, EMFILE, a
// malformed path) is a test-infrastructure problem, not a fence decision, so
// it is reported as ERROR and made fatal — a negative control must prove the
// SPECIFIC denial it claims, not just "any error happened".
func readAndPrint(p string) {
	if _, err := os.ReadFile(p); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			fmt.Println("DENIED", p)
			return
		}
		fmt.Println("ERROR", p, err)
		os.Exit(1)
	} else {
		fmt.Println("READ", p)
	}
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--descendant" {
		// os.Executable() reads /proc/self/exe, which this fence's narrowed
		// grant (stat/status/statm only) denies — using it here would make
		// this negative-control test fail every time it actually runs under
		// the fence. wrap execs argv[0] directly with no PATH search (see
		// landlockProcSelfAllowPaths' doc comment on the exec model), so
		// os.Args[0] is already this binary's own absolute path.
		self := os.Args[0]
		pid := os.Getpid()
		resolved := make([]string, len(args)-1)
		for i, name := range args[1:] {
			resolved[i] = filepath.Join("/proc", strconv.Itoa(pid), name)
		}
		out, err := exec.Command(self, resolved...).CombinedOutput()
		os.Stdout.Write(out)
		if err != nil {
			os.Exit(1)
		}
		return
	}
	for _, p := range args {
		readAndPrint(p)
	}
}
`
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "reader.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write reader source: %v", err)
	}
	readerPath := filepath.Join(projectDir, "procreader")
	build := exec.Command("go", "build", "-o", readerPath, srcPath)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build proc reader: %v\n%s", err, out)
	}
	return readerPath
}

// parseResult pulls rss and cpus off the single "RESULT rss=<n> cpus=<n>" line
// the node script prints, ignoring NockLock's own stderr banners around it.
func parseResult(t *testing.T, out []byte) (rss, cpus int) {
	t.Helper()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			if _, err := fmt.Sscanf(line, "RESULT rss=%d cpus=%d", &rss, &cpus); err != nil {
				t.Fatalf("malformed RESULT line %q: %v", line, err)
			}
			return rss, cpus
		}
	}
	t.Fatalf("no RESULT line in output:\n%s", out)
	return 0, 0
}

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

// TestWrapClaudeCodePresetListsRootAndProtectsAudit is the N10769 regression
// proof. The fresh-project audit DB lives outside the granted root; Landlock
// cannot grant READ_DIR on a root while excluding an audit DB beneath it.
func TestWrapClaudeCodePresetListsRootAndProtectsAudit(t *testing.T) {
	requirePresetUnprivileged(t)
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)
	python, err := exec.LookPath("python3")
	if err != nil {
		if auditStrictlyRequired() {
			t.Fatalf("claude-code root-listing proof needs python3; strict-required mode forbids skipping: %v", err)
		}
		t.Skipf("claude-code root-listing proof needs python3: %v", err)
	}

	// Keep the fixture outside /tmp: the preset grants /tmp, which would make
	// a deny-path assertion vacuous or reject the Landlock ruleset outright.
	base, err := os.MkdirTemp(mustGetwd(t), "preset-root-list-")
	if err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	repo := filepath.Join(base, "project")
	home := filepath.Join(base, "home")
	for _, dir := range []string{repo, filepath.Join(repo, "sub"), filepath.Join(home, ".claude"), filepath.Join(home, ".cache"), filepath.Join(home, ".ssh"), filepath.Join(home, ".local", "state")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("project file\n"), 0o600); err != nil {
		t.Fatalf("write project file: %v", err)
	}
	deniedFile := filepath.Join(home, ".ssh", "secret.txt")
	if err := os.WriteFile(deniedFile, []byte("deny fixture\n"), 0o600); err != nil {
		t.Fatalf("write deny fixture: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	auditDir, err := config.AuditStateDir(repo)
	if err != nil {
		t.Fatalf("resolve audit state dir: %v", err)
	}
	auditDB := filepath.Join(auditDir, "events.db")

	// ls exercises the interposer; Python runs without LD_PRELOAD, so its
	// positive and negative checks prove the kernel fence's own behavior.
	const probe = `import os, sys
entries = os.listdir('.')
assert {'f.txt', 'sub'} <= set(entries), entries
fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
os.close(fd)
with open('f.txt', 'rb') as f:
    assert f.read() == b'project file\n'
for path in sys.argv[1:]:
    try:
        with open(path, 'rb') as f:
            f.read(1)
    except PermissionError:
        continue
    raise AssertionError('protected file was readable: ' + path)
print('ROOT_LISTED_AUDIT_AND_DENY_BLOCKED')`
	cmd := exec.Command(bin, "wrap", "--profile", "claude-code", "--",
		"/bin/sh", "-c", `set -e; ls . >/dev/null; env -u LD_PRELOAD "$1" -c "$2" "$3" "$4"`,
		"root-list-proof", python, probe, auditDB, deniedFile)
	cmd.Dir = repo
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("claude-code root-listing or protection proof failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("ROOT_LISTED_AUDIT_AND_DENY_BLOCKED")) {
		t.Fatalf("wrapped probe did not finish its positive and negative checks:\n%s", out)
	}
	if _, err := os.Stat(auditDB); err != nil {
		t.Fatalf("audit DB negative control was missing: %v", err)
	}
	for _, path := range []string{auditDB, deniedFile} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatalf("protected-file control %s was not readable outside the fence: %v", path, err)
		}
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
