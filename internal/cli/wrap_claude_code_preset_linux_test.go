//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
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
// child's — the child's own dir is granted by the wrap/shim code path instead).
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

// TestLandlockProcSelfAllowPathsStaysNarrow pins the accepted #10764 limitation:
// the in-code /proc/self grant covers ONLY the directly wrapped child (Landlock is
// inode-bound), and it must NOT be widened to reach grandchildren. The one path
// that would reach them — the broad "/proc/" tree — re-opens the sibling
// /proc/<pid>/environ leak #115 removed (see ADR-005). This asserts the grant is
// exactly one entry, the literal "/proc/self", read-only, so a future "fix" for
// grandchild process.memoryUsage() cannot silently re-open that hole here.
func TestLandlockProcSelfAllowPathsStaysNarrow(t *testing.T) {
	got := landlockProcSelfAllowPaths()
	if len(got) != 1 {
		t.Fatalf("landlockProcSelfAllowPaths() returned %d entries, want exactly 1 (#10764/#115): %+v", len(got), got)
	}
	if got[0].Path != "/proc/self" {
		t.Errorf("grant path = %q, want the literal %q (resolving the symlink binds to the wrapper's pid; a broader path re-opens the #115 sibling leak)", got[0].Path, "/proc/self")
	}
	if got[0].Access != landlock.AccessReadOnly {
		t.Errorf("grant access = %q, want %q — the child never writes its own procfs", got[0].Access, landlock.AccessReadOnly)
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

// writeProcTestConfig writes a .nock/config.toml carrying the claude-code
// enforcement posture (Landlock + seccomp required, hardened interposer) that
// grants the given filesystem allow paths. Network is disabled (allow_all) so
// the test needs no proxy or egress; the filesystem fence is the subject.
func writeProcTestConfig(t *testing.T, projectDir string, allowPaths ...string) {
	t.Helper()
	nockDir := filepath.Join(projectDir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("create .nock dir: %v", err)
	}
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
	if err := os.WriteFile(filepath.Join(nockDir, "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}
}

// buildProcReader compiles a static (CGO_ENABLED=0) helper into the project root
// and returns its path. Pure Go means its file reads are raw syscalls the
// LD_PRELOAD interposer never intercepts, so a denial it reports is Landlock's.
// Building it INTO projectDir makes it an existing root child, which Landlock
// grants execute at ruleset-build time.
func buildProcReader(t *testing.T, projectDir string) string {
	t.Helper()
	src := `package main

import (
	"fmt"
	"os"
)

func main() {
	for _, p := range os.Args[1:] {
		if _, err := os.ReadFile(p); err != nil {
			fmt.Println("DENIED", p)
		} else {
			fmt.Println("READ", p)
		}
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
