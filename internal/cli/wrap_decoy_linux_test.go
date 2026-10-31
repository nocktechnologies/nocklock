//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// TestWrapDecoyFileReadIsLogged is the decoy-file recipe proof on Linux: a
// dynamically linked child reads a file named in the user's own [filesystem]
// deny. The read fails, the decoy's contents never reach the child's output,
// and exactly one signed file_blocked row names it. The decoy sits inside the
// fake HOME, outside the project tree Landlock grants (a deny path inside a
// granted tree is refused at startup), so the interposer denies it first and
// that is the path that reports. The negative control reads an undenied
// sibling through the same wrap and gets its contents.
//
// It runs the interposer, so it needs gcc and a private directory under the
// real home for the binary pair (the trust check refuses /tmp).
func TestWrapDecoyFileReadIsLogged(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc unavailable for the filesystem interposer: %v", err)
	}
	moduleCache, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("locate Go module cache before isolating HOME: %v", err)
	}
	t.Setenv("GOMODCACHE", strings.TrimSpace(string(moduleCache)))
	trustedHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	binDir, err := os.MkdirTemp(trustedHome, ".nocklock-decoy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(binDir) })
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	bin := filepath.Join(binDir, "nocklock")
	build := exec.Command("go", "build", "-o", bin, "./cmd/nocklock")
	build.Dir = moduleRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build nocklock: %v\n%s", err, output)
	}
	interposer := filepath.Join(moduleRoot, "internal", "fence", "fs", "interposer", "libfence_fs.c")
	buildLib := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o", filepath.Join(binDir, "libfence_fs.so"), interposer, "-ldl", "-lpthread")
	if output, err := buildLib.CombinedOutput(); err != nil {
		t.Fatalf("build filesystem interposer: %v\n%s", err, output)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))

	projectDir := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	decoyDir := filepath.Join(home, "decoys")
	if err := os.Mkdir(decoyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(decoyDir, "credentials-decoy")
	allowed := filepath.Join(projectDir, "notes.txt")
	for path, contents := range map[string]string{decoy: "FAKE-DECOY-SECRET", allowed: "ordinary-contents"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(projectDir, ".nock"), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(projectDir, ".nock", "config.toml")
	cfgText := fmt.Sprintf(`[project]
name = "decoy-recipe"

[filesystem]
root = %q
mode = "read-write"
linux_enforcement = "preferred"
allow = ["/usr/", "/bin/", "/lib/", "/lib64/", "/etc/ld.so.cache", %q]
deny = [%q]

[network]
allow = ["localhost"]
allow_all = false
`, projectDir, binDir, decoy)
	if err := os.WriteFile(configPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}

	// Negative control: the fence, not the shell script, is what denies. The
	// same read succeeds outside any wrap.
	if got, err := os.ReadFile(decoy); err != nil || string(got) != "FAKE-DECOY-SECRET" {
		t.Fatalf("negative control: unfenced read of decoy = %q, %v", got, err)
	}

	outFile := filepath.Join(projectDir, "out.txt")
	cmd := exec.Command(bin, "wrap", "--", "/bin/sh", "-c", `{ cat "$1"; cat "$2"; } >"$3" 2>/dev/null; exit 0`, "sh", decoy, allowed, outFile)
	cmd.Dir = projectDir
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "XDG_RUNTIME_DIR=/tmp")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wrap failed: %v\n%s", err, output)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ordinary-contents" {
		t.Fatalf("child output = %q, want only the undenied file's contents", got)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	dbPath, root, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatal(err)
	}
	logger, err := logging.NewLogger(dbPath, root)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	events, err := logger.Query(logging.QueryOptions{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, ev := range events {
		if ev.EventType == logging.EventFileBlocked && strings.Contains(ev.Detail, decoy) {
			if !ev.Blocked || ev.Category != "filesystem" {
				t.Errorf("decoy row = category %q blocked %t, want filesystem/true", ev.Category, ev.Blocked)
			}
			rows = append(rows, ev.Detail)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly one file_blocked row naming %s, got %d: %q", decoy, len(rows), rows)
	}
	verified, err := logger.VerifyChain()
	if err != nil || !verified.Intact || verified.SignedEntries == 0 {
		t.Fatalf("audit chain with the decoy row is not an intact signed chain: result=%+v err=%v", verified, err)
	}
}
