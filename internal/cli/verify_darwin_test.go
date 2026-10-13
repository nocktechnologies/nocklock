//go:build darwin

package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestVerifyMacOSFreshInit exercises the installed command's real subprocess
// path: no Linux interposer exists and the default secret filter stays enabled.
func TestVerifyMacOSFreshInit(t *testing.T) {
	requireSandboxExecForWrap(t)
	bin := filepath.Join(t.TempDir(), "nocklock")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "../../cmd/nocklock")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	root := t.TempDir()
	env := []string{"HOME=" + root, "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_STATE_HOME=" + filepath.Join(root, "state"), "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = project
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				t.Fatalf("%v: %v\nstdout: %s\nstderr: %s", args, err, out, e.Stderr)
			}
			t.Fatal(err)
		}
		return out
	}
	run("init")
	var report verifyReport
	out := run("verify", "--json")
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode %s: %v", out, err)
	}
	if report.Summary != (verifySummary{Passed: 3, Skipped: 1}) {
		t.Fatalf("unexpected verification: %s", out)
	}
	for _, check := range report.Checks {
		want := verifyPass
		if check.Fence == "syscall" {
			want = verifySkip
		}
		if check.Result != want {
			t.Errorf("%s: got %s, want %s: %s", check.Fence, check.Result, want, check.Detail)
		}
	}
	t.Logf("real macOS verification: %s", out)
}
