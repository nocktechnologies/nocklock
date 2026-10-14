//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWrapClaudeCodePresetLaunchPath drives the shipped CLI with Landlock and
// seccomp required. It is deliberately hosted-only: never probe kernel fences
// on the resident development host. The existing preset job runs it strictly.
func TestWrapClaudeCodePresetLaunchPath(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		if auditStrictlyRequired() {
			t.Fatal("launch-path acceptance requires a disposable GitHub-hosted runner")
		}
		t.Skip("launch-path acceptance runs only on disposable GitHub-hosted runners")
	}
	requirePresetUnprivileged(t)
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	const marker = "N11777_PATH_TARGET argument with spaces"
	const decoyMarker = "N11777_UNEXPECTED_CWD_TARGET"
	for _, tc := range []struct {
		name       string
		command    string
		path       string
		decoy      string
		nonExec    bool
		wantRefuse bool
	}{
		{name: "absolute_control", command: "/bin/sh", path: "/usr/bin:/bin"},
		{name: "bare_path_target", command: "sh", path: "/usr/bin:/bin"},
		{name: "path_wins_over_cwd_shadow", command: "sh", path: "/usr/bin:/bin", decoy: "sh"},
		{name: "missing_path_target", command: "n11777-probe", decoy: "n11777-probe", wantRefuse: true},
		{name: "non_executable_path_target", command: "n11777-probe", decoy: "n11777-probe", nonExec: true, wantRefuse: true},
		{name: "dot_path_refused", command: "n11777-probe", path: ".", decoy: "n11777-probe", wantRefuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			projectDir := t.TempDir()
			writeProcTestConfig(t, projectDir, "/usr/", "/lib/", "/lib64/", "/bin/", "/etc/", "/dev/")
			path := tc.path
			if path == "" {
				path = t.TempDir()
			}
			if tc.nonExec {
				if err := os.WriteFile(filepath.Join(path, tc.command), []byte("not executable\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.decoy != "" {
				decoy := "#!/bin/sh\nprintf '%s\\n' '" + decoyMarker + "'\n"
				if err := os.WriteFile(filepath.Join(projectDir, tc.decoy), []byte(decoy), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			run := func(t *testing.T, command string) (string, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, bin, "wrap", "--", command, "-c", "printf '%s\\n' '"+marker+"'")
				cmd.Dir = projectDir
				cmd.Env = append(removeEnvVars(os.Environ(), "PATH", "GODEBUG"), "PATH="+path, "GODEBUG=execerrdot=0")
				cmd.WaitDelay = 2 * time.Second
				out, err := cmd.CombinedOutput()
				if ctx.Err() != nil || errors.Is(err, exec.ErrWaitDelay) {
					t.Fatalf("launch-path probe did not complete normally: context=%v err=%v\n%s", ctx.Err(), err, out)
				}
				return string(out), err
			}
			// Prove the same PATH, GODEBUG, directory and fence configuration
			// can launch a known executable before interpreting any refusal.
			if !t.Run("absolute_control_same_environment", func(t *testing.T) {
				out, err := run(t, "/bin/sh")
				if err != nil || !strings.Contains(out, marker) || strings.Contains(out, decoyMarker) {
					t.Fatalf("absolute allowed control failed: %v\n%s", err, out)
				}
			}) {
				return
			}
			out, err := run(t, tc.command)
			if strings.Contains(out, decoyMarker) {
				t.Fatalf("executed a working-directory decoy instead of resolving the requested PATH target:\n%s", out)
			}
			if tc.wantRefuse {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 ||
					!strings.Contains(out, "resolve command \""+tc.command+"\":") || strings.Contains(out, marker) {
					t.Fatalf("expected command-resolution refusal (exit 1), got err=%v\n%s", err, out)
				}
				return
			}
			if err != nil || !strings.Contains(out, marker) {
				t.Fatalf("requested executable did not run through required fences: %v\n%s", err, out)
			}
		})
	}
}
