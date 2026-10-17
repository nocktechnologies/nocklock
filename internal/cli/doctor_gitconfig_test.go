package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// runProtectedDoctorIn runs doctor in dir with every backend stubbed present,
// so the verdict is PROTECTED unless a check changes it.
func runProtectedDoctorIn(t *testing.T, dir string) (string, error) {
	t.Helper()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 9, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		now:            func() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) },
	})
	t.Cleanup(restore)
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	err := doctorCmd.RunE(cmd, nil)
	return out.String(), err
}

// gitInitRepo makes dir a git repository and appends extra to its .git/config.
// The repo is only listed by doctor, never used to run a git command that
// would fire a planted hook.
func gitInitRepo(t *testing.T, dir, extra string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("doctor git config check needs git: %v", err)
	}
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	f, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(extra); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorWarnsOnGitConfigThatRunsPrograms(t *testing.T) {
	dir := t.TempDir()
	gitInitRepo(t, dir, `[core]
	fsmonitor = ./trap.sh
	hooksPath = .githooks
[credential "https://example.com"]
	helper = !evil
[alias]
	st = status
	x = !sh -c id
[pager]
	log = false
[include]
	path = extra.cfg
`)
	// The included file is read too: the trap does not have to sit in .git/config.
	if err := os.WriteFile(filepath.Join(dir, ".git", "extra.cfg"), []byte("[diff \"bin\"]\n\ttextconv = ./conv.sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runProtectedDoctorIn(t, dir)
	if err != nil {
		t.Fatalf("a git config warning must not change doctor's exit code (want 0): %v\n%s", err, out)
	}
	if !strings.Contains(out, "VERDICT: PROTECTED") {
		t.Fatalf("a git config warning must not change the verdict:\n%s", out)
	}
	for _, want := range []string{
		`core.fsmonitor = "./trap.sh"`,
		`core.hookspath = ".githooks"`,
		`credential.https://example.com.helper = "!evil"`,
		`alias.x = "!sh -c id"`,
		`diff.bin.textconv = "./conv.sh" (from .git/extra.cfg)`,
	} {
		if !strings.Contains(out, "⚠ git-config-exec [warning]: Repo git config "+want) {
			t.Errorf("doctor did not warn on %s:\n%s", want, out)
		}
	}
	// Negative controls: keys that do not run a program stay quiet.
	for _, quiet := range []string{"alias.st", "pager.log", "include.path"} {
		if strings.Contains(out, "Repo git config "+quiet+" ") {
			t.Errorf("doctor warned on %s, which runs no program:\n%s", quiet, out)
		}
	}
}

func TestDoctorCleanGitRepoHasNoGitConfigWarning(t *testing.T) {
	dir := t.TempDir()
	gitInitRepo(t, dir, "[core]\n\tfsmonitor = false\n")
	out, err := runProtectedDoctorIn(t, dir)
	if err != nil || !strings.Contains(out, "VERDICT: PROTECTED") {
		t.Fatalf("clean repo must stay PROTECTED: %v\n%s", err, out)
	}
	if strings.Contains(out, "git-config-exec") {
		t.Fatalf("clean repo must not warn on git config:\n%s", out)
	}
}
