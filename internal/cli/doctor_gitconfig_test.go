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

// runProtectedDoctor runs doctor in the current directory with every backend
// stubbed present, so the verdict is PROTECTED unless a check changes it.
func runProtectedDoctor(t *testing.T) (string, error) {
	t.Helper()
	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 9, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		gitConfigExec:  gitConfigExecDoctorChecks,
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
	appendFile(t, filepath.Join(dir, ".git", "config"), extra)
}

// appendFile appends s to the existing file at path.
func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	_, err = f.WriteString(s)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("append to %s: %v", path, err)
	}
}

func TestDoctorWarnsOnGitConfigThatRunsPrograms(t *testing.T) {
	dir := t.TempDir()
	gitInitRepo(t, dir, `[core]
	fsmonitor = ./trap.sh
	hooksPath = .githooks
[credential "https://example.com"]
	helper = !evil
[credential]
	helper =
[gpg "ssh"]
	defaultKeyCommand = ./key.sh
[alias]
	st = status
	x = !sh -c id
[pager]
	log = false
	diff = 10
[extensions]
	worktreeConfig = true
[include]
	path = extra.cfg
`)
	// Included files and config.worktree are read too: the trap does not have
	// to sit in .git/config.
	for name, body := range map[string]string{
		"extra.cfg":       "[diff \"bin\"]\n\ttextconv = ./conv.sh\n",
		"config.worktree": "[filter \"lfs\"]\n\tsmudge = ./smudge.sh\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, ".git", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Doctor scans the repo it runs in, below the project root holding .nock.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, sub)
	out, err := runProtectedDoctor(t)
	if err != nil {
		t.Fatalf("a git config warning must not change doctor's exit code (want 0): %v\n%s", err, out)
	}
	if !strings.Contains(out, "VERDICT: PROTECTED") {
		t.Fatalf("a git config warning must not change the verdict:\n%s", out)
	}
	for _, want := range []string{
		`"core.fsmonitor" = "./trap.sh" (from ".git/config")`,
		`"core.hookspath" = ".githooks"`,
		`"credential.https://example.com.helper" = "!evil"`,
		`"gpg.ssh.defaultkeycommand" = "./key.sh"`,
		`"alias.x" = "!sh -c id"`,
		`"diff.bin.textconv" = "./conv.sh" (from ".git/extra.cfg")`,
		`"filter.lfs.smudge" = "./smudge.sh" (from ".git/config.worktree")`,
	} {
		if !strings.Contains(out, "⚠ git-config-exec [warning]: Repo git config "+want) {
			t.Errorf("doctor did not warn on %s:\n%s", want, out)
		}
	}
	// Negative controls: keys that do not run a program stay quiet.
	for _, quiet := range []string{"alias.st", "pager.log", "pager.diff", "credential.helper", "include.path"} {
		if strings.Contains(out, "Repo git config \""+quiet+"\"") {
			t.Errorf("doctor warned on %s, which runs no program:\n%s", quiet, out)
		}
	}
}

func TestDoctorCleanGitRepoHasNoGitConfigWarning(t *testing.T) {
	dir := t.TempDir()
	gitInitRepo(t, dir, "[core]\n\tfsmonitor = false\n")
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	out, err := runProtectedDoctor(t)
	if err != nil || !strings.Contains(out, "VERDICT: PROTECTED") {
		t.Fatalf("clean repo must stay PROTECTED: %v\n%s", err, out)
	}
	if strings.Contains(out, "git-config-exec") {
		t.Fatalf("clean repo must not warn on git config:\n%s", out)
	}
}
