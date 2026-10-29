package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// A repo that stalls git (an include naming a FIFO blocks the read) must not
// hide its keys: doctor warns that the config is incomplete, within the
// deadline, and the verdict stays PROTECTED.
func TestDoctorWarnsWhenGitConfigCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	gitInitRepo(t, dir, "[core]\n\tfsmonitor = ./trap.sh\n[include]\n\tpath = stall\n")
	if err := syscall.Mkfifo(filepath.Join(dir, ".git", "stall"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	orig := gitConfigScanTimeout
	gitConfigScanTimeout = 300 * time.Millisecond
	t.Cleanup(func() { gitConfigScanTimeout = orig })
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)

	start := time.Now()
	out, err := runProtectedDoctor(t)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("doctor took %s; the git scan must stop at its deadline", elapsed)
	}
	if err != nil || !strings.Contains(out, "VERDICT: PROTECTED") {
		t.Fatalf("an unreadable git config must not change the verdict: %v\n%s", err, out)
	}
	if !strings.Contains(out, "⚠ git-config-exec [incomplete]: Repo git config could not be fully read (timeout)") {
		t.Fatalf("doctor did not warn on a git config it could not read:\n%s", out)
	}
}

func TestDoctorOutsideGitRepoHasNoGitConfigWarning(t *testing.T) {
	dir := t.TempDir()
	// Stop git's repository discovery at dir, so an enclosing repo cannot leak in.
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	out, err := runProtectedDoctor(t)
	if err != nil || strings.Contains(out, "git-config-exec") {
		t.Fatalf("outside a repository doctor must stay quiet on git config: %v\n%s", err, out)
	}
}

// GIT_CONFIG in the caller's environment must not redirect the scan away from
// the repo's own .git/config.
func TestDoctorGitConfigScanIgnoresGitConfigEnv(t *testing.T) {
	dir := t.TempDir()
	gitInitRepo(t, dir, "[core]\n\tfsmonitor = ./trap.sh\n")
	other := filepath.Join(t.TempDir(), "other.cfg")
	if err := os.WriteFile(other, []byte("[core]\n\tbare = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG", other)
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	out, _ := runProtectedDoctor(t)
	if !strings.Contains(out, `Repo git config "core.fsmonitor" = "./trap.sh"`) {
		t.Fatalf("GIT_CONFIG hid the repo's core.fsmonitor:\n%s", out)
	}
}

// The deadline kills git's whole process group: a child git forked without
// exec, still holding the output pipe, does not outlive the call.
func TestDoctorGitTimeoutKillsForkedChild(t *testing.T) {
	bin := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := "#!/bin/sh\n(while :; do sleep 1; done) &\necho $! > '" + pidFile + "'\nwait\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	// exec resolves git on this process's PATH; the child gets the same one.
	path := bin + string(os.PathListSeparator) + os.Getenv("PATH")
	t.Setenv("PATH", path)
	env := []string{"PATH=" + path}

	// Long enough for the fake git to fork and record its child on a loaded
	// runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if _, err := doctorGit(ctx, t.TempDir(), env, "config", "--get", "user.email"); err == nil || ctx.Err() == nil {
		t.Fatalf("hanging git returned err=%v ctx=%v; want a deadline failure", err, ctx.Err())
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("doctorGit took %s; the deadline must stop it", elapsed)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("fake git did not record its child: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("child pid %q: %v", raw, err)
	}
	// The orphan is reaped by init, so poll until the pid is gone; an unreaped
	// zombie counts as gone.
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if gone, _ := processGone(pid); gone {
			break
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("forked child %d outlived the git timeout", pid)
		}
	}
}
