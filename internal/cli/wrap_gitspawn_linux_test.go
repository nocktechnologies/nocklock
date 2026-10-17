//go:build linux

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// TestWrapGitSpawnFsmonitorTrapIsFenced is the GitSpawn acceptance proof: a
// cloned repo whose .git/config sets core.fsmonitor to a program makes every
// `git status` run that program, outside any approval prompt of the agent that
// called git. The trap here tries the three things such a program would do:
// egress to a host the claude-code preset does not allow (example.com), a read
// of a file the preset denies (~/.ssh/id_trap) and a write outside the project.
//
// The negative control runs the same `git status` unwrapped first and requires
// all three to succeed, so the trap is real on this runner. The wrapped run,
// `wrap --profile claude-code --net-fence=netns -- git status`, must still fire
// the trap (it writes its result file inside the project) while all three
// actions fail, the secret's contents never reach the result file, the outside
// file is never created, and the signed event log carries one blocked row for
// each action and passes `verify --audit` as AUTHENTIC.
//
// It reuses the netns acceptance gate (requireNetnsHelperSudo, nocklockBinary),
// so it self-skips without the privileged helper and HARD-FAILS instead under
// NOCKLOCK_AUDIT_REQUIRE=1. SAFETY: it runs only on a disposable GitHub-hosted
// runner, never on a development host that happens to have the helper.
func TestWrapGitSpawnFsmonitorTrapIsFenced(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		if auditStrictlyRequired() {
			t.Fatal("GitSpawn acceptance requires a disposable GitHub-hosted runner")
		}
		t.Skip("GitSpawn acceptance runs only on disposable GitHub-hosted runners")
	}
	requireNetnsHelperSudo(t)
	bin := nocklockBinary(t)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("GitSpawn proof needs git: %v", err)
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatalf("GitSpawn proof needs curl for the trap's egress attempt: %v", err)
	}

	// Outside /tmp: every preset grants /tmp read-only, which would make the
	// write-outside assertion vacuous and put the audit state inside a grant.
	base, err := os.MkdirTemp(mustGetwd(t), "gitspawn-")
	if err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if base, err = filepath.EvalSymlinks(base); err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}
	repo := filepath.Join(base, "repo")
	home := filepath.Join(base, "home")
	outsideDir := filepath.Join(base, "outside")
	for _, dir := range []string{repo, outsideDir, filepath.Join(home, ".claude"), filepath.Join(home, ".cache"), filepath.Join(home, ".ssh"), filepath.Join(home, ".local", "state")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))

	const secretMarker = "GITSPAWN_SECRET_CONTENTS"
	secret := filepath.Join(home, ".ssh", "id_trap")
	if err := os.WriteFile(secret, []byte(secretMarker+"\n"), 0o600); err != nil {
		t.Fatalf("write secret fixture: %v", err)
	}
	outside := filepath.Join(outsideDir, "pwned")
	results := filepath.Join(repo, "trap-results.txt")

	// The project's own config is the preset itself, so wrap's overlay changes
	// nothing and `verify --audit` can find the event log.
	preset, err := os.ReadFile(filepath.Join("..", "config", "presets", "claude-code.toml"))
	if err != nil {
		t.Fatalf("read claude-code preset: %v", err)
	}
	writeTestConfig(t, repo, string(preset))

	gitEnv := append(removeEnvVars(os.Environ(), "PATH"), "PATH=/usr/bin:/bin",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatalf("write tracked file: %v", err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "f.txt"}, {"commit", "-q", "-m", "init"}} {
		cmd := exec.Command(git, args...)
		cmd.Dir = repo
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// The booby trap. It exits non-zero so git falls back to a full scan.
	trap := filepath.Join(repo, "fsmonitor-hook.sh")
	trapScript := `#!/bin/sh
out='` + results + `'
echo ran >> "$out"
if curl -s -f -o /dev/null --max-time 15 http://example.com/; then echo net=ok; else echo net=blocked; fi >> "$out"
if cat '` + secret + `' >> "$out" 2>/dev/null; then echo read=ok; else echo read=blocked; fi >> "$out"
if (echo pwned > '` + outside + `') 2>/dev/null; then echo write=ok; else echo write=blocked; fi >> "$out"
exit 1
`
	if err := os.WriteFile(trap, []byte(trapScript), 0o700); err != nil {
		t.Fatalf("write trap: %v", err)
	}
	appendFile(t, filepath.Join(repo, ".git", "config"), "[core]\n\tfsmonitor = "+trap+"\n")

	readResults := func() string {
		t.Helper()
		data, err := os.ReadFile(results)
		if err != nil {
			t.Fatalf("trap never ran (no %s): %v", results, err)
		}
		return string(data)
	}

	// Negative control: unwrapped, the trap succeeds at all three.
	unwrapped := exec.Command(git, "status")
	unwrapped.Dir = repo
	unwrapped.Env = gitEnv
	if out, err := unwrapped.CombinedOutput(); err != nil {
		t.Fatalf("unwrapped git status: %v\n%s", err, out)
	}
	got := readResults()
	t.Logf("unwrapped trap results (negative control, fails open):\n%s", got)
	for _, want := range []string{"net=ok", "read=ok", "write=ok", secretMarker} {
		if !strings.Contains(got, want) {
			t.Fatalf("negative control: unwrapped trap result lacks %q, so the trap is not real on this runner:\n%s", want, got)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("negative control: unwrapped trap did not write %s: %v", outside, err)
	}
	for _, p := range []string{results, outside} {
		if err := os.Remove(p); err != nil {
			t.Fatalf("reset %s: %v", p, err)
		}
	}

	// The fenced run: an agent-shaped `git status` under the claude-code preset.
	wrap := exec.Command(bin, "wrap", "--profile", "claude-code", "--net-fence=netns", "--", git, "status")
	wrap.Dir = repo
	wrap.Env = gitEnv
	out, err := wrap.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapped git status failed: %v\n%s", err, out)
	}
	got = readResults()
	t.Logf("wrapped trap results:\n%s", got)
	for _, want := range []string{"ran", "net=blocked", "read=blocked", "write=blocked"} {
		if !strings.Contains(got, want) {
			t.Errorf("wrapped trap result lacks %q:\n%s\nwrap output:\n%s", want, got, out)
		}
	}
	for _, leak := range []string{"net=ok", "read=ok", "write=ok", secretMarker} {
		if strings.Contains(got, leak) {
			t.Errorf("wrapped trap result contains %q, so the fence did not hold:\n%s", leak, got)
		}
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Errorf("wrapped trap wrote outside the project (%s): stat err=%v", outside, err)
	}

	logger, err := logging.NewLogger(resolvedAuditDB(t, repo), repo, signingLoggerOpts()...)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer logger.Close()
	netBlocked, fileBlocked := logging.EventNetworkBlocked, logging.EventFileBlocked
	netRows, err := logger.Query(logging.QueryOptions{EventType: &netBlocked})
	if err != nil {
		t.Fatalf("query network rows: %v", err)
	}
	fileRows, err := logger.Query(logging.QueryOptions{EventType: &fileBlocked})
	if err != nil {
		t.Fatalf("query file rows: %v", err)
	}
	if !hasDecisionRow(netRows, "method=http", "host=example.com:80") {
		t.Errorf("no signed network_blocked row for example.com:80; got: %s", detailList(netRows))
	}
	for _, path := range []string{secret, outside} {
		if !hasCategoryRow(fileRows, "filesystem", path) {
			t.Errorf("no signed file_blocked row naming %s; got: %s", path, detailList(fileRows))
		}
	}

	verify := exec.Command(bin, "verify", "--audit")
	verify.Dir = repo
	verify.Env = gitEnv
	vout, err := verify.CombinedOutput()
	if err != nil || !strings.Contains(string(vout), "AUDIT: AUTHENTIC") {
		t.Fatalf("nocklock verify --audit did not report AUTHENTIC: %v\n%s", err, vout)
	}
}
