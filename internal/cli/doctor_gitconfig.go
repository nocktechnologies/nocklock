package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// gitConfigExecKeys are repo-settable git config keys whose value is a program
// git runs: "GitSpawn" (a cloned repo's .git/config runs code on the next git
// call). Keys are lowercased, with a subsection matched by "*"; alias.*,
// pager.*, core.fsmonitor, submodule.*.update and remote.*.url are judged by
// value in gitConfigKeyRunsProgram.
var gitConfigExecKeys = map[string]bool{
	"core.hookspath":            true,
	"core.sshcommand":           true,
	"core.pager":                true,
	"core.editor":               true,
	"core.askpass":              true,
	"core.gitproxy":             true,
	"core.alternaterefscommand": true,
	"sequence.editor":           true,
	"diff.external":             true,
	"gpg.program":               true,
	"credential.helper":         true,
	"credential.*.helper":       true,
	"diff.*.textconv":           true,
	"diff.*.command":            true,
	"merge.*.driver":            true,
	"filter.*.clean":            true,
	"filter.*.smudge":           true,
	"filter.*.process":          true,
	"gpg.*.program":             true,
	"difftool.*.cmd":            true,
	"mergetool.*.cmd":           true,
	"remote.*.uploadpack":       true,
	"remote.*.receivepack":      true,
	"interactive.difffilter":    true,
	"gpg.ssh.defaultkeycommand": true,
	"trailer.*.command":         true,
	"trailer.*.cmd":             true,
	"difftool.*.path":           true,
	"mergetool.*.path":          true,
	"browser.*.cmd":             true,
	"man.*.cmd":                 true,
	"sendemail.*.tocmd":         true,
	"sendemail.*.cccmd":         true,
	"sendemail.*.headercmd":     true,
	"sendemail.tocmd":           true,
	"sendemail.cccmd":           true,
	"sendemail.headercmd":       true,
	"sendemail.sendmailcmd":     true,
}

// gitConfigScanTimeout bounds doctor's git calls (an include can name a FIFO).
var gitConfigScanTimeout = 3 * time.Second

// doctorGit runs git in dir with env and returns its stdout. An inherited
// GIT_DIR, GIT_WORK_TREE or GIT_CONFIG would point git at another repo or
// config file, so they are removed.
func doctorGit(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	// CommandContext kills git at the deadline; WaitDelay bounds the reap if a
	// descendant still holds the output pipe.
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir, "--no-pager"}, args...)...)
	cmd.Env = removeEnvVars(env, "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_CONFIG")
	cmd.WaitDelay = time.Second
	return cmd.Output()
}

// gitConfigExecDoctorChecks lists the repository git config entries for dir
// (.git/config, config.worktree and the files they include) that make git run
// a program, one warning each. Doctor only reads the config: `git config
// --list` runs no hook. It reports nothing when git is missing, dir is not in a
// repository, or git cannot parse or open the config (a bad line, an unreadable
// include): git then reports the error itself and runs nothing, so no program
// the config sets can execute. A config doctor cannot read (a FIFO include that
// stalls past the timeout, or git too old for --show-scope) is itself a
// warning, so a hostile repo cannot hide its keys by stalling the scan.
func gitConfigExecDoctorChecks(dir string) []doctorCheck {
	ctx, cancel := context.WithTimeout(context.Background(), gitConfigScanTimeout)
	defer cancel()
	git := func(args ...string) ([]byte, error) { return doctorGit(ctx, dir, os.Environ(), args...) }
	// rev-parse reads the repo config too, so a timeout here is a stalled
	// repository, not a missing one; the scan below then fails as a timeout.
	if _, err := git("rev-parse", "--git-dir"); err != nil && ctx.Err() == nil {
		return nil
	}
	out, err := git("config", "--includes", "--show-scope", "--show-origin", "--null", "--list")
	if err != nil {
		reason := "git error: " + err.Error()
		if ctx.Err() != nil {
			reason = "timeout"
		}
		return []doctorCheck{{
			Group:    "Sanity",
			Name:     "git-config-exec",
			Severity: doctorWarning,
			Status:   "incomplete",
			Message:  fmt.Sprintf("Repo git config could not be fully read (%s); programs it sets may run under git. Inspect .git/config and its includes.", reason),
			Fix:      "inspect .git/config, config.worktree and every included file",
		}}
	}
	// "<scope>\0file:<origin>\0<key>\n<value>\0" per entry; a key set
	// without "=" has no "\n<value>". Only the repository's own scopes count:
	// system, global and command-line config is not set by a cloned repo.
	fields := bytes.Split(out, []byte{0})
	var checks []doctorCheck
	for i := 0; i+2 < len(fields); i += 3 {
		if scope := string(fields[i]); scope != "local" && scope != "worktree" {
			continue
		}
		origin := strings.TrimPrefix(string(fields[i+1]), "file:")
		key, value, _ := strings.Cut(string(fields[i+2]), "\n")
		if !gitConfigKeyRunsProgram(key, value) {
			continue
		}
		// %q on every repo-controlled string: a subsection name can carry
		// terminal escapes, and none of it is spliced into a command.
		checks = append(checks, doctorCheck{
			Group:    "Sanity",
			Name:     "git-config-exec",
			Severity: doctorWarning,
			Status:   "warning",
			Message: fmt.Sprintf("Repo git config %q = %q (from %q) runs a program whenever git runs here, including git commands an agent runs without asking you. If you did not set it, remove it from that file.",
				key, value, origin),
			Fix: "remove the entry from the named file if you did not set it",
		})
	}
	return checks
}

// gitConfigKeyRunsProgram reports whether key (as git lists it: section and
// name lowercased) names a program git runs.
func gitConfigKeyRunsProgram(key, value string) bool {
	dot, lastDot := strings.Index(key, "."), strings.LastIndex(key, ".")
	if dot < 0 {
		return false
	}
	section := key[:dot]
	switch {
	case value == "":
		// An empty value resets a list (credential.helper) or means true.
		return false
	case section == "alias":
		return strings.HasPrefix(value, "!")
	case section == "submodule" && key[lastDot+1:] == "update":
		return strings.HasPrefix(value, "!")
	case section == "remote" && key[lastDot+1:] == "url":
		return strings.HasPrefix(value, "ext::")
	case section == "pager", key == "core.fsmonitor":
		// A boolean picks git's default pager or built-in daemon, not a program.
		return !isGitBool(value)
	}
	return gitConfigExecKeys[key] || (dot != lastDot && gitConfigExecKeys[section+".*."+key[lastDot+1:]])
}

// isGitBool reports whether git reads value as a boolean.
func isGitBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "false", "no", "off":
		return true
	}
	_, err := strconv.Atoi(strings.TrimSpace(value))
	return err == nil
}
