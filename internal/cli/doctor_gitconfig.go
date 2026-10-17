package cli

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// gitConfigExecKeys are repo-settable git config keys whose value is a program
// git runs: "GitSpawn" (a cloned repo's .git/config runs code on the next git
// call). Keys are lowercased, with a subsection matched by "*"; alias.*,
// pager.* and core.fsmonitor are judged by value in gitConfigKeyRunsProgram.
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
}

// gitConfigExecDoctorChecks lists the local git config entries (.git/config
// and the files it includes) that make git run a program, one warning each.
// Doctor only reads the config: `git config --list` runs no hook. It reports
// nothing when git is missing, times out (an include can name a FIFO), or
// projectRoot is not in a repository.
func gitConfigExecDoctorChecks(projectRoot string) []doctorCheck {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", projectRoot, "--no-pager", "config", "--local", "--includes", "--show-origin", "--null", "--list")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	// --null --show-origin: "file:<origin>\0<key>\n<value>\0" per entry; a key
	// set without "=" has no "\n<value>".
	fields := bytes.Split(out, []byte{0})
	var checks []doctorCheck
	for i := 0; i+1 < len(fields); i += 2 {
		origin := strings.TrimPrefix(string(fields[i]), "file:")
		key, value, _ := strings.Cut(string(fields[i+1]), "\n")
		if !gitConfigKeyRunsProgram(key, value) {
			continue
		}
		checks = append(checks, doctorCheck{
			Group:    "Sanity",
			Name:     "git-config-exec",
			Severity: doctorWarning,
			Status:   "warning",
			Message: fmt.Sprintf("Repo git config %s = %q (from %s) runs a program whenever git runs here, including git commands an agent runs without asking you.",
				key, value, origin),
			Fix: "if you did not set it, remove it with git config --local --unset " + key,
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
	case section == "alias":
		return strings.HasPrefix(value, "!")
	case section == "pager", key == "core.fsmonitor":
		// A boolean picks git's default pager or built-in daemon, not a program.
		return !isGitBool(value)
	case dot != lastDot:
		return gitConfigExecKeys[section+".*."+key[lastDot+1:]]
	}
	return gitConfigExecKeys[key]
}

// isGitBool reports whether git reads value as a boolean.
func isGitBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "true", "yes", "on", "false", "no", "off", "1", "0":
		return true
	}
	return false
}
