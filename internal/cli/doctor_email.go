package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
)

// personalEmailFiles are the agent instruction files read at filesystem.root
// only; doctor does not recurse.
var personalEmailFiles = []string{"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".github/copilot-instructions.md"}

// personalEmailFileLimit is how much of each instruction file is scanned.
const personalEmailFileLimit = 256 << 10

// personalEmailListLimit bounds how many findings the message names.
const personalEmailListLimit = 10

// emailPattern matches local@domain.tld. The TLD must end the label, so a
// versioned path such as toolchain@v0.0.1-go1.27.3.linux-amd64 does not match.
var emailPattern = regexp.MustCompile(`([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[^A-Za-z0-9-]|$)`)

// findPersonalEmails returns the addresses in text that safeEmail does not
// exempt.
func findPersonalEmails(text string) []string {
	var addrs []string
	for _, m := range emailPattern.FindAllStringSubmatch(text, -1) {
		if !safeEmail(m[1]) {
			addrs = append(addrs, m[1])
		}
	}
	return addrs
}

// personalEmailDoctorCheck reports personal email addresses the wrapped agent
// can read: the git identity at filesystem.root, the environment the secret
// fence passes to the child, and agent instruction files at the root.
func personalEmailDoctorCheck(cfg *config.Config) doctorCheck {
	env := os.Environ()
	// wrap refuses an invalid secret fence; the unfiltered env over-reports.
	if fence, err := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block); err == nil {
		env, _ = fencedChildEnv(fence, env)
	}
	return personalEmailCheck(cfg.Filesystem.Root, env)
}

// personalEmailCheck scans root and env. The check is informational: it never
// feeds the verdict, and it never prints a full address or an env value.
func personalEmailCheck(root string, env []string) doctorCheck {
	check := doctorCheck{Group: "Secrets", Name: "personal-email", Severity: doctorInfo, Status: "not-configured", Message: "No filesystem root is configured for personal email inspection."}
	if root == "" {
		return check
	}
	notChecked := func(reason string) doctorCheck {
		check.Status = "not-checked"
		check.Message = "Personal email check: not checked (" + reason + "). The git identity, environment and agent instruction files may still expose an address."
		return check
	}
	root, err := fsfence.ExpandTilde(root)
	if err != nil {
		return notChecked("cannot resolve filesystem.root: " + err.Error())
	}

	var found []string
	seen := map[string]bool{}
	note := func(finding string) {
		if !seen[finding] {
			seen[finding] = true
			found = append(found, finding)
		}
	}
	scan := func(source, text string) {
		for _, addr := range findPersonalEmails(text) {
			note(maskEmail(addr) + " (" + source + ")")
		}
	}

	gitEmail, err := gitUserEmail(root, env)
	if err != nil {
		return notChecked("git user.email: " + err.Error())
	}
	scan("git user.email", gitEmail)

	for _, entry := range env {
		name, value, _ := strings.Cut(entry, "=")
		if len(findPersonalEmails(value)) > 0 {
			// Names only: even a masked value is not printed.
			note("env " + name)
		}
	}

	for _, name := range personalEmailFiles {
		err := scanInstructionFile(filepath.Join(root, name), func(n int, line string) {
			scan(fmt.Sprintf("%s:%d", name, n), line)
		})
		if err != nil {
			return notChecked("cannot read " + name + ": " + err.Error())
		}
	}

	check.Status = "clear"
	check.Message = "No personal email address found in the git identity, the environment passed to the wrapped agent, or agent instruction files at filesystem.root. Deeper files were not checked."
	if len(found) > 0 {
		listed := found
		if len(listed) > personalEmailListLimit {
			listed = append(slices.Clip(found[:personalEmailListLimit]), fmt.Sprintf("%d more", len(found)-personalEmailListLimit))
		}
		check.Severity, check.Status = doctorWarning, "exposed"
		check.Message = "Personal email address readable by the wrapped agent: " + strings.Join(listed, ", ") + ". An agent can copy it into commits or request headers; the network fence sees hostnames, not headers."
		check.Fix = "set a noreply address for agent sessions in this repo (git config user.email <id>+<user>@users.noreply.github.com) and remove personal addresses from agent instruction files"
	}
	return check
}

// gitUserEmail returns the effective user.email git would commit with in dir,
// under gitConfigScanTimeout. Missing git or an unset key is no identity.
func gitUserEmail(dir string, env []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitConfigScanTimeout)
	defer cancel()
	out, err := doctorGit(ctx, dir, env, "config", "--get", "user.email")
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return "", errors.New("timeout")
	case errors.Is(err, exec.ErrNotFound), errors.As(err, &exitErr) && exitErr.ExitCode() == 1:
		return "", nil
	case err != nil:
		return "", err
	}
	return string(out), nil
}

// scanInstructionFile calls line for each line, numbered from 1, in the first
// personalEmailFileLimit bytes of path. A missing or non-regular file (a FIFO
// would stall the read) has no lines.
func scanInstructionFile(path string, line func(n int, text string)) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) || err == nil && !info.Mode().IsRegular() {
		return nil
	}
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, personalEmailFileLimit))
	sc.Buffer(make([]byte, 0, 64<<10), personalEmailFileLimit)
	for n := 1; sc.Scan(); n++ {
		line(n, sc.Text())
	}
	return sc.Err()
}

// safeEmail reports whether addr is a placeholder or noreply address.
func safeEmail(addr string) bool {
	local, domain, _ := strings.Cut(strings.ToLower(addr), "@")
	switch {
	case local == "noreply", local == "no-reply":
		return true
	case domain == "users.noreply.github.com", domain == "example.com", domain == "example.org", domain == "localhost":
		return true
	}
	return false
}

// maskEmail keeps the first character and the domain: k***@example.net.
func maskEmail(addr string) string {
	local, domain, _ := strings.Cut(addr, "@")
	return local[:1] + "***@" + domain
}
