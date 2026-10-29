package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unicode"

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
// exempt. Two user@host shapes are not emails: URL userinfo, where "://" comes
// before the match in the same token with only userinfo characters between
// (scheme://user:pass@host), and an scp-style git remote, whose ":" is
// followed directly by a path (git@github.com:org/repo). A colon followed by a
// space or ending the text is punctuation, so that address is flagged, as is
// an address in a URL's path or query (https://host/?to=user@host).
func findPersonalEmails(text string) []string {
	var addrs []string
	// schemeEnd is the offset just past the last "://" and lastBad the offset
	// of the last character URL userinfo cannot hold (whitespace, "/", "?",
	// "@", a quote). Both advance from the previous match, so a long line is
	// scanned once, not once per match.
	schemeEnd, lastBad, prev := -1, -1, 0
	for _, m := range emailPattern.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2], m[3]
		seg := text[prev:start]
		if i := strings.LastIndex(seg, "://"); i >= 0 {
			schemeEnd = prev + i + len("://")
		}
		if i := strings.LastIndexFunc(seg, notURLUserinfo); i >= 0 {
			lastBad = prev + i
		}
		prev = start
		userinfo := schemeEnd >= 0 && lastBad < schemeEnd
		scpRemote := end+1 < len(text) && text[end] == ':' && !unicode.IsSpace(rune(text[end+1]))
		if userinfo || scpRemote {
			continue
		}
		if addr := text[start:end]; !safeEmail(addr) {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// notURLUserinfo reports whether r cannot appear in URL userinfo (RFC 3986:
// unreserved, percent-encoded, sub-delims and ":").
func notURLUserinfo(r rune) bool {
	return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("-._~%!$&'()*+,;=:", r))
}

// personalEmailDoctorCheck reports personal email addresses the wrapped agent
// can read: the git identity at filesystem.root, the environment wrap passes
// to the child, and agent instruction files at the root.
func personalEmailDoctorCheck(cfg *config.Config) doctorCheck {
	env := os.Environ()
	// wrap refuses an invalid secret fence; the unfiltered env over-reports.
	if fence, err := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block); err == nil {
		env, _ = fencedChildEnv(fence, env)
	}
	return personalEmailCheck(cfg.Filesystem.Root, removeEnvVars(env, ambientProxyEnv...))
}

// personalEmailCheck scans root and env. The check is informational: it never
// feeds the verdict, and it never prints a full address or an env value. A
// finding wins over a source that could not be read.
func personalEmailCheck(root string, env []string) doctorCheck {
	check := doctorCheck{Group: "Secrets", Name: "personal-email", Severity: doctorInfo, Status: "not-configured", Message: "No filesystem root is configured for personal email inspection."}
	if root == "" {
		return check
	}
	var found, unread []string
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

	for _, entry := range env {
		name, value, _ := strings.Cut(entry, "=")
		if len(findPersonalEmails(value)) > 0 {
			// Names only: even a masked value is not printed.
			note("env " + name)
		}
	}

	// Each unread source is named with an error class only: an OS error text
	// carries the path, and a path can hold an address.
	root, err := fsfence.ExpandTilde(root)
	if err != nil {
		unread = append(unread, "filesystem.root: cannot expand ~")
	} else {
		if gitEmail, err := gitUserEmail(root, env); err != nil {
			unread = append(unread, "git user.email: "+err.Error())
		} else {
			scan("git user.email", gitEmail)
		}
		for _, name := range personalEmailFiles {
			err := scanInstructionFile(filepath.Join(root, name), func(n int, line string) {
				scan(fmt.Sprintf("%s:%d", name, n), line)
			})
			if err != nil {
				unread = append(unread, name+": "+fileErrorClass(err))
			}
		}
	}

	switch {
	case len(found) > 0:
		listed := found
		if len(listed) > personalEmailListLimit {
			listed = append(slices.Clip(found[:personalEmailListLimit]), fmt.Sprintf("%d more", len(found)-personalEmailListLimit))
		}
		check.Severity, check.Status = doctorWarning, "exposed"
		check.Message = "Personal email address readable by the wrapped agent: " + strings.Join(listed, ", ") + ". An agent can copy it into commits or request headers; the network fence sees hostnames, not headers."
		if len(unread) > 0 {
			check.Message += " Not checked: " + strings.Join(unread, "; ") + "."
		}
		check.Fix = "set a noreply address for agent sessions in this repo (git config user.email <id>+<user>@users.noreply.github.com) and remove personal addresses from agent instruction files"
	case len(unread) > 0:
		check.Status = "not-checked"
		check.Message = "Personal email check: not checked (" + strings.Join(unread, "; ") + "). The git identity, environment and agent instruction files may still expose an address."
	default:
		check.Status = "clear"
		check.Message = "No personal email address found in the git identity, the environment passed to the wrapped agent, or agent instruction files at filesystem.root. Deeper files were not checked."
	}
	return check
}

// gitUserEmail returns the effective user.email git would commit with in dir,
// under gitConfigScanTimeout. Missing git or an unset key is no identity. An
// error names its class only, never git's output or the path.
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
	case exitErr != nil:
		// "exit status N" or "signal: killed": no output, no path.
		return "", fmt.Errorf("git failed (%v)", exitErr)
	case err != nil && !errors.Is(err, exec.ErrWaitDelay):
		// ErrWaitDelay: git exited 0 and its output is complete, but a process
		// it started still held the pipe; doctorGit has killed it.
		return "", errors.New("git could not run")
	}
	return string(out), nil
}

// fileErrorClass names the class of an instruction file error without its
// text, which carries the path.
func fileErrorClass(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "permission denied"
	}
	return "read error"
}

// scanInstructionFile calls line for each line, numbered from 1, in the first
// personalEmailFileLimit bytes of path. A missing or non-regular file has no
// lines; O_NONBLOCK keeps a FIFO from stalling the open.
func scanInstructionFile(path string, line func(n int, text string)) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return err
	}
	sc := bufio.NewScanner(io.LimitReader(f, personalEmailFileLimit))
	// One byte over the limit, so a single line filling it still fits.
	sc.Buffer(make([]byte, 0, 64<<10), personalEmailFileLimit+1)
	for n := 1; sc.Scan(); n++ {
		line(n, sc.Text())
	}
	return sc.Err()
}

// safeEmail reports whether addr is a placeholder or noreply address.
// @localhost never matches emailPattern, which needs a dotted TLD.
func safeEmail(addr string) bool {
	local, domain, _ := strings.Cut(strings.ToLower(addr), "@")
	switch {
	case local == "noreply", local == "no-reply":
		return true
	case domain == "users.noreply.github.com", domain == "example.com", domain == "example.org":
		return true
	}
	return false
}

// maskEmail keeps the first character and the domain: k***@example.net.
func maskEmail(addr string) string {
	local, domain, _ := strings.Cut(addr, "@")
	return local[:1] + "***@" + domain
}
