package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// Placeholder addresses only: example.net is reserved but not on the safe list.
const (
	testPersonalEmail = "pat.person@example.net"
	testPersonalMask  = "p***@example.net"
)

// emailTestEnv is a hermetic child environment: no system or global git
// config, so only the temp repo's identity counts.
func emailTestEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
	}, extra...)
}

func TestPersonalEmailCheck(t *testing.T) {
	tests := []struct {
		name       string
		gitEmail   string
		env        []string
		files      map[string]string
		noRoot     bool
		wantStatus string
		wantIn     []string
	}{
		{name: "personal git email", gitEmail: testPersonalEmail, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (git user.email)"}},
		{name: "noreply git email", gitEmail: "12345+someone@users.noreply.github.com", wantStatus: "clear"},
		{name: "placeholder addresses", gitEmail: "noreply@example.net", env: []string{"CONTACT=no-reply@example.net", "DOCS=dev@example.com"}, files: map[string]string{"AGENTS.md": "Mail dev@example.org.\n"}, wantStatus: "clear"},
		{name: "versioned path is not an email", env: []string{"GOTOOLCHAIN_BIN=/mod/golang.org/toolchain@v0.0.1-go1.27.3.linux-amd64/bin"}, wantStatus: "clear"},
		{name: "sentence-ending address", files: map[string]string{"GEMINI.md": "Mail " + testPersonalEmail + "."}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (GEMINI.md:1)"}},
		{name: "env var", env: []string{"OWNER_CONTACT=Pat <" + testPersonalEmail + ">"}, wantStatus: "exposed", wantIn: []string{"env OWNER_CONTACT"}},
		{name: "instruction file line", files: map[string]string{"CLAUDE.md": "# Project\n\nAsk " + testPersonalEmail + " for access.\n"}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (CLAUDE.md:3)"}},
		{name: "nested instruction file", files: map[string]string{".github/copilot-instructions.md": testPersonalEmail}, wantStatus: "exposed", wantIn: []string{".github/copilot-instructions.md:1"}},
		{name: "deeper file not scanned", files: map[string]string{"sub/CLAUDE.md": testPersonalEmail}, wantStatus: "clear"},
		{name: "git remote and URL userinfo", env: []string{"PROXY_URL=http://pat@proxy.example.net:8080"}, files: map[string]string{"AGENTS.md": "git clone git@github.com:org/repo.git\n"}, wantStatus: "clear"},
		{name: "URL userinfo with password", files: map[string]string{"AGENTS.md": "Fetch https://u:p@mail.example.net/feed\n"}, wantStatus: "clear"},
		{name: "userinfo without a scheme", files: map[string]string{"AGENTS.md": "Login pat:" + testPersonalEmail + "\n"}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (AGENTS.md:1)"}},
		{name: "address in a URL query", files: map[string]string{"AGENTS.md": "Book at https://cal.example.net/x?email=" + testPersonalEmail + "\n"}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (AGENTS.md:1)"}},
		{name: "address after a URL in compact JSON", env: []string{`OWNER_JSON={"url":"https://a.example.net","owner":"` + testPersonalEmail + `"}`}, wantStatus: "exposed", wantIn: []string{"env OWNER_JSON"}},
		{name: "address after a URL in a table cell", files: map[string]string{"AGENTS.md": "|https://a.example.net|" + testPersonalEmail + "|\n"}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (AGENTS.md:1)"}},
		{name: "scp remote", files: map[string]string{"AGENTS.md": "git@github.com:org/repo.git\n"}, wantStatus: "clear"},
		{name: "colon at end of line", files: map[string]string{"AGENTS.md": "Owner " + testPersonalEmail + ":\n"}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (AGENTS.md:1)"}},
		{name: "colon then text", files: map[string]string{"AGENTS.md": testPersonalEmail + ": call before deploys\n"}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (AGENTS.md:1)"}},
		{name: "single line over the scan limit", files: map[string]string{".cursorrules": testPersonalEmail + " " + strings.Repeat("x", personalEmailFileLimit)}, wantStatus: "exposed", wantIn: []string{testPersonalMask + " (.cursorrules:1)"}},
		{name: "no root", noRoot: true, gitEmail: testPersonalEmail, wantStatus: "not-configured"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if tt.gitEmail != "" {
				gitInitRepo(t, root, "[user]\n\temail = "+tt.gitEmail+"\n")
			}
			for name, body := range tt.files {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.noRoot {
				root = ""
			}
			check := personalEmailCheck(root, emailTestEnv(t, tt.env...))
			if check.Group != "Secrets" || check.Name != "personal-email" || check.Status != tt.wantStatus {
				t.Fatalf("got %+v, want status %s", check, tt.wantStatus)
			}
			wantSeverity := doctorInfo
			if tt.wantStatus == "exposed" {
				wantSeverity = doctorWarning
				if !strings.Contains(check.Fix, "users.noreply.github.com") {
					t.Fatalf("exposed check has no noreply fix: %+v", check)
				}
			}
			if check.Severity != wantSeverity {
				t.Fatalf("severity %s, want %s: %+v", check.Severity, wantSeverity, check)
			}
			for _, want := range tt.wantIn {
				if !strings.Contains(check.Message, want) {
					t.Fatalf("message lacks %q: %s", want, check.Message)
				}
			}
			encoded, _ := json.Marshal(check)
			if strings.Contains(string(encoded), testPersonalEmail) {
				t.Fatalf("full address printed: %s", encoded)
			}
		})
	}
}

// A git that hangs must not stall doctor: the check stops at the deadline and
// says not-checked.
func TestPersonalEmailCheckGitTimeout(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	orig := gitConfigScanTimeout
	gitConfigScanTimeout = 300 * time.Millisecond
	t.Cleanup(func() { gitConfigScanTimeout = orig })

	start := time.Now()
	check := personalEmailCheck(t.TempDir(), emailTestEnv(t))
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("check took %s; the git call must stop at its deadline", elapsed)
	}
	if check.Severity != doctorInfo || check.Status != "not-checked" || !strings.Contains(check.Message, "timeout") {
		t.Fatalf("hanging git not reported as not-checked: %+v", check)
	}

	// A finding from another source still warns, naming what was not checked.
	check = personalEmailCheck(t.TempDir(), emailTestEnv(t, "OWNER_CONTACT="+testPersonalEmail))
	if check.Status != "exposed" || !strings.Contains(check.Message, "Not checked: git user.email: timeout") {
		t.Fatalf("finding hidden by the git timeout: %+v", check)
	}
}

// An unreadable source is named by file and error class only. The OS error
// text carries the path, so a root directory named like an address must not
// reach the report through it.
func TestPersonalEmailCheckErrorHidesAddress(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	const dirEmail = "root.owner@example.net"
	root := filepath.Join(t.TempDir(), dirEmail)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("owner: "+testPersonalEmail+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// AGENTS.md is read after CLAUDE.md, so the error follows a match.
	if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte(testPersonalEmail), 0o000); err != nil {
		t.Fatal(err)
	}
	check := personalEmailCheck(root, emailTestEnv(t))
	if check.Status != "exposed" || !strings.Contains(check.Message, "Not checked: AGENTS.md: permission denied.") {
		t.Fatalf("unreadable file not named by class: %+v", check)
	}
	var text, encoded bytes.Buffer
	report := doctorReport{Checks: []doctorCheck{check}}
	renderDoctorHuman(&text, report)
	if err := renderDoctorJSON(&encoded, report); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{text.String(), encoded.String()} {
		for _, addr := range []string{testPersonalEmail, dirEmail} {
			if strings.Contains(out, addr) {
				t.Fatalf("full address %q printed:\n%s", addr, out)
			}
		}
	}

	// Control: with AGENTS.md readable the same root reports no unread source.
	if err := os.Chmod(filepath.Join(root, "AGENTS.md"), 0o600); err != nil {
		t.Fatal(err)
	}
	if check := personalEmailCheck(root, emailTestEnv(t)); check.Status != "exposed" || strings.Contains(check.Message, "Not checked") {
		t.Fatalf("readable root reported an unread source: %+v", check)
	}
}

// A FIFO named like an instruction file must not stall doctor.
func TestPersonalEmailCheckSkipsFIFO(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "CLAUDE.md"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	done := make(chan doctorCheck, 1)
	go func() { done <- personalEmailCheck(root, emailTestEnv(t)) }()
	select {
	case check := <-done:
		if check.Status != "clear" {
			t.Fatalf("FIFO changed the result: %+v", check)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("personal email check blocked on a FIFO")
	}
}

// doctorGit strips git's redirecting variables from a copy: the caller's env,
// which the check scans afterwards, is unchanged.
func TestDoctorGitKeepsCallerEnv(t *testing.T) {
	env := []string{"GIT_DIR=/nonexistent", "PATH=" + os.Getenv("PATH")}
	_, _ = doctorGit(context.Background(), t.TempDir(), env, "--version")
	if env[0] != "GIT_DIR=/nonexistent" {
		t.Fatalf("doctorGit modified the caller env: %q", env)
	}
}

// The finding reaches the text and JSON reports masked, and a warning does not
// change the verdict or the exit code.
func TestDoctorPersonalEmailReport(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte("owner: "+testPersonalEmail+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	caps := doctorCapabilities{goos: "linux", fsBackend: func() error { return nil }, landlockABI: func() (int, error) { return 9, nil }, syscallBackend: func() bool { return true }, networkBackend: func() error { return nil }, sandboxExec: func() error { return nil }, now: time.Now}
	if got := runDoctor(caps); got.Verdict != doctorVerdictProtected {
		t.Fatalf("control verdict %s: %+v", got.Verdict, got.Checks)
	}
	caps.personalEmail = func(cfg *config.Config) doctorCheck {
		return personalEmailCheck(cfg.Filesystem.Root, emailTestEnv(t, "OWNER_CONTACT="+testPersonalEmail))
	}
	got := runDoctor(caps)
	if got.Verdict != doctorVerdictProtected || doctorExitCode(got.Verdict) != 0 {
		t.Fatalf("personal email changed the verdict: %+v", got)
	}
	var exposed bool
	for _, check := range got.Checks {
		exposed = exposed || check.Name == "personal-email" && check.Status == "exposed"
	}
	if !exposed {
		t.Fatalf("personal-email not exposed: %+v", got.Checks)
	}
	var text, encoded bytes.Buffer
	renderDoctorHuman(&text, got)
	if err := renderDoctorJSON(&encoded, got); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{text.String(), encoded.String()} {
		if strings.Contains(out, testPersonalEmail) {
			t.Fatalf("full address printed:\n%s", out)
		}
		if !strings.Contains(out, testPersonalMask+" (CLAUDE.md:1)") || !strings.Contains(out, "env OWNER_CONTACT") {
			t.Fatalf("finding missing from report:\n%s", out)
		}
	}
}

// The production entry point scans the env wrap passes: the secret fence
// decides what reaches the child, and wrap's proxy strip removes the proxy
// variables. GIT_AUTHOR_EMAIL and GIT_COMMITTER_EMAIL are reported by name.
func TestPersonalEmailDoctorCheckUsesChildEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_AUTHOR_EMAIL", testPersonalEmail)
	t.Setenv("GIT_COMMITTER_EMAIL", testPersonalEmail)
	t.Setenv("HTTPS_PROXY", "http://proxy.example.net/?owner="+testPersonalEmail)
	t.Setenv("NOCKTEST_BLOCKED_CONTACT", testPersonalEmail)
	cfg := &config.Config{}
	cfg.Filesystem.Root = root
	cfg.Secrets.Block = []string{"NOCKTEST_BLOCKED_*"}
	check := personalEmailDoctorCheck(cfg)
	for _, want := range []string{"env GIT_AUTHOR_EMAIL", "env GIT_COMMITTER_EMAIL"} {
		if !strings.Contains(check.Message, want) {
			t.Fatalf("message lacks %q: %+v", want, check)
		}
	}
	for _, stripped := range []string{"env HTTPS_PROXY", "env NOCKTEST_BLOCKED_CONTACT"} {
		if strings.Contains(check.Message, stripped) {
			t.Fatalf("reported %q, which wrap does not pass to the child: %+v", stripped, check)
		}
	}

	// A pass list (the default config has one) keeps everything else from the
	// child, so the git variables are not reported.
	cfg.Secrets.Pass = []string{"HOME", "PATH"}
	if check := personalEmailDoctorCheck(cfg); strings.Contains(check.Message, "env GIT_AUTHOR_EMAIL") {
		t.Fatalf("reported a variable the pass list withholds: %+v", check)
	}
}

// A whitespace-free line packed with addresses is scanned once, not once per
// match: a hostile instruction file cannot stall doctor.
func TestFindPersonalEmailsLongTokenIsLinear(t *testing.T) {
	line := strings.Repeat("a@b.co,", 30000)
	start := time.Now()
	if got := len(findPersonalEmails(line)); got != 30000 {
		t.Fatalf("found %d addresses, want 30000", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("scan took %s; it must not rescan the token per match", elapsed)
	}
}
