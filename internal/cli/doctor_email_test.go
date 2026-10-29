package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
