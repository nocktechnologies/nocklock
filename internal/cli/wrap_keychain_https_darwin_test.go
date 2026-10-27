//go:build darwin

package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

// This live control uses public HTTPS and system certificate validation: a
// private CA or insecure TLS option would mask a broken trust-service boundary.
// CI opts in explicitly; ordinary offline unit runs do not contact GitHub.
func TestWrapMacOSKeychainHTTPSCompatibility(t *testing.T) {
	if os.Getenv("NOCKLOCK_KEYCHAIN_HTTPS_REQUIRE") != "1" {
		t.Skip("live GitHub HTTPS controls require NOCKLOCK_KEYCHAIN_HTTPS_REQUIRE=1")
	}
	requireSandboxExecForWrap(t)
	project := t.TempDir()
	probe := filepath.Join(project, "go-https-probe")
	buildCtx, buildCancel := context.WithTimeout(context.Background(), time.Minute)
	defer buildCancel()
	if out, err := exec.CommandContext(buildCtx, "go", "build", "-o", probe, "testdata/https_probe.go").CombinedOutput(); err != nil {
		t.Fatalf("build Go HTTPS probe: %v\n%s", err, out)
	}
	claudeBinary := os.Getenv("NOCKLOCK_KEYCHAIN_CLAUDE_BINARY")
	if claudeBinary != "" && !filepath.IsAbs(claudeBinary) {
		t.Fatal("NOCKLOCK_KEYCHAIN_CLAUDE_BINARY must be an absolute installed executable path")
	}
	t.Setenv("HOME", isolatedTestHome(t))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// The preset permits these variables; no provider credential is needed.
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	body, err := config.ProfileTOML("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	writeTestConfig(t, project, body)
	withWorkingDir(t, project)
	script := `set -eu
: "${HTTPS_PROXY:?NockLock proxy must be configured}"
/usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin /usr/bin/curl -q \
  --proxy "$HTTPS_PROXY" --noproxy '' --max-time 45 --fail --silent --show-error \
  https://github.com/ -o "$1/https.html"
/usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin HTTPS_PROXY="$HTTPS_PROXY" \
  "$1/go-https-probe" > "$1/go-https.txt"
/usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false \
  /usr/bin/git -c credential.helper= -c http.proxy="$HTTPS_PROXY" \
  -c http.sslVerify=true -c http.lowSpeedLimit=1 -c http.lowSpeedTime=45 \
  ls-remote https://github.com/nocktechnologies/nocklock.git HEAD > "$1/git-head.txt"
if [ -n "$2" ]; then
  /usr/bin/env -i HOME="$HOME" PATH=/opt/homebrew/bin:/usr/bin:/bin \
    HTTPS_PROXY="$HTTPS_PROXY" "$2" --version > "$1/claude-version.txt"
fi
printf preset-launch-ok > "$1/preset.txt"
`
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	if err := wrapCmd.RunE(cmd, []string{"--profile", "claude-code", "--require-enforced-egress",
		"--", "/bin/sh", "-c", script, "sh", project, claudeBinary}); err != nil {
		t.Fatalf("HTTPS/git controls under the Claude Code preset failed: %v", err)
	}
	page, err := os.ReadFile(filepath.Join(project, "https.html"))
	if err != nil || len(page) == 0 {
		t.Fatalf("HTTPS fetch returned no page: %v", err)
	}
	goResult, err := os.ReadFile(filepath.Join(project, "go-https.txt"))
	if err != nil || strings.TrimSpace(string(goResult)) != "go-https-ok" {
		t.Fatalf("Go system-root HTTPS failed: %q, %v", goResult, err)
	}
	ref, err := os.ReadFile(filepath.Join(project, "git-head.txt"))
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{40,64}\s+HEAD\s*$`).Match(ref) {
		t.Fatalf("git ls-remote returned no valid HEAD: %q, %v", ref, err)
	}
	launch, err := os.ReadFile(filepath.Join(project, "preset.txt"))
	if err != nil || strings.TrimSpace(string(launch)) != "preset-launch-ok" {
		t.Fatalf("preset launch did not finish: %q, %v", launch, err)
	}
	if claudeBinary != "" {
		version, err := os.ReadFile(filepath.Join(project, "claude-version.txt"))
		if err != nil || !strings.Contains(string(version), "Claude Code") {
			t.Fatalf("installed Claude Code launch failed: %q, %v", version, err)
		}
		t.Logf("Installed Claude Code launch: %s", strings.TrimSpace(string(version)))
	}
	t.Log("PASS: system curl and Go HTTPS, system git ls-remote HTTPS, and claude-code preset launch with enforced proxy egress")
}
