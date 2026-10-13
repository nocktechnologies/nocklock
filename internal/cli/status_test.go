package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/spf13/cobra"
)

func TestStatusReportsUnixSocketBoundaryReason(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix-socket isolation status is Linux-only")
	}
	setStatusTestState(t)
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, config.Dir), 0o700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, config.Dir, config.File), []byte(config.DefaultTOML()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(project)

	abi, abiErr := landlock.DetectABI()
	status, _ := unixSocketBoundaryStatus(abi, abiErr)
	want := "Unix-socket isolation: " + status + " (" + unixSocketBoundaryMessage(abi, abiErr) + ")"

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := statusCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), want) {
		t.Fatalf("status output missing %q:\n%s", want, out.String())
	}
}

// TestStatusNeverClaimsActive: right after init no wrap session exists, so
// status must say "configured" and never "active".
func TestStatusNeverClaimsActive(t *testing.T) {
	setStatusTestState(t)
	dir := t.TempDir()
	writeTestConfig(t, dir, config.DefaultTOML())
	withWorkingDir(t, dir)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	if err := statusCmd.RunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(strings.ToLower(got), "active (") || strings.Contains(got, ": active") {
		t.Fatalf("status claims an active fence:\n%s", got)
	}
	for _, want := range []string{"Secret fence: configured", "Filesystem fence: configured", "Network fence: configured", "no active session"} {
		if !strings.Contains(got, want) {
			t.Fatalf("status missing %q:\n%s", want, got)
		}
	}
}

func TestStatusDoesNotClaimUnixSocketIsolationOutsideConfinedEgress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix-socket isolation status is Linux-only")
	}
	setStatusTestState(t)
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, config.Dir), 0o700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	policy := `[filesystem]
root = "."

[network]
allow = ["example.com"]
allow_all = false

[syscall]
enforcement = "off"
`
	if err := os.WriteFile(filepath.Join(project, config.Dir, config.File), []byte(policy), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(project)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := statusCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("status: %v", err)
	}
	line := "Unix-socket isolation: not applicable (configured egress level is ADVISORY"
	if !strings.Contains(out.String(), line) || strings.Contains(out.String(), "Unix-socket isolation: enforceable") {
		t.Fatalf("status must not claim Unix-socket isolation without CONFINED egress; want %q:\n%s", line, out.String())
	}
}

func TestStatusReportsStrictUnixSocketRefusalBelowABI9(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix-socket isolation status is Linux-only")
	}
	abi, err := landlock.DetectABI()
	if err != nil {
		t.Fatalf("detect Landlock ABI: %v", err)
	}
	if abi >= landlock.MinUnixSocketABI {
		t.Skipf("strict refusal below ABI 9 is not applicable on ABI %d", abi)
	}
	setStatusTestState(t)
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, config.Dir), 0o700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	policy := strings.Replace(config.DefaultTOML(), "require_unix_socket_isolation = false", "require_unix_socket_isolation = true", 1)
	if err := os.WriteFile(filepath.Join(project, config.Dir, config.File), []byte(policy), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(project)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := statusCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), "Unix-socket isolation: unavailable") ||
		!strings.Contains(out.String(), "Wrap will refuse because network.require_unix_socket_isolation = true") {
		t.Fatalf("status must report strict wrap refusal below ABI 9:\n%s", out.String())
	}
}

func setStatusTestState(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))
}
