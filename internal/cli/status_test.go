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
