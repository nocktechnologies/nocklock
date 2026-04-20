package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

// TestRemoveEnvVars covers the removeEnvVars helper used to clear NO_PROXY.
func TestRemoveEnvVarsRemovesMatchingKeys(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"NO_PROXY=localhost",
		"no_proxy=127.0.0.1",
		"PATH=/usr/bin",
	}
	result := removeEnvVars(env, "NO_PROXY", "no_proxy")

	for _, entry := range result {
		if strings.HasPrefix(entry, "NO_PROXY=") || strings.HasPrefix(entry, "no_proxy=") {
			t.Errorf("removeEnvVars left %q in result", entry)
		}
	}
	if len(result) != 2 {
		t.Errorf("expected 2 remaining entries, got %d: %v", len(result), result)
	}
}

func TestRemoveEnvVarsPreservesOtherVars(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin", "TERM=xterm"}
	result := removeEnvVars(env, "NO_PROXY")
	if len(result) != len(env) {
		t.Errorf("expected %d entries unchanged, got %d", len(env), len(result))
	}
}

func TestRemoveEnvVarsEmptyInput(t *testing.T) {
	result := removeEnvVars(nil, "NO_PROXY")
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestRemoveEnvVarsNoKeysSpecified(t *testing.T) {
	env := []string{"A=1", "B=2"}
	result := removeEnvVars(env)
	if len(result) != 2 {
		t.Errorf("expected 2 entries with no keys to remove, got %d", len(result))
	}
}

func TestRemoveEnvVarsExactKeyWithoutEquals(t *testing.T) {
	// An env entry without "=" is unusual but should match on bare key.
	env := []string{"WEIRD_ENTRY", "NORMAL=value"}
	result := removeEnvVars(env, "WEIRD_ENTRY")
	if len(result) != 1 || result[0] != "NORMAL=value" {
		t.Errorf("expected only NORMAL=value, got %v", result)
	}
}

func TestWrapDryRunValidatesConfigWithoutCommand(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, config.DefaultTOML())
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--dry-run"})
	if err != nil {
		t.Fatalf("dry run should validate config without a child command: %v", err)
	}
}

func TestWrapDryRunRejectsMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, "[network]\nallow_all = \"sometimes\"\n")
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--dry-run"})
	if err == nil {
		t.Fatal("expected dry run to reject malformed config")
	}
	if !strings.Contains(err.Error(), "failed to load config") {
		t.Fatalf("expected config load error, got: %v", err)
	}
}

func TestWrapDryRunRequiresConfig(t *testing.T) {
	dir := t.TempDir()
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--dry-run"})
	if err == nil {
		t.Fatal("expected dry run to fail without config")
	}
	if !strings.Contains(err.Error(), "no NockLock config found") {
		t.Fatalf("expected missing config error, got: %v", err)
	}
}

func writeTestConfig(t *testing.T, dir, contents string) {
	t.Helper()
	nockDir := filepath.Join(dir, config.Dir)
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nockDir, config.File), []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}
