package cli

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
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
	writeTestConfig(t, dir, dryRunTestTOML())
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

func TestWrapDryRunPrintsAllowPrivateRangesFlag(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, dryRunTestTOML())
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = wrapCmd.RunE(cmd, []string{"--dry-run", "--allow-private-ranges"})
	})
	if runErr != nil {
		t.Fatalf("dry run should accept allow-private-ranges flag: %v", runErr)
	}
	if !strings.Contains(stdout, "private_ranges=allowed") {
		t.Fatalf("dry run policy should show private ranges allowed, got:\n%s", stdout)
	}
}

func TestEffectiveWrapConfigPreservesAllowPrivateRanges(t *testing.T) {
	cfg := config.DefaultConfig()

	effective := effectiveWrapConfig(&cfg, WrapFlags{AllowPrivateRanges: true})
	if !effective.Network.AllowPrivateRanges {
		t.Fatal("expected allow-private-ranges CLI flag to be reflected in effective config")
	}

	cfg.Network.AllowPrivateRanges = true
	effective = effectiveWrapConfig(&cfg, WrapFlags{})
	if !effective.Network.AllowPrivateRanges {
		t.Fatal("expected config allow_private_ranges to be preserved in effective config")
	}
}

func TestValidateWrapRuntimeConfigRejectsUnsupportedFilesystemFence(t *testing.T) {
	if fsfence.IsSupported() {
		t.Skip("filesystem fence is supported on this platform")
	}

	cfg := config.DefaultConfig()
	err := validateWrapRuntimeConfig(&cfg)
	if err == nil {
		t.Fatal("expected configured filesystem fence to fail closed on unsupported platform")
	}
	if !strings.Contains(err.Error(), "filesystem fence configured but not supported on "+runtime.GOOS) {
		t.Fatalf("expected unsupported filesystem fence error, got: %v", err)
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

func dryRunTestTOML() string {
	return strings.Replace(config.DefaultTOML(), "[filesystem]\nroot = \".\"", "[filesystem]\nroot = \"\"", 1)
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

// withWorkingDir uses os.Chdir, which mutates global process state for every
// goroutine. t.Cleanup restores the previous cwd after the test, but tests that
// call withWorkingDir must not call t.Parallel(); use a subprocess-style helper
// if cwd-sensitive assertions need parallel execution.
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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	defer r.Close()
	os.Stdout = w
	defer func() {
		os.Stdout = orig
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	return string(out)
}
