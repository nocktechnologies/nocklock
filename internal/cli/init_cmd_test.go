package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

func TestInitConfigBodyRuntimeUsesEmbeddedProfile(t *testing.T) {
	body, runtimeName, err := initConfigBody(" aider ")
	if err != nil {
		t.Fatalf("initConfigBody(aider): %v", err)
	}
	if runtimeName != "aider" {
		t.Fatalf("runtimeName = %q, want aider", runtimeName)
	}
	if !strings.Contains(body, `name = "aider"`) || !strings.Contains(body, "api.anthropic.com") {
		t.Fatalf("runtime body did not contain aider preset:\n%s", body)
	}
}

func TestInitConfigBodyUnknownRuntimeFailsClosed(t *testing.T) {
	_, _, err := initConfigBody("missing")
	if err == nil {
		t.Fatal("expected unknown runtime to fail")
	}
	if !strings.Contains(err.Error(), `unknown profile "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "valid profiles: [aider claude-code codex gemini-cli goose opencode]") {
		t.Fatalf("error did not list valid profiles: %v", err)
	}
}

func TestInitRuntimeRoundTripsThroughConfigLoad(t *testing.T) {
	for _, runtimeName := range []string{"aider", "gemini-cli", "opencode"} {
		t.Run(runtimeName, func(t *testing.T) {
			dir := t.TempDir()
			withWorkingDir(t, dir)
			initRuntime = runtimeName
			t.Cleanup(func() { initRuntime = "" })

			if err := initCmd.RunE(&cobra.Command{}, nil); err != nil {
				t.Fatalf("init --runtime %s: %v", runtimeName, err)
			}

			configPath := filepath.Join(dir, config.Dir, config.File)
			cfg, err := config.Load(configPath)
			if err != nil {
				t.Fatalf("Load(%s): %v", configPath, err)
			}
			want, err := config.LoadProfile(runtimeName)
			if err != nil {
				t.Fatalf("LoadProfile(%s): %v", runtimeName, err)
			}
			want.ProfileName = ""
			if !reflect.DeepEqual(cfg, want) {
				t.Fatalf("init config mismatch\n got: %+v\nwant: %+v", cfg, want)
			}
			info, err := os.Stat(configPath)
			if err != nil {
				t.Fatalf("stat config: %v", err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Fatalf("config mode = %v, want 0600", got)
			}
		})
	}
}

func TestInitRuntimeOnExistingConfigFailsAndDiffReports(t *testing.T) {
	dir := t.TempDir()
	withWorkingDir(t, dir)
	t.Cleanup(func() { initRuntime, initDiff = "", false })
	if err := initCmd.RunE(&cobra.Command{}, nil); err != nil {
		t.Fatalf("plain init: %v", err)
	}
	configPath := filepath.Join(dir, config.Dir, config.File)
	before, _ := os.ReadFile(configPath)

	initRuntime = "claude-code"
	err := initCmd.RunE(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "--diff") {
		t.Fatalf("want non-zero error pointing at --diff, got %v", err)
	}

	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	initDiff = true
	if err := initCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("init --diff: %v", err)
	}
	if !strings.Contains(out.String(), "+ ") || !strings.Contains(out.String(), "CLAUDE_CODE_OAUTH_TOKEN") {
		t.Fatalf("diff missing preset additions:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "- ") || !strings.Contains(out.String(), "*_TOKEN*") {
		t.Fatalf("diff missing removed *_TOKEN* block:\n%s", out.String())
	}
	after, _ := os.ReadFile(configPath)
	if string(before) != string(after) {
		t.Fatal("--diff modified the config")
	}

	// Matching config reports no difference; --diff without --runtime errors.
	if err := os.WriteFile(configPath, []byte(mustProfileTOML(t, "claude-code")), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := initCmd.RunE(cmd, nil); err != nil || !strings.Contains(out.String(), "already matches") {
		t.Fatalf("identical config: err=%v out=%q", err, out.String())
	}
	initRuntime = ""
	if err := initCmd.RunE(cmd, nil); err == nil {
		t.Fatal("--diff without --runtime must fail")
	}
}

func mustProfileTOML(t *testing.T, name string) string {
	t.Helper()
	s, err := config.ProfileTOML(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
