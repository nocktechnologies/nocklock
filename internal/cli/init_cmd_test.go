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
