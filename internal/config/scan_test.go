package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSecretScanSettingsAreOptionalAndValidated(t *testing.T) {
	for _, tc := range []struct {
		name, toml string
		valid      bool
	}{
		{"old", "[secrets]\npass = [\"PATH\"]", true},
		{"enabled", "[secrets]\nscan_env=true\nscan_paths=[\"src\", \".env\"]\nscan_env_allow=[\"PROVIDER_KEY\"]", true},
		{"traversal", "[secrets]\nscan_paths=[\"../outside\"]", false},
		{"absolute", "[secrets]\nscan_paths=[\"/tmp\"]", false},
		{"empty", "[secrets]\nscan_paths=[\"\"]", false},
		{"glob", "[secrets]\nscan_env_allow=[\"*_KEY\"]", false},
		{"value", "[secrets]\nscan_env_allow=[\"KEY=value\"]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t, err=%v", tc.valid, err)
			}
			if tc.name == "old" && (cfg.Secrets.ScanEnv || len(cfg.Secrets.ScanPaths) > 0) {
				t.Fatal("old config enabled preflight")
			}
			if tc.name == "enabled" && !strings.Contains(cfg.EffectivePolicy(), "required before launch") {
				t.Fatal("missing policy summary")
			}
		})
	}
}

func TestOverlayCannotWeakenSecretPreflight(t *testing.T) {
	base := DefaultConfig()
	base.Secrets.ScanEnv = true
	base.Secrets.ScanPaths = []string{"src"}
	base.Secrets.ScanEnvAllow = []string{"PROVIDER_KEY"}
	path := filepath.Join(t.TempDir(), "overlay.toml")
	if err := os.WriteFile(path, []byte("[secrets]\nscan_env=false\nscan_paths=[\".env\"]\nscan_env_allow=[\"PROVIDER_KEY\", \"EXTRA_KEY\"]"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOverlay(base, path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Secrets.ScanEnv || !slices.Equal(got.Secrets.ScanPaths, []string{"src", ".env"}) || !slices.Equal(got.Secrets.ScanEnvAllow, []string{"PROVIDER_KEY"}) {
		t.Fatalf("overlay weakened scan: %+v", got.Secrets)
	}
	got.Secrets.ScanPaths[0] = "changed"
	if base.Secrets.ScanPaths[0] != "src" {
		t.Fatal("overlay mutated base")
	}
}
