package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func scanToken() string { return "ghp_" + strings.Repeat("aB3x", 9) }

func scanTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	withWorkingDir(t, dir)
	t.Setenv("HOME", dir)
	return dir
}

func TestScanCommandJSONAndExitStatus(t *testing.T) {
	for _, kind := range []string{"clean", "finding", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			dir := scanTestDir(t)
			body := "ordinary prose"
			if kind == "finding" {
				body = scanToken()
			}
			if kind != "incomplete" {
				if err := os.WriteFile(filepath.Join(dir, "input"), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := newScanCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"--json", "input"})
			err := cmd.Execute()
			if (err == nil) != (kind == "clean") {
				t.Fatalf("wrong exit: %v", err)
			}
			var report secrets.ScanReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if report.Safe() != (kind == "clean") || report.Complete != (kind != "incomplete") {
				t.Fatalf("wrong report: %+v", report)
			}
			if strings.Contains(out.String(), scanToken()) {
				t.Fatal("CLI exposed a value")
			}
		})
	}
}

func TestWrapSecretPreflightControlsChildLaunch(t *testing.T) {
	for _, kind := range []string{"clean", "env-finding", "file-finding", "missing", "disabled", "exception", "name-filtered"} {
		t.Run(kind, func(t *testing.T) {
			dir := scanTestDir(t)
			toml := plainLaunchTOML(t)
			if kind != "disabled" {
				toml = strings.Replace(toml, "scan_env = false", "scan_env = true", 1)
			}
			if kind == "file-finding" || kind == "missing" {
				toml = strings.Replace(toml, "scan_paths = []", "scan_paths = [\"input\"]", 1)
				if kind == "file-finding" {
					if err := os.WriteFile(filepath.Join(dir, "input"), []byte(scanToken()), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if kind == "exception" {
				toml = strings.Replace(toml, "scan_env_allow = []", "scan_env_allow = [\"USER\"]", 1)
			}
			if kind == "env-finding" || kind == "disabled" || kind == "exception" {
				t.Setenv("USER", scanToken())
			}
			if kind == "name-filtered" {
				t.Setenv("AWS_ACCESS_KEY_ID", "AKIA"+strings.Repeat("A", 16))
			}
			writeTestConfig(t, dir, toml)
			marker := filepath.Join(dir, "child-started")
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			var out bytes.Buffer
			cmd.SetErr(&out)
			err := wrapCmd.RunE(cmd, []string{"--", "sh", "-c", `printf started > "$1"`, "sh", marker})
			blocked := kind == "env-finding" || kind == "file-finding" || kind == "missing"
			if (err != nil) != blocked {
				t.Fatalf("unexpected launch error: %v", err)
			}
			_, statErr := os.Stat(marker)
			if blocked && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("refused child executed")
			}
			if !blocked && statErr != nil {
				t.Fatalf("clean child did not execute: %v", statErr)
			}
			if strings.Contains(out.String(), scanToken()) {
				t.Fatal("preflight exposed a value")
			}
			logger, err := logging.NewLogger(filepath.Join(dir, ".nock", "events.db"), dir)
			if err != nil {
				t.Fatal(err)
			}
			defer logger.Close()
			events, err := logger.Query(logging.QueryOptions{Limit: 10000})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			fenceEvents := 0
			lastFenceEventIndex := -1
			preflightIndex := -1
			for i, event := range events {
				if strings.Contains(event.Detail, scanToken()) {
					t.Fatal("audit retained a secret value")
				}
				if strings.HasPrefix(event.Detail, "preflight ") {
					found = true
					preflightIndex = i
					if event.Blocked != blocked {
						t.Fatal("wrong preflight audit outcome")
					}
				} else if event.Category == "secret" && (event.EventType == logging.EventSecretBlocked || event.EventType == logging.EventSecretPassed) {
					fenceEvents++
					lastFenceEventIndex = i
				}
			}
			if found != (kind != "disabled") {
				t.Fatal("preflight audit missing or unexpectedly enabled")
			}
			if blocked && (fenceEvents == 0 || preflightIndex <= lastFenceEventIndex) {
				t.Fatal("refused preflight omitted or preceded secret-fence audit events")
			}
		})
	}
}

func TestSecretPreflightRefusesWhenAuditFails(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Secrets.ScanEnv = true
	err := runSecretPreflight(context.Background(), &cfg, ".nock/config.toml", []string{"USER=clean"}, "test", func([]logging.Event) error { return errors.New("audit unavailable") }, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("audit failure ignored: %v", err)
	}
}

func TestSecretPreflightUsesProjectRootFromNestedDirectory(t *testing.T) {
	dir := scanTestDir(t)
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "input"), []byte(scanToken()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Join(dir, "subdir")); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Secrets.ScanPaths = []string{"input"}
	var recorded []logging.Event
	err := runSecretPreflight(context.Background(), &cfg, filepath.Join(dir, ".nock", "config.toml"), nil, "test", func(e []logging.Event) error { recorded = e; return nil }, io.Discard)
	if err == nil || len(recorded) != 2 || !strings.Contains(recorded[0].Detail, "github-token") {
		t.Fatalf("scan did not use project root: %v", err)
	}
}

func TestSecretPreflightDryRunDoesNotScanOrCreateAuditLog(t *testing.T) {
	dir := scanTestDir(t)
	toml := strings.Replace(plainLaunchTOML(t), "scan_paths = []", "scan_paths = [\"missing\"]", 1)
	writeTestConfig(t, dir, toml)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--dry-run"}); err != nil {
		t.Fatalf("dry run executed preflight: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".nock", "events.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created audit DB")
	}
}

func TestSecretPreflightExceptionsCannotOverrideNameBlocks(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Secrets.ScanEnv = true
	cfg.Secrets.ScanEnvAllow = []string{"AWS_ACCESS_KEY_ID"}
	fence, err := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block)
	if err != nil {
		t.Fatal(err)
	}
	filtered, blocked := fence.Filter([]string{"AWS_ACCESS_KEY_ID=AKIA" + strings.Repeat("A", 16)})
	if len(filtered) != 0 || len(blocked) != 1 {
		t.Fatal("name block weakened")
	}
	err = runSecretPreflight(context.Background(), &cfg, ".nock/config.toml", filtered, "test", func([]logging.Event) error { return nil }, io.Discard)
	if err != nil {
		t.Fatalf("removed variable should not cause a scan refusal: %v", err)
	}
}
